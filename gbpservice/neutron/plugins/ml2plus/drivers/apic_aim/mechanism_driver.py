# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sqlalchemy as sa

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim.common import utils
from aim import config as aim_cfg
from aim import context as aim_context
from aim import utils as aim_utils
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions
from neutron.common import topics as n_topics
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models
from opflexagent import constants as ofcst
from opflexagent import rpc as ofrpc
from oslo_log import log

from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_l3 as a_l3
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import extension_db
from oslo_serialization.jsonutils import netaddr

LOG = log.getLogger(__name__)

DEVICE_OWNER_SNAT_PORT = 'apic:snat-pool'


# REVISIT(rkukura): Consider making these APIC name constants
# configurable, although changing them would break an existing
# deployment.

ANY_FILTER_NAME = 'AnyFilter'
ANY_FILTER_ENTRY_NAME = 'AnyFilterEntry'
DEFAULT_VRF_NAME = 'DefaultVRF'
UNROUTED_VRF_NAME = 'UnroutedVRF'
COMMON_TENANT_NAME = 'common'
ROUTER_SUBJECT_NAME = 'route'

AGENT_TYPE_DVS = 'DVS agent'
VIF_TYPE_DVS = 'dvs'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]


class UnsupportedRoutingTopology(exceptions.BadRequest):
    message = _("All router interfaces for a network must share either the "
                "same router or the same subnet.")


class SnatPortsInUse(exceptions.SubnetInUse):
    def __init__(self, **kwargs):
        kwargs['reason'] = _('Subnet has SNAT IP addresses allocated')
        super(SnatPortsInUse, self).__init__(**kwargs)


class SnatPoolCannotBeUsedForFloatingIp(exceptions.InvalidInput):
    message = _("Floating IP cannot be allocated in SNAT host pool subnet.")


NO_ADDR_SCOPE = object()


class ApicMechanismDriver(api_plus.MechanismDriver):
    # TODO(rkukura): Derivations of tenant_aname throughout need to
    # take sharing into account.

    def __init__(self):
        LOG.info(_LI("APIC AIM MD __init__"))

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))
        self.project_name_cache = cache.ProjectNameCache()
        self.name_mapper = apic_mapper.APICNameMapper()
        self.aim = aim_manager.AimManager()
        self._core_plugin = None
        self._l3_plugin = None
        self.aim_cfg_mgr = aim_cfg.ConfigManager(
            aim_context.AimContext(db_api.get_session()),
            host=aim_cfg.CONF.host)
        # Get APIC configuration and subscribe for changes
        self.enable_metadata_opt = self.aim_cfg_mgr.get_option_and_subscribe(
            self._set_enable_metadata_opt, 'enable_optimized_metadata', 'apic')
        self.enable_dhcp_opt = self.aim_cfg_mgr.get_option_and_subscribe(
            self._set_enable_dhcp_opt, 'enable_optimized_dhcp', 'apic')
        self.ap_name = self.aim_cfg_mgr.get_option_and_subscribe(
            self._set_ap_name, 'apic_app_profile_name', 'apic')
        self.notifier = ofrpc.AgentNotifierApi(n_topics.AGENT)

    def ensure_tenant(self, plugin_context, tenant_id):
        LOG.debug("APIC AIM MD ensuring tenant_id: %s", tenant_id)

        if not tenant_id:
            # The l3_db module creates gateway ports with empty string
            # project IDs in order to hide those ports from
            # users. Since we are not currently mapping ports to
            # anything in AIM, we can ignore these. Any other cases
            # where empty string project IDs are used may require
            # mapping AIM resources under some actual Tenant.
            return

        self.project_name_cache.ensure_project(tenant_id)

        # TODO(rkukura): Move the following to calls made from
        # precommit methods so AIM Tenants, ApplicationProfiles, and
        # Filters are [re]created whenever needed.
        session = plugin_context.session
        with session.begin(subtransactions=True):
            tenant_aname = self._get_tenant_name(session, tenant_id)

            aim_ctx = aim_context.AimContext(session)

            tenant = aim_resource.Tenant(name=tenant_aname)
            if not self.aim.get(aim_ctx, tenant):
                self.aim.create(aim_ctx, tenant)
            ap = aim_resource.ApplicationProfile(tenant_name=tenant_aname,
                                                 name=self.ap_name)
            if not self.aim.get(aim_ctx, ap):
                self.aim.create(aim_ctx, ap)

            filter = aim_resource.Filter(tenant_name=tenant_aname,
                                         name=ANY_FILTER_NAME,
                                         display_name='Any Filter')
            if not self.aim.get(aim_ctx, filter):
                self.aim.create(aim_ctx, filter)

            entry = aim_resource.FilterEntry(tenant_name=tenant_aname,
                                             filter_name=ANY_FILTER_NAME,
                                             name=ANY_FILTER_ENTRY_NAME,
                                             display_name='Any FilterEntry')
            if not self.aim.get(aim_ctx, entry):
                self.aim.create(aim_ctx, entry)

    def create_network_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating network: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        if self._is_external(current):
            l3out, ext_net, ns = self._get_aim_nat_strategy(current)
            if not ext_net:
                return  # Unmanaged external network
            ns.create_l3outside(aim_ctx, l3out)
            ns.create_external_network(aim_ctx, ext_net)
            ns.update_external_cidrs(aim_ctx, ext_net,
                                     current[cisco_apic.EXTERNAL_CIDRS])
        else:
            bd, epg = self._map_network(session, current)

            dname = aim_utils.sanitize_display_name(current['name'])
            vrf = self._ensure_unrouted_vrf(aim_ctx)
            vmms, phys = self.get_aim_domains(aim_ctx)

            bd.display_name = dname
            bd.vrf_name = vrf.name
            bd.enable_arp_flood = True
            bd.enable_routing = False
            bd.limit_ip_learn_to_subnets = True
            # REVISIT(rkukura): When AIM changes default
            # ep_move_detect_mode value to 'garp', remove it here.
            bd.ep_move_detect_mode = 'garp'
            self.aim.create(aim_ctx, bd)

            epg.display_name = dname
            epg.bd_name = bd.name
            epg.openstack_vmm_domain_names = vmms
            epg.physical_domain_names = phys
            self.aim.create(aim_ctx, epg)

    def update_network_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating network: %s", current)

        # TODO(amitbose) - Handle inter-conversion between external and
        # private networks

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        is_ext = self._is_external(current)
        if (not is_ext and
            current['name'] != original['name']):

            bd, epg = self._map_network(session, current)

            dname = aim_utils.sanitize_display_name(current['name'])

            self.aim.update(aim_ctx, bd, display_name=dname)
            self.aim.update(aim_ctx, epg, display_name=dname)

        if is_ext:
            _, ext_net, ns = self._get_aim_nat_strategy(current)
            if ext_net:
                old = sorted(original[cisco_apic.EXTERNAL_CIDRS])
                new = sorted(current[cisco_apic.EXTERNAL_CIDRS])
                if old != new:
                    ns.update_external_cidrs(aim_ctx, ext_net, new)
                # TODO(amitbose) Propagate name updates to AIM

    def delete_network_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting network: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        if self._is_external(current):
            l3out, ext_net, ns = self._get_aim_nat_strategy(current)
            if not ext_net:
                return  # Unmanaged external network
            ns.delete_external_network(aim_ctx, ext_net)
            # TODO(amitbose) delete L3out only if no other Neutron
            # network is using the L3out
            ns.delete_l3outside(aim_ctx, l3out)
        else:
            bd, epg = self._map_network(session, current)

            self.aim.delete(aim_ctx, epg)
            self.aim.delete(aim_ctx, bd)

            self.name_mapper.delete_apic_name(session, current['id'])

    def extend_network_dict(self, session, network_db, result):
        LOG.debug("APIC AIM MD extending dict for network: %s", result)

        sync_state = cisco_apic.SYNC_NOT_APPLICABLE
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        if network_db.external is not None:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if ext_net:
                sync_state = self._merge_status(aim_ctx, sync_state, ext_net)
                kls = {aim_resource.BridgeDomain: cisco_apic.BD,
                       aim_resource.EndpointGroup: cisco_apic.EPG,
                       aim_resource.VRF: cisco_apic.VRF}
                for o in (ns.get_l3outside_resources(aim_ctx, l3out) or []):
                    if type(o) in kls:
                        dist_names[kls[type(o)]] = o.dn
                        sync_state = self._merge_status(aim_ctx, sync_state,
                                                        o)
        else:
            # REVISIT(rkukura): Consider optimizing this method by
            # persisting the network->VRF relationship.

            bd, epg = self._map_network(session, network_db)

            dist_names[cisco_apic.BD] = bd.dn
            sync_state = self._merge_status(aim_ctx, sync_state, bd)

            dist_names[cisco_apic.EPG] = epg.dn
            sync_state = self._merge_status(aim_ctx, sync_state, epg)

            # See if this network is interfaced to any routers.
            rp = (session.query(l3_db.RouterPort).
                  join(models_v2.Port).
                  filter(models_v2.Port.network_id == network_db.id,
                         l3_db.RouterPort.port_type ==
                         n_constants.DEVICE_OWNER_ROUTER_INTF).first())
            if rp:
                # A network is constrained to only one subnetpool per
                # address family. To support both single and dual
                # stack, use the IPv4 address scope's VRF if it
                # exists, and otherwise use the IPv6 address scope's
                # VRF. For dual stack, the plan is for identity NAT to
                # move IPv6 traffic from the IPv4 address scope's VRF
                # to the IPv6 address scope's VRF.
                #
                # REVISIT(rkukura): Ignore subnets that are not
                # attached to any router, or maybe just do a query
                # joining RouterPorts, Ports, Subnets, SubnetPools and
                # AddressScopes.
                pool_dbs = {subnet.subnetpool
                            for subnet in network_db.subnets
                            if subnet.subnetpool}
                scope_id = None
                for pool_db in pool_dbs:
                    if pool_db.ip_version == 4:
                        scope_id = pool_db.address_scope_id
                        break
                    elif pool_db.ip_version == 6:
                        scope_id = pool_db.address_scope_id
                if scope_id:
                    scope_db = self._scope_by_id(session, scope_id)
                    vrf = self._map_address_scope(session, scope_db)
                else:
                    router_db = (session.query(l3_db.Router).
                                 filter_by(id=rp.router_id).
                                 one())
                    vrf = self._map_default_vrf(session, router_db)
            else:
                vrf = self._map_unrouted_vrf()

            dist_names[cisco_apic.VRF] = vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_subnet_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        if network_db.external is not None and current['gateway_ip']:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            ns.create_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(current))

        # Neutron subnets in non-external networks are mapped to AIM
        # Subnets as they are added to routers as interfaces.

    def update_subnet_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        is_ext = network_db.external is not None
        session = context._plugin_context.session

        # If subnet is no longer a SNAT pool, check if SNAT IP ports
        # are allocated
        if (is_ext and original[cisco_apic.SNAT_HOST_POOL] and
            not current[cisco_apic.SNAT_HOST_POOL] and
            self._has_snat_ip_ports(context._plugin_context, current['id'])):
                raise SnatPortsInUse(subnet_id=current['id'])

        if (not is_ext and
            current['name'] != original['name']):

            bd = self._map_network(session, network_db, True)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            current['id']):
                router_db = self.l3_plugin._get_router(context._plugin_context,
                                                       router_id)
                dname = aim_utils.sanitize_display_name(
                    router_db.name + " - " +
                    (current['name'] or current['cidr']))

                sn = self._map_subnet(current, gw_ip, bd)
                self.aim.update(aim_ctx, sn, display_name=dname)

        elif (is_ext and current['gateway_ip'] != original['gateway_ip']):

            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            ns.delete_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(original))
            ns.create_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(current))

    def delete_subnet_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        if network_db.external is not None and current['gateway_ip']:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            ns.delete_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(current))

        # Non-external neutron subnets are unmapped from AIM Subnets as
        # they are removed from routers.

    def extend_subnet_dict(self, session, subnet_db, result):
        LOG.debug("APIC AIM MD extending dict for subnet: %s", result)

        sync_state = cisco_apic.SYNC_NOT_APPLICABLE
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        network_db = (session.query(models_v2.Network).
                      filter_by(id=subnet_db.network_id).
                      one())
        if network_db.external is not None:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if ext_net:
                sub = ns.get_subnet(aim_ctx, l3out,
                                    self._subnet_to_gw_ip_mask(subnet_db))
                if sub:
                    dist_names[cisco_apic.SUBNET] = sub.dn
                    sync_state = self._merge_status(aim_ctx, sync_state, sub)
        else:
            bd = self._map_network(session, network_db, True)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            subnet_db.id):
                sn = self._map_subnet(subnet_db, gw_ip, bd)
                dist_names[gw_ip] = sn.dn
                sync_state = self._merge_status(aim_ctx, sync_state, sn)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    # TODO(rkukura): Implement update_subnetpool_precommit to handle
    # changing subnetpool's address_scope_id.

    def create_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        dname = aim_utils.sanitize_display_name(current['name'])

        vrf = self._map_address_scope(session, current)
        vrf.display_name = dname
        self.aim.create(aim_ctx, vrf)

        # ML2Plus does not extend address scope dict after precommit.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, vrf)
        current[cisco_apic.DIST_NAMES] = {cisco_apic.VRF: vrf.dn}
        current[cisco_apic.SYNC_STATE] = sync_state

    def update_address_scope_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating address_scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        if current['name'] != original['name']:
            dname = aim_utils.sanitize_display_name(current['name'])

            vrf = self._map_address_scope(session, current)

            self.aim.update(aim_ctx, vrf, display_name=dname)

    def delete_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        vrf = self._map_address_scope(session, current)

        self.aim.delete(aim_ctx, vrf)

        self.name_mapper.delete_apic_name(session, current['id'])

    def extend_address_scope_dict(self, session, scope_db, result):
        LOG.debug("APIC AIM MD extending dict for address scope: %s", result)

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        vrf = self._map_address_scope(session, scope_db)

        dist_names[cisco_apic.VRF] = vrf.dn
        sync_state = self._merge_status(aim_ctx, sync_state, vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_router(self, context, current):
        LOG.debug("APIC AIM MD creating router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        contract, subject = self._map_router(session, current)

        dname = aim_utils.sanitize_display_name(current['name'])

        contract.display_name = dname
        self.aim.create(aim_ctx, contract)

        subject.display_name = dname
        subject.bi_filters = [ANY_FILTER_NAME]
        self.aim.create(aim_ctx, subject)

        # External-gateway information about the router will be handled
        # when the first router-interface port is created

        # REVISIT(rkukura): Consider having L3 plugin extend router
        # dict again after calling this function.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, contract)
        sync_state = self._merge_status(aim_ctx, sync_state, subject)
        current[cisco_apic.DIST_NAMES] = {a_l3.CONTRACT: contract.dn,
                                          a_l3.CONTRACT_SUBJECT:
                                          subject.dn}
        current[cisco_apic.SYNC_STATE] = sync_state

    def update_router(self, context, current, original):
        LOG.debug("APIC AIM MD updating router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        if current['name'] != original['name']:
            contract, subject = self._map_router(session, current)

            name = current['name']
            dname = aim_utils.sanitize_display_name(name)

            self.aim.update(aim_ctx, contract, display_name=dname)
            self.aim.update(aim_ctx, subject, display_name=dname)

            # REVISIT(rkukura): Refactor to share common code below
            # with extend_router_dict. Also consider using joins to
            # fetch the subnet_db and network_db as part of the
            # initial query.
            for intf in (session.query(models_v2.IPAllocation).
                         join(models_v2.Port).
                         join(l3_db.RouterPort).
                         filter(l3_db.RouterPort.router_id == current['id'],
                                l3_db.RouterPort.port_type ==
                                n_constants.DEVICE_OWNER_ROUTER_INTF)):

                subnet_db = (session.query(models_v2.Subnet).
                             filter_by(id=intf.subnet_id).
                             one())
                network_db = (session.query(models_v2.Network).
                              filter_by(id=subnet_db.network_id).
                              one())

                dname = aim_utils.sanitize_display_name(
                    name + " - " + (subnet_db.name or subnet_db.cidr))

                bd = self._map_network(session, network_db, True)
                sn = self._map_subnet(subnet_db, intf.ip_address, bd)

                self.aim.update(aim_ctx, sn, display_name=dname)

        def is_diff(old, new, attr):
            return sorted(old[attr]) != sorted(new[attr])

        old_net = (original.get('external_gateway_info') or
                   {}).get('network_id')
        new_net = (current.get('external_gateway_info') or
                   {}).get('network_id')
        if old_net and not new_net:
            self._delete_snat_ip_ports_if_reqd(context, old_net,
                                               current['id'])
        if ((old_net != new_net or
             is_diff(original, current, a_l3.EXTERNAL_PROVIDED_CONTRACTS) or
             is_diff(original, current, a_l3.EXTERNAL_CONSUMED_CONTRACTS)) and
            self._get_router_intf_count(session, current)):

            if old_net == new_net:
                old_net = None
            old_net = self.plugin.get_network(context,
                                              old_net) if old_net else None
            new_net = self.plugin.get_network(context,
                                              new_net) if new_net else None
            self._manage_external_connectivity(context,
                                               current, old_net, new_net)

        # REVISIT(rkukura): Update extension attributes?

    def delete_router(self, context, current):
        LOG.debug("APIC AIM MD deleting router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        # Handling of external-gateway information is done when the router
        # interface ports are deleted, or the external-gateway is
        # cleared through update_router. At least one of those need
        # to happen before a router can be deleted, so we don't
        # need to do anything special when router is deleted

        contract, subject = self._map_router(session, current)

        self.aim.delete(aim_ctx, subject)
        self.aim.delete(aim_ctx, contract)

        self.name_mapper.delete_apic_name(session, current['id'])

    def extend_router_dict(self, session, router_db, result):
        LOG.debug("APIC AIM MD extending dict for router: %s", result)

        # REVISIT(rkukura): Consider optimizing this method by
        # persisting the router->VRF relationship.

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        contract, subject = self._map_router(session, router_db)

        dist_names[a_l3.CONTRACT] = contract.dn
        sync_state = self._merge_status(aim_ctx, sync_state, contract)

        dist_names[a_l3.CONTRACT_SUBJECT] = subject.dn
        sync_state = self._merge_status(aim_ctx, sync_state, subject)

        # REVISIT(rkukura): Consider moving the SubnetPool query below
        # into this loop, although that might be less efficient when
        # many subnets are from the same pool.
        active = False
        for intf in (session.query(models_v2.IPAllocation).
                     join(models_v2.Port).
                     join(l3_db.RouterPort).
                     filter(l3_db.RouterPort.router_id == router_db.id,
                            l3_db.RouterPort.port_type ==
                            n_constants.DEVICE_OWNER_ROUTER_INTF)):

            active = True
            subnet_db = (session.query(models_v2.Subnet).
                         filter_by(id=intf.subnet_id).
                         one())
            network_db = (session.query(models_v2.Network).
                          filter_by(id=subnet_db.network_id).
                          one())

            bd = self._map_network(session, network_db, True)
            sn = self._map_subnet(subnet_db, intf.ip_address, bd)

            dist_names[intf.ip_address] = sn.dn
            sync_state = self._merge_status(aim_ctx, sync_state, sn)

        if active:
            # Find this router's IPv4 address scope if it has one, or
            # else its IPv6 address scope.
            scope_id = None
            for pool_db in (session.query(models_v2.SubnetPool).
                            join(models_v2.Subnet,
                                 models_v2.Subnet.subnetpool_id ==
                                 models_v2.SubnetPool.id).
                            join(models_v2.IPAllocation).
                            join(models_v2.Port).
                            join(l3_db.RouterPort).
                            filter(l3_db.RouterPort.router_id == router_db.id,
                                   l3_db.RouterPort.port_type ==
                                   n_constants.DEVICE_OWNER_ROUTER_INTF).
                            distinct()):
                if pool_db.ip_version == 4:
                    scope_id = pool_db.address_scope_id
                    break
                elif pool_db.ip_version == 6:
                    scope_id = pool_db.address_scope_id
            if scope_id:
                scope_db = self._scope_by_id(session, scope_id)
                vrf = self._map_address_scope(session, scope_db)
            else:
                vrf = self._map_default_vrf(session, router_db)

            dist_names[a_l3.VRF] = vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def add_router_interface(self, context, router, port, subnets):
        LOG.debug("APIC AIM MD adding subnets %(subnets)s to router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router, 'port': port})

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = port['network_id']
        network_db = self.plugin._get_network(context, network_id)
        bd, epg = self._map_network(session, network_db)

        contract = self._map_router(session, router, True)

        # Create AIM Subnet(s) for each added Neutron subnet.
        for subnet in subnets:
            gw_ip = self._ip_for_subnet(subnet, port['fixed_ips'])

            dname = aim_utils.sanitize_display_name(
                router['name'] + " - " +
                (subnet['name'] or subnet['cidr']))

            sn = self._map_subnet(subnet, gw_ip, bd)
            sn.display_name = dname
            sn = self.aim.create(aim_ctx, sn)

        # Ensure network's EPG provides/consumes router's Contract.

        epg = self.aim.get(aim_ctx, epg)

        contracts = epg.consumed_contract_names
        if contract.name not in contracts:
            contracts.append(contract.name)
            epg = self.aim.update(aim_ctx, epg,
                                  consumed_contract_names=contracts)

        contracts = epg.provided_contract_names
        if contract.name not in contracts:
            contracts.append(contract.name)
            epg = self.aim.update(aim_ctx, epg,
                                  provided_contract_names=contracts)

        # Find up to two existing router interfaces for this
        # network. The interface currently being added is not
        # included, because the RouterPort has not yet been added to
        # the DB session.
        intfs = (session.query(l3_db.RouterPort.router_id,
                               models_v2.IPAllocation.subnet_id).
                 join(models_v2.Port).
                 join(models_v2.IPAllocation).
                 filter(models_v2.Port.network_id == network_id,
                        l3_db.RouterPort.port_type ==
                        n_constants.DEVICE_OWNER_ROUTER_INTF).
                 limit(2).
                 all())
        if intfs:
            # Since the EPGs that provide/consume routers' contracts
            # are at network rather than subnet granularity,
            # topologies where different subnets on the same network
            # are interfaced to different routers, which are valid in
            # Neutron, would result in unintended routing. We
            # therefore require that all router interfaces for a
            # network share either the same router or the same subnet.

            different_router = False
            different_subnet = False
            router_id = router['id']
            subnet_ids = [subnet['id'] for subnet in subnets]
            for existing_router_id, existing_subnet_id in intfs:
                if router_id != existing_router_id:
                    different_router = True
                for subnet_id in subnet_ids:
                    if subnet_id != existing_subnet_id:
                        different_subnet = True
            if different_router and different_subnet:
                raise UnsupportedRoutingTopology()

        # Number of existing router interface ports excluding the
        # one we are adding right now
        intf_count = self._get_router_intf_count(session, router)

        if not intfs or not intf_count:
            scope_id = self._get_address_scope_id_for_subnets(
                context, subnets)

        if not intfs:
            # No existing interfaces, so enable routing for BD and set
            # its VRF.
            vrf = None
            if scope_id != NO_ADDR_SCOPE:
                scope_db = self._scope_by_id(session, scope_id)
                vrf = self._map_address_scope(session, scope_db)
            else:
                vrf = self._ensure_default_vrf(aim_ctx, router)

            bd = self.aim.update(aim_ctx, bd, enable_routing=True,
                                 vrf_name=vrf.name)

        # If this is first interface-port, then that will determine
        # the VRF for this router. Setup exteral-connectivity for VRF
        # if external-gateway is set.
        if (router.gw_port_id and not intf_count):
            net = self.plugin.get_network(context,
                                          router.gw_port.network_id)
            self._manage_external_connectivity(
                context, router, None, net, scope_id=scope_id)

    def remove_router_interface(self, context, router_id, port_db, subnets):
        LOG.debug("APIC AIM MD removing subnets %(subnets)s from router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router_id, 'port': port_db})

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = port_db.network_id
        network_db = self.plugin._get_network(context, network_id)
        bd, epg = self._map_network(session, network_db)

        router_db = (session.query(l3_db.Router).
                     filter_by(id=router_id).
                     one())
        contract = self._map_router(session, router_db, True)

        # Remove AIM Subnet(s) for each removed Neutron subnet.
        for subnet in subnets:
            gw_ip = self._ip_for_subnet(subnet, port_db.fixed_ips)
            sn = self._map_subnet(subnet, gw_ip, bd)
            self.aim.delete(aim_ctx, sn)

        # Find remaining routers with interfaces to this network.
        router_ids = [r[0] for r in
                      session.query(l3_db.RouterPort.router_id).
                      join(models_v2.Port).
                      filter(models_v2.Port.network_id == network_id,
                             l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).distinct()]

        # If network is no longer connected to this router, stop
        # network's EPG from providing/consuming this router's
        # Contract.
        if router_id not in router_ids:
            epg = self.aim.get(aim_ctx, epg)

            contracts = [name for name in epg.consumed_contract_names
                         if name != contract.name]
            epg = self.aim.update(aim_ctx, epg,
                                  consumed_contract_names=contracts)

            contracts = [name for name in epg.provided_contract_names
                         if name != contract.name]
            epg = self.aim.update(aim_ctx, epg,
                                  provided_contract_names=contracts)

        # If network is no longer connected to any router, make the
        # network's BD unrouted.
        if not router_ids:
            vrf = self._map_unrouted_vrf()
            bd = self.aim.update(aim_ctx, bd, enable_routing=False,
                                 vrf_name=vrf.name)

        # If this was the last interface-port, then we no longer know
        # the VRF for this router. So update external-conectivity to
        # exclude this router.
        if (router_db.gw_port_id and
            not self._get_router_intf_count(session, router_db)):
            net = self.plugin.get_network(context,
                                          router_db.gw_port.network_id)
            scope_id = self._get_address_scope_id_for_subnets(
                context, subnets)
            self._manage_external_connectivity(
                context, router_db, net, None, scope_id=scope_id)

            self._delete_snat_ip_ports_if_reqd(context, net['id'],
                                               router_id)

    def bind_port(self, context):
        current = context.current
        LOG.debug("Attempting to bind port %(port)s on network %(net)s",
                  {'port': current['id'],
                   'net': context.network.current['id']})

        # TODO(rkukura): Add support for baremetal hosts, SR-IOV and
        # other situations requiring dynamic segments.

        # Check the VNIC type.
        vnic_type = current.get(portbindings.VNIC_TYPE,
                                portbindings.VNIC_NORMAL)
        if vnic_type not in [portbindings.VNIC_NORMAL]:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        # For compute ports, try to bind DVS agent first.
        if current['device_owner'].startswith('compute:'):
            if self._agent_bind_port(context, AGENT_TYPE_DVS,
                                     self._dvs_bind_port):
                return

        # Try to bind OpFlex agent.
        if self._agent_bind_port(context, ofcst.AGENT_TYPE_OPFLEX_OVS,
                                 self._opflex_bind_port):
            return

        # If we reached here, it means that either there is no active opflex
        # agent running on the host, or the agent on the host is not
        # configured for this physical network. Treat the host as a physical
        # node (i.e. has no OpFlex agent running) and try binding
        # hierarchically if the network-type is OpFlex.
        self._bind_physical_node(context)

    def update_port_precommit(self, context):
        port = context.current
        if (self._use_static_path(context, use_original=True) and
            context.original_host and
            context.original_host != context.host):
            # remove static binding for old host
            self._update_static_path(context, host=context.original_host,
                segment=context.original_bottom_bound_segment, remove=True)
            self._release_dynamic_segment(context, use_original=True)

        if self._is_port_bound(port) and self._use_static_path(context):
            self._update_static_path(context)

    def delete_port_postcommit(self, context):
        port = context.current
        if self._use_static_path(context) and self._is_port_bound(port):
            self._update_static_path(context, remove=True)
            self._release_dynamic_segment(context)

    def create_floatingip(self, context, current):
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def update_floatingip(self, context, original, current):
        if (original['port_id'] and
            original['port_id'] != current['port_id']):
            self._notify_port_update(context, original['port_id'])
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def delete_floatingip(self, context, current):
        if current['port_id']:
            self._notify_port_update(context, current['port_id'])

    def _agent_bind_port(self, context, agent_type, bind_strategy):
        current = context.current
        for agent in context.host_agents(agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if bind_strategy(context, segment, agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return True
            else:
                LOG.warning(_LW("Refusing to bind port %(port)s to dead "
                                "agent: %(agent)s"),
                            {'port': current['id'], 'agent': agent})

    def _opflex_bind_port(self, context, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if self._is_opflex_type(network_type):
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug("Checking segment: %(segment)s "
                      "for physical network: %(mappings)s ",
                      {'segment': segment, 'mappings': opflex_mappings})
            if (opflex_mappings is not None and
                segment[api.PHYSICAL_NETWORK] not in opflex_mappings):
                return False
        elif network_type != 'local':
            return False

        self._complete_binding(context, segment)
        return True

    def _dvs_bind_port(self, context, segment, agent):
        # TODO(rkukura): Implement DVS port binding
        return False

    def _bind_physical_node(self, context):
        # Bind physical nodes hierarchically by creating a dynamic segment.
        for segment in context.segments_to_bind:
            net_type = segment[api.NETWORK_TYPE]
            # TODO(amitbose) For ports on baremetal (Ironic) hosts, use
            # binding:profile to decide if dynamic segment should be created.
            if self._is_opflex_type(net_type):
                # TODO(amitbose) Consider providing configuration options
                # for picking network-type and physical-network name
                # for the dynamic segment
                dyn_seg = context.allocate_dynamic_segment(
                    {api.NETWORK_TYPE: pconst.TYPE_VLAN})
                LOG.info(_LI('Allocated dynamic-segment %(s)s for port %(p)s'),
                         {'s': dyn_seg, 'p': context.current['id']})
                dyn_seg['aim_ml2_created'] = True
                context.continue_binding(segment[api.ID], [dyn_seg])
                return True
            elif segment.get('aim_ml2_created'):
                # Complete binding if another driver did not bind the
                # dynamic segment that we created.
                self._complete_binding(context, segment)
                return True

    def _complete_binding(self, context, segment):
        context.set_binding(segment[api.ID],
                            portbindings.VIF_TYPE_OVS,
                            {portbindings.CAP_PORT_FILTER: False,
                             portbindings.OVS_HYBRID_PLUG: False})

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = manager.NeutronManager.get_plugin()
        return self._core_plugin

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._l3_plugin = plugins[pconst.L3_ROUTER_NAT]
        return self._l3_plugin

    def _merge_status(self, aim_ctx, sync_state, resource):
        status = self.aim.get_status(aim_ctx, resource)
        if not status:
            # REVISIT(rkukura): This should only occur if the AIM
            # resource has not yet been created when
            # extend_<resource>_dict() runs at the begining of a
            # create operation. In this case, the real sync_state
            # value will be generated, either in
            # create_<resource>_precommit() or in a 2nd call to
            # extend_<resource>_dict() after the precommit phase,
            # depending on the resource. It might be safer to force
            # sync_state to a SYNC_MISSING value here that is not
            # overwritten on subsequent calls to _merge_status(), in
            # case the real sync_state value somehow does not get
            # generated. But sync_state handling in general needs to
            # be revisited (and properly tested), so we can deal with
            # this at that time.
            return sync_state
        if status.is_error():
            sync_state = cisco_apic.SYNC_ERROR
        elif status.is_build() and sync_state is not cisco_apic.SYNC_ERROR:
            sync_state = cisco_apic.SYNC_BUILD
        return (cisco_apic.SYNC_SYNCED
                if sync_state is cisco_apic.SYNC_NOT_APPLICABLE
                else sync_state)

    def _ip_for_subnet(self, subnet, fixed_ips):
        subnet_id = subnet['id']
        for fixed_ip in fixed_ips:
            if fixed_ip['subnet_id'] == subnet_id:
                return fixed_ip['ip_address']

    def _subnet_router_ips(self, session, subnet_id):
        return (session.query(models_v2.IPAllocation.ip_address,
                              l3_db.RouterPort.router_id).
                join(models_v2.Port).
                filter(
                    models_v2.IPAllocation.subnet_id == subnet_id,
                    l3_db.RouterPort.port_type ==
                    n_constants.DEVICE_OWNER_ROUTER_INTF
                ))

    def _scope_by_id(self, session, scope_id):
        return (session.query(address_scope_db.AddressScope).
                filter_by(id=scope_id).
                one())

    def _map_network(self, session, network, bd_only=False):
        tenant_aname = self._get_tenant_name(session, network['tenant_id'])

        id = network['id']
        name = network['name']
        aname = self.name_mapper.network(session, id, name)
        LOG.debug("Mapped network_id %(id)s with name %(name)s to %(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname)
        if bd_only:
            return bd
        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname)
        return bd, epg

    def _map_external_network(self, session, network):
        l3out, ext_net, ns = self._get_aim_nat_strategy(network)
        if ext_net:
            aim_ctx = aim_context.AimContext(db_session=session)
            for o in (ns.get_l3outside_resources(aim_ctx, l3out) or []):
                if isinstance(o, aim_resource.EndpointGroup):
                    return o

    def _map_network_to_epg(self, session, network):
        if self._is_external(network):
            return self._map_external_network(session, network)
        return self._map_network(session, network)[1]

    def _map_subnet(self, subnet, gw_ip, bd):
        prefix_len = subnet['cidr'].split('/')[1]
        gw_ip_mask = gw_ip + '/' + prefix_len

        sn = aim_resource.Subnet(tenant_name=bd.tenant_name,
                                 bd_name=bd.name,
                                 gw_ip_mask=gw_ip_mask)
        return sn

    def _map_address_scope(self, session, scope):
        tenant_aname = self._get_tenant_name(session, scope['tenant_id'])

        id = scope['id']
        name = scope['name']
        aname = self.name_mapper.address_scope(session, id, name)
        LOG.debug("Mapped address_scope_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=aname)
        return vrf

    def _map_router(self, session, router, contract_only=False):
        tenant_aname = self._get_tenant_name(session, router['tenant_id'])

        id = router['id']
        name = router['name']
        aname = self.name_mapper.router(session, id, name)
        LOG.debug("Mapped router_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        contract = aim_resource.Contract(tenant_name=tenant_aname,
                                         name=aname)
        if contract_only:
            return contract
        subject = aim_resource.ContractSubject(tenant_name=tenant_aname,
                                               contract_name=aname,
                                               name=ROUTER_SUBJECT_NAME)
        return contract, subject

    def _map_default_vrf(self, session, router):
        tenant_aname = self._get_tenant_name(session, router['tenant_id'])

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=DEFAULT_VRF_NAME)
        return vrf

    def _map_unrouted_vrf(self):
        vrf = aim_resource.VRF(tenant_name=COMMON_TENANT_NAME,
                               name=UNROUTED_VRF_NAME)
        return vrf

    def _get_tenant_name(self, session, project_id):
        project_name = self.project_name_cache.get_project_name(project_id)
        # REVISIT(rkukura): This should be name_mapper.project.
        tenant_aname = self.name_mapper.tenant(session, project_id,
                                               project_name)
        LOG.debug("Mapped project_id %(id)s with name %(name)s to %(aname)s",
                  {'id': project_id, 'name': project_name,
                   'aname': tenant_aname})
        return tenant_aname

    def _ensure_common_tenant(self, aim_ctx):
        attrs = aim_resource.Tenant(name=COMMON_TENANT_NAME,
                                    display_name='Common Tenant')
        tenant = self.aim.get(aim_ctx, attrs)
        if not tenant:
            LOG.info(_LI("Creating common tenant"))
            tenant = self.aim.create(aim_ctx, attrs)
        return tenant

    def _ensure_unrouted_vrf(self, aim_ctx):
        self._ensure_common_tenant(aim_ctx)
        attrs = self._map_unrouted_vrf()
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            attrs.display_name = 'Common Unrouted VRF'
            LOG.info(_LI("Creating common unrouted VRF"))
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _ensure_default_vrf(self, aim_ctx, router):
        attrs = self._map_default_vrf(aim_ctx.db_session, router)
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            attrs.display_name = 'Default Routed VRF'
            LOG.info(_LI("Creating default VRF for %s"), attrs.tenant_name)
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    # DB Configuration callbacks
    def _set_enable_metadata_opt(self, new_conf):
        self.enable_metadata_opt = new_conf['value']

    def _set_enable_dhcp_opt(self, new_conf):
        self.enable_dhcp_opt = new_conf['value']

    def _set_ap_name(self, new_conf):
        self.ap_name = new_conf['value']

    def get_aim_domains(self, aim_ctx):
        vmms = [x.name for x in self.aim.find(aim_ctx, aim_resource.VMMDomain)
                if x.type == utils.OPENSTACK_VMM_TYPE]
        phys = [x.name for x in
                self.aim.find(aim_ctx, aim_resource.PhysicalDomain)]
        return vmms, phys

    def _is_external(self, network):
        return network.get('router:external')

    def _nat_type_to_strategy(self, nat_type):
        ns_cls = nat_strategy.DistributedNatStrategy
        if nat_type == '':
            ns_cls = nat_strategy.NoNatStrategy
        elif nat_type == 'edge':
            ns_cls = nat_strategy.EdgeNatStrategy
        ns = ns_cls(self.aim)
        ns.app_profile_name = self.ap_name
        return ns

    def _get_aim_nat_strategy(self, network):
        if not self._is_external(network):
            return None, None, None
        ext_net_dn = (network.get(cisco_apic.DIST_NAMES, {})
                      .get(cisco_apic.EXTERNAL_NETWORK))
        if not ext_net_dn:
            return None, None, None
        nat_type = network.get(cisco_apic.NAT_TYPE)
        aim_ext_net = aim_resource.ExternalNetwork.from_dn(ext_net_dn)
        aim_l3out = aim_resource.L3Outside(
            tenant_name=aim_ext_net.tenant_name, name=aim_ext_net.l3out_name)
        return aim_l3out, aim_ext_net, self._nat_type_to_strategy(nat_type)

    def _get_aim_nat_strategy_db(self, session, network_db):
        if network_db.external is not None:
            extn_db = extension_db.ExtensionDbMixin()
            extn_info = extn_db.get_network_extn_db(session, network_db.id)
            if extn_info and cisco_apic.EXTERNAL_NETWORK in extn_info:
                dn = extn_info[cisco_apic.EXTERNAL_NETWORK]
                a_ext_net = aim_resource.ExternalNetwork.from_dn(dn)
                a_l3out = aim_resource.L3Outside(
                    tenant_name=a_ext_net.tenant_name,
                    name=a_ext_net.l3out_name)
                ns = self._nat_type_to_strategy(
                        extn_info[cisco_apic.NAT_TYPE])
                return a_l3out, a_ext_net, ns
        return None, None, None

    def _subnet_to_gw_ip_mask(self, subnet):
        return aim_resource.Subnet.to_gw_ip_mask(
            subnet['gateway_ip'], int(subnet['cidr'].split('/')[1]))

    def _get_router_intf_count(self, session, router):
        return (session.query(l3_db.RouterPort)
                .filter(l3_db.RouterPort.router_id == router['id'])
                .filter(l3_db.RouterPort.port_type ==
                        n_constants.DEVICE_OWNER_ROUTER_INTF)
                .count())

    def _get_address_scope_id_for_subnets(self, context, subnets):
        # Assuming that all the subnets provided are consistent w.r.t.
        # address-scope, use the first available subnet to determine
        # address-scope. If subnets is a mix of v4 and v6 subnets,
        # then v4 subnets are given preference.
        subnets = sorted(subnets, key=lambda x: x['ip_version'])

        scope_id = NO_ADDR_SCOPE
        subnetpool_id = subnets[0]['subnetpool_id'] if subnets else None
        if subnetpool_id:
            subnetpool_db = self.plugin._get_subnetpool(context,
                                                        subnetpool_id)
            scope_id = (subnetpool_db.address_scope_id or NO_ADDR_SCOPE)
        return scope_id

    def _get_address_scope_id_for_router(self, session, router):
        scope_id = NO_ADDR_SCOPE
        for pool_db in (session.query(models_v2.SubnetPool)
                        .join(models_v2.Subnet,
                              models_v2.Subnet.subnetpool_id ==
                              models_v2.SubnetPool.id)
                        .join(models_v2.IPAllocation)
                        .join(models_v2.Port)
                        .join(l3_db.RouterPort)
                        .filter(l3_db.RouterPort.router_id == router['id'],
                                l3_db.RouterPort.port_type ==
                                n_constants.DEVICE_OWNER_ROUTER_INTF)
                        .filter(models_v2.SubnetPool.address_scope_id is not
                                None)
                        .distinct()):
            if pool_db.ip_version == 4:
                scope_id = pool_db.address_scope_id
                break
            elif pool_db.ip_version == 6:
                scope_id = pool_db.address_scope_id
        return scope_id

    def _get_other_routers_in_same_vrf(self, session, router,
                                       scope_id=None):
        scope_id = (scope_id or
                    self._get_address_scope_id_for_router(session, router))
        if scope_id != NO_ADDR_SCOPE:
            rtr_dbs = (session.query(l3_db.Router)
                       .join(l3_db.RouterPort)
                       .join(models_v2.Port)
                       .join(models_v2.IPAllocation)
                       .join(models_v2.Subnet)
                       .join(models_v2.SubnetPool,
                             models_v2.Subnet.subnetpool_id ==
                             models_v2.SubnetPool.id)
                       .filter(l3_db.RouterPort.port_type ==
                               n_constants.DEVICE_OWNER_ROUTER_INTF)
                       .filter(models_v2.SubnetPool.address_scope_id ==
                               scope_id)
                       .distinct())
        else:
            qry = (session.query(l3_db.Router)
                   .join(l3_db.RouterPort)
                   .join(models_v2.Port)
                   .join(models_v2.IPAllocation)
                   .join(models_v2.Subnet)
                   .filter(l3_db.Router.tenant_id == router['tenant_id'])
                   .filter(l3_db.RouterPort.port_type ==
                           n_constants.DEVICE_OWNER_ROUTER_INTF))
            rtr_dbs = (qry.filter(models_v2.Subnet.subnetpool_id.is_(None))
                       .distinct())
            rtr_dbs = {r.id: r for r in rtr_dbs}
            rtr_dbs_1 = (qry.join(models_v2.SubnetPool,
                                  models_v2.Subnet.subnetpool_id ==
                                  models_v2.SubnetPool.id)
                         .filter(models_v2.SubnetPool.address_scope_id.is_(
                                    None))
                         .distinct())
            rtr_dbs.update({r.id: r for r in rtr_dbs_1})
            rtr_dbs = rtr_dbs.values()

        return (scope_id, [r for r in rtr_dbs if r.id != router['id']])

    def _manage_external_connectivity(self, context, router, old_network,
                                      new_network, scope_id=None):
        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)
        scope_id, other_rtr_db = self._get_other_routers_in_same_vrf(
            session, router, scope_id=scope_id)
        ext_db = extension_db.ExtensionDbMixin()

        if scope_id != NO_ADDR_SCOPE:
            scope_db = (session.query(address_scope_db.AddressScope)
                        .filter_by(id=scope_id).one())
            vrf = self._map_address_scope(session, scope_db)
        else:
            vrf = self._map_default_vrf(session, router)

        prov = set()
        cons = set()

        def update_contracts(r_id, r_name):
            contract_aname = self.name_mapper.router(session, r_id, r_name)
            prov.add(contract_aname)
            cons.add(contract_aname)

            r_info = ext_db.get_router_extn_db(session, r_id)
            prov.update(r_info[a_l3.EXTERNAL_PROVIDED_CONTRACTS])
            cons.update(r_info[a_l3.EXTERNAL_CONSUMED_CONTRACTS])

        if old_network:
            _, ext_net, ns = self._get_aim_nat_strategy(old_network)
            if ext_net:
                rtr_old = [r for r in other_rtr_db
                           if (r.gw_port_id and
                               r.gw_port.network_id == old_network['id'])]
                prov = set()
                cons = set()
                for r in rtr_old:
                    update_contracts(r.id, r.name)

                if rtr_old:
                    ext_net.provided_contract_names = sorted(prov)
                    ext_net.consumed_contract_names = sorted(cons)
                    ns.connect_vrf(aim_ctx, ext_net, vrf)
                else:
                    ns.disconnect_vrf(aim_ctx, ext_net, vrf)
        if new_network:
            _, ext_net, ns = self._get_aim_nat_strategy(new_network)
            if ext_net:
                rtr_new = [r for r in other_rtr_db
                           if (r.gw_port_id and
                               r.gw_port.network_id == new_network['id'])]
                prov = set()
                cons = set()
                for r in rtr_new:
                    update_contracts(r.id, r.name)
                update_contracts(router['id'], router['name'])
                ext_net.provided_contract_names = sorted(prov)
                ext_net.consumed_contract_names = sorted(cons)
                ns.connect_vrf(aim_ctx, ext_net, vrf)

    def _is_port_bound(self, port):
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _notify_port_update(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context, port_id)
        if self._is_port_bound(port):
            LOG.debug("APIC notify port %s", port['id'])
            self.notifier.port_update(plugin_context, port)

    def get_or_allocate_snat_ip(self, plugin_context, host_or_vrf,
                                ext_network):
        """Fetch or allocate SNAT IP on the external network.

        IP allocation is done by creating a port on the external network,
        and associating an owner with it. The owner could be the ID of
        a host (or VRF) if SNAT IP allocation per host (or per VRF) is
        desired.
        If IP was found or successfully allocated, returns a dict like:
            {'host_snat_ip': <ip_addr>,
             'gateway_ip': <gateway_ip of subnet>,
             'prefixlen': <prefix_length_of_subnet>}
        """
        session = plugin_context.session
        snat_port = (session.query(models_v2.Port)
                     .filter(models_v2.Port.network_id == ext_network['id'],
                             models_v2.Port.device_id == host_or_vrf,
                             models_v2.Port.device_owner ==
                             DEVICE_OWNER_SNAT_PORT)
                     .first())
        snat_ip = None
        if not snat_port or snat_port.fixed_ips is None:
            # allocate SNAT port
            extn_db_sn = extension_db.SubnetExtensionDb
            snat_subnets = (session.query(models_v2.Subnet)
                            .join(extn_db_sn)
                            .filter(models_v2.Subnet.network_id ==
                                    ext_network['id'])
                            .filter(extn_db_sn.snat_host_pool.is_(True))
                            .all())
            if not snat_subnets:
                LOG.info(_LI('No subnet in external network %s is marked as '
                             'SNAT-pool'),
                         ext_network['id'])
                return
            for snat_subnet in snat_subnets:
                try:
                    attrs = {'device_id': host_or_vrf,
                             'device_owner': DEVICE_OWNER_SNAT_PORT,
                             'tenant_id': ext_network['tenant_id'],
                             'name': 'snat-pool-port:%s' % host_or_vrf,
                             'network_id': ext_network['id'],
                             'mac_address': attributes.ATTR_NOT_SPECIFIED,
                             'fixed_ips': [{'subnet_id': snat_subnet.id}],
                             'admin_state_up': False}
                    port = self.plugin.create_port(plugin_context,
                                                   {'port': attrs})
                    if port and port['fixed_ips']:
                        snat_ip = port['fixed_ips'][0]['ip_address']
                        break
                except exceptions.IpAddressGenerationFailure:
                    LOG.info(_LI('No more addresses available in subnet %s '
                                 'for SNAT IP allocation'),
                             snat_subnet['id'])
        else:
            snat_ip = snat_port.fixed_ips[0].ip_address
            snat_subnet = (session.query(models_v2.Subnet)
                           .filter(models_v2.Subnet.id ==
                                   snat_port.fixed_ips[0].subnet_id)
                           .one())

        if snat_ip:
            return {'host_snat_ip': snat_ip,
                    'gateway_ip': snat_subnet['gateway_ip'],
                    'prefixlen': int(snat_subnet['cidr'].split('/')[1])}

    def _has_snat_ip_ports(self, plugin_context, subnet_id):
        session = plugin_context.session
        return (session.query(models_v2.Port)
                .join(models_v2.IPAllocation)
                .filter(models_v2.IPAllocation.subnet_id == subnet_id)
                .filter(models_v2.Port.device_owner == DEVICE_OWNER_SNAT_PORT)
                .first())

    def _delete_snat_ip_ports_if_reqd(self, plugin_context,
                                      ext_network_id, exclude_router_id):
        session = plugin_context.session
        # if there are no routers uplinked to the external network,
        # then delete any ports allocated for SNAT IP
        gw_qry = (session.query(models_v2.Port)
                  .filter(models_v2.Port.network_id == ext_network_id,
                          models_v2.Port.device_owner ==
                          n_constants.DEVICE_OWNER_ROUTER_GW,
                          models_v2.Port.device_id != exclude_router_id))
        if not gw_qry.first():
            snat_ports = (session.query(models_v2.Port.id)
                          .filter(models_v2.Port.network_id == ext_network_id,
                                  models_v2.Port.device_owner ==
                                  DEVICE_OWNER_SNAT_PORT)
                          .all())
            for p in snat_ports:
                try:
                    self.plugin.delete_port(plugin_context, p[0])
                except exceptions.NeutronException as ne:
                    LOG.warning(_LW('Failed to delete SNAT port %(port)s: '
                                    '%(ex)s'),
                                {'port': p, 'ex': ne})

    def check_floatingip_external_address(self, context, floatingip):
        session = context.session
        if floatingip.get('subnet_id'):
            sn_ext = (extension_db.ExtensionDbMixin()
                      .get_subnet_extn_db(session,
                                          floatingip['subnet_id']))
            if sn_ext.get(cisco_apic.SNAT_HOST_POOL, False):
                raise SnatPoolCannotBeUsedForFloatingIp()
        elif floatingip.get('floating_ip_address'):
            extn_db_sn = extension_db.SubnetExtensionDb
            cidrs = (session.query(models_v2.Subnet.cidr)
                    .join(extn_db_sn)
                    .filter(models_v2.Subnet.network_id ==
                            floatingip['floating_network_id'])
                    .filter(extn_db_sn.snat_host_pool.is_(True))
                    .all())
            cidrs = netaddr.IPSet([c[0] for c in cidrs])
            if floatingip['floating_ip_address'] in cidrs:
                raise SnatPoolCannotBeUsedForFloatingIp()

    def get_subnets_for_fip(self, context, floatingip):
        session = context.session
        extn_db_sn = extension_db.SubnetExtensionDb
        other_sn = (session.query(models_v2.Subnet.id)
                    .outerjoin(extn_db_sn)
                    .filter(models_v2.Subnet.network_id ==
                            floatingip['floating_network_id'])
                    .filter(sa.or_(extn_db_sn.snat_host_pool.is_(False),
                                   extn_db_sn.snat_host_pool.is_(None)))
                    .all())
        return [s[0] for s in other_sn]

    def _is_opflex_type(self, net_type):
        return net_type == ofcst.TYPE_OPFLEX

    def _is_supported_non_opflex_type(self, net_type):
        return net_type in [pconst.TYPE_VLAN]

    def _use_static_path(self, port_context, use_original=False):
        bound_seg = (port_context.original_bottom_bound_segment if use_original
                     else port_context.bottom_bound_segment)
        return (bound_seg and
                self._is_supported_non_opflex_type(
                    bound_seg[api.NETWORK_TYPE]))

    def _update_static_path(self, port_context, host=None, segment=None,
                            remove=False):
        host = host or port_context.host
        segment = segment or port_context.bottom_bound_segment
        session = port_context._plugin_context.session

        if not segment:
            LOG.debug('Port %s is not bound to any segment',
                      port_context.current['id'])
            return
        if remove:
            # check if there are any other ports from this network on the host
            exist = (session.query(models.PortBindingLevel)
                     .filter_by(host=host, segment_id=segment['id'])
                     .filter(models.PortBindingLevel.port_id !=
                             port_context.current['id'])
                     .first())
            if exist:
                return
        else:
            if (segment.get(api.NETWORK_TYPE) in [pconst.TYPE_VLAN]):
                seg = segment[api.SEGMENTATION_ID]
            else:
                LOG.info(_LI('Unsupported segmentation type for static path '
                             'binding: %s'),
                         segment.get(api.NETWORK_TYPE))
                return

        aim_ctx = aim_context.AimContext(db_session=session)
        host_link = self.aim.find(aim_ctx, aim_infra.HostLink, host_name=host)
        if not host_link or not host_link[0].path:
            LOG.warning(_LW('No host link information found for host %s'),
                        host)
            return
        host_link = host_link[0].path

        epg = self._map_network_to_epg(session, port_context.network.current)
        if not epg:
            LOG.info(_LI('Network %s does not map to any EPG'),
                     port_context.network.current['id'])
            return
        epg = self.aim.get(aim_ctx, epg)
        static_paths = [p for p in epg.static_paths
                        if p.get('path') != host_link]
        if not remove:
            static_paths.append({'path': host_link, 'encap': 'vlan-%s' % seg})
        LOG.debug('Setting static paths for EPG %s to %s', epg, static_paths)
        self.aim.update(aim_ctx, epg, static_paths=static_paths)

    def _release_dynamic_segment(self, port_context, use_original=False):
        top = (port_context.original_top_bound_segment if use_original
               else port_context.top_bound_segment)
        btm = (port_context.original_bottom_bound_segment if use_original
               else port_context.bottom_bound_segment)
        if (top and btm and
            self._is_opflex_type(top[api.NETWORK_TYPE]) and
            self._is_supported_non_opflex_type(btm[api.NETWORK_TYPE])):
            # if there are no other ports bound to segment, release the segment
            ports = (port_context._plugin_context.session
                     .query(models.PortBindingLevel)
                     .filter_by(segment_id=btm[api.ID])
                     .filter(models.PortBindingLevel.port_id !=
                             port_context.current['id'])
                     .first())
            if not ports:
                LOG.info(_LI('Releasing dynamic-segment %(s)s for port %(p)s'),
                         {'s': btm, 'p': port_context.current['id']})
                port_context.release_dynamic_segment(btm[api.ID])
