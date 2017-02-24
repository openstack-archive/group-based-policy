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

import copy
import netaddr
import sqlalchemy as sa

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim.common import utils
from aim import context as aim_context
from aim import utils as aim_utils
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.agent import securitygroups_rpc
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics as n_topics
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import l3_db
from neutron.db.models import allowed_address_pair as n_addr_pair_db
from neutron.db import models_v2
from neutron.db import rbac_db_models
from neutron.db import segments_db
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models
from opflexagent import constants as ofcst
from opflexagent import rpc as ofrpc
from oslo_config import cfg
from oslo_log import log
import oslo_messaging

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (rpc as
    apic_topo_rpc)
from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_l3 as a_l3
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import config  # noqa
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import exceptions
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import extension_db

LOG = log.getLogger(__name__)
DEVICE_OWNER_SNAT_PORT = 'apic:snat-pool'
local_api.BATCH_NOTIFICATIONS = True

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

NO_ADDR_SCOPE = object()


class KeystoneNotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        event_type='identity.project.update')

    def __init__(self, mechanism_driver):
        self._driver = mechanism_driver

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        LOG.debug("Keystone notification getting called!")

        tenant_id = payload.get('resource_info')
        # malformed notification?
        if not tenant_id:
            return None

        new_project_name = (self._driver.project_name_cache.
                            update_project_name(tenant_id))
        if not new_project_name:
            return None

        # we only update tenants which have been created in APIC. For other
        # cases, their nameAlias will be set when the first resource is being
        # created under that tenant
        session = db_api.get_session()
        tenant_aname = self._driver.name_mapper.project(session, tenant_id)
        aim_ctx = aim_context.AimContext(session)
        tenant = aim_resource.Tenant(name=tenant_aname)
        if not self._driver.aim.get(aim_ctx, tenant):
            return None

        self._driver.aim.update(aim_ctx, tenant,
            display_name=aim_utils.sanitize_display_name(new_project_name))
        return oslo_messaging.NotificationResult.HANDLED


class ApicMechanismDriver(api_plus.MechanismDriver):

    class TopologyRpcEndpoint(object):
        target = oslo_messaging.Target(version='1.2')

        def __init__(self, mechanism_driver):
            self.md = mechanism_driver

        def update_link(self, *args, **kwargs):
            self.md.update_link(*args, **kwargs)

        def delete_link(self, *args, **kwargs):
            self.md.delete_link(*args, **kwargs)

    def __init__(self):
        LOG.info(_LI("APIC AIM MD __init__"))

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))
        self.project_name_cache = cache.ProjectNameCache()
        self.name_mapper = apic_mapper.APICNameMapper()
        self.aim = aim_manager.AimManager()
        self._core_plugin = None
        self._l3_plugin = None
        self._gbp_plugin = None
        self._aim_mapping = None
        # Get APIC configuration and subscribe for changes
        self.enable_metadata_opt = (
            cfg.CONF.ml2_apic_aim.enable_optimized_metadata)
        self.enable_dhcp_opt = (
            cfg.CONF.ml2_apic_aim.enable_optimized_dhcp)
        self.ap_name = 'OpenStack'
        self.apic_system_id = cfg.CONF.apic_system_id
        self.notifier = ofrpc.AgentNotifierApi(n_topics.AGENT)
        self.sg_enabled = securitygroups_rpc.is_firewall_enabled()
        # setup APIC topology RPC handler
        self.topology_conn = n_rpc.create_connection()
        self.topology_conn.create_consumer(apic_topo_rpc.TOPIC_APIC_SERVICE,
                                           [self.TopologyRpcEndpoint(self)],
                                           fanout=False)
        self.topology_conn.consume_in_threads()
        self.keystone_notification_exchange = (cfg.CONF.ml2_apic_aim.
                                               keystone_notification_exchange)
        self.keystone_notification_topic = (cfg.CONF.ml2_apic_aim.
                                            keystone_notification_topic)
        self._setup_keystone_notification_listeners()
        self.apic_optimized_dhcp_lease_time = (cfg.CONF.ml2_apic_aim.
                                               apic_optimized_dhcp_lease_time)

    def _setup_keystone_notification_listeners(self):
        targets = [oslo_messaging.Target(
                    exchange=self.keystone_notification_exchange,
                    topic=self.keystone_notification_topic, fanout=True)]
        endpoints = [KeystoneNotificationEndpoint(self)]
        pool = "cisco_aim_listener-workers"
        server = oslo_messaging.get_notification_listener(
            n_rpc.NOTIFICATION_TRANSPORT, targets, endpoints,
            executor='eventlet', pool=pool)
        server.start()

    def ensure_tenant(self, plugin_context, project_id):
        LOG.debug("APIC AIM MD ensuring AIM Tenant for project_id: %s",
                  project_id)

        if not project_id:
            # The l3_db module creates gateway ports with empty string
            # project IDs in order to hide those ports from
            # users. Since we are not currently mapping ports to
            # anything in AIM, we can ignore these. Any other cases
            # where empty string project IDs are used may require
            # mapping AIM resources under some actual Tenant.
            return

        self.project_name_cache.ensure_project(project_id)

        # TODO(rkukura): Move the following to calls made from
        # precommit methods so AIM Tenants, ApplicationProfiles, and
        # Filters are [re]created whenever needed.
        session = plugin_context.session
        with session.begin(subtransactions=True):
            tenant_aname = self.name_mapper.project(session, project_id)
            project_name = self.project_name_cache.get_project_name(project_id)
            if project_name is None:
                project_name = ''
            aim_ctx = aim_context.AimContext(session)
            tenant = aim_resource.Tenant(name=tenant_aname,
                display_name=aim_utils.sanitize_display_name(project_name))
            if not self.aim.get(aim_ctx, tenant):
                self.aim.create(aim_ctx, tenant)
            ap = aim_resource.ApplicationProfile(tenant_name=tenant_aname,
                                                 name=self.ap_name)
            if not self.aim.get(aim_ctx, ap):
                self.aim.create(aim_ctx, ap)

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
            bd, epg = self._map_network(session, current, None)

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
            network_db = self.plugin._get_network(
                context._plugin_context, current['id'])

            vrf = self._get_routed_vrf_for_network(session, network_db)
            bd, epg = self._map_network(session, network_db, vrf)

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
            bd, epg = self._map_network(session, current, None)

            self.aim.delete(aim_ctx, epg)
            self.aim.delete(aim_ctx, bd)

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
            vrf = self._get_routed_vrf_for_network(session, network_db)
            bd, epg = self._map_network(session, network_db, vrf)

            dist_names[cisco_apic.BD] = bd.dn
            sync_state = self._merge_status(aim_ctx, sync_state, bd)

            dist_names[cisco_apic.EPG] = epg.dn
            sync_state = self._merge_status(aim_ctx, sync_state, epg)

            vrf = vrf or self._map_unrouted_vrf()
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
                raise exceptions.SnatPortsInUse(subnet_id=current['id'])

        if (not is_ext and
            current['name'] != original['name']):

            vrf = self._get_routed_vrf_for_network(session, network_db)
            bd = self._map_network(session, network_db, vrf, True)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            current['id']):
                router_db = self.l3_plugin._get_router(context._plugin_context,
                                                       router_id)
                dname = aim_utils.sanitize_display_name(
                    router_db.name + "-" +
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
            vrf = self._get_routed_vrf_for_network(session, network_db)
            bd = self._map_network(session, network_db, vrf, True)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            subnet_db.id):
                sn = self._map_subnet(subnet_db, gw_ip, bd)
                dist_names[gw_ip] = sn.dn
                sync_state = self._merge_status(aim_ctx, sync_state, sn)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def update_subnetpool_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating subnetpool: %s", current)

        session = context._plugin_context.session

        current_scope_id = current['address_scope_id']
        original_scope_id = original['address_scope_id']
        if current_scope_id != original_scope_id:
            # Find router interfaces involving subnets from this pool.
            pool_id = current['id']
            rps = (session.query(l3_db.RouterPort).
                   join(models_v2.Port).
                   join(models_v2.IPAllocation).
                   join(models_v2.Subnet).
                   filter(models_v2.Subnet.subnetpool_id == pool_id,
                          l3_db.RouterPort.port_type ==
                          n_constants.DEVICE_OWNER_ROUTER_INTF).
                   all())
            if rps:
                # TODO(rkukura): Implement moving the effected router
                # interfaces from one scope to another, from scoped to
                # unscoped, and from unscoped to scoped. This might
                # require moving the BDs and EPGs of routed networks
                # associated with the pool to the new scope's
                # project's Tenant. With multi-scope routing, it also
                # might result in individual routers being associated
                # with more or fewer scopes. Updates from scoped to
                # unscoped might still need to be rejected due to
                # overlap within a Tenant's default VRF. For now, we
                # just reject the update.
                raise exceptions.ScopeUpdateNotSupported()

    def create_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        dname = aim_utils.sanitize_display_name(current['name'])

        vrf = self._map_address_scope(session, current)
        if not self.aim.get(aim_ctx, vrf):
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

            vrf = self.aim.get(aim_ctx,
                               self._map_address_scope(session, current))
            if vrf and not vrf.monitored:
                self.aim.update(aim_ctx, vrf, display_name=dname)

    def delete_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        vrf = self.aim.get(aim_ctx, self._map_address_scope(session, current))
        if vrf and not vrf.monitored:
            self.aim.delete(aim_ctx, vrf)

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

        filter = self._ensure_any_filter(aim_ctx)

        contract, subject = self._map_router(session, current)

        dname = aim_utils.sanitize_display_name(current['name'])

        contract.display_name = dname
        self.aim.create(aim_ctx, contract)

        subject.display_name = dname
        subject.bi_filters = [filter.name]
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

            # REVISIT(rkukura): Refactor to share common code below with
            # extend_router_dict.
            for intf in (session.query(models_v2.IPAllocation).
                         join(models_v2.Port).
                         join(l3_db.RouterPort).
                         filter(l3_db.RouterPort.router_id == current['id'],
                                l3_db.RouterPort.port_type ==
                                n_constants.DEVICE_OWNER_ROUTER_INTF)):

                # TODO(rkukura): Avoid separate queries for these.
                subnet_db = (session.query(models_v2.Subnet).
                             filter_by(id=intf.subnet_id).
                             one())
                network_db = (session.query(models_v2.Network).
                              filter_by(id=subnet_db.network_id).
                              one())

                dname = aim_utils.sanitize_display_name(
                    name + "-" + (subnet_db.name or subnet_db.cidr))

                # REVISIT: This might be expensive, so consider
                # caching the BDs for networks that have been
                # processed.
                vrf = self._get_routed_vrf_for_network(session, network_db)

                bd = self._map_network(session, network_db, vrf, True)
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
                affected_port_ids = []
            else:
                # SNAT information of ports on the subnet that interface
                # with the router will change because router's gateway
                # changed.
                sub_ids = self._get_router_interface_subnets(session,
                                                             current['id'])
                affected_port_ids = self._get_non_router_ports_in_subnets(
                    session, sub_ids)

            old_net = self.plugin.get_network(context,
                                              old_net) if old_net else None
            new_net = self.plugin.get_network(context,
                                              new_net) if new_net else None
            self._manage_external_connectivity(context,
                                               current, old_net, new_net)

            # Send a port update so that SNAT info may be recalculated for
            # affected ports in the interfaced subnets.
            self._notify_port_update_bulk(context, affected_port_ids)

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

            # TODO(rkukura): Avoid separate queries for these.
            subnet_db = (session.query(models_v2.Subnet).
                         filter_by(id=intf.subnet_id).
                         one())
            network_db = (session.query(models_v2.Network).
                          filter_by(id=subnet_db.network_id).
                          one())

            # TODO(rkukura): This can be very expensive, and there can
            # be multiple subnets per network, so cache the BDs for
            # networks that have been processed. Also, without
            # multi-scope routing, there should be exactly one VRF per
            # router. With multi-scope routing, we should be able to
            # determine the set of VRFs and the subnets accociated
            # with each.
            vrf = self._get_routed_vrf_for_network(session, network_db)

            bd = self._map_network(session, network_db, vrf, True)
            sn = self._map_subnet(subnet_db, intf.ip_address, bd)

            dist_names[intf.ip_address] = sn.dn
            sync_state = self._merge_status(aim_ctx, sync_state, sn)

        if active:
            # TODO(rkukura): With multi-scope routing, there will be
            # multiple VRF DNs, so include the scope_id or 'no-scope'
            # in the key.
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

        # Find the address_scope(s) for the new interface.
        #
        # TODO(rkukura): To support IPv6 and dual-stack routing, we
        # will need both the v4 and v6 scopes. For now, we reject
        # adding v6 subnets. Dual-stack topologies will use the v4
        # scope, with OpFlex "identity NAT" moving v6 traffic to the
        # v6 scope's VRF.
        for subnet in subnets:
            if subnet['ip_version'] != 4:
                raise exceptions.IPv6RoutingNotSupported()
        scope_id = self._get_address_scope_id_for_subnets(context, subnets)

        # Find number of existing interface ports on the router,
        # excluding the one we are adding.
        router_intf_count = self._get_router_intf_count(session, router)

        # TODO(rkukura): Support multi-scope routing. For now, we
        # reject adding an interface that does not match the scope of
        # any existing interfaces.
        if (router_intf_count and
            (scope_id !=
             self._get_address_scope_id_for_router(session, router))):
            raise exceptions.MultiScopeRoutingNotSupported()

        # Find up to two existing router interfaces for this
        # network. The interface currently being added is not
        # included, because the RouterPort has not yet been added to
        # the DB session.
        net_intfs = (session.query(l3_db.RouterPort.router_id,
                                   models_v2.IPAllocation.subnet_id).
                     join(models_v2.Port).
                     join(models_v2.IPAllocation).
                     filter(models_v2.Port.network_id == network_id,
                            l3_db.RouterPort.port_type ==
                            n_constants.DEVICE_OWNER_ROUTER_INTF).
                     limit(2).
                     all())
        if net_intfs:
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
            for existing_router_id, existing_subnet_id in net_intfs:
                if router_id != existing_router_id:
                    different_router = True
                for subnet_id in subnet_ids:
                    if subnet_id != existing_subnet_id:
                        different_subnet = True
            if different_router and different_subnet:
                raise exceptions.UnsupportedRoutingTopology()

        nets_to_notify = set()
        ports_to_notify = set()
        router_topo_moved = False

        # Ensure that all the BDs and EPGs in the resulting topology
        # are mapped under the same Tenant so that the BDs can all
        # reference the topology's VRF and the EPGs can all provide
        # and consume the router's Contract. This is handled
        # differently for scoped and unscoped topologies.
        if scope_id != NO_ADDR_SCOPE:
            # TODO(rkukura): Scoped topologies are simple, until we
            # support IPv6 routing. Then, we will need to figure out
            # if a v6-only network should use its own v6 scope, or a
            # v4 scope that's already part of the router
            # topology. Adding a v4 interface to a previously v6-only
            # network may require moving the existing network (and its
            # subnets) from the v6 scope to the v4 scope. Multi-scope
            # routers will further complicate this with multiple v4
            # scopes to choose between for v6-only networks.
            scope = self._scope_by_id(session, scope_id)
            vrf = self._map_address_scope(session, scope)
        else:
            # TODO(rkukura): The unscoped case will need to handle
            # IPv6 and, and will have to coexist with address_scopes
            # for multi-scope routing.
            intf_topology = self._network_topology(session, network_db)
            router_topology = self._router_topology(session, router['id'])

            intf_shared_net = self._topology_shared(intf_topology)
            router_shared_net = self._topology_shared(router_topology)

            intf_vrf = self._map_default_vrf(
                session, intf_shared_net or network_db)
            router_vrf = (
                self._map_default_vrf(
                    session,
                    router_shared_net or router_topology.itervalues().next())
                if router_topology else None)

            # Choose VRF and move one topology if necessary.
            if router_vrf and intf_vrf.identity != router_vrf.identity:
                if intf_shared_net and router_shared_net:
                    raise exceptions.UnscopedSharedNetworkProjectConflict(
                        net1=intf_shared_net.id,
                        proj1=intf_shared_net.tenant_id,
                        net2=router_shared_net.id,
                        proj2=router_shared_net.tenant_id)
                elif intf_shared_net:
                    # Interface topology has shared network, so move
                    # router topology.
                    vrf = self._ensure_default_vrf(aim_ctx, intf_vrf)
                    self._move_topology(
                        aim_ctx, router_topology, router_vrf, vrf,
                        nets_to_notify)
                    router_topo_moved = True
                    # REVISIT: Delete router_vrf if no longer used?
                elif router_shared_net:
                    # Router topology has shared network, so move
                    # interface topology, unless first interface for
                    # network.
                    vrf = router_vrf
                    if net_intfs:
                        self._move_topology(
                            aim_ctx, intf_topology, intf_vrf, vrf,
                            nets_to_notify)
                    # REVISIT: Delete intf_vrf if no longer used?
                else:
                    # This should never happen.
                    LOG.error(_LE("Interface topology %(intf_topology)s and "
                                  "router topology %(router_topology)s have "
                                  "different VRFs, but neither is shared"),
                              {'intf_topology': intf_topology,
                               'router_topology': router_topology})
                    raise exceptions.InternalError()
            else:
                vrf = self._ensure_default_vrf(aim_ctx, intf_vrf)

        # Associate or map network, depending on whether it has other
        # interfaces.
        if not net_intfs:
            # First interface for network.
            bd, epg = self._associate_network_with_vrf(
                aim_ctx, network_db, vrf, nets_to_notify)
        else:
            # Network is already routed.
            bd, epg = self._map_network(session, network_db, vrf)

        # Create AIM Subnet(s) for each added Neutron subnet.
        for subnet in subnets:
            gw_ip = self._ip_for_subnet(subnet, port['fixed_ips'])

            dname = aim_utils.sanitize_display_name(
                router['name'] + "-" +
                (subnet['name'] or subnet['cidr']))

            sn = self._map_subnet(subnet, gw_ip, bd)
            sn.display_name = dname
            sn = self.aim.create(aim_ctx, sn)

        # Ensure network's EPG provides/consumes router's Contract.

        contract = self._map_router(session, router, True)
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

        # If external-gateway is set, handle external-connectivity changes.
        if router.gw_port_id:
            net = self.plugin.get_network(context,
                                          router.gw_port.network_id)
            # If this is first interface-port, then that will determine
            # the VRF for this router. Setup external-connectivity for VRF.
            if not router_intf_count:
                self._manage_external_connectivity(context, router, None, net,
                                                   vrf)
            elif router_topo_moved:
                # Router moved from router_vrf to vrf, so
                # 1. Update router_vrf's external connectivity to exclude
                #    router
                # 2. Update vrf's external connectivity to include router
                self._manage_external_connectivity(context, router, net, None,
                                                   router_vrf)
                self._manage_external_connectivity(context, router, None, net,
                                                   vrf)

            # SNAT information of ports on the subnet will change because
            # of router interface addition. Send a port update so that it may
            # be recalculated.
            port_ids = self._get_non_router_ports_in_subnets(
                session,
                [subnet['id'] for subnet in subnets])
            ports_to_notify.update(port_ids)

        # Enqueue notifications for all affected ports.
        if nets_to_notify:
            port_ids = self._get_non_router_ports_in_networks(
                session, nets_to_notify)
            ports_to_notify.update(port_ids)
        if ports_to_notify:
            self._notify_port_update_bulk(context, ports_to_notify)

    def remove_router_interface(self, context, router_id, port_db, subnets):
        LOG.debug("APIC AIM MD removing subnets %(subnets)s from router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router_id, 'port': port_db})

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = port_db.network_id
        network_db = self.plugin._get_network(context, network_id)

        # Find the address_scope(s) for the old interface.
        #
        # TODO(rkukura): Handle IPv6 and dual-stack routing.
        scope_id = self._get_address_scope_id_for_subnets(context, subnets)

        old_vrf = self._get_routed_vrf_for_network(session, network_db)

        bd, epg = self._map_network(session, network_db, old_vrf)

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

        nets_to_notify = set()
        ports_to_notify = set()
        router_topo_moved = False

        # If unscoped topologies have split, move VRFs as needed.
        if scope_id == NO_ADDR_SCOPE:
            # If the interface's network has not become unrouted, see
            # if its topology must be moved.
            if router_ids:
                intf_topology = self._network_topology(session, network_db)
                intf_shared_net = self._topology_shared(intf_topology)
                intf_vrf = self._map_default_vrf(
                    session, intf_shared_net or network_db)
                if old_vrf.identity != intf_vrf.identity:
                    self._move_topology(
                        aim_ctx, intf_topology, old_vrf, intf_vrf,
                        nets_to_notify)

            # See if the router's topology must be moved.
            router_topology = self._router_topology(session, router_db.id)
            if router_topology:
                router_shared_net = self._topology_shared(router_topology)
                router_vrf = self._map_default_vrf(
                    session,
                    router_shared_net or router_topology.itervalues().next())
                if old_vrf.identity != router_vrf.identity:
                    self._move_topology(
                        aim_ctx, router_topology, old_vrf, router_vrf,
                        nets_to_notify)
                    router_topo_moved = True

        # If network is no longer connected to any router, make the
        # network's BD unrouted.
        if not router_ids:
            self._dissassociate_network_from_vrf(
                aim_ctx, network_db, old_vrf, nets_to_notify)

        # If external-gateway is set, handle external-connectivity changes.
        if router_db.gw_port_id:
            net = self.plugin.get_network(context,
                                          router_db.gw_port.network_id)
            # If this was the last interface-port, then we no longer know
            # the VRF for this router. So update external-conectivity to
            # exclude this router.
            if not self._get_router_intf_count(session, router_db):
                self._manage_external_connectivity(
                    context, router_db, net, None, old_vrf)

                self._delete_snat_ip_ports_if_reqd(context, net['id'],
                                                   router_id)
            elif router_topo_moved:
                # Router moved from old_vrf to router_vrf, so
                # 1. Update old_vrf's external connectivity to exclude router
                # 2. Update router_vrf's external connectivity to include
                #    router
                self._manage_external_connectivity(context, router_db, net,
                                                   None, old_vrf)
                self._manage_external_connectivity(context, router_db, None,
                                                   net, router_vrf)

            # SNAT information of ports on the subnet will change because
            # of router interface removal. Send a port update so that it may
            # be recalculated.
            port_ids = self._get_non_router_ports_in_subnets(
                session,
                [subnet['id'] for subnet in subnets])
            ports_to_notify.update(port_ids)

        # Enqueue notifications for all affected ports.
        if nets_to_notify:
            port_ids = self._get_non_router_ports_in_networks(
                session, nets_to_notify)
            ports_to_notify.update(port_ids)
        if ports_to_notify:
            self._notify_port_update_bulk(context, ports_to_notify)

    def bind_port(self, context):
        port = context.current
        LOG.debug("Attempting to bind port %(port)s on network %(net)s",
                  {'port': port['id'],
                   'net': context.network.current['id']})

        # Check the VNIC type.
        vnic_type = port.get(portbindings.VNIC_TYPE,
                             portbindings.VNIC_NORMAL)
        if vnic_type not in [portbindings.VNIC_NORMAL]:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        if port['device_owner'].startswith('compute:'):
            if (self.aim_mapping and not
                    self.aim_mapping.check_allow_vm_names(context, port)):
                return

            # For compute ports, try to bind DVS agent first.
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
        if (self._use_static_path(context.original_bottom_bound_segment) and
            context.original_host != context.host):
            # remove static binding for old host
            self._update_static_path(context, host=context.original_host,
                segment=context.original_bottom_bound_segment, remove=True)
            self._release_dynamic_segment(context, use_original=True)

        if (self._is_port_bound(port) and
                self._use_static_path(context.bottom_bound_segment)):
            self._update_static_path(context)

    def delete_port_precommit(self, context):
        port = context.current
        if (self._is_port_bound(port) and
                self._use_static_path(context.bottom_bound_segment)):
            self._update_static_path(context, remove=True)
            self._release_dynamic_segment(context)

    def create_floatingip(self, context, current):
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update_for_fip(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def update_floatingip(self, context, original, current):
        if (original['port_id'] and
            original['port_id'] != current['port_id']):
            self._notify_port_update_for_fip(context, original['port_id'])
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update_for_fip(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def delete_floatingip(self, context, current):
        if current['port_id']:
            self._notify_port_update_for_fip(context, current['port_id'])

    # Topology RPC method handler
    def update_link(self, context, host, interface, mac,
                    switch, module, port, port_description=''):
        LOG.debug('Topology RPC: update_link: %s',
                  ', '.join([str(p) for p in
                             (host, interface, mac, switch, module, port,
                              port_description)]))
        if not switch:
            self.delete_link(context, host, interface, mac, switch, module,
                             port)
            return

        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)
        hlink = self.aim.get(aim_ctx,
                             aim_infra.HostLink(host_name=host,
                                                interface_name=interface))
        if not hlink or hlink.path != port_description:
            attrs = dict(interface_mac=mac,
                         switch_id=switch, module=module, port=port,
                         path=port_description)
            if hlink:
                old_path = hlink.path
                hlink = self.aim.update(aim_ctx, hlink, **attrs)
            else:
                old_path = None
                hlink = aim_infra.HostLink(host_name=host,
                                           interface_name=interface,
                                           **attrs)
                hlink = self.aim.create(aim_ctx, hlink)
            # Update static paths of all EPGs with ports on the host
            nets_segs = self._get_non_opflex_segments_on_host(context, host)
            for net, seg in nets_segs:
                self._update_static_path_for_network(session, net, seg,
                                                     old_path=old_path,
                                                     new_path=hlink.path)

    # Topology RPC method handler
    def delete_link(self, context, host, interface, mac, switch, module, port):
        LOG.debug('Topology RPC: delete_link: %s',
                  ', '.join([str(p) for p in
                             (host, interface, mac, switch, module, port)]))
        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)

        hlink = self.aim.get(aim_ctx,
                             aim_infra.HostLink(host_name=host,
                                                interface_name=interface))
        if not hlink:
            return

        self.aim.delete(aim_ctx, hlink)
        # if there are no more host-links for this host (multiple links may
        # exist with VPC), update EPGs with ports on this host to remove
        # the static path to this host
        if not self.aim.find(aim_ctx, aim_infra.HostLink, host_name=host,
                             path=hlink.path):
            nets_segs = self._get_non_opflex_segments_on_host(context, host)
            for net, seg in nets_segs:
                self._update_static_path_for_network(session, net, seg,
                                                     old_path=hlink.path)

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
        context.set_binding(
            segment[api.ID], portbindings.VIF_TYPE_OVS,
            {portbindings.CAP_PORT_FILTER: self.sg_enabled,
             portbindings.OVS_HYBRID_PLUG: self.sg_enabled})

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

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    @property
    def aim_mapping(self):
        if not self._aim_mapping and self.gbp_plugin:
            self._aim_mapping = (self.gbp_plugin.policy_driver_manager.
                                 policy_drivers['aim_mapping'].obj)
        return self._aim_mapping

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

    def _get_routed_vrf_for_network(self, session, network_db):
        # REVISIT: This function leverages AIM's persistence of BDs,
        # VRFs, and the BD->VRF relationship, for the purpose of
        # determining what Tenant the network's BD and EPG are
        # currently mapped under. Consider persisting this information
        # directly in this mechanism driver instead. Alternatively,
        # use AimManager.find to get the BDs and EPGs by name,
        # avoiding the need to use this function to get the VRF and
        # then call _map_network.
        aim_ctx = aim_context.AimContext(session)
        bd_name = self.name_mapper.network(session, network_db.id)
        bds = self.aim.find(
            aim_ctx, aim_resource.BridgeDomain, name=bd_name)
        if len(bds) != 1:
            LOG.error(_LE("Failed to determine VRF for network %(net)s "
                          "due to missing or extra BDs: %(bds)s"),
                      {'net': network_db, 'bds': bds})
            return
        bd = bds[0]
        if bd.enable_routing:
            vrfs = (
                self.aim.find(
                    aim_ctx, aim_resource.VRF, tenant_name=bd.tenant_name,
                    name=bd.vrf_name) or
                self.aim.find(
                    aim_ctx, aim_resource.VRF, tenant_name=COMMON_TENANT_NAME,
                    name=bd.vrf_name))
            if len(vrfs) != 1:
                LOG.error(_LE("Failed to determine VRF for network %(net)s "
                              "due to missing or extra VRFs for BD %(bd)s: "
                              "%(vrfs)s"),
                          {'net': network_db, 'bd': bd, 'vrfs': vrfs})
            # Return only the identity since that is what would be
            # returned if we persisted the identity. Also, certain UTs
            # will break if we include other state, like
            # display_names.
            vrf = aim_resource.VRF(
                tenant_name=vrfs[0].tenant_name, name=vrfs[0].name)
            LOG.debug("Routed VRF for network %(net)s in project %(proj)s "
                      "is %(vrf)s",
                      {'net': network_db.id, 'proj': network_db.tenant_id,
                       'vrf': vrf})
            return vrf

    def _get_vrf_for_router(self, session, router):
        # REVISIT: Return list of VRFs for when multi-scope routing is
        # supported?
        network_db = (session.query(models_v2.Network).
                      join(models_v2.Port).
                      join(l3_db.RouterPort).
                      filter(l3_db.RouterPort.router_id == router['id'],
                             l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).
                      first())
        if network_db:
            return self._get_routed_vrf_for_network(session, network_db)

    def _get_address_scope_id_for_vrf(self, session, vrf):
        # Returns the ID of an address-scope that corresponds to a VRF,
        # if any.

        # Check if unrouted VRF
        if self._map_unrouted_vrf().identity == vrf.identity:
            return

        # Check if pre-existing VRF for an address-scope
        extn_db = extension_db.ExtensionDbMixin()
        scope_id = extn_db.get_address_scope_by_vrf_dn(session, vrf.dn)

        # Check if orchestrated VRF for an address-scope
        if not scope_id and vrf.name != DEFAULT_VRF_NAME:
            scope_id = self.name_mapper.reverse_address_scope(session,
                                                              vrf.name)
        return scope_id

    def _get_routers_for_vrf(self, session, vrf):
        # REVISIT: Persist router/VRF relationship?

        scope_id = self._get_address_scope_id_for_vrf(session, vrf)
        if scope_id:
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
            # For an unscoped VRF, first find all the routed BDs
            # referencing the VRF.
            aim_ctx = aim_context.AimContext(session)
            bds = self.aim.find(
                aim_ctx, aim_resource.BridgeDomain,
                tenant_name=vrf.tenant_name,
                vrf_name=DEFAULT_VRF_NAME,
                enable_routing=True)

            # Then find network IDs for those BDs mapped from networks.
            net_ids = []
            for bd in bds:
                id = self.name_mapper.reverse_network(
                    session, bd.name, enforce=False)
                if id:
                    net_ids.append(id)

            # Then find routers interfaced to those networks.
            rtr_dbs = (session.query(l3_db.Router).
                       join(l3_db.RouterPort).
                       join(models_v2.Port).
                       filter(models_v2.Port.network_id.in_(net_ids),
                              l3_db.RouterPort.port_type ==
                              n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct())
        return rtr_dbs

    def _associate_network_with_vrf(self, aim_ctx, network_db, new_vrf,
                                    nets_to_notify):
        LOG.debug("Associating previously unrouted network %(net_id)s named "
                  "'%(net_name)s' in project %(net_tenant)s with VRF %(vrf)s",
                  {'net_id': network_db.id, 'net_name': network_db.name,
                   'net_tenant': network_db.tenant_id, 'vrf': new_vrf})

        # NOTE: Must only be called for networks that are not yet
        # attached to any router.

        session = aim_ctx.db_session

        old_tenant_name = self.name_mapper.project(
            session, network_db.tenant_id)

        if (new_vrf.tenant_name != COMMON_TENANT_NAME and
            old_tenant_name != new_vrf.tenant_name):
            # Move BD and EPG to new VRF's Tenant, set VRF, and make
            # sure routing is enabled.
            LOG.debug("Moving network from tenant %(old)s to tenant %(new)s",
                      {'old': old_tenant_name, 'new': new_vrf.tenant_name})

            bd, epg = self._map_network(session, network_db, None)

            bd = self.aim.get(aim_ctx, bd)
            self.aim.delete(aim_ctx, bd)
            bd.tenant_name = new_vrf.tenant_name
            bd.enable_routing = True
            bd.vrf_name = new_vrf.name
            bd = self.aim.create(aim_ctx, bd)

            epg = self.aim.get(aim_ctx, epg)
            self.aim.delete(aim_ctx, epg)
            # ensure app profile exists in destination tenant
            ap = aim_resource.ApplicationProfile(
                tenant_name=new_vrf.tenant_name, name=self.ap_name)
            if not self.aim.get(aim_ctx, ap):
                self.aim.create(aim_ctx, ap)
            epg.tenant_name = new_vrf.tenant_name
            epg = self.aim.create(aim_ctx, epg)
        else:
            # Just set VRF and enable routing.
            bd, epg = self._map_network(session, network_db, new_vrf)
            bd = self.aim.update(aim_ctx, bd, enable_routing=True,
                                 vrf_name=new_vrf.name)

        # All non-router ports on this network need to be notified
        # since their BD's VRF and possibly their BD's and EPG's
        # Tenants have changed.
        nets_to_notify.add(network_db.id)

        return bd, epg

    def _dissassociate_network_from_vrf(self, aim_ctx, network_db, old_vrf,
                                        nets_to_notify):
        LOG.debug("Dissassociating network %(net_id)s named '%(net_name)s' in "
                  "project %(net_tenant)s from VRF %(vrf)s",
                  {'net_id': network_db.id, 'net_name': network_db.name,
                   'net_tenant': network_db.tenant_id, 'vrf': old_vrf})

        session = aim_ctx.db_session

        bd, epg = self._map_network(session, network_db, old_vrf)
        new_vrf = self._map_unrouted_vrf()

        new_tenant_name = self.name_mapper.project(
            session, network_db.tenant_id)

        # REVISIT(rkukura): Share code with _associate_network_with_vrf?
        if (old_vrf.tenant_name != COMMON_TENANT_NAME and
            old_vrf.tenant_name != new_tenant_name):
            # Move BD and EPG to network's Tenant, set unrouted VRF,
            # and disable routing.
            LOG.debug("Moving network from tenant %(old)s to tenant %(new)s",
                      {'old': old_vrf.tenant_name, 'new': new_tenant_name})

            bd = self.aim.get(aim_ctx, bd)
            self.aim.delete(aim_ctx, bd)
            bd.tenant_name = new_tenant_name
            bd.enable_routing = False
            bd.vrf_name = new_vrf.name
            bd = self.aim.create(aim_ctx, bd)

            epg = self.aim.get(aim_ctx, epg)
            self.aim.delete(aim_ctx, epg)
            epg.tenant_name = new_tenant_name
            epg = self.aim.create(aim_ctx, epg)
        else:
            # Just set unrouted VRF and disable routing.
            bd = self.aim.update(aim_ctx, bd, enable_routing=False,
                                 vrf_name=new_vrf.name)

        # All non-router ports on this network need to be notified
        # since their BD's VRF and possibly their BD's and EPG's
        # Tenants have changed.
        nets_to_notify.add(network_db.id)

    def _move_topology(self, aim_ctx, topology, old_vrf, new_vrf,
                       nets_to_notify):
        LOG.info(_LI("Moving routed networks %(topology)s from VRF "
                     "%(old_vrf)s to VRF %(new_vrf)s"),
                 {'topology': topology.keys(),
                  'old_vrf': old_vrf,
                  'new_vrf': new_vrf})

        # TODO(rkukura): Validate that nothing in new_vrf overlaps
        # with topology.

        session = aim_ctx.db_session

        for network_db in topology.itervalues():
            if old_vrf.tenant_name != new_vrf.tenant_name:
                # New VRF is in different Tenant, so move BD, EPG, and
                # all Subnets to new VRF's Tenant and set BD's VRF.
                LOG.debug("Moving network %(net)s from tenant %(old)s to "
                          "tenant %(new)s",
                          {'net': network_db.id,
                           'old': old_vrf.tenant_name,
                           'new': new_vrf.tenant_name})

                bd, epg = self._map_network(session, network_db, old_vrf)

                old_bd = self.aim.get(aim_ctx, bd)
                new_bd = copy.copy(old_bd)
                new_bd.tenant_name = new_vrf.tenant_name
                new_bd.vrf_name = new_vrf.name
                bd = self.aim.create(aim_ctx, new_bd)
                for subnet in self.aim.find(
                        aim_ctx, aim_resource.Subnet,
                        tenant_name=old_bd.tenant_name, bd_name=old_bd.name):
                    self.aim.delete(aim_ctx, subnet)
                    subnet.tenant_name = bd.tenant_name
                    subnet = self.aim.create(aim_ctx, subnet)
                self.aim.delete(aim_ctx, old_bd)

                epg = self.aim.get(aim_ctx, epg)
                self.aim.delete(aim_ctx, epg)
                epg.tenant_name = new_vrf.tenant_name
                epg = self.aim.create(aim_ctx, epg)
            else:
                # New VRF is in same Tenant, so just set BD's VRF.
                bd, _ = self._map_network(session, network_db, new_vrf)
                bd = self.aim.update(aim_ctx, bd, vrf_name=new_vrf.name)

        # All non-router ports on all networks in topology need to be
        # notified since their BDs' VRFs and possibly their BDs' and
        # EPGs' Tenants have changed.
        nets_to_notify.update(topology.keys())

    def _router_topology(self, session, router_id):
        LOG.debug("Getting topology for router %s", router_id)
        visited_networks = {}
        visited_router_ids = set()
        self._expand_topology_for_routers(
            session, visited_networks, visited_router_ids, [router_id])
        LOG.debug("Returning router topology %s", visited_networks)
        return visited_networks

    def _network_topology(self, session, network_db):
        LOG.debug("Getting topology for network %s", network_db.id)
        visited_networks = {}
        visited_router_ids = set()
        self._expand_topology_for_networks(
            session, visited_networks, visited_router_ids, [network_db])
        LOG.debug("Returning network topology %s", visited_networks)
        return visited_networks

    def _expand_topology_for_routers(self, session, visited_networks,
                                     visited_router_ids, new_router_ids):
        LOG.debug("Adding routers %s to topology", new_router_ids)
        added_ids = set(new_router_ids) - visited_router_ids
        if added_ids:
            visited_router_ids |= added_ids
            LOG.debug("Querying for networks interfaced to routers %s",
                      added_ids)
            query = (session.query(models_v2.Network).
                     join(models_v2.Port).
                     join(l3_db.RouterPort).
                     filter(l3_db.RouterPort.router_id.in_(added_ids)))
            if visited_networks:
                query = query.filter(
                    ~models_v2.Network.id.in_(visited_networks.keys()))
            results = (query.filter(l3_db.RouterPort.port_type ==
                                    n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct().
                       all())
            self._expand_topology_for_networks(
                session, visited_networks, visited_router_ids, results)

    def _expand_topology_for_networks(self, session, visited_networks,
                                      visited_router_ids, new_networks):
        LOG.debug("Adding networks %s to topology",
                  [net.id for net in new_networks])
        added_ids = []
        for net in new_networks:
            if net.id not in visited_networks:
                visited_networks[net.id] = net
                added_ids.append(net.id)
        if added_ids:
            LOG.debug("Querying for routers interfaced to networks %s",
                      added_ids)
            query = (session.query(l3_db.RouterPort.router_id).
                     join(models_v2.Port).
                     filter(models_v2.Port.network_id.in_(added_ids)))
            if visited_router_ids:
                query = query.filter(
                    ~l3_db.RouterPort.router_id.in_(visited_router_ids))
            results = (query.filter(l3_db.RouterPort.port_type ==
                                    n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct().
                       all())
            self._expand_topology_for_routers(
                session, visited_networks, visited_router_ids,
                [result[0] for result in results])

    def _topology_shared(self, topology):
        for network_db in topology.values():
            for entry in network_db.rbac_entries:
                # Access is enforced by Neutron itself, and we only
                # care whether or not the network is shared, so we
                # ignore the entry's target_tenant.
                if entry.action == rbac_db_models.ACCESS_SHARED:
                    return network_db

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

    def _map_network(self, session, network, vrf, bd_only=False):
        tenant_aname = (vrf.tenant_name
                        if vrf and vrf.tenant_name != COMMON_TENANT_NAME
                        else self.name_mapper.project(
                                session, network['tenant_id']))
        id = network['id']
        aname = self.name_mapper.network(session, id)

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

    def _map_subnet(self, subnet, gw_ip, bd):
        prefix_len = subnet['cidr'].split('/')[1]
        gw_ip_mask = gw_ip + '/' + prefix_len

        sn = aim_resource.Subnet(tenant_name=bd.tenant_name,
                                 bd_name=bd.name,
                                 gw_ip_mask=gw_ip_mask)
        return sn

    def _map_address_scope(self, session, scope):
        id = scope['id']
        extn_db = extension_db.ExtensionDbMixin()
        scope_extn = extn_db.get_address_scope_extn_db(session, id)
        if scope_extn and scope_extn.get(cisco_apic.VRF):
            vrf = aim_resource.VRF.from_dn(scope_extn[cisco_apic.VRF])
        else:
            tenant_aname = self.name_mapper.project(
                session, scope['tenant_id'])
            aname = self.name_mapper.address_scope(session, id)
            vrf = aim_resource.VRF(tenant_name=tenant_aname, name=aname)
        return vrf

    def _map_router(self, session, router, contract_only=False):
        id = router['id']
        aname = self.name_mapper.router(session, id)

        contract = aim_resource.Contract(tenant_name=COMMON_TENANT_NAME,
                                         name=aname)
        if contract_only:
            return contract
        subject = aim_resource.ContractSubject(tenant_name=COMMON_TENANT_NAME,
                                               contract_name=aname,
                                               name=ROUTER_SUBJECT_NAME)
        return contract, subject

    def _map_default_vrf(self, session, network):
        tenant_aname = self.name_mapper.project(session, network['tenant_id'])

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=DEFAULT_VRF_NAME)
        return vrf

    def _map_unrouted_vrf(self):
        vrf = aim_resource.VRF(
            tenant_name=COMMON_TENANT_NAME,
            name=self.apic_system_id + '_' + UNROUTED_VRF_NAME)
        return vrf

    def _ensure_common_tenant(self, aim_ctx):
        attrs = aim_resource.Tenant(name=COMMON_TENANT_NAME,
            display_name=aim_utils.sanitize_display_name('CommonTenant'))
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
            attrs.display_name = (
                aim_utils.sanitize_display_name('CommonUnroutedVRF'))
            LOG.info(_LI("Creating common unrouted VRF"))
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _ensure_any_filter(self, aim_ctx):
        self._ensure_common_tenant(aim_ctx)

        filter_name = self.apic_system_id + '_' + ANY_FILTER_NAME
        dname = aim_utils.sanitize_display_name("AnyFilter")
        filter = aim_resource.Filter(tenant_name=COMMON_TENANT_NAME,
                                     name=filter_name,
                                     display_name=dname)
        if not self.aim.get(aim_ctx, filter):
            LOG.info(_LI("Creating common Any Filter"))
            self.aim.create(aim_ctx, filter)

        dname = aim_utils.sanitize_display_name("AnyFilterEntry")
        entry = aim_resource.FilterEntry(tenant_name=COMMON_TENANT_NAME,
                                         filter_name=filter_name,
                                         name=ANY_FILTER_ENTRY_NAME,
                                         display_name=dname)
        if not self.aim.get(aim_ctx, entry):
            LOG.info(_LI("Creating common Any FilterEntry"))
            self.aim.create(aim_ctx, entry)

        return filter

    def _ensure_default_vrf(self, aim_ctx, attrs):
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            attrs.display_name = (
                aim_utils.sanitize_display_name('DefaultRoutedVRF'))
            LOG.info(_LI("Creating default VRF for %s"), attrs.tenant_name)
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _get_epg_for_network(self, session, network):
        if self._is_external(network):
            return self._map_external_network(session, network)
        # REVISIT(rkukura): Can the network_db be passed in?
        network_db = (session.query(models_v2.Network).
                      filter_by(id=network['id']).
                      one())
        vrf = self._get_routed_vrf_for_network(session, network_db)
        return self._map_network(session, network_db, vrf)[1]

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
                        .filter(models_v2.SubnetPool
                                .address_scope_id.isnot(None))
                        .distinct()):
            if pool_db.ip_version == 4:
                scope_id = pool_db.address_scope_id
                break
            elif pool_db.ip_version == 6:
                scope_id = pool_db.address_scope_id
        return scope_id

    def _manage_external_connectivity(self, context, router, old_network,
                                      new_network, vrf=None):
        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)

        vrf = vrf or self._get_vrf_for_router(session, router)
        # Keep only the identity attributes of the VRF so that calls to
        # nat-library have consistent resource values. This
        # is mainly required to ease unit-test verification.
        vrf = aim_resource.VRF(tenant_name=vrf.tenant_name, name=vrf.name)
        rtr_dbs = self._get_routers_for_vrf(session, vrf)
        ext_db = extension_db.ExtensionDbMixin()

        prov = set()
        cons = set()

        def update_contracts(router):
            contract = self._map_router(session, router, True)
            prov.add(contract.name)
            cons.add(contract.name)

            r_info = ext_db.get_router_extn_db(session, router['id'])
            prov.update(r_info[a_l3.EXTERNAL_PROVIDED_CONTRACTS])
            cons.update(r_info[a_l3.EXTERNAL_CONSUMED_CONTRACTS])

        if old_network:
            _, ext_net, ns = self._get_aim_nat_strategy(old_network)
            if ext_net:
                rtr_old = [r for r in rtr_dbs
                           if (r.gw_port_id and
                               r.gw_port.network_id == old_network['id'])]
                prov = set()
                cons = set()
                for r in rtr_old:
                    update_contracts(r)

                if rtr_old:
                    ext_net.provided_contract_names = sorted(prov)
                    ext_net.consumed_contract_names = sorted(cons)
                    ns.connect_vrf(aim_ctx, ext_net, vrf)
                else:
                    ns.disconnect_vrf(aim_ctx, ext_net, vrf)
        if new_network:
            _, ext_net, ns = self._get_aim_nat_strategy(new_network)
            if ext_net:
                rtr_new = [r for r in rtr_dbs
                           if (r.gw_port_id and
                               r.gw_port.network_id == new_network['id'])]
                prov = set()
                cons = set()
                for r in rtr_new:
                    update_contracts(r)
                update_contracts(router)
                ext_net.provided_contract_names = sorted(prov)
                ext_net.consumed_contract_names = sorted(cons)
                ns.connect_vrf(aim_ctx, ext_net, vrf)

    def _is_port_bound(self, port):
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _notify_port_update(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context.elevated(), port_id)
        if self._is_port_bound(port):
            LOG.debug("Enqueing notify for port %s", port['id'])
            txn = local_api.get_outer_transaction(
                plugin_context.session.transaction)
            local_api.send_or_queue_notification(plugin_context.session,
                                                 txn, self.notifier,
                                                 'port_update',
                                                 [plugin_context, port])

    def _notify_port_update_for_fip(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context.elevated(), port_id)
        ports_to_notify = [port_id]
        fixed_ips = [x['ip_address'] for x in port['fixed_ips']]
        if fixed_ips:
            addr_pair = (
                plugin_context.session.query(
                    n_addr_pair_db.AllowedAddressPair)
                .join(models_v2.Port)
                .filter(models_v2.Port.network_id == port['network_id'])
                .filter(n_addr_pair_db.AllowedAddressPair.ip_address.in_(
                    fixed_ips)).all())
            ports_to_notify.extend([x['port_id'] for x in addr_pair])
        for p in sorted(ports_to_notify):
            self._notify_port_update(plugin_context, p)

    def _notify_port_update_bulk(self, plugin_context, port_ids):
        # REVISIT: Is a single query for all ports possible?
        for p_id in port_ids:
            self._notify_port_update(plugin_context, p_id)

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
                except n_exceptions.IpAddressGenerationFailure:
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
                except n_exceptions.NeutronException as ne:
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
                raise exceptions.SnatPoolCannotBeUsedForFloatingIp()
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
                raise exceptions.SnatPoolCannotBeUsedForFloatingIp()

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

    def _use_static_path(self, bound_segment):
        return (bound_segment and
                self._is_supported_non_opflex_type(
                    bound_segment[api.NETWORK_TYPE]))

    def _update_static_path_for_network(self, session, network, segment,
                                        old_path=None, new_path=None):
        if new_path and not segment:
            return

        epg = self._get_epg_for_network(session, network)
        if not epg:
            LOG.info(_LI('Network %s does not map to any EPG'), network['id'])
            return

        if segment:
            if segment.get(api.NETWORK_TYPE) in [pconst.TYPE_VLAN]:
                seg = 'vlan-%s' % segment[api.SEGMENTATION_ID]
            else:
                LOG.debug('Unsupported segmentation type for static path '
                          'binding: %s',
                          segment.get(api.NETWORK_TYPE))
                return

        aim_ctx = aim_context.AimContext(db_session=session)
        epg = self.aim.get(aim_ctx, epg)
        to_remove = [old_path] if old_path else []
        to_remove.extend([new_path] if new_path else [])
        if to_remove:
            epg.static_paths = [p for p in epg.static_paths
                                if p.get('path') not in to_remove]
        if new_path:
            epg.static_paths.append({'path': new_path, 'encap': seg})
        LOG.debug('Setting static paths for EPG %s to %s',
                  epg, epg.static_paths)
        self.aim.update(aim_ctx, epg, static_paths=epg.static_paths)

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

        aim_ctx = aim_context.AimContext(db_session=session)
        host_link = self.aim.find(aim_ctx, aim_infra.HostLink, host_name=host)
        if not host_link or not host_link[0].path:
            LOG.warning(_LW('No host link information found for host %s'),
                        host)
            return
        host_link = host_link[0].path

        self._update_static_path_for_network(
            session, port_context.network.current, segment,
            **{'old_path' if remove else 'new_path': host_link})

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

    def _get_non_opflex_segments_on_host(self, context, host):
        session = context.session
        segments = (session.query(segments_db.NetworkSegment)
                    .join(models.PortBindingLevel)
                    .filter_by(host=host)
                    .all())
        net_ids = set([])
        result = []
        for seg in segments:
            if (self._is_supported_non_opflex_type(seg[api.NETWORK_TYPE]) and
                    seg.network_id not in net_ids):
                net = self.plugin.get_network(context, seg.network_id)
                result.append((net, segments_db._make_segment_dict(seg)))
                net_ids.add(seg.network_id)
        return result

    def _get_router_interface_subnets(self, session, router_id):
        subnet_ids = (session.query(models_v2.IPAllocation.subnet_id)
                      .join(l3_db.RouterPort,
                            models_v2.IPAllocation.port_id ==
                            l3_db.RouterPort.port_id)
                      .filter(l3_db.RouterPort.router_id == router_id)
                      .distinct())
        return [s[0] for s in subnet_ids]

    def _get_non_router_ports_in_subnets(self, session, subnet_ids):
        if not subnet_ids:
            return []
        port_ids = (session.query(models_v2.IPAllocation.port_id)
                    .join(models_v2.Port)
                    .filter(models_v2.IPAllocation.subnet_id.in_(subnet_ids))
                    .filter(models_v2.Port.device_owner !=
                            n_constants.DEVICE_OWNER_ROUTER_INTF)
                    .all())
        return [p[0] for p in port_ids]

    def _get_non_router_ports_in_networks(self, session, network_ids):
        if not network_ids:
            return []
        port_ids = (session.query(models_v2.Port.id).
                    filter(models_v2.Port.network_id.in_(network_ids)).
                    filter(models_v2.Port.device_owner !=
                           n_constants.DEVICE_OWNER_ROUTER_INTF).
                    all())
        return [p[0] for p in port_ids]
