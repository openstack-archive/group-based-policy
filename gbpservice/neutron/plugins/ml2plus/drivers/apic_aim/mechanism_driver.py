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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim.common import utils
from aim import config as aim_cfg
from aim import context as aim_context
from aim import utils as aim_utils
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.common import constants as n_constants
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from opflexagent import constants as ofcst
from oslo_log import log

from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_l3
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model

LOG = log.getLogger(__name__)

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


class ApicMechanismDriver(api_plus.MechanismDriver):
    # TODO(rkukura): Derivations of tenant_aname throughout need to
    # take sharing into account.

    def __init__(self):
        LOG.info(_LI("APIC AIM MD __init__"))

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))
        self.project_name_cache = cache.ProjectNameCache()
        self.db = model.DbModel()
        self.name_mapper = apic_mapper.APICNameMapper(self.db, log)
        self.aim = aim_manager.AimManager()
        self._core_plugin = None
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

    def ensure_tenant(self, plugin_context, tenant_id):
        LOG.debug("APIC AIM MD ensuring tenant_id: %s", tenant_id)

        self.project_name_cache.ensure_project(tenant_id)

        # TODO(rkukura): Move the following to calls made from
        # precommit methods so AIM Tenants, ApplicationProfiles, and
        # Filters are [re]created whenever needed.
        session = plugin_context.session
        with session.begin(subtransactions=True):
            project_name = self.project_name_cache.get_project_name(tenant_id)
            tenant_aname = self.name_mapper.tenant(session, tenant_id,
                                                   project_name)
            LOG.debug("Mapped tenant_id %(id)s with name %(name)s to "
                      "%(aname)s",
                      {'id': tenant_id, 'name': project_name,
                       'aname': tenant_aname})

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
        LOG.debug("APIC AIM MD creating network: %s", context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.network(session, id, name)
        LOG.debug("Mapped network_id %(id)s with name %(name)s to %(aname)s",
                  {'id': id, 'name': name, 'aname': aname})
        dname = aim_utils.sanitize_display_name(name)

        aim_ctx = aim_context.AimContext(session)

        vrf = self._get_unrouted_vrf(aim_ctx)

        # REVISIT(rkukura): When AIM changes default
        # ep_move_detect_mode value to 'garp', remove it here.
        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname,
                                       display_name=dname,
                                       vrf_name=vrf.name,
                                       enable_arp_flood=True,
                                       enable_routing=False,
                                       limit_ip_learn_to_subnets=True,
                                       ep_move_detect_mode='garp')
        self.aim.create(aim_ctx, bd)
        vmms, phys = self.get_aim_domains(aim_ctx)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname, display_name=dname,
                                         bd_name=aname,
                                         openstack_vmm_domain_names=vmms,
                                         physical_domain_names=phys)
        self.aim.create(aim_ctx, epg)

    def update_network_precommit(self, context):
        LOG.debug("APIC AIM MD updating network: %s", context.current)

        if context.current['name'] != context.original['name']:
            session = context._plugin_context.session

            tenant_id = context.current['tenant_id']
            tenant_aname = self.name_mapper.tenant(session, tenant_id)
            LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                      {'id': tenant_id, 'aname': tenant_aname})

            id = context.current['id']
            name = context.current['name']
            aname = self.name_mapper.network(session, id, name)
            LOG.debug("Mapped network_id %(id)s with name %(name)s to "
                      "%(aname)s",
                      {'id': id, 'name': name, 'aname': aname})
            dname = aim_utils.sanitize_display_name(context.current['name'])

            aim_ctx = aim_context.AimContext(session)

            bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                           name=aname)
            bd = self.aim.update(aim_ctx, bd, display_name=dname)

            epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                             app_profile_name=self.ap_name,
                                             name=aname)
            epg = self.aim.update(aim_ctx, epg, display_name=dname)

    def delete_network_precommit(self, context):
        LOG.debug("APIC AIM MD deleting network: %s", context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.network(session, id, name)
        LOG.debug("Mapped network_id %(id)s with name %(name)s to %(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_ctx = aim_context.AimContext(session)

        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname)
        self.aim.delete(aim_ctx, epg)

        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname)
        self.aim.delete(aim_ctx, bd)

        self.name_mapper.delete_apic_name(session, id)

    def extend_network_dict(self, session, network_db, result):
        LOG.debug("APIC AIM MD extending dict for network: %s", result)

        # REVISIT(rkukura): Consider optimizing this method by
        # persisting the network->VRF relationship.

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        tenant_id = network_db.tenant_id
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = network_db.id
        name = network_db.name
        aname = self.name_mapper.network(session, id, name)
        LOG.debug("Mapped network_id %(id)s with name %(name)s to %(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                           name=aname)
        dist_names[cisco_apic.BD] = aim_bd.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_bd)

        aim_epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                             app_profile_name=self.ap_name,
                                             name=aname)
        dist_names[cisco_apic.EPG] = aim_epg.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_epg)

        # See if this network is interfaced to any routers.
        rp = (session.query(l3_db.RouterPort).
              join(models_v2.Port).
              filter(models_v2.Port.network_id == network_db.id,
                     l3_db.RouterPort.port_type ==
                     n_constants.DEVICE_OWNER_ROUTER_INTF).first())
        if rp:
            # A network is constrained to only one subnetpool per
            # address family. To support both single and dual stack,
            # use the IPv4 address scope's VRF if it exists, and
            # otherwise use the IPv6 address scope's VRF. For dual
            # stack, the plan is for identity NAT to move IPv6 traffic
            # from the IPv4 address scope's VRF to the IPv6 address
            # scope's VRF.
            #
            # REVISIT(rkukura): Ignore subnets that are not attached
            # to any router, or maybe just do a query joining
            # RouterPorts, Ports, Subnets, SubnetPools and
            # AddressScopes.
            pool_dbs = {subnet.subnetpool for subnet in network_db.subnets
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
                scope_tenant_id = scope_db.tenant_id
                vrf_tenant_aname = self.name_mapper.tenant(session,
                                                           scope_tenant_id)
                LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                          {'id': scope_tenant_id, 'aname': vrf_tenant_aname})

                vrf_aname = self.name_mapper.address_scope(session, scope_id)
                LOG.debug("Mapped address_scope_id %(id)s to %(aname)s",
                          {'id': scope_id, 'aname': vrf_aname})
            else:
                vrf_tenant_aname = tenant_aname  # REVISIT(rkukura)
                vrf_aname = DEFAULT_VRF_NAME
        else:
            vrf_tenant_aname = COMMON_TENANT_NAME
            vrf_aname = UNROUTED_VRF_NAME
        aim_vrf = aim_resource.VRF(tenant_name=vrf_tenant_aname,
                                   name=vrf_aname)
        dist_names[cisco_apic.VRF] = aim_vrf.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_subnet_precommit(self, context):
        LOG.debug("APIC AIM MD creating subnet: %s", context.current)
        # Neutron subnets are mapped to AIM Subnets as they are added
        # to routers as interfaces.

    def update_subnet_precommit(self, context):
        LOG.debug("APIC AIM MD updating subnet: %s", context.current)

        if context.current['name'] != context.original['name']:
            session = context._plugin_context.session

            network_id = context.current['network_id']
            network_db = self.plugin._get_network(context._plugin_context,
                                                  network_id)

            network_tenant_id = network_db.tenant_id
            network_tenant_aname = self.name_mapper.tenant(session,
                                                           network_tenant_id)
            LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                      {'id': network_tenant_id, 'aname': network_tenant_aname})

            network_aname = self.name_mapper.network(session, network_id)
            LOG.info(_LI("Mapped network_id %(id)s to %(aname)s"),
                     {'id': network_id, 'aname': network_aname})

            # TODO(rkukura): Combine subnet name and name of
            # interfaced router to build display name for each mapped
            # Subnet.
            dname = aim_utils.sanitize_display_name(context.current['name'])

            aim_ctx = aim_context.AimContext(session)
            prefix_len = context.current['cidr'].split('/')[1]
            subnet_id = context.current['id']

            for intf in self._subnet_router_interfaces(session, subnet_id):
                gw_ip = intf.ip_address
                gw_ip_mask = gw_ip + '/' + prefix_len
                aim_subnet = aim_resource.Subnet(tenant_name=
                                                 network_tenant_aname,
                                                 bd_name=network_aname,
                                                 gw_ip_mask=gw_ip_mask)
                self.aim.update(aim_ctx, aim_subnet, display_name=dname)

    def delete_subnet_precommit(self, context):
        LOG.debug("APIC AIM MD deleting subnet: %s", context.current)
        # Neutron subnets are unmapped from AIM Subnets as they are
        # removed from routers.

    def extend_subnet_dict(self, session, subnet_db, result):
        LOG.debug("APIC AIM MD extending dict for subnet: %s", result)

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        prefix_len = subnet_db.cidr.split('/')[1]

        network_id = subnet_db.network_id
        network_db = (session.query(models_v2.Network).
                      filter_by(id=network_id).
                      one())
        network_tenant_id = network_db.tenant_id

        network_tenant_aname = self.name_mapper.tenant(session,
                                                       network_tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': network_tenant_id, 'aname': network_tenant_aname})

        network_aname = self.name_mapper.network(session, network_id)
        LOG.debug("Mapped network_id %(id)s to %(aname)s",
                  {'id': network_id, 'aname': network_aname})

        subnet_id = subnet_db.id
        for intf in self._subnet_router_interfaces(session, subnet_id):
            gw_ip = intf.ip_address
            gw_ip_mask = gw_ip + '/' + prefix_len
            aim_subnet = aim_resource.Subnet(tenant_name=network_tenant_aname,
                                             bd_name=network_aname,
                                             gw_ip_mask=gw_ip_mask)
            dist_names[gw_ip] = aim_subnet.dn
            sync_state = self._merge_status(aim_ctx, sync_state, aim_subnet)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    # TODO(rkukura): Implement update_subnetpool_precommit to handle
    # changing subnetpool's address_scope_id.

    def create_address_scope_precommit(self, context):
        LOG.debug("APIC AIM MD creating address scope: %s", context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.address_scope(session, id, name)
        LOG.debug("Mapped address_scope_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})
        dname = aim_utils.sanitize_display_name(name)

        aim_ctx = aim_context.AimContext(session)

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=aname,
                               display_name=dname)
        self.aim.create(aim_ctx, vrf)

        # ML2Plus does not extend address scope dict after precommit.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, vrf)
        context.current[cisco_apic.DIST_NAMES] = {cisco_apic.VRF:
                                                  vrf.dn}
        context.current[cisco_apic.SYNC_STATE] = sync_state

    def update_address_scope_precommit(self, context):
        LOG.debug("APIC AIM MD updating address_scope: %s", context.current)

        if context.current['name'] != context.original['name']:
            session = context._plugin_context.session

            tenant_id = context.current['tenant_id']
            tenant_aname = self.name_mapper.tenant(session, tenant_id)
            LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                      {'id': tenant_id, 'aname': tenant_aname})

            id = context.current['id']
            name = context.current['name']
            aname = self.name_mapper.address_scope(session, id, name)
            LOG.debug("Mapped address_scope_id %(id)s with name %(name)s to "
                      "%(aname)s",
                      {'id': id, 'name': name, 'aname': aname})
            dname = aim_utils.sanitize_display_name(name)

            aim_ctx = aim_context.AimContext(session)

            vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                   name=aname)
            vrf = self.aim.update(aim_ctx, vrf, display_name=dname)

    def delete_address_scope_precommit(self, context):
        LOG.debug("APIC AIM MD deleting address scope: %s", context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.address_scope(session, id, name)
        LOG.debug("Mapped address_scope_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_ctx = aim_context.AimContext(session)

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=aname)
        self.aim.delete(aim_ctx, vrf)

        self.name_mapper.delete_apic_name(session, id)

    def extend_address_scope_dict(self, session, scope_db, result):
        LOG.debug("APIC AIM MD extending dict for address scope: %s", result)

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        tenant_id = scope_db.tenant_id
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = scope_db.id
        name = scope_db.name
        aname = self.name_mapper.address_scope(session, id, name)
        LOG.debug("Mapped address_scope_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                   name=aname)
        dist_names[cisco_apic.VRF] = aim_vrf.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_router(self, context, current):
        LOG.debug("APIC AIM MD creating router: %s", current)

        session = context.session

        tenant_id = current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = current['id']
        name = current['name']
        aname = self.name_mapper.router(session, id, name)
        LOG.debug("Mapped router_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})
        dname = aim_utils.sanitize_display_name(name)

        aim_ctx = aim_context.AimContext(session)

        contract = aim_resource.Contract(tenant_name=tenant_aname,
                                         name=aname,
                                         display_name=dname)
        self.aim.create(aim_ctx, contract)

        subject = aim_resource.ContractSubject(tenant_name=tenant_aname,
                                               contract_name=aname,
                                               name=ROUTER_SUBJECT_NAME,
                                               display_name=dname,
                                               bi_filters=[ANY_FILTER_NAME])
        self.aim.create(aim_ctx, subject)

        # REVISIT(rkukura): Consider having L3 plugin extend router
        # dict again after calling this function.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, contract)
        sync_state = self._merge_status(aim_ctx, sync_state, subject)
        current[cisco_apic.DIST_NAMES] = {cisco_apic_l3.CONTRACT: contract.dn,
                                          cisco_apic_l3.CONTRACT_SUBJECT:
                                          subject.dn}
        current[cisco_apic.SYNC_STATE] = sync_state

    def update_router(self, context, current, original):
        LOG.debug("APIC AIM MD updating router: %s", current)

        if current['name'] != original['name']:
            session = context.session

            tenant_id = current['tenant_id']
            tenant_aname = self.name_mapper.tenant(session, tenant_id)
            LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                      {'id': tenant_id, 'aname': tenant_aname})

            id = current['id']
            name = current['name']
            aname = self.name_mapper.router(session, id, name)
            LOG.debug("Mapped router_id %(id)s with name %(name)s to "
                      "%(aname)s",
                      {'id': id, 'name': name, 'aname': aname})
            dname = aim_utils.sanitize_display_name(name)

            aim_ctx = aim_context.AimContext(session)

            contract = aim_resource.Contract(tenant_name=tenant_aname,
                                             name=aname)
            contract = self.aim.update(aim_ctx, contract, display_name=dname)

            subject = aim_resource.ContractSubject(tenant_name=tenant_aname,
                                                   contract_name=aname,
                                                   name=ROUTER_SUBJECT_NAME)
            subject = self.aim.update(aim_ctx, subject, display_name=dname)

        # REVISIT(rkukura): Update extension attributes?

    def delete_router(self, context, current):
        LOG.debug("APIC AIM MD deleting router: %s", current)

        session = context.session

        tenant_id = current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = current['id']
        name = current['name']
        aname = self.name_mapper.router(session, id, name)
        LOG.debug("Mapped router_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_ctx = aim_context.AimContext(session)

        subject = aim_resource.ContractSubject(tenant_name=tenant_aname,
                                               contract_name=aname,
                                               name=ROUTER_SUBJECT_NAME)
        self.aim.delete(aim_ctx, subject)

        contract = aim_resource.Contract(tenant_name=tenant_aname,
                                         name=aname)
        self.aim.delete(aim_ctx, contract)

        self.name_mapper.delete_apic_name(session, id)

    def extend_router_dict(self, session, router_db, result):
        LOG.debug("APIC AIM MD extending dict for router: %s", result)

        # REVISIT(rkukura): Consider optimizing this method by
        # persisting the router->VRF relationship.

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        tenant_id = router_db.tenant_id
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': tenant_id, 'aname': tenant_aname})

        id = router_db.id
        name = router_db.name
        aname = self.name_mapper.router(session, id, name)
        LOG.debug("Mapped router_id %(id)s with name %(name)s to "
                  "%(aname)s",
                  {'id': id, 'name': name, 'aname': aname})

        aim_contract = aim_resource.Contract(tenant_name=tenant_aname,
                                             name=aname)
        dist_names[cisco_apic_l3.CONTRACT] = aim_contract.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_contract)

        aim_subject = aim_resource.ContractSubject(tenant_name=tenant_aname,
                                                   contract_name=aname,
                                                   name=ROUTER_SUBJECT_NAME)
        dist_names[cisco_apic_l3.CONTRACT_SUBJECT] = aim_subject.dn
        sync_state = self._merge_status(aim_ctx, sync_state, aim_subject)

        # See if this router has any attached interfaces.
        if (session.query(l3_db.RouterPort).
            filter(l3_db.RouterPort.router_id == id,
                   l3_db.RouterPort.port_type ==
                   n_constants.DEVICE_OWNER_ROUTER_INTF).
            count()):
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
                            filter(l3_db.RouterPort.router_id == id,
                                   l3_db.RouterPort.port_type ==
                                   n_constants.DEVICE_OWNER_ROUTER_INTF).
                            distinct()):
                LOG.debug("got pool_db: %s", pool_db)
                if pool_db.ip_version == 4:
                    scope_id = pool_db.address_scope_id
                    break
                elif pool_db.ip_version == 6:
                    scope_id = pool_db.address_scope_id
            if scope_id:
                scope_db = self._scope_by_id(session, scope_id)
                scope_tenant_id = scope_db.tenant_id
                vrf_tenant_aname = self.name_mapper.tenant(session,
                                                           scope_tenant_id)
                LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                          {'id': scope_tenant_id, 'aname': vrf_tenant_aname})

                vrf_aname = self.name_mapper.address_scope(session, scope_id)
                LOG.debug("Mapped address_scope_id %(id)s to %(aname)s",
                          {'id': scope_id, 'aname': vrf_aname})
            else:
                vrf_tenant_aname = tenant_aname  # REVISIT(rkukura)
                vrf_aname = DEFAULT_VRF_NAME

            aim_vrf = aim_resource.VRF(tenant_name=vrf_tenant_aname,
                                       name=vrf_aname)
            dist_names[cisco_apic_l3.VRF] = aim_vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, aim_vrf)

        # TODO(rkukura): Also include interfaced Subnets. This
        # probably means splitting the above SubnetPool query to first
        # query for subnets, add the corresponding AIM subnet, then
        # check the subnet's subnetpool's address scope.

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def add_router_interface(self, context, router, port, subnets):
        LOG.debug("APIC AIM MD adding subnets %(subnets)s to router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router, 'port': port})

        session = context.session

        network_id = port['network_id']
        network_db = self.plugin._get_network(context, network_id)

        network_tenant_id = network_db.tenant_id
        network_tenant_aname = self.name_mapper.tenant(session,
                                                       network_tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': network_tenant_id, 'aname': network_tenant_aname})

        network_aname = self.name_mapper.network(session, network_id)
        LOG.info(_LI("Mapped network_id %(id)s to %(aname)s"),
                 {'id': network_id, 'aname': network_aname})

        router_tenant_id = router['tenant_id']
        router_tenant_aname = self.name_mapper.tenant(session,
                                                      router_tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': router_tenant_id, 'aname': router_tenant_aname})

        router_id = router['id']
        router_aname = self.name_mapper.router(session, router_id)
        LOG.info(_LI("Mapped router_id %(id)s to %(aname)s"),
                 {'id': router_id, 'aname': router_aname})

        aim_ctx = aim_context.AimContext(session)

        # Create AIM Subnet(s) for each added Neutron subnet.
        for subnet in subnets:
            gw_ip = self._ip_for_subnet(subnet, port['fixed_ips'])
            prefix_len = subnet['cidr'].split('/')[1]
            gw_ip_mask = gw_ip + '/' + prefix_len

            aim_subnet = aim_resource.Subnet(tenant_name=network_tenant_aname,
                                             bd_name=network_aname,
                                             gw_ip_mask=gw_ip_mask,
                                             display_name=subnet['name'])
            aim_subnet = self.aim.create(aim_ctx, aim_subnet)

        # Ensure network's EPG provides/consumes router's Contract.

        aim_epg = aim_resource.EndpointGroup(tenant_name=network_tenant_aname,
                                             app_profile_name=self.ap_name,
                                             name=network_aname)
        aim_epg = self.aim.get(aim_ctx, aim_epg)

        contracts = aim_epg.consumed_contract_names
        if router_aname not in contracts:
            contracts.append(router_aname)
            aim_epg = self.aim.update(aim_ctx, aim_epg,
                                      consumed_contract_names=contracts)

        contracts = aim_epg.provided_contract_names
        if router_aname not in contracts:
            contracts.append(router_aname)
            aim_epg = self.aim.update(aim_ctx, aim_epg,
                                      provided_contract_names=contracts)

        # Find routers with interfaces to this network. The current
        # interface is not included, because the RouterPort has not
        # yet been added to the DB session.
        router_ids = [r[0] for r in
                      session.query(l3_db.RouterPort.router_id).
                      join(models_v2.Port).
                      filter(models_v2.Port.network_id == network_id,
                             l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).distinct()]

        # TODO(rkukura): Validate topology.

        if not router_ids:
            # Enable routing for BD and set VRF.

            subnetpool_id = subnets[0]['subnetpool_id']
            if subnetpool_id:
                subnetpool_db = self.plugin._get_subnetpool(context,
                                                            subnetpool_id)
                address_scope_id = subnetpool_db.address_scope_id
                if address_scope_id:
                    vrf_aname = self.name_mapper.address_scope(
                        session, address_scope_id)
                    LOG.debug("Mapped address_scope_id %(id)s to %(aname)s",
                              {'id': id, 'aname': vrf_aname})
                else:
                    vrf_aname = self._get_default_vrf(
                        aim_ctx, router_tenant_aname).name
            else:
                vrf_aname = self._get_default_vrf(
                    aim_ctx, router_tenant_aname).name

            aim_bd = aim_resource.BridgeDomain(
                tenant_name=network_tenant_aname, name=network_aname)
            aim_bd = self.aim.update(aim_ctx, aim_bd, enable_routing=True,
                                     vrf_name=vrf_aname)

    def remove_router_interface(self, context, router_id, port_db, subnets):
        LOG.debug("APIC AIM MD removing subnets %(subnets)s from router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router_id, 'port': port_db})

        session = context.session

        network_id = port_db.network_id
        network_db = self.plugin._get_network(context, network_id)

        network_tenant_id = network_db.tenant_id
        network_tenant_aname = self.name_mapper.tenant(session,
                                                       network_tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': network_tenant_id, 'aname': network_tenant_aname})

        network_aname = self.name_mapper.network(session, network_id)
        LOG.info(_LI("Mapped network_id %(id)s to %(aname)s"),
                 {'id': network_id, 'aname': network_aname})

        router_db = (session.query(l3_db.Router).
                     filter_by(id=router_id).
                     one())
        router_tenant_id = router_db.tenant_id
        router_tenant_aname = self.name_mapper.tenant(session,
                                                      router_tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(aname)s",
                  {'id': router_tenant_id, 'aname': router_tenant_aname})

        router_aname = self.name_mapper.router(session, router_id)
        LOG.info(_LI("Mapped router_id %(id)s to %(aname)s"),
                 {'id': router_id, 'aname': router_aname})

        aim_ctx = aim_context.AimContext(session)

        # Remove AIM Subnet(s) for each removed Neutron subnet.
        for subnet in subnets:
            gw_ip = self._ip_for_subnet(subnet, port_db.fixed_ips)
            prefix_len = subnet['cidr'].split('/')[1]
            gw_ip_mask = gw_ip + '/' + prefix_len

            aim_subnet = aim_resource.Subnet(tenant_name=network_tenant_aname,
                                             bd_name=network_aname,
                                             gw_ip_mask=gw_ip_mask)
            self.aim.delete(aim_ctx, aim_subnet)

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
            aim_epg = aim_resource.EndpointGroup(
                tenant_name=network_tenant_aname,
                app_profile_name=self.ap_name,
                name=network_aname)
            aim_epg = self.aim.get(aim_ctx, aim_epg)

            contracts = [aname for aname in aim_epg.consumed_contract_names
                         if aname != router_aname]
            aim_epg = self.aim.update(aim_ctx, aim_epg,
                                      consumed_contract_names=contracts)

            contracts = [aname for aname in aim_epg.provided_contract_names
                         if aname != router_aname]
            aim_epg = self.aim.update(aim_ctx, aim_epg,
                                      provided_contract_names=contracts)

        # If network is no longer connected to any router, make the
        # network's BD unrouted.
        if not router_ids:
            vrf = self._get_unrouted_vrf(aim_ctx)

            aim_bd = aim_resource.BridgeDomain(
                tenant_name=network_tenant_aname, name=network_aname)
            aim_bd = self.aim.update(aim_ctx, aim_bd, enable_routing=False,
                                     vrf_name=vrf.name)

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on network %(net)s",
                  {'port': context.current['id'],
                   'net': context.network.current['id']})

        # TODO(rkukura): Add support for baremetal hosts, SR-IOV and
        # other situations requiring dynamic segments.

        # Check the VNIC type.
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in [portbindings.VNIC_NORMAL]:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        # For compute ports, try to bind DVS agent first.
        if context.current['device_owner'].startswith('compute:'):
            if self._agent_bind_port(context, AGENT_TYPE_DVS,
                                     self._dvs_bind_port):
                return

        # Try to bind OpFlex agent.
        self._agent_bind_port(context, ofcst.AGENT_TYPE_OPFLEX_OVS,
                              self._opflex_bind_port)

    def _agent_bind_port(self, context, agent_type, bind_strategy):
        for agent in context.host_agents(agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if bind_strategy(context, segment, agent):
                        LOG.debug("Bound using segment: %s", segment)
            else:
                LOG.warning(_LW("Refusing to bind port %(port)s to dead "
                                "agent: %(agent)s"),
                            {'port': context.current['id'], 'agent': agent})

    def _opflex_bind_port(self, context, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == ofcst.TYPE_OPFLEX:
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug("Checking segment: %(segment)s "
                      "for physical network: %(mappings)s ",
                      {'segment': segment, 'mappings': opflex_mappings})
            if (opflex_mappings is not None and
                segment[api.PHYSICAL_NETWORK] not in opflex_mappings):
                return False
        elif network_type != 'local':
            return False

        context.set_binding(segment[api.ID],
                            portbindings.VIF_TYPE_OVS,
                            {portbindings.CAP_PORT_FILTER: False,
                             portbindings.OVS_HYBRID_PLUG: False})

    def _dvs_bind_port(self, context, segment, agent):
        # TODO(rkukura): Implement DVS port binding
        return False

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = manager.NeutronManager.get_plugin()
        return self._core_plugin

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
        return sync_state

    def _ip_for_subnet(self, subnet, fixed_ips):
        subnet_id = subnet['id']
        for fixed_ip in fixed_ips:
            if fixed_ip['subnet_id'] == subnet_id:
                return fixed_ip['ip_address']

    def _subnet_router_interfaces(self, session, subnet_id):
        return (session.query(models_v2.IPAllocation).
                join(models_v2.Port).
                join(l3_db.RouterPort).
                filter(
                    models_v2.IPAllocation.subnet_id == subnet_id,
                    l3_db.RouterPort.port_type ==
                    n_constants.DEVICE_OWNER_ROUTER_INTF
                ))

    def _scope_by_id(self, session, scope_id):
        return (session.query(address_scope_db.AddressScope).
                filter_by(id=scope_id).
                one())

    def _get_common_tenant(self, aim_ctx):
        attrs = aim_resource.Tenant(name=COMMON_TENANT_NAME,
                                    display_name='Common Tenant')
        tenant = self.aim.get(aim_ctx, attrs)
        if not tenant:
            LOG.info(_LI("Creating common tenant"))
            tenant = self.aim.create(aim_ctx, attrs)
        return tenant

    def _get_unrouted_vrf(self, aim_ctx):
        tenant = self._get_common_tenant(aim_ctx)
        attrs = aim_resource.VRF(tenant_name=tenant.name,
                                 name=UNROUTED_VRF_NAME,
                                 display_name='Common Unrouted VRF')
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            LOG.info(_LI("Creating common unrouted VRF"))
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _get_default_vrf(self, aim_ctx, tenant_aname):
        attrs = aim_resource.VRF(tenant_name=tenant_aname,
                                 name=DEFAULT_VRF_NAME,
                                 display_name='Default Routed VRF')
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            LOG.info(_LI("Creating default VRF for %s"), tenant_aname)
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
