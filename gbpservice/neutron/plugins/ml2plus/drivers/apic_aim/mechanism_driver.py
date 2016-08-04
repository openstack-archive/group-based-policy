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
from aim import config as aim_cfg
from aim import context as aim_context
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.common import constants as n_constants
# from neutron.db import models_v2
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from opflexagent import constants as ofcst
from oslo_log import log

from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim.extensions import (
    cisco_apic)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model

LOG = log.getLogger(__name__)
UNROUTED_VRF_NAME = 'UnroutedVRF'
COMMON_TENANT_NAME = 'common'
AGENT_TYPE_DVS = 'DVS agent'
VIF_TYPE_DVS = 'dvs'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]


class ApicMechanismDriver(api_plus.MechanismDriver):

    def __init__(self):
        LOG.info(_LI("APIC AIM MD __init__"))

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))
        self.project_name_cache = cache.ProjectNameCache()
        self.db = model.DbModel()
        self.name_mapper = apic_mapper.APICNameMapper(self.db, log)
        self.aim = aim_manager.AimManager()
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
        LOG.info(_LI("APIC AIM MD ensuring tenant_id: %s"), tenant_id)

        self.project_name_cache.ensure_project(tenant_id)

        # TODO(rkukura): Move the following to precommit methods so
        # AIM tenants and application profiles are created whenever
        # needed.
        session = plugin_context.session
        with session.begin(subtransactions=True):
            project_name = self.project_name_cache.get_project_name(tenant_id)
            LOG.debug("Got project_name: %s", project_name)
            tenant_aname = self.name_mapper.tenant(session, tenant_id,
                                                   project_name)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_aname})

            aim_ctx = aim_context.AimContext(session)

            tenant = aim_resource.Tenant(name=tenant_aname)
            if not self.aim.get(aim_ctx, tenant):
                self.aim.create(aim_ctx, tenant)
            ap = aim_resource.ApplicationProfile(tenant_name=tenant_aname,
                                                 name=self.ap_name)
            if not self.aim.get(aim_ctx, ap):
                self.aim.create(aim_ctx, ap)

    def create_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating network: %s"), context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.network(session, id, name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': aname})
        dname = self._make_display_name(name)

        aim_ctx = aim_context.AimContext(session)

        vrf = self._get_unrouted_vrf(aim_ctx)

        bd = aim_resource.BridgeDomain(
            tenant_name=tenant_aname,
            name=aname,
            display_name=dname,
            vrf_name=vrf.name,
            enable_arp_flood=True,
            enable_routing=False,
            limit_ip_learn_to_subnets=True)
        self.aim.create(aim_ctx, bd)

        epg = aim_resource.EndpointGroup(
            tenant_name=tenant_aname,
            app_profile_name=self.ap_name,
            name=aname,
            display_name=dname,
            bd_name=aname)
        self.aim.create(aim_ctx, epg)

    def update_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD updating network: %s"),
                 context.current)

        if context.current['name'] != context.original['name']:
            session = context._plugin_context.session

            tenant_id = context.current['tenant_id']
            tenant_aname = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_aname})

            aname = self.name_mapper.network(session,
                                             context.current['id'])
            LOG.info(_LI("Mapped network_id %(id)s to %(apic_name)s"),
                     {'id': id, 'apic_name': aname})

            dname = self._make_display_name(context.current['name'])

            aim_ctx = aim_context.AimContext(session)

            bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                           name=aname)
            bd = self.aim.update(aim_ctx, bd, display_name=dname)

            epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                             app_profile_name=self.ap_name,
                                             name=aname)
            epg = self.aim.update(aim_ctx, epg, display_name=dname)

    def delete_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting network: %s"), context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})

        id = context.current['id']
        aname = self.name_mapper.network(session, id)
        LOG.info(_LI("Mapped network_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': aname})

        aim_ctx = aim_context.AimContext(session)

        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname)
        self.aim.delete(aim_ctx, epg)

        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname)
        self.aim.delete(aim_ctx, bd)

        self.name_mapper.delete_apic_name(session, id)

    def extend_network_dict(self, session, base_model, result):
        LOG.info(_LI("APIC AIM MD extending dict for network: %s"), result)

        sync_state = cisco_apic.SYNC_SYNCED

        tenant_id = result['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})
        if not tenant_aname:
            return

        id = result['id']
        aname = self.name_mapper.network(session, id)
        LOG.info(_LI("Mapped network_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': aname})
        if not aname:
            return

        aim_ctx = aim_context.AimContext(session)

        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname)
        bd = self.aim.get(aim_ctx, bd)
        LOG.debug("got BD with DN: %s", bd.dn)

        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname)
        epg = self.aim.get(aim_ctx, epg)
        LOG.debug("got EPG with DN: %s", epg.dn)

        result[cisco_apic.DIST_NAMES] = {cisco_apic.BD: bd.dn,
                                         cisco_apic.EPG: epg.dn}

        bd_status = self.aim.get_status(aim_ctx, bd)
        sync_state = self._merge_status(sync_state, bd_status)
        epg_status = self.aim.get_status(aim_ctx, epg)
        sync_state = self._merge_status(sync_state, epg_status)
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating subnet: %s"), context.current)

    def update_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD updating subnet: %s"), context.current)

    def delete_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting subnet: %s"), context.current)

    def extend_subnet_dict(self, session, base_model, result):
        LOG.info(_LI("APIC AIM MD extending dict for subnet: %s"), result)

        sync_state = cisco_apic.SYNC_SYNCED

        result[cisco_apic.DIST_NAMES] = {}
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_address_scope_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating address scope: %s"),
                 context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})

        id = context.current['id']
        name = context.current['name']
        aname = self.name_mapper.address_scope(session, id, name)
        LOG.info(_LI("Mapped address_scope_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': aname})

        aim_ctx = aim_context.AimContext(session)

        vrf = aim_resource.VRF(
            tenant_name=tenant_aname,
            name=aname,
            display_name=self._make_display_name(name))
        self.aim.create(aim_ctx, vrf)
        vrf_dn = vrf.dn
        vrf_status = self.aim.get_status(aim_ctx, vrf)
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(sync_state, vrf_status)

        # ML2Plus does not extend address scope dict after precommit.
        context.current[cisco_apic.DIST_NAMES] = {cisco_apic.VRF:
                                                  vrf_dn}
        context.current[cisco_apic.SYNC_STATE] = sync_state

    def update_address_scope_precommit(self, context):
        LOG.info(_LI("APIC AIM MD updating address_scope: %s"),
                 context.current)

        if context.current['name'] != context.original['name']:
            session = context._plugin_context.session

            tenant_id = context.current['tenant_id']
            tenant_aname = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_aname})

            aname = self.name_mapper.address_scope(session,
                                                   context.current['id'])
            LOG.info(_LI("Mapped address_scope_id %(id)s to %(apic_name)s"),
                     {'id': id, 'apic_name': aname})

            dname = self._make_display_name(context.current['name'])

            aim_ctx = aim_context.AimContext(session)

            vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                   name=aname)
            vrf = self.aim.update(aim_ctx, vrf, display_name=dname)

    def delete_address_scope_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting address scope: %s"),
                 context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})

        id = context.current['id']
        aname = self.name_mapper.address_scope(session, id)
        LOG.info(_LI("Mapped address_scope_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': aname})

        aim_ctx = aim_context.AimContext(session)

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=aname)
        self.aim.delete(aim_ctx, vrf)

        self.name_mapper.delete_apic_name(session, id)

    def extend_address_scope_dict(self, session, base_model, result):
        LOG.info(_LI("APIC AIM MD extending dict for address scope: %s"),
                 result)

        sync_state = cisco_apic.SYNC_SYNCED

        tenant_id = result['tenant_id']
        tenant_aname = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_aname})
        if not tenant_aname:
            return

        id = result['id']
        aname = self.name_mapper.address_scope(session, id)
        LOG.info(_LI("Mapped address_scope_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': aname})
        if not aname:
            return

        aim_ctx = aim_context.AimContext(session)

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=aname)
        vrf = self.aim.get(aim_ctx, vrf)
        if vrf:
            vrf_dn = vrf.dn
            LOG.debug("got VRF with DN: %s", vrf_dn)
            vrf_status = self.aim.get_status(aim_ctx, vrf)
            sync_state = self._merge_status(sync_state, vrf_status)
        else:
            # This should always get replaced with the real DN during
            # precommit.
            vrf_dn = "AIM VRF not yet created"
        result[cisco_apic.DIST_NAMES] = {cisco_apic.VRF: vrf_dn}
        result[cisco_apic.SYNC_STATE] = sync_state

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

    def _merge_status(self, sync_state, status):
        if status.is_error():
            sync_state = cisco_apic.SYNC_ERROR
        elif status.is_build() and sync_state is not cisco_apic.SYNC_ERROR:
            sync_state = cisco_apic.SYNC_BUILD
        return sync_state

    def _gateway_ip_mask(self, subnet):
        gateway_ip = subnet['gateway_ip']
        if gateway_ip:
            prefix_len = subnet['cidr'].split('/')[1]
            return gateway_ip + '/' + prefix_len

    def _make_display_name(self, name):
        return name[:59]

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
                                 display_name='Common Unrouted Context')
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            LOG.info(_LI("Creating common unrouted VRF"))
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    # DB Configuration callbacks
    def _set_enable_metadata_opt(self, new_conf):
        self.enable_metadata_opt = new_conf['value']

    def _set_enable_dhcp_opt(self, new_conf):
        self.enable_dhcp_opt = new_conf['value']

    def _set_ap_name(self, new_conf):
        self.ap_name = new_conf['value']
