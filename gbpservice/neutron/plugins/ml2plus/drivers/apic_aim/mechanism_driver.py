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
from aim import context as aim_context
from keystoneclient.v2_0 import client as keyclient
from neutron._i18n import _LI
from neutron.db import models_v2
from oslo_config import cfg
from oslo_log import log

from gbpservice.neutron.plugins.ml2plus import driver_api
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim.extensions import (
    cisco_apic)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model

LOG = log.getLogger(__name__)
AP_NAME = 'NeutronAP'


class ApicMechanismDriver(driver_api.MechanismDriver):

    def __init__(self):
        LOG.info(_LI("APIC AIM MD __init__"))

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))
        self.db = model.DbModel()
        self.name_mapper = apic_mapper.APICNameMapper(
            self.db, log, keyclient, cfg.CONF.keystone_authtoken)
        self.aim = aim_manager.AimManager()

    def ensure_tenant(self, plugin_context, tenant_id):
        LOG.info(_LI("APIC AIM MD ensuring tenant_id: %s"), tenant_id)

        session = plugin_context.session

        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        aim_ctx = aim_context.AimContext(session)

        tenant = aim_resource.Tenant(name=str(tenant_name))
        if not self.aim.get(aim_ctx, tenant):
            self.aim.create(aim_ctx, tenant)

        ap = aim_resource.ApplicationProfile(tenant_name=str(tenant_name),
                                             name=AP_NAME)
        if not self.aim.get(aim_ctx, ap):
            self.aim.create(aim_ctx, ap)

    def create_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating network: %s"), context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = context.current['id']
        name = context.current['name']
        bd_name = self.name_mapper.network(session, id, name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': bd_name})

        aim_ctx = aim_context.AimContext(session)

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(bd_name))
        self.aim.create(aim_ctx, bd)

        epg = aim_resource.EndpointGroup(tenant_name=str(tenant_name),
                                         app_profile_name=AP_NAME,
                                         name=str(bd_name))
        self.aim.create(aim_ctx, epg)

    def delete_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting network: %s"), context.current)

        session = context._plugin_context.session

        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = context.current['id']
        bd_name = self.name_mapper.network(session, id)
        LOG.info(_LI("Mapped network_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': bd_name})

        aim_ctx = aim_context.AimContext(session)

        epg = aim_resource.EndpointGroup(tenant_name=str(tenant_name),
                                         app_profile_name=AP_NAME,
                                         name=str(bd_name))
        self.aim.delete(aim_ctx, epg)

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(bd_name))
        self.aim.delete(aim_ctx, bd)

        self.name_mapper.delete_apic_name(session, id)

    def extend_network_dict(self, session, base_model, result):
        LOG.info(_LI("APIC AIM MD extending dict for network: %s"), result)

        sync_state = cisco_apic.SYNC_SYNCED

        tenant_id = result['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = result['id']
        name = result['name']
        bd_name = self.name_mapper.network(session, id, name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': bd_name})

        aim_ctx = aim_context.AimContext(session)

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(bd_name))
        bd = self.aim.get(aim_ctx, bd)
        LOG.debug("got BD with DN: %s", bd.dn)

        epg = aim_resource.EndpointGroup(tenant_name=str(tenant_name),
                                         app_profile_name=AP_NAME,
                                         name=str(bd_name))
        epg = self.aim.get(aim_ctx, epg)
        LOG.debug("got EPG with DN: %s", epg.dn)

        result[cisco_apic.DIST_NAMES] = {cisco_apic.BD: bd.dn,
                                         cisco_apic.EPG: epg.dn}

        bd_status = self.aim.get_status(aim_ctx, bd)
        self._merge_status(sync_state, bd_status)
        epg_status = self.aim.get_status(aim_ctx, epg)
        self._merge_status(sync_state, epg_status)
        result[cisco_apic.SYNC_STATE] = sync_state

    def create_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating subnet: %s"), context.current)

        # REVISIT(rkukura): Do we need to do any of the
        # constraints/scope stuff?

        gateway_ip_mask = self._gateway_ip_mask(context.current)
        if gateway_ip_mask:
            session = context._plugin_context.session

            network_id = context.current['network_id']
            # REVISIT(rkukura): Should Ml2Plus extend SubnetContext
            # with network?
            network = (session.query(models_v2.Network).
                       filter_by(id=network_id).
                       one())

            tenant_id = network.tenant_id
            tenant_name = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_name})

            network_name = network.name
            bd_name = self.name_mapper.network(session, network_id,
                                               network_name)
            LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                         "%(apic_name)s"),
                     {'id': network_id, 'name': network_name,
                      'apic_name': bd_name})

            aim_ctx = aim_context.AimContext(session)

            subnet = aim_resource.Subnet(tenant_name=str(tenant_name),
                                         bd_name=str(bd_name),
                                         gw_ip_mask=gateway_ip_mask)
            subnet = self.aim.create(aim_ctx, subnet)
            subnet_dn = subnet.dn
            subnet_status = self.aim.get_status(aim_ctx, subnet)
            sync_state = cisco_apic.SYNC_SYNCED
            self._merge_status(sync_state, subnet_status)

            # ML2 does not extend subnet dict after precommit.
            context.current[cisco_apic.DIST_NAMES] = {cisco_apic.SUBNET:
                                                      subnet_dn}
            context.current[cisco_apic.SYNC_STATE] = sync_state

    def update_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD updating subnet: %s"), context.current)

        if context.current['gateway_ip'] != context.original['gateway_ip']:
            session = context._plugin_context.session

            network_id = context.current['network_id']
            # REVISIT(rkukura): Should Ml2Plus extend SubnetContext
            # with network?
            network = (session.query(models_v2.Network).
                       filter_by(id=network_id).
                       one())

            tenant_id = network.tenant_id
            tenant_name = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_name})

            network_name = network.name
            bd_name = self.name_mapper.network(session, network_id,
                                               network_name)
            LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                         "%(apic_name)s"),
                     {'id': network_id, 'name': network_name,
                      'apic_name': bd_name})

            aim_ctx = aim_context.AimContext(session)

            gateway_ip_mask = self._gateway_ip_mask(context.original)
            if gateway_ip_mask:
                subnet = aim_resource.Subnet(tenant_name=str(tenant_name),
                                             bd_name=str(bd_name),
                                             gw_ip_mask=gateway_ip_mask)
                self.aim.delete(aim_ctx, subnet)

            gateway_ip_mask = self._gateway_ip_mask(context.current)
            if gateway_ip_mask:
                subnet = aim_resource.Subnet(tenant_name=str(tenant_name),
                                             bd_name=str(bd_name),
                                             gw_ip_mask=gateway_ip_mask)
                subnet = self.aim.create(aim_ctx, subnet)
                subnet_dn = subnet.dn
                subnet_status = self.aim.get_status(aim_ctx, subnet)
                sync_state = cisco_apic.SYNC_SYNCED
                self._merge_status(sync_state, subnet_status)

                # ML2 does not extend subnet dict after precommit.
                context.current[cisco_apic.DIST_NAMES] = {cisco_apic.SUBNET:
                                                          subnet_dn}
                context.current[cisco_apic.SYNC_STATE] = sync_state

    def delete_subnet_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting subnet: %s"), context.current)

        gateway_ip_mask = self._gateway_ip_mask(context.current)
        if gateway_ip_mask:
            session = context._plugin_context.session

            network_id = context.current['network_id']
            # REVISIT(rkukura): Should Ml2Plus extend SubnetContext
            # with network?
            network = (session.query(models_v2.Network).
                       filter_by(id=network_id).
                       one())

            tenant_id = network.tenant_id
            tenant_name = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_name})

            network_name = network.name
            bd_name = self.name_mapper.network(session, network_id,
                                               network_name)
            LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                         "%(apic_name)s"),
                     {'id': network_id, 'name': network_name,
                      'apic_name': bd_name})

            aim_ctx = aim_context.AimContext(session)

            subnet = aim_resource.Subnet(tenant_name=str(tenant_name),
                                         bd_name=str(bd_name),
                                         gw_ip_mask=gateway_ip_mask)
            self.aim.delete(aim_ctx, subnet)

    def extend_subnet_dict(self, session, base_model, result):
        LOG.info(_LI("APIC AIM MD extending dict for subnet: %s"), result)

        subnet_dn = None
        sync_state = cisco_apic.SYNC_SYNCED

        gateway_ip_mask = self._gateway_ip_mask(result)
        if gateway_ip_mask:
            network_id = result['network_id']
            network = (session.query(models_v2.Network).
                       filter_by(id=network_id).
                       one())

            tenant_id = network.tenant_id
            tenant_name = self.name_mapper.tenant(session, tenant_id)
            LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                     {'id': tenant_id, 'apic_name': tenant_name})

            network_name = network.name
            bd_name = self.name_mapper.network(session, network_id,
                                               network_name)
            LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                         "%(apic_name)s"),
                     {'id': network_id, 'name': network_name,
                      'apic_name': bd_name})

            aim_ctx = aim_context.AimContext(session)

            subnet = aim_resource.Subnet(tenant_name=str(tenant_name),
                                         bd_name=str(bd_name),
                                         gw_ip_mask=gateway_ip_mask)
            subnet = self.aim.get(aim_ctx, subnet)
            if subnet:
                LOG.debug("got Subnet with DN: %s", subnet.dn)
                subnet_dn = subnet.dn
                subnet_status = self.aim.get_status(aim_ctx, subnet)
                self._merge_status(sync_state, subnet_status)
            else:
                # This should always get replaced with the real DN
                # during precommit.
                subnet_dn = "AIM Subnet not yet created"

        result[cisco_apic.DIST_NAMES] = {cisco_apic.SUBNET: subnet_dn}
        result[cisco_apic.SYNC_STATE] = sync_state

    def _merge_status(self, sync_state, status):
        if status.is_error():
            sync_state = cisco_apic.SYNC_ERROR
        elif status.is_build() and sync_state is not cisco_apic.SYNC_ERROR:
            sync_state = cisco_apic.SYNC_BUILD

    def _gateway_ip_mask(self, subnet):
        gateway_ip = subnet['gateway_ip']
        if gateway_ip:
            prefix_len = subnet['cidr'].split('/')[1]
            return gateway_ip + '/' + prefix_len
