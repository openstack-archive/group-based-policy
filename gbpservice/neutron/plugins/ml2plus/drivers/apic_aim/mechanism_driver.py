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
from oslo_config import cfg
from oslo_log import log

from gbpservice.neutron.plugins.ml2plus import driver_api
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model

LOG = log.getLogger(__name__)


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

        tenant_name = self.name_mapper.tenant(plugin_context, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

    def create_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating network: %s"), context.current)

        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(context._plugin_context,
                                              tenant_id, None)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = context.current['id']
        name = context.current['name']
        network_name = self.name_mapper.network(context._plugin_context,
                                                id, name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': network_name})

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(network_name))
        aim_ctx = aim_context.AimContext(context._plugin_context.session)
        self.aim.create(aim_ctx, bd)

    def delete_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD deleting network: %s"), context.current)

        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(context._plugin_context,
                                              tenant_id, None)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = context.current['id']
        network_name = self.name_mapper.network(context._plugin_context, id)
        LOG.info(_LI("Mapped network_id %(id)s to %(apic_name)s"),
                 {'id': id, 'apic_name': network_name})

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(network_name))
        aim_ctx = aim_context.AimContext(context._plugin_context.session)
        self.aim.delete(aim_ctx, bd)

        self.name_mapper.delete_apic_name(context._plugin_context, id)
