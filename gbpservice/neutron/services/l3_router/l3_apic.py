# Copyright (c) 2015 Cisco Systems Inc.
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

from neutron.common import constants as q_const
from neutron import context as n_ctx
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.plugins.common import constants

from apic_ml2.neutron.services.l3_router import apic_driver_api as api


class ApicGBPL3ServicePlugin(common_db_mixin.CommonDbMixin,
        extraroute_db.ExtraRoute_db_mixin,
        l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        super(ApicGBPL3ServicePlugin, self).__init__()
        self._apic_driver = apic_driver.ApicGBPL3Driver(self)

    def _update_router_gw_info(self, context, router_id, info, router=None):
        super(ApicGBPL3ServicePlugin, self)._update_router_gw_info(
            context, router_id, info, router)
        if info and 'network_id' in info:
            filters = {'device_id': [router_id],
                       'device_owner': [q_const.DEVICE_OWNER_ROUTER_GW],
                       'network_id': [info['network_id']]}
            ports = self._core_plugin.get_ports(context.elevated(),
                                                filters=filters)
            self._core_plugin.update_port_status(
                context, ports[0]['id'], q_const.PORT_STATUS_ACTIVE)

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    def add_router_interface(self, context, router_id, interface_info):
        port = super(ApicGBPL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        return self._apic_driver.add_router_interface_postcommit(
            context, router_id, interface_info
        )

    def remove_router_interface(self, context, router_id, interface_info):
        self._apic_driver.remove_router_interface_precommit(
            context, router_id, interface_info)
        super(ApicGBPL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    # Floating IP API
    def create_floatingip(self, context, floatingip):
        fip_context = api.FipContext(floatingip)
        res = self._apic_driver.create_floatingip_precommit(context, fip_context)
        if not res:
            res = super(ApicGBPL3ServicePlugin, self).create_floatingip(
                context, floatingip)
        self._apic_driver.create_floatingip_postcommit(context, fip_context)

    def update_floatingip(self, context, id, floatingip):
        fip_context = api.FipContext(floatingip)
        self._apic_driver.update_floatingip_precommit(context, id, fip_context)
        res = super(ApicGBPL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)
        self._apic_driver.update_floatingip_postcommit(context, id, fip_context)
        return res

    def delete_floatingip(self, context, id):
        fip_context = api.FipContext(floatingip)
        self._apic_driver.delete_floatingip_precommit(context, id, fip_context)
        res = super(ApicGBPL3ServicePlugin, self).delete_floatingip(
                context, id)
        self._apic_driver.delete_floatingip_postcommit(context, id, fip_context)
        return res
