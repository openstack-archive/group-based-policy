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
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_dvr_db
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants


class ApicGBPL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
        l3_dvr_db.L3_NAT_with_dvr_db_mixin,
        extraroute_db.ExtraRoute_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        super(ApicGBPL3ServicePlugin, self).__init__()
        self._apic_gbp = None

    def _get_port_id_for_router_interface(self, context, router_id, subnet_id):
        filters = {'device_id': [router_id],
                   'device_owner': [q_const.DEVICE_OWNER_ROUTER_INTF],
                   'fixed_ips': {'subnet_id': [subnet_id]}}
        ports = self.get_ports(context.elevated(), filters=filters)
        return ports[0]['id']

    def _update_router_gw_info(self, context, router_id, info, router=None):
        super(ApicGBPL3ServicePlugin, self)._update_router_gw_info(
            context, router_id, info, router)
        if 'network_id' in info:
            filters = {'device_id': [router_id],
                       'device_owner': [q_const.DEVICE_OWNER_ROUTER_GW],
                       'network_id': [info['network_id']]}
            ports = self.get_ports(context.elevated(), filters=filters)
            manager.NeutronManager.get_plugin().update_port_status(
                context, ports[0]['id'], q_const.PORT_STATUS_ACTIVE)

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    @property
    def apic_gbp(self):
        if not self._apic_gbp:
            self._apic_gbp = manager.NeutronManager.get_service_plugins()[
                'GROUP_POLICY'].policy_driver_manager.policy_drivers[
                'apic'].obj
        return self._apic_gbp

    def add_router_interface(self, context, router_id, interface_info):
        super(ApicGBPL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        if 'subnet_id' in interface_info:
            port_id = self._get_port_id_for_router_interface(
                context, router_id, interface_info['subnet_id'])
        else:
            port_id = interface_info['port_id']

        manager.NeutronManager.get_plugin().update_port_status(context,
                port_id, q_const.PORT_STATUS_ACTIVE)

    def remove_router_interface(self, context, router_id, interface_info):
        if 'subnet_id' in interface_info:
            port_id = self._get_port_id_for_router_interface(
                context, router_id, interface_info['subnet_id'])
        else:
            port_id = interface_info['port_id']

        manager.NeutronManager.get_plugin().update_port_status(context,
                port_id, q_const.PORT_STATUS_DOWN)
        super(ApicGBPL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    # Floating IP API
    def create_floatingip(self, context, floatingip):
        res = None
        fip = floatingip['floatingip']
        if self.apic_gbp and not fip.get('subnet_id'):
            tenant_id = self._get_tenant_id_for_create(context, fip)
            fip_id = self.apic_gbp.create_floatingip_in_nat_pool(context,
                tenant_id, floatingip)
            res = self.get_floatingip(context, fip_id) if fip_id else None
        if not res:
            res = super(ApicGBPL3ServicePlugin, self).create_floatingip(
                context, floatingip)
        port_id = floatingip.get('floatingip', {}).get('port_id')
        self._notify_port_update(port_id)
        if res:
            res['status'] = self._update_floatingip_status(context, res['id'])
        return res

    def update_floatingip(self, context, id, floatingip):
        port_id = [self._get_port_mapped_to_floatingip(context, id)]
        res = super(ApicGBPL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)
        port_id.append(floatingip.get('floatingip', {}).get('port_id'))
        for p in port_id:
            self._notify_port_update(p)
        status = self._update_floatingip_status(context, id)
        if res:
            res['status'] = status
        return res

    def delete_floatingip(self, context, id):
        port_id = self._get_port_mapped_to_floatingip(context, id)
        res = super(ApicGBPL3ServicePlugin, self).delete_floatingip(
                context, id)
        self._notify_port_update(port_id)
        return res

    def _get_port_mapped_to_floatingip(self, context, fip_id):
        try:
            fip = self.get_floatingip(context, fip_id)
            return fip.get('port_id')
        except l3.FloatingIPNotFound:
            pass
        return None

    def _notify_port_update(self, port_id):
        context = n_ctx.get_admin_context()
        if self.apic_gbp and port_id:
            self.apic_gbp._notify_port_update(context, port_id)
            ptg, _ = self.apic_gbp._port_id_to_ptg(context, port_id)
            if ptg:
                self.apic_gbp._notify_head_chain_ports(ptg['id'])

    def _update_floatingip_status(self, context, fip_id):
        status = q_const.FLOATINGIP_STATUS_DOWN
        try:
            fip = self.get_floatingip(context, fip_id)
            if fip.get('port_id'):
                status = q_const.FLOATINGIP_STATUS_ACTIVE
            self.update_floatingip_status(context, fip_id, status)
        except l3.FloatingIPNotFound:
            pass
        return status
