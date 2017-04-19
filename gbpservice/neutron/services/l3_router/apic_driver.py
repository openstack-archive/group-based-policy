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

from neutron import context as n_ctx
from neutron.extensions import l3
from neutron import manager
from neutron_lib import constants as q_const

from apic_ml2.neutron.services.l3_router import apic_driver_api


class ApicGBPL3Driver(apic_driver_api.ApicL3DriverBase):

    def __init__(self, plugin):
        super(ApicGBPL3Driver, self).__init__()
        self._plugin = plugin
        self._apic_gbp = None

    @property
    def apic_gbp(self):
        if not self._apic_gbp:
            self._apic_gbp = manager.NeutronManager.get_service_plugins()[
                'GROUP_POLICY'].policy_driver_manager.policy_drivers[
                'apic'].obj
        return self._apic_gbp

    def _get_port_id_for_router_interface(self, context, router_id, subnet_id):
        filters = {'device_id': [router_id],
                   'device_owner': [q_const.DEVICE_OWNER_ROUTER_INTF],
                   'fixed_ips': {'subnet_id': [subnet_id]}}
        ports = self._plugin._core_plugin.get_ports(context.elevated(),
                                                    filters=filters)
        return ports[0]['id']

    def _update_router_gw_info(self, context, router_id, info, router=None):
        super(ApicGBPL3Driver, self)._update_router_gw_info(
            context, router_id, info, router)
        if info and 'network_id' in info:
            filters = {'device_id': [router_id],
                       'device_owner': [q_const.DEVICE_OWNER_ROUTER_GW],
                       'network_id': [info['network_id']]}
            ports = self._plugin._core_plugin.get_ports(context.elevated(),
                                                        filters=filters)
            self._plugin._core_plugin.update_port_status(
                context, ports[0]['id'], q_const.PORT_STATUS_ACTIVE)

    def add_router_interface_postcommit(self, context, router_id,
                                        interface_info):
        if 'subnet_id' in interface_info:
            port_id = self._get_port_id_for_router_interface(
                context, router_id, interface_info['subnet_id'])
        else:
            port_id = interface_info['port_id']

        self._plugin._core_plugin.update_port_status(context,
            port_id, q_const.PORT_STATUS_ACTIVE)

    def remove_router_interface_precommit(self, context, router_id,
                                          interface_info):
        if 'subnet_id' in interface_info:
            port_id = self._get_port_id_for_router_interface(
                context, router_id, interface_info['subnet_id'])
        else:
            port_id = interface_info['port_id']

        self._plugin._core_plugin.update_port_status(context,
            port_id, q_const.PORT_STATUS_DOWN)

    # Floating IP API
    def create_floatingip_precommit(self, context, floatingip):
        fip = floatingip['floatingip']
        tenant_id = self._plugin._get_tenant_id_for_create(context, fip)
        if self.apic_gbp:
            context.nat_pool_list = []
            for nat_pool in self.apic_gbp.nat_pool_iterator(context,
                    tenant_id, floatingip):
                context.nat_pool_list.append(nat_pool)

    def create_floatingip_postcommit(self, context, floatingip):
        port_id = floatingip.get('floatingip', {}).get('port_id')
        self._notify_port_update(port_id)
        if getattr(context, 'result', None):
            context.result['status'] = self._update_floatingip_status(
                context, context.result['id'])

    def update_floatingip_precommit(self, context, id, floatingip):
        port_id = self._get_port_mapped_to_floatingip(context, id)
        context.port_id_list = [port_id]

    def update_floatingip_postcommit(self, context, id, floatingip):
        port_id_list = getattr(context, 'port_id_list', [])
        port_id_list.append(
            floatingip.get('floatingip', {}).get('port_id'))
        for p in port_id_list:
            self._notify_port_update(p)
        status = self._update_floatingip_status(context, id)
        if getattr(context, 'result', None):
            context.result['status'] = status

    def delete_floatingip_precommit(self, context, id):
        port_id_list = [self._get_port_mapped_to_floatingip(context, id)]
        context.port_id_list = port_id_list

    def delete_floatingip_postcommit(self, context, id):
        self._notify_port_update(context.port_id_list[0])

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
            fip = self._plugin.get_floatingip(context, fip_id)
            if fip.get('port_id'):
                status = q_const.FLOATINGIP_STATUS_ACTIVE
            self._plugin.update_floatingip_status(context, fip_id, status)
        except l3.FloatingIPNotFound:
            pass
        return status

    def _get_port_mapped_to_floatingip(self, context, fip_id):
        try:
            fip = self._plugin.get_floatingip(context, fip_id)
            return fip.get('port_id')
        except l3.FloatingIPNotFound:
            pass
        return None
