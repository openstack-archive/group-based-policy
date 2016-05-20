# Copyright (c) 2016 Cisco Systems
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

import mock
from neutron.common import constants as q_const
from neutron import context

import apicapi.apic_mapper  # noqa

from gbpservice.neutron.services.l3_router import l3_apic
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_apic_mapping)


TENANT = 'tenant1'
ROUTER = 'router1'
SUBNET = 'subnet1'
NETWORK = 'network1'
PORT = 'port1'
NETWORK_NAME = 'one_network'
FLOATINGIP = 'fip1'


# TODO(tbachman): create better test class hierarchy to inherit
class TestCiscoApicGBPL3Driver(test_apic_mapping.ApicMappingTestCase):

    def setUp(self):
        super(TestCiscoApicGBPL3Driver, self).setUp()

        # Some actual dicts to return
        self.subnet = {'network_id': NETWORK, 'tenant_id': TENANT}
        self.port = {'tenant_id': TENANT,
                     'network_id': NETWORK,
                     'fixed_ips': [{'subnet_id': SUBNET}],
                     'id': PORT}
        self.interface_info = {'subnet': {'subnet_id': SUBNET},
                               'port': {'port_id': self.port['id']}}
        self.floatingip = {'id': FLOATINGIP,
                           'floating_network_id': NETWORK_NAME,
                           'port_id': PORT}
        self.context = context.get_admin_context()
        self.context.tenant_id = TENANT

        # Create our plugin, but mock some superclass and
        # core plugin methods
        self.plugin = l3_apic.ApicGBPL3ServicePlugin()
        self.plugin._apic_driver._notify_port_update = mock.Mock()
        self.plugin._apic_driver._apic_gbp = mock.Mock()

        self.plugin._core_plugin.get_ports = mock.Mock(
            return_value=[self.port])
        self.plugin._core_plugin.get_port = mock.Mock(return_value=self.port)
        self.plugin._core_plugin.get_subnet = mock.Mock(
            return_value = self.subnet)
        self.plugin._core_plugin.update_port_status = mock.Mock()

        # Floating IP updates to agents are mocked
        self.plugin.update_floatingip_status = mock.Mock()
        self.plugin.get_floatingip = mock.Mock(return_value=self.floatingip)

    # This is so we can inherit from the ApicMappingTestCase
    # TODO(tbachman): fix hack used because of class hierarchy
    def test_reverse_on_delete(self):
        pass

    def _check_call_list(self, expected, observed):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        self.assertFalse(
            len(observed),
            msg='There are more calls than expected: %s' % str(observed))

    def _test_add_router_interface_postcommit(self, interface_info):
        apic_driver = self.plugin._apic_driver
        apic_driver.add_router_interface_postcommit(self.context,
                                                    ROUTER, interface_info)
        test_assert = self.plugin._core_plugin.update_port_status
        test_assert.assert_called_once_with(self.context,
            self.port['id'], q_const.PORT_STATUS_ACTIVE)

    def test_add_router_interface_postcommit_subnet(self):
        self._test_add_router_interface_postcommit(
            self.interface_info['subnet'])

    def test_add_router_interface_postcommit_port(self):
        self._test_add_router_interface_postcommit(self.interface_info['port'])

    def _test_remove_router_interface_precommit(self, interface_info):
        plugin = self.plugin._core_plugin
        apic_driver = self.plugin._apic_driver
        apic_driver.remove_router_interface_precommit(self.context, ROUTER,
                                                      interface_info)
        plugin.update_port_status.assert_called_once_with(
            self.context, mock.ANY, q_const.PORT_STATUS_DOWN)

    def test_remove_router_interface_precommit_subnet(self):
        self._test_remove_router_interface_precommit(
            self.interface_info['subnet'])

    def test_remove_router_interface_precommit_port(self):
        self._test_remove_router_interface_precommit(
            self.interface_info['port'])

    def _dummy_generator(self, context, tenant_id, floatingip):
        self._dummy_list = [0, 1, 2, 3]
        for item in self._dummy_list:
            yield item

    def test_create_floatingip_precommit(self):
        fip = {'floatingip': self.floatingip,
               'id': FLOATINGIP, 'port_id': PORT}
        apic_driver = self.plugin._apic_driver
        apic_gbp = apic_driver.apic_gbp
        apic_gbp.nat_pool_iterator = self._dummy_generator
        apic_driver.create_floatingip_precommit(self.context, fip)
        for nat_pool in self.context.nat_pool_list:
            self.assertTrue(nat_pool in self._dummy_list)

    def test_create_floatingip_postcommit(self):
        fip = {'floatingip': self.floatingip,
               'id': FLOATINGIP, 'port_id': PORT}
        apic_driver = self.plugin._apic_driver
        self.context.result = fip
        apic_driver.create_floatingip_postcommit(self.context, fip)
        apic_driver._notify_port_update.assert_called_once_with(PORT)
        apic_driver._plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
        self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])

    def test_update_floatingip_precommit(self):
        fip = {'floatingip': self.floatingip}
        apic_driver = self.plugin._apic_driver
        apic_driver.update_floatingip_precommit(self.context, FLOATINGIP, fip)
        self.assertEqual(PORT, self.context.port_id_list[0])

    def test_update_floatingip_postcommit(self):
        fip = {'floatingip': self.floatingip,
               'id': FLOATINGIP, 'port_id': PORT}
        self.context.port_id_list = []
        apic_driver = self.plugin._apic_driver
        apic_driver.update_floatingip_postcommit(self.context, FLOATINGIP, fip)
        self.assertEqual(self.port['id'], self.context.port_id_list[0])
        apic_driver._notify_port_update.assert_called_once_with(PORT)
        apic_driver._plugin.update_floatingip_status.assert_called_once_with(
            mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)

    def test_delete_floatingip_precommit(self):
        apic_driver = self.plugin._apic_driver
        apic_driver.delete_floatingip_precommit(self.context, FLOATINGIP)
        self.assertEqual(PORT, self.context.port_id_list[0])

    def test_delete_floatingip_postcommit(self):
        self.context.port_id_list = [PORT]
        apic_driver = self.plugin._apic_driver
        apic_driver.delete_floatingip_postcommit(self.context, FLOATINGIP)
        apic_driver._notify_port_update.assert_called_once_with(PORT)
