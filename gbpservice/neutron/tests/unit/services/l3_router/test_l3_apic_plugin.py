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
from neutron.common import exceptions as n_exc
from neutron import context

from gbpservice.neutron.services.l3_router import l3_apic
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_apic_mapping)


TENANT = 'tenant1'
ROUTER = 'router1'
SUBNET = 'subnet1'
NETWORK = 'network1'
PORT = 'port1'
NETWORK_NAME = 'one_network'
TEST_SEGMENT1 = 'test-segment1'
FLOATINGIP = 'fip1'


# TODO(tbachman): create better test class hierarchy to inherit
class TestCiscoApicL3Plugin(test_apic_mapping.ApicMappingTestCase):
    '''Test class for the Cisco APIC L3 Plugin

       This is a set of tests specific to the Cisco APIC
       L3 plugin. It currently derives from the ApicMappingTestCase
       class so that it can inherit test infrastructure from those classes.
    '''

    def setUp(self):
        super(TestCiscoApicL3Plugin, self).setUp()

        # Some actual dicts to return
        self.subnet = {'network_id': NETWORK, 'tenant_id': TENANT}
        self.port = {'tenant_id': TENANT,
                     'network_id': NETWORK,
                     'fixed_ips': [{'subnet_id': SUBNET}],
                     'id': 'port_id'}
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

        self.plugin._core_plugin.get_ports = mock.Mock(
            return_value=[self.port])
        self.plugin._core_plugin.get_port = mock.Mock(return_value=self.port)
        self.plugin._core_plugin.get_subnet = mock.Mock(
            return_value = self.subnet)
        self.plugin._core_plugin.update_port_status = mock.Mock()

        # Floating IP updates to agents are mocked
        self.plugin.update_floatingip_status = mock.Mock()
        self.plugin.get_floatingip = mock.Mock(return_value=self.floatingip)

    def _check_call_list(self, expected, observed):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        self.assertFalse(
            len(observed),
            msg='There are more calls than expected: %s' % str(observed))

    def _test_add_router_interface(self, interface_info):
        with mock.patch('neutron.db.l3_db.'
                        'L3_NAT_db_mixin.add_router_interface') as if_mock:
            if_mock.return_value = self.port
            port = self.plugin.add_router_interface(self.context,
                                                    ROUTER, interface_info)
            self.assertEqual(port, self.port)
            test_assert = self.plugin._core_plugin.update_port_status
            test_assert.assert_called_once_with(self.context,
                self.port['id'], q_const.PORT_STATUS_ACTIVE)

    def _test_remove_router_interface(self, interface_info):
        with mock.patch('neutron.db.l3_db.'
                        'L3_NAT_db_mixin.remove_router_interface') as if_mock:
            self.plugin.remove_router_interface(self.context, ROUTER,
                                                interface_info)
            self.assertEqual(1, if_mock.call_count)

    def test_add_router_interface_subnet(self):
        self._test_add_router_interface(self.interface_info['subnet'])

    def test_add_router_interface_port(self):
        self._test_add_router_interface(self.interface_info['port'])

    def test_remove_router_interface_subnet(self):
        self._test_remove_router_interface(self.interface_info['subnet'])

    def test_remove_router_interface_port(self):
        self._test_remove_router_interface(self.interface_info['port'])

    def test_create_router_gateway_fails(self):
        # Force _update_router_gw_info failure
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        '_update_router_gw_info',
                        side_effect=n_exc.NeutronException):
            data = {'router': {'tenant_id': 'foo',
                'name': 'router1', 'admin_state_up': True,
                'external_gateway_info': {'network_id': 'some_uuid'}}}
            # Verify router doesn't persist on failure
            self.assertRaises(n_exc.NeutronException,
                              self.plugin.create_router, self.context, data)
            routers = self.plugin.get_routers(self.context)
            self.assertEqual(0, len(routers))

    def test_floatingip_port_notify_on_create(self):
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'create_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            # create floating-ip with mapped port
            plugin = self.plugin
            plugin.create_floatingip(self.context,
                                     {'floatingip': self.floatingip})
            plugin._apic_driver._notify_port_update.assert_called_once_with(
                PORT)

    def test_floatingip_port_notify_on_reassociate(self):
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'update_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            # associate with different port
            new_fip = {'port_id': 'port-another'}
            self.plugin.update_floatingip(self.context, FLOATINGIP,
                                          {'floatingip': new_fip})
            self._check_call_list(
                [mock.call(PORT),
                 mock.call('port-another')],
                self.plugin._apic_driver._notify_port_update.call_args_list)

    def test_floatingip_port_notify_on_disassociate(self):
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'update_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            # dissociate mapped port
            plugin = self.plugin
            plugin.update_floatingip(self.context, FLOATINGIP,
                                     {'floatingip': {}})
            plugin._apic_driver._notify_port_update.assert_any_call(
                PORT)

    def test_floatingip_port_notify_on_delete(self):
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.delete_floatingip'):
            # delete
            plugin = self.plugin
            plugin.delete_floatingip(self.context, FLOATINGIP)
            plugin._apic_driver._notify_port_update.assert_called_once_with(
                PORT)

    def test_floatingip_status(self):
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'create_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            # create floating-ip with mapped port
            fip = self.plugin.create_floatingip(self.context,
                {'floatingip': self.floatingip})
            self.plugin.update_floatingip_status.assert_called_once_with(
                mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
            self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])

        # dissociate mapped-port
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'update_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            self.plugin.update_floatingip_status.reset_mock()
            self.floatingip.pop('port_id')
            fip = self.plugin.update_floatingip(self.context, FLOATINGIP,
                {'floatingip': self.floatingip})
            self.plugin.update_floatingip_status.assert_called_once_with(
                mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_DOWN)
            self.assertEqual(q_const.FLOATINGIP_STATUS_DOWN, fip['status'])

        # re-associate mapped-port
        with mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.'
                        'update_floatingip',
                        new=mock.Mock(return_value=self.floatingip)):
            self.plugin.update_floatingip_status.reset_mock()
            self.floatingip['port_id'] = PORT
            fip = self.plugin.update_floatingip(self.context, FLOATINGIP,
                {'floatingip': self.floatingip})
            self.plugin.update_floatingip_status.assert_called_once_with(
                mock.ANY, FLOATINGIP, q_const.FLOATINGIP_STATUS_ACTIVE)
            self.assertEqual(q_const.FLOATINGIP_STATUS_ACTIVE, fip['status'])
