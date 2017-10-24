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
from neutron.tests.unit import testlib_api
from neutron_lib import context
from oslo_db import exception as exc
from oslo_utils import importutils

from gbpservice.neutron.db import all_models  # noqa
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    port_ha_ipaddress_binding as ha)

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class PortToHAIPAddressBindingTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(PortToHAIPAddressBindingTestCase, self).setUp()
        self.plugin = importutils.import_object(DB_PLUGIN_KLASS)
        self.context = context.get_admin_context()
        self.net1_data = {'network': {'id': 'fake-net1-id',
                                      'name': 'net1',
                                      'admin_state_up': True,
                                      'tenant_id': 'test-tenant',
                                      'shared': False}}
        self.net2_data = {'network': {'id': 'fake-net2-id',
                                      'name': 'net2',
                                      'admin_state_up': True,
                                      'tenant_id': 'test-tenant',
                                      'shared': False}}
        self.port1_data = {'port': {'id': 'fake-port1-id',
                                    'name': 'port1',
                                    'network_id': 'fake-net1-id',
                                    'tenant_id': 'test-tenant',
                                    'device_id': 'fake_device',
                                    'device_owner': 'fake_owner',
                                    'fixed_ips': [],
                                    'mac_address': 'fake-mac',
                                    'admin_state_up': True}}
        # Port that is in the same network as port_1
        self.port1_2_data = {'port': {'id': 'fake-port1-2-id',
                                      'name': 'port1',
                                      'network_id': 'fake-net1-id',
                                      'tenant_id': 'test-tenant',
                                      'device_id': 'fake_device',
                                      'device_owner': 'fake_owner',
                                      'fixed_ips': [],
                                      'mac_address': 'fake-mac-2',
                                      'admin_state_up': True}}
        self.port2_data = {'port': {'id': 'fake-port2-id',
                                    'name': 'port2',
                                    'network_id': 'fake-net2-id',
                                    'tenant_id': 'test-tenant',
                                    'device_id': 'fake_device',
                                    'device_owner': 'fake_owner',
                                    'fixed_ips': [],
                                    'mac_address': 'fake-mac',
                                    'admin_state_up': True}}
        self.ha_ip1 = "ha-ip-1"
        self.ha_ip2 = "ha-ip-2"
        self.plugin.create_network(self.context, self.net1_data)
        self.plugin.create_network(self.context, self.net2_data)
        self.port1 = self.plugin.create_port(self.context, self.port1_data)
        self.port1_2 = self.plugin.create_port(self.context, self.port1_2_data)
        self.port2 = self.plugin.create_port(self.context, self.port2_data)
        self.port_haip = ha.PortForHAIPAddress()

    def test_set_and_get_port_to_ha_ip_binding(self):
        # Test new HA IP address to port binding can be created
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertEqual(self.port1['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])
        # In this test case we also test that same HA IP address can be set/get
        # for two different ports in different networks
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port2['id'], self.ha_ip1)
        self.assertEqual(self.port2['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])
        # Test get
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port2['network_id'])
        self.assertEqual(self.port2['id'], obj['port_id'])

    def test_port_to_multiple_ha_ip_binding(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip1)
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip2)
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip2, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])

    def test_delete_port_for_ha_ip_binding(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip1)
        result = self.port_haip.delete_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertEqual(1, result)
        obj = self.port_haip.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port2['network_id'])
        self.assertIsNone(obj)

    def test_get_ha_ip_addresses_for_port(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip1)
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip2)
        ha_ips = self.port_haip.get_ha_ipaddresses_for_port(self.port1['id'])
        self.assertEqual(sorted([self.ha_ip1, self.ha_ip2]), ha_ips)

    def test_idempotent(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip1)
        obj = self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                          self.ha_ip1)
        self.assertEqual(self.port1['id'], obj['port_id'])
        self.assertEqual(self.ha_ip1, obj['ha_ip_address'])

    def test_set_non_existing_port(self):
        self.assertRaises(exc.DBReferenceError,
                          self.port_haip.set_port_id_for_ha_ipaddress,
                          "fake", self.ha_ip1)

    def test_delete_non_existing_entry(self):
        self.port_haip.set_port_id_for_ha_ipaddress(self.port1['id'],
                                                    self.ha_ip1)
        result = self.port_haip.delete_port_id_for_ha_ipaddress(
            self.port1['id'], "fake")
        self.assertEqual(0, result)
        result = self.port_haip.delete_port_id_for_ha_ipaddress("fake",
                                                                self.ha_ip1)
        self.assertEqual(0, result)

    def test_ip_owner_update(self):
        mixin = ha.HAIPOwnerDbMixin()
        mixin._get_plugin = mock.Mock(return_value=self.plugin)
        ip_owner_info = {'port': self.port1['id'],
                         'ip_address_v4': self.ha_ip1}

        # set new owner
        ports = mixin.update_ip_owner(ip_owner_info)
        obj = mixin.ha_ip_handler.get_port_for_ha_ipaddress(
            self.ha_ip1, self.port1['network_id'])
        self.assertEqual(self.port1['id'], obj['port_id'])
        self.assertTrue(self.port1['id'] in ports)

        # update owner
        self.port2_data['port']['id'] = 'fake-port3-id'
        self.port2_data['port']['network_id'] = self.port1['network_id']
        self.port2_data['port']['mac_address'] = 'fake-mac-3'
        port3 = self.plugin.create_port(self.context, self.port2_data)

        ip_owner_info['port'] = port3['id']
        ports = mixin.update_ip_owner(ip_owner_info)
        obj = mixin.ha_ip_handler.get_port_for_ha_ipaddress(
            self.ha_ip1, port3['network_id'])
        self.assertEqual(port3['id'], obj['port_id'])

    def test_ip_replaced(self):
        mixin = ha.HAIPOwnerDbMixin()
        mixin._get_plugin = mock.Mock(return_value=self.plugin)
        ip_owner_info = {'port': self.port1['id'],
                         'ip_address_v4': self.ha_ip1}
        mixin.update_ip_owner(ip_owner_info)
        # Verify only one entry is there
        dump = mixin.ha_ip_handler.get_ha_port_associations()
        self.assertEqual(1, len(dump))
        self.assertEqual(self.port1['id'], dump[0].port_id)
        self.assertEqual(self.ha_ip1, dump[0].ha_ip_address)

        # Now override with port1_2
        ip_owner_info['port'] = self.port1_2['id']
        mixin.update_ip_owner(ip_owner_info)
        # Verify still one entry exists
        dump = mixin.ha_ip_handler.get_ha_port_associations()
        self.assertEqual(1, len(dump))
        self.assertEqual(self.port1_2['id'], dump[0].port_id)
        self.assertEqual(self.ha_ip1, dump[0].ha_ip_address)

        # Override again, but with a different net_id to keep both records
        ip_owner_info['port'] = self.port1['id']
        ip_owner_info['network_id'] = 'new_net_id'
        mixin.update_ip_owner(ip_owner_info)
        # Verify still one entry exists
        dump = mixin.ha_ip_handler.get_ha_port_associations()
        self.assertEqual(2, len(dump))

    def test_duplicate_entry_handled_gracefully(self):
        self.port_haip.set_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        # Set this twice, without hijacking the query
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertEqual(obj.port_id, self.port1['id'])
        self.assertEqual(obj.ha_ip_address, self.ha_ip1)
        # Now simulate null return from query
        self.port_haip._get_ha_ipaddress = mock.Mock(return_value=None)
        obj = self.port_haip.set_port_id_for_ha_ipaddress(
            self.port1['id'], self.ha_ip1)
        self.assertIsNone(obj)
