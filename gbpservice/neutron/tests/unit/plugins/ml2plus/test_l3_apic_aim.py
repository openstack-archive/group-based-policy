# Copyright (c) 2017 Cisco Systems
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
from neutron_lib import context

from gbpservice.neutron.services.apic_aim import l3_plugin
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver)


TENANT = 'tenant1'
ROUTER = 'router1'
NETWORK = 'network1'
CIDR = '10.0.0.0/16'


class TestCiscoApicAimL3Plugin(test_aim_mapping_driver.AIMBaseTestCase):
    '''Test class for the Cisco APIC AIM L3 Plugin

       This is a set of tests specific to the Cisco APIC AIM
       L3 plugin. It currently derives from the AIMBaseTestCase
       class so that it can inherit test infrastructure from those classes.
    '''

    def _verify_event_handler_calls(self, data, expected_call_count=1):
        if not hasattr(data, '__iter__') or isinstance(data, dict):
            data = [data]
        self.assertEqual(expected_call_count, self.handler_mock.call_count)
        call_idx = -1
        for item in data:
            if item:
                model = self.handler_mock.call_args_list[call_idx][0][-1]
                self.assertEqual(model['id'], item['id'])
                self.assertEqual(model['tenant_id'], item['tenant_id'])
            call_idx = call_idx - 1

    def setUp(self):
        handler_patch = mock.patch(
            'neutron.quota.resource.TrackedResource._db_event_handler')
        self.handler_mock = handler_patch.start()
        def_sec_group_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_ensure_default_security_group')
        def_sec_group_patch.start()
        super(TestCiscoApicAimL3Plugin, self).setUp()
        get_sec_group_port_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_get_security_groups_on_port')
        get_sec_group_port_patch.start()

        # Set up L2 objects for L3 test
        attr = {'tenant_id': TENANT}
        resp = self._create_network(self.fmt, NETWORK, True, **attr)
        self.network = self.deserialize(self.fmt, resp)['network']
        attr.update({'network_id': self.network['id']})
        resp = self._create_subnet(self.fmt, self.network['id'], CIDR, **attr)
        self.subnet = self.deserialize(self.fmt, resp)['subnet']
        resp = self._create_port(self.fmt, self.network['id'],
                                 tenant_id=TENANT)
        self.port = self.deserialize(self.fmt, resp)['port']
        self.interface_info = {'subnet': {'subnet_id': self.subnet['id']},
                               'port': {'port_id': self.port['id']}}
        self.context = context.get_admin_context()
        self.context.tenant_id = TENANT

        self.plugin = l3_plugin.ApicL3Plugin()

    def _test_add_router_interface(self, interface_info):

        attr = {'router': {'tenant_id': TENANT,
                           'admin_state_up': True,
                           'name': ROUTER}}
        router = self.plugin.create_router(self.context, attr)

        with mock.patch('neutron.callbacks.registry.notify'):
            info = self.plugin.add_router_interface(self.context,
                                                    router['id'],
                                                    interface_info)
            self.assertEqual(info['id'], router['id'])
            self.assertEqual(info['tenant_id'], TENANT)
            if interface_info.get('port_id'):
                self.assertEqual(info['port_id'], self.port['id'])
            else:
                self.assertNotEqual(info['port_id'], self.port['id'])
            self.assertEqual(info['subnet_id'], self.subnet['id'])
            self.assertEqual(info['network_id'], self.network['id'])

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

    def test_create_delete_floating_ip_triggers_event(self):
        net = self._make_network('json', 'meh', True)
        subnet = self._make_subnet('json', net, '14.0.0.1',
                                   '14.0.0.0/24')['subnet']
        self._set_net_external(subnet['network_id'])
        kwargs = {'floatingip': {'tenant_id': TENANT,
                                 'subnet_id': subnet['id'],
                                 'floating_network_id': subnet['network_id']}}
        self.handler_mock.reset_mock()
        floatingip = self.plugin.create_floatingip(self.context, kwargs)
        internal_ports = self._show('ports',
                                    floatingip['port_id'])['ports']
        for port in internal_ports:
            if port['device_owner'] == 'network:floatingip' and (
                    port['device_id'] == floatingip['id']):
                internal_port = port
        # When a floatingip is created it also creates port, therefore
        # there will be four calls in total to the event handler
        self._verify_event_handler_calls(floatingip,
                                         expected_call_count=2)
        self._delete('floatingips', floatingip['id'])
        # Expecting 2 more calls - 1 for the port, 1 for the floatingip
        self._verify_event_handler_calls(
            [internal_port, floatingip], expected_call_count=4)
