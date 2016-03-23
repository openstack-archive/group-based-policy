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

import mock

from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

from gbpservice.neutron.tests.unit.plugins.ml2plus.drivers import (
    mechanism_logger as mech_logger)

PLUGIN_NAME = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'


# This is just a quick sanity test that basic ML2 plugin functionality
# is preserved.

class Ml2PlusPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger_plus', 'test'],
                                     'ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')
        super(Ml2PlusPluginV2TestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()


class TestEnsureTenant(Ml2PlusPluginV2TestCase):
    def test_network(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_network(self.fmt, 'net', True, tenant_id='t1')
            et.assert_called_once_with(mock.ANY, 't1')

    def test_network_bulk(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            networks = [{'network': {'name': 'n1',
                                     'tenant_id': 't1'}},
                        {'network': {'name': 'n2',
                                     'tenant_id': 't2'}},
                        {'network': {'name': 'n3',
                                     'tenant_id': 't1'}}]
            res = self._create_bulk_from_list(self.fmt, 'network', networks)
            self.assertEqual(201, res.status_int)
            et.assert_has_calls([mock.call(mock.ANY, 't1'),
                                 mock.call(mock.ANY, 't2')],
                                any_order=True)
            self.assertEqual(2, et.call_count)

    def test_subnet(self):
        net = self._make_network(self.fmt, 'net', True)

        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_subnet(self.fmt, net, None, '10.0.0.0/24',
                              tenant_id='t1')
            et.assert_called_once_with(mock.ANY, 't1')

    def test_subnet_bulk(self):
        net = self._make_network(self.fmt, 'net', True)
        network_id = net['network']['id']

        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            subnets = [{'subnet': {'name': 's1',
                                   'network_id': network_id,
                                   'ip_version': 4,
                                   'cidr': '10.0.1.0/24',
                                   'tenant_id': 't1'}},
                       {'subnet': {'name': 's2',
                                   'network_id': network_id,
                                   'ip_version': 4,
                                   'cidr': '10.0.2.0/24',
                                   'tenant_id': 't2'}},
                       {'subnet': {'name': 'n3',
                                   'network_id': network_id,
                                   'ip_version': 4,
                                   'cidr': '10.0.3.0/24',
                                   'tenant_id': 't1'}}]
            res = self._create_bulk_from_list(self.fmt, 'subnet', subnets)
            self.assertEqual(201, res.status_int)
            et.assert_has_calls([mock.call(mock.ANY, 't1'),
                                 mock.call(mock.ANY, 't2')],
                                any_order=True)
            self.assertEqual(2, et.call_count)

    def test_port(self):
        net = self._make_network(self.fmt, 'net', True)

        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_port(self.fmt, net['network']['id'], tenant_id='t1')
            et.assert_called_once_with(mock.ANY, 't1')

    def test_port_bulk(self):
        net = self._make_network(self.fmt, 'net', True)
        network_id = net['network']['id']

        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            ports = [{'port': {'name': 's1',
                               'network_id': network_id,
                               'tenant_id': 't1'}},
                     {'port': {'name': 's2',
                               'network_id': network_id,
                               'tenant_id': 't2'}},
                     {'port': {'name': 'n3',
                               'network_id': network_id,
                               'tenant_id': 't1'}}]
            res = self._create_bulk_from_list(self.fmt, 'port', ports)
            self.assertEqual(201, res.status_int)
            et.assert_has_calls([mock.call(mock.ANY, 't1'),
                                 mock.call(mock.ANY, 't2')],
                                any_order=True)
            self.assertEqual(2, et.call_count)


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      Ml2PlusPluginV2TestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            Ml2PlusPluginV2TestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2,
                     Ml2PlusPluginV2TestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        Ml2PlusPluginV2TestCase):
    pass


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       Ml2PlusPluginV2TestCase):
    pass


class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           Ml2PlusPluginV2TestCase):
    pass
