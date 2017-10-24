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
import testtools

from neutron.api import extensions
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
from neutron_lib.plugins import directory
from oslo_config import cfg

from gbpservice.neutron.db import all_models  # noqa
import gbpservice.neutron.extensions
from gbpservice.neutron.tests.unit.plugins.ml2plus.drivers import (
    mechanism_logger as mech_logger)

PLUGIN_NAME = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'


# This is just a quick sanity test that basic ML2 plugin functionality
# is preserved.

class Ml2PlusPluginV2TestCase(test_address_scope.AddressScopeTestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        cfg.CONF.set_override('mechanism_drivers',
                ['logger_plus', 'test'], group='ml2')
        cfg.CONF.set_override('network_vlan_ranges',
                ['physnet1:1000:1099'], group='ml2_type_vlan')

        extensions.append_api_extensions_path(
            gbpservice.neutron.extensions.__path__)
        super(Ml2PlusPluginV2TestCase, self).setUp(PLUGIN_NAME)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.port_create_status = 'DOWN'
        self.plugin = directory.get_plugin()
        self.plugin.start_rpc_listeners()

    def exist_checker(self, getter):
        def verify(context):
            obj = getter(context._plugin_context, context.current['id'])
            self.assertIsNotNone(obj)
            return mock.DEFAULT
        return verify


class TestEnsureTenant(Ml2PlusPluginV2TestCase):
    def test_network(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_network(self.fmt, 'net', True, tenant_id='t1')
            et.assert_has_calls([mock.call(mock.ANY, 't1')])
            self.assertEqual(2, et.call_count)

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
            self.assertEqual(4, et.call_count)

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
            et.assert_has_calls([mock.call(mock.ANY, 't1')])
            self.assertEqual(2, et.call_count)

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
            self.assertEqual(4, et.call_count)

    def test_subnetpool(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_subnetpool(self.fmt, ['10.0.0.0/8'], name='sp1',
                                  tenant_id='t1')
            et.assert_called_once_with(mock.ANY, 't1')

    def test_address_scope(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'ensure_tenant') as et:
            self._make_address_scope(self.fmt, 4, name='as1', tenant_id='t1')
            et.assert_called_once_with(mock.ANY, 't1')


class TestSubnetPool(Ml2PlusPluginV2TestCase):
    def test_create(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'create_subnetpool_precommit') as pre:
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'create_subnetpool_postcommit') as post:
                self._make_subnetpool(self.fmt, ['10.0.0.0/8'], name='sp1',
                                      tenant_id='t1')

                self.assertEqual(1, pre.call_count)
                self.assertEqual('sp1',
                                 pre.call_args[0][0].current['name'])
                self.assertIsNone(pre.call_args[0][0].original)

                self.assertEqual(1, post.call_count)
                self.assertEqual('sp1',
                                 post.call_args[0][0].current['name'])
                self.assertIsNone(post.call_args[0][0].original)

    def test_update(self):
        subnetpool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='sp1', tenant_id='t1')['subnetpool']
        data = {'subnetpool': {'name': 'newnameforsubnetpool'}}
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'update_subnetpool_precommit') as pre:
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'update_subnetpool_postcommit') as post:
                res = self._update('subnetpools', subnetpool['id'],
                                   data)['subnetpool']
                self.assertEqual('newnameforsubnetpool', res['name'])

                self.assertEqual(1, pre.call_count)
                self.assertEqual('newnameforsubnetpool',
                                 pre.call_args[0][0].current['name'])
                self.assertEqual('sp1',
                                 pre.call_args[0][0].original['name'])

                self.assertEqual(1, post.call_count)
                self.assertEqual('newnameforsubnetpool',
                                 post.call_args[0][0].current['name'])
                self.assertEqual('sp1',
                                 post.call_args[0][0].original['name'])

    def test_delete(self):
        subnetpool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='sp1', tenant_id='t1')['subnetpool']
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'delete_subnetpool_precommit') as pre:
            pre.side_effect = self.exist_checker(
                                self.plugin.get_subnetpool)
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'delete_subnetpool_postcommit') as post:
                self._delete('subnetpools', subnetpool['id'])

                self.assertEqual(1, pre.call_count)
                self.assertEqual('sp1',
                                 pre.call_args[0][0].current['name'])
                self.assertIsNone(pre.call_args[0][0].original)

                self.assertEqual(1, post.call_count)
                self.assertEqual('sp1',
                                 post.call_args[0][0].current['name'])
                self.assertIsNone(post.call_args[0][0].original)


class TestAddressScope(Ml2PlusPluginV2TestCase):
    def test_create(self):
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'create_address_scope_precommit') as pre:
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'create_address_scope_postcommit') as post:
                self._make_address_scope(self.fmt, 4, name='as1',
                                         tenant_id='t1')

                self.assertEqual(1, pre.call_count)
                self.assertEqual('as1',
                                 pre.call_args[0][0].current['name'])
                self.assertIsNone(pre.call_args[0][0].original)

                self.assertEqual(1, post.call_count)
                self.assertEqual('as1',
                                 post.call_args[0][0].current['name'])
                self.assertIsNone(post.call_args[0][0].original)

    def test_update(self):
        address_scope = self._make_address_scope(
            self.fmt, 4, name='as1', tenant_id='t1')['address_scope']
        data = {'address_scope': {'name': 'newnameforaddress_scope'}}
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'update_address_scope_precommit') as pre:
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'update_address_scope_postcommit') as post:
                res = self._update('address-scopes', address_scope['id'],
                                   data)['address_scope']
                self.assertEqual('newnameforaddress_scope', res['name'])

                self.assertEqual(1, pre.call_count)
                self.assertEqual('newnameforaddress_scope',
                                 pre.call_args[0][0].current['name'])
                self.assertEqual('as1',
                                 pre.call_args[0][0].original['name'])

                self.assertEqual(1, post.call_count)
                self.assertEqual('newnameforaddress_scope',
                                 post.call_args[0][0].current['name'])
                self.assertEqual('as1',
                                 post.call_args[0][0].original['name'])

    def test_delete(self):
        address_scope = self._make_address_scope(
            self.fmt, 4, name='as1', tenant_id='t1')['address_scope']
        with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                               'delete_address_scope_precommit') as pre:
            pre.side_effect = self.exist_checker(self.plugin.get_address_scope)
            with mock.patch.object(mech_logger.LoggerPlusMechanismDriver,
                                   'delete_address_scope_postcommit') as post:
                self._delete('address-scopes', address_scope['id'])

                self.assertEqual(1, pre.call_count)
                self.assertEqual('as1',
                                 pre.call_args[0][0].current['name'])
                self.assertIsNone(pre.call_args[0][0].original)

                self.assertEqual(1, post.call_count)
                self.assertEqual('as1',
                                 post.call_args[0][0].current['name'])
                self.assertIsNone(post.call_args[0][0].original)


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2BasicGet(test_plugin.TestBasicGet,
                      Ml2PlusPluginV2TestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            Ml2PlusPluginV2TestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2PortsV2(test_plugin.TestPortsV2,
                     Ml2PlusPluginV2TestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        Ml2PlusPluginV2TestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       Ml2PlusPluginV2TestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           Ml2PlusPluginV2TestCase):
    pass
