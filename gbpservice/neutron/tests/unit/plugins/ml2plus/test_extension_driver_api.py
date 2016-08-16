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
import uuid

from neutron import context
from neutron import manager
from neutron.plugins.ml2 import config

from gbpservice.neutron.tests.unit.plugins.ml2plus.drivers import (
    extension_test as ext_test)
from gbpservice.neutron.tests.unit.plugins.ml2plus import test_plugin


class ExtensionDriverTestCase(test_plugin.Ml2PlusPluginV2TestCase):

    _extension_drivers = ['test_ml2plus']

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(ExtensionDriverTestCase, self).setUp()
        self._plugin = manager.NeutronManager.get_plugin()
        self._ctxt = context.get_admin_context()

    def _verify_subnetpool_create(self, code, exc_reason):
        tenant_id = str(uuid.uuid4())
        data = {'subnetpool': {'prefixes': ['10.0.0.0/8'],
                               'name': 'sp1',
                               'tenant_id': tenant_id}}
        req = self.new_create_request('subnetpools', data)
        res = req.get_response(self.api)
        self.assertEqual(code, res.status_int)

        subnetpool = self.deserialize(self.fmt, res)
        if exc_reason:
            self.assertEqual(exc_reason,
                             subnetpool['NeutronError']['type'])

        return (subnetpool, tenant_id)

    def _verify_subnetpool_update(self, subnetpool, code, exc_reason):
        sp_id = subnetpool['subnetpool']['id']
        new_name = 'a_brand_new_name'
        data = {'subnetpool': {'name': new_name}}
        req = self.new_update_request('subnetpools', data, sp_id)
        res = req.get_response(self.api)
        self.assertEqual(code, res.status_int)
        error = self.deserialize(self.fmt, res)
        self.assertEqual(exc_reason,
                         error['NeutronError']['type'])

    def test_faulty_process_create_subnetpool(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_create_subnetpool',
                               side_effect=TypeError):
            subnetpool, tenant_id = self._verify_subnetpool_create(
                500, 'HTTPInternalServerError')
            # Verify the operation is rolled back
            query_params = "tenant_id=%s" % tenant_id
            subnetpools = self._list('subnetpools', query_params=query_params)
            self.assertFalse(subnetpools['subnetpools'])

    def test_faulty_process_update_subnetpool(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_subnetpool',
                               side_effect=TypeError):
            subnetpool, tid = self._verify_subnetpool_create(201, None)
            self._verify_subnetpool_update(subnetpool, 500,
                                           'HTTPInternalServerError')

    def test_faulty_extend_subnetpool_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'extend_subnetpool_dict',
                               side_effect=[None, None, TypeError]):
            subnetpool, tid = self._verify_subnetpool_create(201, None)
            self._verify_subnetpool_update(subnetpool, 400,
                                           'ExtensionDriverError')

    def test_subnetpool_attr(self):
        with self.subnetpool(['10.0.0.0/8'], name='sp1',
                             tenant_id='t1') as subnetpool:
            # Test create subnetpool
            ent = subnetpool['subnetpool'].get('subnetpool_extension')
            self.assertIsNotNone(ent)

            # Test list subnetpools
            res = self._list('subnetpools')
            val = res['subnetpools'][0].get('subnetpool_extension')
            self.assertEqual('Test_SubnetPool_Extension_extend', val)

            # Test subnetpool update
            data = {'subnetpool':
                    {'subnetpool_extension':
                     'Test_SubnetPool_Extension_Update'}}
            res = self._update('subnetpools', subnetpool['subnetpool']['id'],
                               data)
            val = res['subnetpool'].get('subnetpool_extension')
            self.assertEqual('Test_SubnetPool_Extension_Update_update', val)

    def test_extend_subnetpool_dict(self):
        with mock.patch.object(
                ext_test.TestExtensionDriver,
                'process_update_subnetpool') as pus, mock.patch.object(
                    ext_test.TestExtensionDriver,
                    'extend_subnetpool_dict') as esd, self.subnetpool(
                        ['10.0.0.0/8'], name='sp1',
                        tenant_id='t1') as subnetpool:
            subnetpool_id = subnetpool['subnetpool']['id']
            subnetpool_data = {'subnetpool': {'id': subnetpool_id}}
            self._plugin.update_subnetpool(self._ctxt, subnetpool_id,
                                           subnetpool_data)
            self.assertTrue(pus.called)
            self.assertTrue(esd.called)

    def _verify_address_scope_create(self, code, exc_reason):
        tenant_id = str(uuid.uuid4())
        data = {'address_scope': {'ip_version': 4,
                                  'name': 'as1',
                                  'tenant_id': tenant_id}}
        req = self.new_create_request('address-scopes', data)
        res = req.get_response(self.ext_api)
        self.assertEqual(code, res.status_int)

        address_scope = self.deserialize(self.fmt, res)
        if exc_reason:
            self.assertEqual(exc_reason,
                             address_scope['NeutronError']['type'])

        return (address_scope, tenant_id)

    def _verify_address_scope_update(self, address_scope, code, exc_reason):
        as_id = address_scope['address_scope']['id']
        new_name = 'a_brand_new_name'
        data = {'address_scope': {'name': new_name}}
        req = self.new_update_request('address-scopes', data, as_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(code, res.status_int)
        error = self.deserialize(self.fmt, res)
        self.assertEqual(exc_reason,
                         error['NeutronError']['type'])

    def test_faulty_process_create_address_scope(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_create_address_scope',
                               side_effect=TypeError):
            address_scope, tenant_id = self._verify_address_scope_create(
                500, 'HTTPInternalServerError')
            # Verify the operation is rolled back
            query_params = "tenant_id=%s" % tenant_id
            address_scopes = self._list('address-scopes',
                                        query_params=query_params)
            self.assertFalse(address_scopes['address_scopes'])

    def test_faulty_process_update_address_scope(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'process_update_address_scope',
                               side_effect=TypeError):
            address_scope, tid = self._verify_address_scope_create(201, None)
            self._verify_address_scope_update(address_scope, 500,
                                              'HTTPInternalServerError')

    def test_faulty_extend_address_scope_dict(self):
        with mock.patch.object(ext_test.TestExtensionDriver,
                               'extend_address_scope_dict',
                               side_effect=[None, None, TypeError]):
            address_scope, tid = self._verify_address_scope_create(201, None)
            self._verify_address_scope_update(address_scope, 400,
                                              'ExtensionDriverError')

    def test_address_scope_attr(self):
        with self.address_scope(4, name='as1',
                                tenant_id='t1') as address_scope:
            # Test create address_scope
            ent = address_scope['address_scope'].get('address_scope_extension')
            self.assertIsNotNone(ent)

            # Test list address_scopes
            res = self._list('address-scopes')
            val = res['address_scopes'][0].get('address_scope_extension')
            self.assertEqual('Test_AddressScope_Extension_extend', val)

            # Test address_scope update
            data = {'address_scope':
                    {'address_scope_extension':
                     'Test_AddressScope_Extension_Update'}}
            res = self._update('address-scopes',
                               address_scope['address_scope']['id'], data)
            val = res['address_scope'].get('address_scope_extension')
            self.assertEqual('Test_AddressScope_Extension_Update_update', val)

    def test_extend_address_scope_dict(self):
        with mock.patch.object(
                ext_test.TestExtensionDriver,
                'process_update_address_scope') as puas, mock.patch.object(
                    ext_test.TestExtensionDriver,
                    'extend_address_scope_dict') as easd, self.address_scope(
                        4, name='as1', tenant_id='t1') as address_scope:
            address_scope_id = address_scope['address_scope']['id']
            address_scope_data = {'address_scope': {'id': address_scope_id}}
            self._plugin.update_address_scope(self._ctxt, address_scope_id,
                                              address_scope_data)
            self.assertTrue(puas.called)
            self.assertTrue(easd.called)


class DBExtensionDriverTestCase(test_plugin.Ml2PlusPluginV2TestCase):
    _extension_drivers = ['testdb_ml2plus']

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(DBExtensionDriverTestCase, self).setUp()
        self._plugin = manager.NeutronManager.get_plugin()
        self._ctxt = context.get_admin_context()

    def test_subnetpool_attr(self):
        with self.subnetpool(['10.0.0.0/8'], name='sp1',
                             tenant_id='t1') as subnetpool:
            # Test create with default value.
            sp_id = subnetpool['subnetpool']['id']
            val = subnetpool['subnetpool']['subnetpool_extension']
            self.assertEqual("", val)
            res = self._show('subnetpools', sp_id)
            val = res['subnetpool']['subnetpool_extension']
            self.assertEqual("", val)

            # Test list.
            res = self._list('subnetpools')
            val = res['subnetpools'][0]['subnetpool_extension']
            self.assertEqual("", val)

        # Test create with explicit value.
        data = {'subnetpool':
                {'prefixes': ['10.0.0.0/8'],
                 'name': 'sp2',
                 'tenant_id': 't1',
                 'subnetpool_extension': 'abc'}}
        req = self.new_create_request('subnetpools', data, self.fmt)
        res = req.get_response(self.api)
        subnetpool = self.deserialize(self.fmt, res)
        subnetpool_id = subnetpool['subnetpool']['id']
        val = subnetpool['subnetpool']['subnetpool_extension']
        self.assertEqual("abc", val)
        res = self._show('subnetpools', subnetpool_id)
        val = res['subnetpool']['subnetpool_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'subnetpool': {'subnetpool_extension': "def"}}
        res = self._update('subnetpools', subnetpool_id, data)
        val = res['subnetpool']['subnetpool_extension']
        self.assertEqual("def", val)
        res = self._show('subnetpools', subnetpool_id)
        val = res['subnetpool']['subnetpool_extension']
        self.assertEqual("def", val)

    def test_address_scope_attr(self):
        with self.address_scope(4, name='as1',
                                tenant_id='t1') as address_scope:
            # Test create with default value.
            as_id = address_scope['address_scope']['id']
            val = address_scope['address_scope']['address_scope_extension']
            self.assertEqual("", val)
            res = self._show('address-scopes', as_id)
            val = res['address_scope']['address_scope_extension']
            self.assertEqual("", val)

            # Test list.
            res = self._list('address-scopes')
            val = res['address_scopes'][0]['address_scope_extension']
            self.assertEqual("", val)

        # Test create with explicit value.
        data = {'address_scope':
                {'ip_version': 4,
                 'name': 'as2',
                 'tenant_id': 't1',
                 'address_scope_extension': 'abc'}}
        req = self.new_create_request('address-scopes', data, self.fmt)
        res = req.get_response(self.ext_api)
        address_scope = self.deserialize(self.fmt, res)
        address_scope_id = address_scope['address_scope']['id']
        val = address_scope['address_scope']['address_scope_extension']
        self.assertEqual("abc", val)
        res = self._show('address-scopes', address_scope_id)
        val = res['address_scope']['address_scope_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'address_scope': {'address_scope_extension': "def"}}
        res = self._update('address-scopes', address_scope_id, data)
        val = res['address_scope']['address_scope_extension']
        self.assertEqual("def", val)
        res = self._show('address-scopes', address_scope_id)
        val = res['address_scope']['address_scope_extension']
        self.assertEqual("def", val)
