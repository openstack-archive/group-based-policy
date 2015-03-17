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

import copy

import mock
from webob import exc

from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension

from gbpservice.neutron.extensions import servicechain

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path
SERVICE_CHAIN_PLUGIN_BASE_NAME = (
    servicechain.ServiceChainPluginBase.__module__ + '.' +
    servicechain.ServiceChainPluginBase.__name__)
SERVICECHAIN_URI = 'servicechain'
SERVICECHAIN_NODES_URI = SERVICECHAIN_URI + '/' + 'servicechain_nodes'
SERVICECHAIN_SPECS_URI = SERVICECHAIN_URI + '/' + 'servicechain_specs'
SERVICECHAIN_INSTANCES_URI = SERVICECHAIN_URI + '/' + 'servicechain_instances'


class ServiceChainExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(ServiceChainExtensionTestCase, self).setUp()
        plural_mappings = {}
        self._setUpExtension(
            SERVICE_CHAIN_PLUGIN_BASE_NAME, constants.SERVICECHAIN,
            servicechain.RESOURCE_ATTRIBUTE_MAP, servicechain.Servicechain,
            SERVICECHAIN_URI, plural_mappings=plural_mappings)
        self.instance = self.plugin.return_value

    def _test_create_servicechain_node(self, data, expected_value,
                                       default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_servicechain_node.return_value = expected_value
        res = self.api.post(_get_path(SERVICECHAIN_NODES_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.instance.create_servicechain_node.assert_called_once_with(
            mock.ANY, servicechain_node=default_data)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_node', res)
        self.assertEqual(expected_value, res['servicechain_node'])

    def _get_create_servicechain_node_default_attrs(self):
        return {
            'name': '',
            'description': '',
            'config': '',
            'shared': False
        }

    def _get_create_servicechain_node_attrs(self):
        return {
            'name': 'servicechain1',
            'service_type': 'FIREWALL',
            'tenant_id': _uuid(),
            'description': 'test servicechain node',
            'config': 'test_config',
            'shared': True
        }

    def _get_update_servicechain_node_attrs(self):
        return {
            'name': 'new_name',
        }

    def test_create_servicechain_node_with_defaults(self):
        servicechain_node_id = _uuid()
        data = {
            'servicechain_node': {
                'service_type': 'FIREWALL',
                'tenant_id': _uuid(),
                'config': 'test_config'
            }
        }
        default_attrs = self._get_create_servicechain_node_default_attrs()
        default_data = copy.copy(data)
        default_data['servicechain_node'].update(default_attrs)
        expected_value = dict(default_data['servicechain_node'])
        expected_value['id'] = servicechain_node_id

        self._test_create_servicechain_node(data, expected_value, default_data)

    def test_create_servicechain_node(self):
        servicechain_node_id = _uuid()
        data = {
            'servicechain_node': self._get_create_servicechain_node_attrs()
        }
        expected_value = dict(data['servicechain_node'])
        expected_value['id'] = servicechain_node_id

        self._test_create_servicechain_node(data, expected_value)

    def test_list_servicechain_nodes(self):
        servicechain_node_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': servicechain_node_id}]
        self.instance.get_servicechain_nodes.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_NODES_URI, fmt=self.fmt))

        self.instance.get_servicechain_nodes.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_nodes', res)
        self.assertEqual(expected_value, res['servicechain_nodes'])

    def test_get_servicechain_node(self):
        servicechain_node_id = _uuid()
        expected_value = {
            'tenant_id': _uuid(), 'id': servicechain_node_id}
        self.instance.get_servicechain_node.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_NODES_URI,
                                     id=servicechain_node_id,
                                     fmt=self.fmt))

        self.instance.get_servicechain_node.assert_called_once_with(
            mock.ANY, servicechain_node_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_node', res)
        self.assertEqual(expected_value, res['servicechain_node'])

    def test_update_servicechain_node(self):
        servicechain_node_id = _uuid()
        update_data = {
            'servicechain_node': self._get_update_servicechain_node_attrs()
        }
        expected_value = {'tenant_id': _uuid(), 'id': servicechain_node_id}
        self.instance.update_servicechain_node.return_value = expected_value

        res = self.api.put(_get_path(SERVICECHAIN_NODES_URI,
                                     id=servicechain_node_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_servicechain_node.assert_called_once_with(
            mock.ANY, servicechain_node_id, servicechain_node=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_node', res)
        self.assertEqual(expected_value, res['servicechain_node'])

    def test_delete_servicechain_node(self):
        self._test_entity_delete('servicechain_node')

    def _test_create_servicechain_spec(self, data, expected_value,
                                       default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_servicechain_spec.return_value = expected_value

        res = self.api.post(_get_path(SERVICECHAIN_SPECS_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.instance.create_servicechain_spec.assert_called_once_with(
            mock.ANY, servicechain_spec=default_data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_spec', res)
        self.assertEqual(expected_value, res['servicechain_spec'])

    def _get_create_servicechain_spec_default_attrs(self):
        return {
            'name': '',
            'description': '',
            'nodes': [],
            'shared': False,
        }

    def _get_create_servicechain_spec_attrs(self):
        return {
            'name': 'servicechainspec1',
            'nodes': [_uuid(), _uuid()],
            'tenant_id': _uuid(),
            'description': 'test servicechain spec',
            'shared': True
        }

    def _get_update_servicechain_spec_attrs(self):
        return {
            'name': 'new_name',
            'nodes': [_uuid()]
        }

    def test_create_servicechain_spec_with_defaults(self):
        servicechain_spec_id = _uuid()
        data = {
            'servicechain_spec': {
                'nodes': [_uuid(), _uuid()], 'tenant_id': _uuid()
            }
        }
        default_attrs = self._get_create_servicechain_spec_default_attrs()
        default_data = copy.copy(data)
        default_data['servicechain_spec'].update(default_attrs)
        expected_value = dict(default_data['servicechain_spec'])
        expected_value['id'] = servicechain_spec_id

        self._test_create_servicechain_spec(data, expected_value, default_data)

    def test_create_servicechain_spec(self):
        servicechain_spec_id = _uuid()
        data = {
            'servicechain_spec': self._get_create_servicechain_spec_attrs()
        }
        expected_value = dict(data['servicechain_spec'])
        expected_value['id'] = servicechain_spec_id

        self._test_create_servicechain_spec(data, expected_value)

    def test_list_servicechain_specs(self):
        servicechain_spec_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': servicechain_spec_id}]
        self.instance.get_servicechain_specs.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_SPECS_URI, fmt=self.fmt))

        self.instance.get_servicechain_specs.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_specs', res)
        self.assertEqual(expected_value, res['servicechain_specs'])

    def test_get_servicechain_spec(self):
        servicechain_spec_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': servicechain_spec_id}
        self.instance.get_servicechain_spec.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_SPECS_URI,
                                     id=servicechain_spec_id,
                                     fmt=self.fmt))

        self.instance.get_servicechain_spec.assert_called_once_with(
            mock.ANY, servicechain_spec_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_spec', res)
        self.assertEqual(expected_value, res['servicechain_spec'])

    def test_update_servicechain_spec(self):
        servicechain_spec_id = _uuid()
        update_data = {
            'servicechain_spec': self._get_update_servicechain_spec_attrs()
        }
        expected_value = {'tenant_id': _uuid(), 'id': servicechain_spec_id}
        self.instance.update_servicechain_spec.return_value = expected_value

        res = self.api.put(_get_path(SERVICECHAIN_SPECS_URI,
                                     id=servicechain_spec_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_servicechain_spec.assert_called_once_with(
            mock.ANY, servicechain_spec_id, servicechain_spec=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_spec', res)
        self.assertEqual(expected_value, res['servicechain_spec'])

    def test_delete_servicechain_spec(self):
        self._test_entity_delete('servicechain_spec')

    def _test_create_servicechain_instance(self, data, expected_value,
                                           default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_servicechain_instance.return_value = (
            expected_value)
        res = self.api.post(_get_path(SERVICECHAIN_INSTANCES_URI,
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.instance.create_servicechain_instance.assert_called_once_with(
            mock.ANY, servicechain_instance=default_data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_instance', res)
        self.assertEqual(expected_value, res['servicechain_instance'])

    def _get_create_servicechain_instance_default_attrs(self):
        return {'name': '', 'description': '', 'config_param_values': "{}"}

    def _get_create_servicechain_instance_attrs(self):
        return {
            'name': 'servicechaininstance1',
            'servicechain_specs': [_uuid()],
            'tenant_id': _uuid(),
            'provider_ptg_id': _uuid(),
            'consumer_ptg_id': _uuid(),
            'classifier_id': _uuid(),
            'config_param_values': "{}",
            'description': 'test servicechain instance'
        }

    def _get_update_servicechain_instance_attrs(self):
        return {
            'name': 'new_name',
            'servicechain_specs': [_uuid()]
        }

    def test_create_servicechain_instance_with_defaults(self):
        servicechain_instance_id = _uuid()
        data = {
            'servicechain_instance': {
                'servicechain_specs': [_uuid()],
                'tenant_id': _uuid(),
                'provider_ptg_id': _uuid(),
                'consumer_ptg_id': _uuid(),
                'classifier_id': _uuid(),
            }
        }
        default_attrs = self._get_create_servicechain_instance_default_attrs()
        default_data = copy.copy(data)
        default_data['servicechain_instance'].update(default_attrs)
        expected_value = dict(default_data['servicechain_instance'])
        expected_value['id'] = servicechain_instance_id

        self._test_create_servicechain_instance(data, expected_value,
                                                default_data)

    def test_create_servicechain_instance(self):
        servicechain_instance_id = _uuid()
        data = {'servicechain_instance':
                self._get_create_servicechain_instance_attrs()}
        expected_value = dict(data['servicechain_instance'])
        expected_value['id'] = servicechain_instance_id

        self._test_create_servicechain_instance(data, expected_value)

    def test_list_servicechain_instances(self):
        servicechain_instance_id = _uuid()
        expected_value = [{'tenant_id': _uuid(),
                           'id': servicechain_instance_id}]
        self.instance.get_servicechain_instances.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_INSTANCES_URI, fmt=self.fmt))

        self.instance.get_servicechain_instances.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_instances', res)
        self.assertEqual(expected_value, res['servicechain_instances'])

    def test_get_servicechain_instance(self):
        servicechain_instance_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': servicechain_instance_id}
        self.instance.get_servicechain_instance.return_value = expected_value

        res = self.api.get(_get_path(SERVICECHAIN_INSTANCES_URI,
                                     id=servicechain_instance_id,
                                     fmt=self.fmt))

        self.instance.get_servicechain_instance.assert_called_once_with(
            mock.ANY, servicechain_instance_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_instance', res)
        self.assertEqual(expected_value, res['servicechain_instance'])

    def test_update_servicechain_instance(self):
        servicechain_instance_id = _uuid()
        update_data = {'servicechain_instance':
                       self._get_update_servicechain_instance_attrs()}
        expected_value = {'tenant_id': _uuid(), 'id': servicechain_instance_id}
        self.instance.update_servicechain_instance.return_value = (
            expected_value)

        res = self.api.put(_get_path(SERVICECHAIN_INSTANCES_URI,
                                     id=servicechain_instance_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_servicechain_instance.assert_called_once_with(
            mock.ANY, servicechain_instance_id,
            servicechain_instance=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('servicechain_instance', res)
        self.assertEqual(expected_value, res['servicechain_instance'])

    def test_delete_servicechain_instance(self):
        self._test_entity_delete('servicechain_instance')
