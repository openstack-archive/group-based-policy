#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy

import mock
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension
from webob import exc

from gbp.neutron.extensions import group_policy as gp

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path
GP_PLUGIN_BASE_NAME = (
    gp.GroupPolicyPluginBase.__module__ + '.' +
    gp.GroupPolicyPluginBase.__name__)
GROUPPOLICY_URI = 'grouppolicy'
ENDPOINTS_URI = GROUPPOLICY_URI + '/' + 'endpoints'
ENDPOINT_GROUPS_URI = GROUPPOLICY_URI + '/' + 'endpoint_groups'
L2_POLICIES_URI = GROUPPOLICY_URI + '/' + 'l2_policies'
L3_POLICIES_URI = GROUPPOLICY_URI + '/' + 'l3_policies'
POLICY_RULES_URI = GROUPPOLICY_URI + '/' + 'policy_rules'
POLICY_CLASSIFIERS_URI = GROUPPOLICY_URI + '/' + 'policy_classifiers'
POLICY_ACTIONS_URI = GROUPPOLICY_URI + '/' + 'policy_actions'


class GroupPolicyExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(GroupPolicyExtensionTestCase, self).setUp()
        plural_mappings = {'l2_policy': 'l2_policies',
                           'l3_policy': 'l3_policies'}
        self._setUpExtension(
            GP_PLUGIN_BASE_NAME, constants.GROUP_POLICY,
            gp.RESOURCE_ATTRIBUTE_MAP, gp.Group_policy, GROUPPOLICY_URI,
            plural_mappings=plural_mappings)
        self.instance = self.plugin.return_value

    def _test_create_endpoint(self, data, expected_value, default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_endpoint.return_value = expected_value
        res = self.api.post(_get_path(ENDPOINTS_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_endpoint.assert_called_once_with(
            mock.ANY, endpoint=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(expected_value, res['endpoint'])

    def _get_create_endpoint_default_attrs(self):
        return {'name': '', 'description': ''}

    def _get_create_endpoint_attrs(self):
        return {'name': 'ep1', 'endpoint_group_id': _uuid(),
                'tenant_id': _uuid(), 'description': 'test endpoint'}

    def _get_update_endpoint_attrs(self):
        return {'name': 'new_name'}

    def test_create_endpoint_with_defaults(self):
        endpoint_id = _uuid()
        data = {'endpoint': {'endpoint_group_id': _uuid(),
                             'tenant_id': _uuid()}}
        default_attrs = self._get_create_endpoint_default_attrs()
        default_data = copy.copy(data)
        default_data['endpoint'].update(default_attrs)
        expected_value = dict(default_data['endpoint'])
        expected_value['id'] = endpoint_id

        self._test_create_endpoint(data, expected_value, default_data)

    def test_create_endpoint(self):
        endpoint_id = _uuid()
        data = {'endpoint': self._get_create_endpoint_attrs()}
        expected_value = dict(data['endpoint'])
        expected_value['id'] = endpoint_id

        self._test_create_endpoint(data, expected_value)

    def test_list_endpoints(self):
        endpoint_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': endpoint_id}]

        self.instance.get_endpoints.return_value = expected_value

        res = self.api.get(_get_path(ENDPOINTS_URI, fmt=self.fmt))

        self.instance.get_endpoints.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoints', res)
        self.assertEqual(expected_value, res['endpoints'])

    def test_get_endpoint(self):
        endpoint_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': endpoint_id}

        self.instance.get_endpoint.return_value = expected_value

        res = self.api.get(_get_path(ENDPOINTS_URI, id=endpoint_id,
                                     fmt=self.fmt))

        self.instance.get_endpoint.assert_called_once_with(
            mock.ANY, endpoint_id, fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(expected_value, res['endpoint'])

    def test_update_endpoint(self):
        endpoint_id = _uuid()
        update_data = {'endpoint': self._get_update_endpoint_attrs()}
        expected_value = {'tenant_id': _uuid(), 'id': endpoint_id}

        self.instance.update_endpoint.return_value = expected_value

        res = self.api.put(_get_path(ENDPOINTS_URI, id=endpoint_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_endpoint.assert_called_once_with(
            mock.ANY, endpoint_id, endpoint=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint', res)
        self.assertEqual(expected_value, res['endpoint'])

    def test_delete_endpoint(self):
        self._test_entity_delete('endpoint')

    def _test_create_endpoint_group(self, data, expected_value,
                                    default_data=None):
        if not default_data:
            default_data = data

        self.instance.create_endpoint_group.return_value = expected_value
        res = self.api.post(_get_path(ENDPOINT_GROUPS_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_endpoint_group.assert_called_once_with(
            mock.ANY, endpoint_group=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(expected_value, res['endpoint_group'])

    def _get_create_endpoint_group_default_attrs(self):
        return {'name': '', 'description': '', 'l2_policy_id': None,
                'provided_contracts': {}, 'consumed_contracts': {}}

    def _get_create_endpoint_group_attrs(self):
        return {'name': 'epg1', 'tenant_id': _uuid(),
                'description': 'test endpoint group', 'l2_policy_id': _uuid(),
                'provided_contracts': {_uuid(): None},
                'consumed_contracts': {_uuid(): None}}

    def _get_update_endpoint_group_attrs(self):
        return {'name': 'new_name'}

    def test_create_endpoint_group_with_defaults(self):
        endpoint_group_id = _uuid()
        data = {'endpoint_group': {'tenant_id': _uuid()}}
        default_attrs = self._get_create_endpoint_group_default_attrs()
        default_data = copy.copy(data)
        default_data['endpoint_group'].update(default_attrs)
        expected_value = copy.deepcopy(default_data['endpoint_group'])
        expected_value['id'] = endpoint_group_id

        self._test_create_endpoint_group(data, expected_value, default_data)

    def test_create_endpoint_group(self):
        endpoint_group_id = _uuid()
        data = {'endpoint_group': self._get_create_endpoint_group_attrs()}
        expected_value = copy.deepcopy(data['endpoint_group'])
        expected_value['id'] = endpoint_group_id

        self._test_create_endpoint_group(data, expected_value)

    def test_list_endpoint_groups(self):
        endpoint_group_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': endpoint_group_id}]

        self.instance.get_endpoint_groups.return_value = expected_value

        res = self.api.get(_get_path(ENDPOINT_GROUPS_URI, fmt=self.fmt))

        self.instance.get_endpoint_groups.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint_groups', res)
        self.assertEqual(expected_value, res['endpoint_groups'])

    def test_get_endpoint_group(self):
        endpoint_group_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': endpoint_group_id}

        self.instance.get_endpoint_group.return_value = expected_value

        res = self.api.get(_get_path(ENDPOINT_GROUPS_URI, id=endpoint_group_id,
                                     fmt=self.fmt))

        self.instance.get_endpoint_group.assert_called_once_with(
            mock.ANY, endpoint_group_id, fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(expected_value, res['endpoint_group'])

    def test_update_endpoint_group(self):
        endpoint_group_id = _uuid()
        update_data = {'endpoint_group':
                       self._get_update_endpoint_group_attrs()}
        expected_value = {'tenant_id': _uuid(), 'id': endpoint_group_id}

        self.instance.update_endpoint_group.return_value = expected_value

        res = self.api.put(_get_path(ENDPOINT_GROUPS_URI,
                                     id=endpoint_group_id, fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_endpoint_group.assert_called_once_with(
            mock.ANY, endpoint_group_id, endpoint_group=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('endpoint_group', res)
        self.assertEqual(expected_value, res['endpoint_group'])

    def test_delete_endpoint_group(self):
        self._test_entity_delete('endpoint_group')

    def _test_create_l2_policy(self, data, expected_value, default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_l2_policy.return_value = expected_value
        res = self.api.post(_get_path(L2_POLICIES_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_l2_policy.assert_called_once_with(
            mock.ANY, l2_policy=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l2_policy', res)
        self.assertEqual(expected_value, res['l2_policy'])

    def _get_create_l2_policy_default_attrs(self):
        return {'name': '', 'description': ''}

    def _get_create_l2_policy_attrs(self):
        return {'name': 'l2p1', 'tenant_id': _uuid(),
                'description': 'test L2 policy', 'l3_policy_id': _uuid()}

    def _get_update_l2_policy_attrs(self):
        return {'name': 'new_name'}

    def test_create_l2_policy_with_defaults(self):
        l2_policy_id = _uuid()
        data = {'l2_policy': {'tenant_id': _uuid(), 'l3_policy_id': _uuid()}}
        default_attrs = self._get_create_l2_policy_default_attrs()
        default_data = copy.copy(data)
        default_data['l2_policy'].update(default_attrs)
        expected_value = dict(default_data['l2_policy'])
        expected_value['id'] = l2_policy_id

        self._test_create_l2_policy(data, expected_value, default_data)

    def test_create_l2_policy(self):
        l2_policy_id = _uuid()
        data = {'l2_policy': self._get_create_l2_policy_attrs()}
        expected_value = dict(data['l2_policy'])
        expected_value['id'] = l2_policy_id

        self._test_create_l2_policy(data, expected_value)

    def test_list_l2_policies(self):
        l2_policy_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': l2_policy_id}]

        self.instance.get_l2_policies.return_value = expected_value

        res = self.api.get(_get_path(L2_POLICIES_URI, fmt=self.fmt))

        self.instance.get_l2_policies.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l2_policies', res)
        self.assertEqual(expected_value, res['l2_policies'])

    def test_get_l2_policy(self):
        l2_policy_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': l2_policy_id}

        self.instance.get_l2_policy.return_value = expected_value

        res = self.api.get(_get_path(L2_POLICIES_URI, id=l2_policy_id,
                                     fmt=self.fmt))

        self.instance.get_l2_policy.assert_called_once_with(
            mock.ANY, l2_policy_id, fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l2_policy', res)
        self.assertEqual(expected_value, res['l2_policy'])

    def test_update_l2_policy(self):
        l2_policy_id = _uuid()
        update_data = {'l2_policy': self._get_update_l2_policy_attrs()}
        expected_value = {'tenant_id': _uuid(), 'id': l2_policy_id}

        self.instance.update_l2_policy.return_value = expected_value

        res = self.api.put(_get_path(L2_POLICIES_URI, id=l2_policy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_l2_policy.assert_called_once_with(
            mock.ANY, l2_policy_id, l2_policy=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l2_policy', res)
        self.assertEqual(expected_value, res['l2_policy'])

    def test_delete_l2_policy(self):
        self._test_entity_delete('l2_policy')

    def _test_create_l3_policy(self, data, expected_value, default_data=None):
        if not default_data:
            default_data = data
        self.instance.create_l3_policy.return_value = expected_value
        res = self.api.post(_get_path(L3_POLICIES_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_l3_policy.assert_called_once_with(
            mock.ANY, l3_policy=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l3_policy', res)
        self.assertEqual(res['l3_policy'], expected_value)

    def _get_create_l3_policy_default_attrs(self):
        return {'name': '', 'description': '', 'ip_version': 4,
                'ip_pool': '10.0.0.0/8', 'subnet_prefix_length': 24}

    def _get_create_l3_policy_attrs(self):
        return {'name': 'l3p1', 'tenant_id': _uuid(),
                'description': 'test L3 policy', 'ip_version': 6,
                'ip_pool': 'fd01:2345:6789::/48',
                'subnet_prefix_length': 64}

    def _get_update_l3_policy_attrs(self):
        return {'name': 'new_name'}

    def test_create_l3_policy_with_defaults(self):
        l3_policy_id = _uuid()
        data = {'l3_policy': {'tenant_id': _uuid()}}
        default_attrs = self._get_create_l3_policy_default_attrs()
        default_data = copy.copy(data)
        default_data['l3_policy'].update(default_attrs)
        expected_value = dict(default_data['l3_policy'])
        expected_value['id'] = l3_policy_id

        self._test_create_l3_policy(data, expected_value, default_data)

    def test_create_l3_policy(self):
        l3_policy_id = _uuid()
        data = {'l3_policy': self._get_create_l3_policy_attrs()}
        expected_value = dict(data['l3_policy'])
        expected_value.update({'id': l3_policy_id})

        self._test_create_l3_policy(data, expected_value)

    def test_list_l3_policies(self):
        l3_policy_id = _uuid()
        expected_value = [{'tenant_id': _uuid(), 'id': l3_policy_id}]

        self.instance.get_l3_policies.return_value = expected_value

        res = self.api.get(_get_path(L3_POLICIES_URI, fmt=self.fmt))

        self.instance.get_l3_policies.assert_called_once_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l3_policies', res)
        self.assertEqual(expected_value, res['l3_policies'])

    def test_get_l3_policy(self):
        l3_policy_id = _uuid()
        expected_value = {'tenant_id': _uuid(), 'id': l3_policy_id}

        self.instance.get_l3_policy.return_value = expected_value

        res = self.api.get(_get_path(L3_POLICIES_URI, id=l3_policy_id,
                                     fmt=self.fmt))

        self.instance.get_l3_policy.assert_called_once_with(
            mock.ANY, l3_policy_id, fields=mock.ANY)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l3_policy', res)
        self.assertEqual(expected_value, res['l3_policy'])

    def test_update_l3_policy(self):
        l3_policy_id = _uuid()
        update_data = {'l3_policy': self._get_update_l3_policy_attrs()}
        expected_value = {'tenant_id': _uuid(), 'id': l3_policy_id}

        self.instance.update_l3_policy.return_value = expected_value

        res = self.api.put(_get_path(L3_POLICIES_URI, id=l3_policy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        self.instance.update_l3_policy.assert_called_once_with(
            mock.ANY, l3_policy_id, l3_policy=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('l3_policy', res)
        self.assertEqual(expected_value, res['l3_policy'])

    def test_delete_l3_policy(self):
        self._test_entity_delete('l3_policy')

    def _test_create_policy_action(self, data, expected_value,
                                   default_data=None):
        if not default_data:
            default_data = data

        self.instance.create_policy_action.return_value = expected_value
        res = self.api.post(_get_path(POLICY_ACTIONS_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_policy_action.assert_called_once_with(
            mock.ANY, policy_action=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(expected_value, res['policy_action'])

    def _get_create_policy_action_default_attrs(self):
        return {'name': '',
                'description': '',
                'action_type': 'allow',
                'action_value': None}

    def _get_create_policy_action_attrs(self):
        return {'name': 'pa1',
                'tenant_id': _uuid(),
                'description': 'test policy action',
                'action_type': 'redirect',
                'action_value': _uuid()}

    def _get_update_policy_action_attrs(self):
        return {'name': 'new_name'}

    def test_create_policy_action_with_defaults(self):
        policy_action_id = _uuid()
        data = {'policy_action': {'tenant_id': _uuid()}}
        default_attrs = self._get_create_policy_action_default_attrs()
        default_data = copy.copy(data)
        default_data['policy_action'].update(default_attrs)
        expected_value = dict(default_data['policy_action'])
        expected_value['id'] = policy_action_id

        self._test_create_policy_action(data, expected_value, default_data)

    def test_create_policy_action(self):
        policy_action_id = _uuid()
        data = {'policy_action': self._get_create_policy_action_attrs()}
        expected_value = dict(data['policy_action'])
        expected_value['id'] = policy_action_id

        self._test_create_policy_action(data, expected_value)

    def test_list_policy_actions(self):
        policy_action_id = _uuid()
        expected_value = [{'tenant_id': _uuid(),
                           'id': policy_action_id}]

        instance = self.plugin.return_value
        instance.get_policy_actions.return_value = expected_value

        res = self.api.get(_get_path(POLICY_ACTIONS_URI, fmt=self.fmt))

        instance.get_policy_actions.assert_called_once_with(mock.ANY,
                                                            fields=mock.ANY,
                                                            filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_policy_action(self):
        policy_action_id = _uuid()
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_action_id}

        instance = self.plugin.return_value
        instance.get_policy_action.return_value = expected_value

        res = self.api.get(_get_path(POLICY_ACTIONS_URI,
                                     id=policy_action_id, fmt=self.fmt))

        instance.get_policy_action.assert_called_once_with(mock.ANY,
                                                           policy_action_id,
                                                           fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(expected_value, res['policy_action'])

    def test_update_policy_action(self):
        policy_action_id = _uuid()
        update_data = {'policy_action':
                       self._get_update_policy_action_attrs()}
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_action_id}

        instance = self.plugin.return_value
        instance.update_policy_action.return_value = expected_value

        res = self.api.put(_get_path(POLICY_ACTIONS_URI,
                                     id=policy_action_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_policy_action.assert_called_once_with(
            mock.ANY, policy_action_id, policy_action=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_action', res)
        self.assertEqual(expected_value, res['policy_action'])

    def test_delete_policy_action(self):
        self._test_entity_delete('policy_action')

    def _test_create_policy_classifier(self, data, expected_value,
                                       default_data=None):
        if not default_data:
            default_data = data

        self.instance.create_policy_classifier.return_value = expected_value
        res = self.api.post(_get_path(POLICY_CLASSIFIERS_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_policy_classifier.assert_called_once_with(
            mock.ANY, policy_classifier=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('policy_classifier', res)
        self.assertEqual(expected_value, res['policy_classifier'])

    def _get_create_policy_classifier_default_attrs(self):
        return {'name': '',
                'description': '',
                'protocol': None,
                'port_range': None,
                'direction': None}

    def _get_create_policy_classifier_attrs(self):
        return {'name': 'pc1',
                'description': 'test policy classifier',
                'tenant_id': _uuid(),
                'protocol': 'tcp',
                'port_range': '100:200',
                'direction': 'in'}

    def _get_update_policy_classifier_attrs(self):
        return {'name': 'new_name'}

    def test_create_policy_classifier_with_defaults(self):
        policy_classifier_id = _uuid()
        data = {'policy_classifier': {'tenant_id': _uuid()}}
        default_attrs = self._get_create_policy_classifier_default_attrs()
        default_data = copy.copy(data)
        default_data['policy_classifier'].update(default_attrs)
        expected_value = dict(default_data['policy_classifier'])
        expected_value['id'] = policy_classifier_id

        self._test_create_policy_classifier(data, expected_value, default_data)

    def test_create_policy_classifier(self):
        policy_classifier_id = _uuid()
        data = {'policy_classifier':
                self._get_create_policy_classifier_attrs()}
        expected_value = dict(data['policy_classifier'])
        expected_value['id'] = policy_classifier_id

        self._test_create_policy_classifier(data, expected_value)

    def test_list_policy_classifiers(self):
        policy_classifier_id = _uuid()
        expected_value = [{'tenant_id': _uuid(),
                           'id': policy_classifier_id}]

        instance = self.plugin.return_value
        instance.get_policy_classifiers.return_value = expected_value

        res = self.api.get(_get_path(POLICY_CLASSIFIERS_URI, fmt=self.fmt))

        instance.get_policy_classifiers.assert_called_once_with(mock.ANY,
                                                                fields=
                                                                mock.ANY,
                                                                filters=
                                                                mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_policy_classifier(self):
        policy_classifier_id = _uuid()
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_classifier_id}

        instance = self.plugin.return_value
        instance.get_policy_classifier.return_value = expected_value

        res = self.api.get(_get_path(POLICY_CLASSIFIERS_URI,
                                     id=policy_classifier_id, fmt=self.fmt))

        instance.get_policy_classifier.assert_called_once_with(
            mock.ANY, policy_classifier_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_classifier', res)
        self.assertEqual(expected_value, res['policy_classifier'])

    def test_update_policy_classifier(self):
        policy_classifier_id = _uuid()
        update_data = {'policy_classifier':
                       self._get_update_policy_classifier_attrs()}
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_classifier_id}

        instance = self.plugin.return_value
        instance.update_policy_classifier.return_value = expected_value

        res = self.api.put(_get_path(POLICY_CLASSIFIERS_URI,
                                     id=policy_classifier_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_policy_classifier.assert_called_once_with(
            mock.ANY, policy_classifier_id, policy_classifier=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_classifier', res)
        self.assertEqual(expected_value, res['policy_classifier'])

    def test_delete_policy_classifier(self):
        self._test_entity_delete('policy_action')

    def _test_create_policy_rule(self, data, expected_value,
                                 default_data=None):
        if not default_data:
            default_data = data

        self.instance.create_policy_rule.return_value = expected_value
        res = self.api.post(_get_path(POLICY_RULES_URI, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        self.instance.create_policy_rule.assert_called_once_with(
            mock.ANY, policy_rule=default_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('policy_rule', res)
        self.assertEqual(expected_value, res['policy_rule'])

    def _get_create_policy_rule_default_attrs(self):
        return {'name': '',
                'description': '',
                'enabled': True,
                'policy_actions': []}

    def _get_create_policy_rule_attrs(self):
        return {'name': 'pr1',
                'description': 'test policy rule',
                'tenant_id': _uuid(),
                'enabled': True,
                'policy_classifier_id': _uuid(),
                'policy_actions': [_uuid()]}

    def _get_update_policy_rule_attrs(self):
        return {'name': 'new_name'}

    def test_create_policy_rule_with_defaults(self):
        policy_rule_id = _uuid()
        data = {'policy_rule': {'tenant_id': _uuid(), 'policy_classifier_id':
                                _uuid()}}
        default_attrs = self._get_create_policy_rule_default_attrs()
        default_data = copy.copy(data)
        default_data['policy_rule'].update(default_attrs)
        expected_value = dict(default_data['policy_rule'])
        expected_value['id'] = policy_rule_id

        self._test_create_policy_rule(data, expected_value, default_data)

    def test_create_policy_rule(self):
        policy_rule_id = _uuid()
        data = {'policy_rule':
                self._get_create_policy_rule_attrs()}
        expected_value = dict(data['policy_rule'])
        expected_value['id'] = policy_rule_id

        self._test_create_policy_rule(data, expected_value)

    def test_list_policy_rules(self):
        policy_rule_id = _uuid()
        expected_value = [{'tenant_id': _uuid(),
                           'id': policy_rule_id}]

        instance = self.plugin.return_value
        instance.get_policy_rules.return_value = expected_value

        res = self.api.get(_get_path(POLICY_RULES_URI, fmt=self.fmt))

        instance.get_policy_rules.assert_called_once_with(mock.ANY,
                                                          fields=mock.ANY,
                                                          filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_get_policy_rule(self):
        policy_rule_id = _uuid()
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_rule_id}

        instance = self.plugin.return_value
        instance.get_policy_rule.return_value = expected_value

        res = self.api.get(_get_path(POLICY_RULES_URI,
                                     id=policy_rule_id, fmt=self.fmt))

        instance.get_policy_rule.assert_called_once_with(
            mock.ANY, policy_rule_id, fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_rule', res)
        self.assertEqual(expected_value, res['policy_rule'])

    def test_update_policy_rule(self):
        policy_rule_id = _uuid()
        update_data = {'policy_rule':
                       self._get_update_policy_rule_attrs()}
        expected_value = {'tenant_id': _uuid(),
                          'id': policy_rule_id}

        instance = self.plugin.return_value
        instance.update_policy_rule.return_value = expected_value

        res = self.api.put(_get_path(POLICY_RULES_URI,
                                     id=policy_rule_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_policy_rule.assert_called_once_with(
            mock.ANY, policy_rule_id, policy_rule=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('policy_rule', res)
        self.assertEqual(expected_value, res['policy_rule'])

    def test_delete_policy_rule(self):
        self._test_entity_delete('policy_action')


class TestGroupPolicyAttributeConverters(base.BaseTestCase):

    def test_convert_action_to_case_insensitive(self):
        self.assertEqual(
            gp.convert_action_to_case_insensitive('ALLOW'), 'allow')
        self.assertEqual(gp.convert_action_to_case_insensitive('In'), 'in')
        self.assertEqual(gp.convert_action_to_case_insensitive('bi'), 'bi')
        self.assertEqual(gp.convert_action_to_case_insensitive(''), '')

    def test_convert_port_to_string(self):
        self.assertEqual(gp.convert_port_to_string(100), '100')
        self.assertEqual(gp.convert_port_to_string('200'), '200')
        self.assertEqual(gp.convert_port_to_string(''), '')

    def test_convert_protocol_check_valid_protocols(self):
        self.assertEqual(gp.convert_protocol('tcp'), constants.TCP)
        self.assertEqual(gp.convert_protocol('TCP'), constants.TCP)
        self.assertEqual(gp.convert_protocol('udp'), constants.UDP)
        self.assertEqual(gp.convert_protocol('UDP'), constants.UDP)
        self.assertEqual(gp.convert_protocol('icmp'), constants.ICMP)
        self.assertEqual(gp.convert_protocol('ICMP'), constants.ICMP)

    def test_convert_protocol_check_invalid_protocols(self):
        self.assertRaises(gp.GroupPolicyInvalidProtocol,
                          gp.convert_protocol, 'garbage')


class TestGroupPolicyAttributeValidators(base.BaseTestCase):

    def test_validate_port_range(self):
        self.assertIsNone(gp._validate_port_range(None))
        self.assertIsNone(gp._validate_port_range('10'))
        self.assertIsNone(gp._validate_port_range(10))
        self.assertEqual(gp._validate_port_range(-1),
                         "Invalid port '-1', valid range 0 < port < 65536")
        self.assertEqual(gp._validate_port_range('66000'),
                         "Invalid port '66000', valid range 0 < port < 65536")
        self.assertIsNone(gp._validate_port_range('10:20'))
        self.assertIsNone(gp._validate_port_range('1:65535'))
        self.assertEqual(gp._validate_port_range('0:65535'),
                         "Invalid port '0', valid range 0 < port < 65536")
        self.assertEqual(gp._validate_port_range('1:65536'),
                         "Invalid port '65536', valid range 0 < port < 65536")
        msg = gp._validate_port_range('abc:efg')
        self.assertEqual(msg, "Port 'abc' is not a valid number")
        msg = gp._validate_port_range('1:efg')
        self.assertEqual(msg, "Port 'efg' is not a valid number")
        msg = gp._validate_port_range('-1:10')
        self.assertEqual(msg,
                         "Invalid port '-1', valid range 0 < port < 65536")
        msg = gp._validate_port_range('66000:10')
        self.assertEqual(msg,
                         "Invalid port '66000', valid range 0 < port < 65536")
        msg = gp._validate_port_range('10:66000')
        self.assertEqual(msg,
                         "Invalid port '66000', valid range 0 < port < 65536")
        msg = gp._validate_port_range('1:-10')
        self.assertEqual(msg,
                         "Invalid port '-10', valid range 0 < port < 65536")
