# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import webob.exc

from neutron.api import extensions
from neutron.api.v2 import attributes as nattr
from neutron import context
from neutron.openstack.common import importutils
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extensions

from gbp.neutron.db.grouppolicy import group_policy_db as gpdb
import gbp.neutron.extensions
from gbp.neutron.extensions import group_policy as gpolicy


JSON_FORMAT = 'json'
_uuid = uuidutils.generate_uuid


class GroupPolicyDBTestBase(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    fmt = JSON_FORMAT

    def _get_resource_plural(self, resource):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        return resource_plural

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        resource_plural = self._get_resource_plural(resource)

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _get_test_policy_target_attrs(
        self, name='pt1', description='test pt', policy_target_group_id=None):
        attrs = {'name': name, 'description': description,
                 'policy_target_group_id': policy_target_group_id,
                 'tenant_id': self._tenant_id}

        return attrs

    def _get_test_policy_target_group_attrs(self, name='ptg1',
                                            description='test ptg',
                                            l2_policy_id=None,
                                            provided_policy_rule_sets=None,
                                            consumed_policy_rule_sets=None):
        pprs_ids = cprs_ids = []
        if provided_policy_rule_sets:
            pprs_ids = [pprs_id for pprs_id in provided_policy_rule_sets]
        if consumed_policy_rule_sets:
            cprs_ids = [cc_id for cc_id in consumed_policy_rule_sets]
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'l2_policy_id': l2_policy_id,
                 'provided_policy_rule_sets': pprs_ids,
                 'consumed_policy_rule_sets': cprs_ids}

        return attrs

    def _get_test_l2_policy_attrs(self, name='l2p1',
                                  description='test l2_policy',
                                  l3_policy_id=None):
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'l3_policy_id': l3_policy_id}

        return attrs

    def _get_test_l3_policy_attrs(self, name='l3p1',
                                  description='test l3_policy',
                                  ip_version=4, ip_pool='10.0.0.0/8',
                                  subnet_prefix_length=24,
                                  external_segments=None):
        external_segments = external_segments or {}
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'ip_version': ip_version,
                 'ip_pool': ip_pool,
                 'subnet_prefix_length': subnet_prefix_length,
                 'external_segments': external_segments}

        return attrs

    def _get_test_network_service_policy_attrs(
        self, name='nsp1', description='test network_service_policy',
        network_service_policy_id=None, network_service_params=None):
        if not network_service_params:
            network_service_params = []
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'network_service_params': network_service_params}

        return attrs

    def _get_test_policy_classifier_attrs(self, name='pc1',
                                          description='test pc',
                                          protocol=None, port_range=None,
                                          direction=None):
        attrs = {'name': name, 'description': description,
                 'protocol': protocol, 'port_range': port_range,
                 'direction': direction, 'tenant_id': self._tenant_id}

        return attrs

    def _get_test_policy_action_attrs(self, name='pa1',
                                      description='test pa',
                                      action_type='allow',
                                      action_value=None):
        attrs = {'name': name, 'description': description,
                 'action_type': action_type, 'action_value': action_value,
                 'tenant_id': self._tenant_id}

        return attrs

    def _get_test_policy_rule_attrs(self, policy_classifier_id, name='pr1',
                                    description='test pr', policy_actions=None,
                                    enabled=True):
        if not policy_actions:
            policy_actions = []
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'policy_classifier_id': policy_classifier_id,
                 'policy_actions': policy_actions, 'enabled': enabled}

        return attrs

    def _get_test_prs_attrs(self, name='policy_rule_set1',
                            description='test policy_rule_set',
                            child_policy_rule_sets=None,
                            policy_rules=None):
        if not child_policy_rule_sets:
            child_policy_rule_sets = []
        if not policy_rules:
            policy_rules = []
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'child_policy_rule_sets': child_policy_rule_sets,
                 'policy_rules': policy_rules}

        return attrs

    def _get_test_ep_attrs(self, name='ep_1', description='test ep',
                           external_segments=None,
                           provided_policy_rule_sets=None,
                           consumed_policy_rule_sets=None):
        pprs_ids = cprs_ids = es_ids = []
        if provided_policy_rule_sets:
            pprs_ids = [pprs_id for pprs_id in provided_policy_rule_sets]
        if consumed_policy_rule_sets:
            cprs_ids = [cc_id for cc_id in consumed_policy_rule_sets]
        if external_segments:
            es_ids = [es_id for es_id in external_segments]
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'external_segments': es_ids,
                 'provided_policy_rule_sets': pprs_ids,
                 'consumed_policy_rule_sets': cprs_ids}
        return attrs

    def _get_test_es_attrs(self, name='es_1', description='test es',
                           ip_version=4, cidr='172.0.0.0/8',
                           external_routes=None,
                           port_address_translation=False):
        ear = external_routes or []
        attrs = {'name': name, 'description': description,
                 'ip_version': ip_version,
                 'tenant_id': self._tenant_id, 'cidr': cidr,
                 'external_routes': ear,
                 'port_address_translation': port_address_translation}
        return attrs

    def _get_test_np_attrs(self, name='es_1', description='test es',
                           ip_version=4, ip_pool='10.160.0.0/16',
                           external_segment_id=None):
        attrs = {'name': name, 'description': description,
                 'ip_version': ip_version,
                 'tenant_id': self._tenant_id, 'ip_pool': ip_pool,
                 'external_segment_id': external_segment_id}
        return attrs

    def create_policy_target(self, policy_target_group_id=None,
                             expected_res_status=None, **kwargs):
        defaults = {'name': 'pt1', 'description': 'test pt'}
        defaults.update(kwargs)

        data = {'policy_target':
                {'policy_target_group_id': policy_target_group_id,
                 'tenant_id': self._tenant_id}}
        data['policy_target'].update(defaults)

        pt_req = self.new_create_request('policy_targets', data, self.fmt)
        pt_res = pt_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(pt_res.status_int, expected_res_status)
        elif pt_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=pt_res.status_int)

        pt = self.deserialize(self.fmt, pt_res)

        return pt

    def create_policy_target_group(self, l2_policy_id=None,
                                   expected_res_status=None, **kwargs):
        defaults = {'name': 'ptg1', 'description': 'test ptg',
                    'provided_policy_rule_sets': {},
                    'consumed_policy_rule_sets': {}}
        defaults.update(kwargs)

        data = {'policy_target_group': {'tenant_id': self._tenant_id,
                                        'l2_policy_id': l2_policy_id}}
        data['policy_target_group'].update(defaults)

        ptg_req = self.new_create_request(
            'policy_target_groups', data, self.fmt)
        ptg_res = ptg_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(ptg_res.status_int, expected_res_status)
        elif ptg_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=ptg_res.status_int)

        ptg = self.deserialize(self.fmt, ptg_res)

        return ptg

    def create_l2_policy(self, l3_policy_id=None, expected_res_status=None,
                         **kwargs):
        defaults = {'name': 'l2p1', 'description': 'test l2_policy'}
        defaults.update(kwargs)

        data = {'l2_policy': {'l3_policy_id': l3_policy_id,
                              'tenant_id': self._tenant_id}}
        data['l2_policy'].update(defaults)

        l2p_req = self.new_create_request('l2_policies', data, self.fmt)
        l2p_res = l2p_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(l2p_res.status_int, expected_res_status)
        elif l2p_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=l2p_res.status_int)

        l2p = self.deserialize(self.fmt, l2p_res)

        return l2p

    def create_l3_policy(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'l3p1', 'description': 'test l3_policy',
                    'ip_version': 4, 'ip_pool': '10.0.0.0/8',
                    'subnet_prefix_length': 24, 'external_segments': {}}
        defaults.update(kwargs)

        data = {'l3_policy': {'tenant_id': self._tenant_id}}
        data['l3_policy'].update(defaults)

        l3p_req = self.new_create_request('l3_policies', data, self.fmt)
        l3p_res = l3p_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(l3p_res.status_int, expected_res_status)
        elif l3p_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=l3p_res.status_int)

        l3p = self.deserialize(self.fmt, l3p_res)

        return l3p

    def create_network_service_policy(
        self, expected_res_status=None, **kwargs):
        defaults = {'name': 'nsp1',
                    'description': 'test network_service_policy',
                    'network_service_params': []}
        defaults.update(kwargs)

        data = {'network_service_policy': {'tenant_id': self._tenant_id}}
        data['network_service_policy'].update(defaults)

        nsp_req = self.new_create_request('network_service_policies',
                                          data, self.fmt)
        nsp_res = nsp_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(expected_res_status, nsp_res.status_int)
        elif nsp_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=nsp_res.status_int)

        nsp = self.deserialize(self.fmt, nsp_res)

        return nsp

    def create_policy_classifier(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'pc1', 'description': 'test pc', 'protocol': None,
                    'port_range': None, 'direction': None}
        defaults.update(kwargs)
        kwargs = defaults

        data = {'policy_classifier': {'tenant_id': self._tenant_id}}
        data['policy_classifier'].update(kwargs)

        pc_req = self.new_create_request('policy_classifiers', data, self.fmt)
        pc_res = pc_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(pc_res.status_int, expected_res_status)
        elif pc_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=pc_res.status_int)

        pc = self.deserialize(self.fmt, pc_res)

        return pc

    def create_policy_action(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'pa1', 'description': 'test pa',
                    'action_type': 'allow', 'action_value': None}
        defaults.update(kwargs)
        kwargs = defaults

        data = {'policy_action': {'tenant_id': self._tenant_id}}
        data['policy_action'].update(kwargs)

        pa_req = self.new_create_request('policy_actions', data, self.fmt)
        pa_res = pa_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(pa_res.status_int, expected_res_status)
        elif pa_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=pa_res.status_int)

        pa = self.deserialize(self.fmt, pa_res)

        return pa

    def create_policy_rule(self, policy_classifier_id,
                           expected_res_status=None, **kwargs):
        defaults = {'name': 'pr1', 'description': 'test pr',
                    'policy_classifier_id': policy_classifier_id,
                    'policy_actions': None, 'enabled': True}
        defaults.update(kwargs)
        kwargs = defaults

        data = {'policy_rule': {'tenant_id': self._tenant_id}}
        data['policy_rule'].update(kwargs)

        pr_req = self.new_create_request('policy_rules', data, self.fmt)
        pr_res = pr_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(pr_res.status_int, expected_res_status)
        elif pr_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=pr_res.status_int)

        pr = self.deserialize(self.fmt, pr_res)

        return pr

    def create_policy_rule_set(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'policy_rule_set1',
                    'description': 'test policy_rule_set',
                    'child_policy_rule_sets': [], 'policy_rules': []}
        defaults.update(kwargs)
        kwargs = defaults

        data = {'policy_rule_set': {'tenant_id': self._tenant_id}}
        data['policy_rule_set'].update(kwargs)

        prs_req = self.new_create_request('policy_rule_sets', data, self.fmt)
        prs_res = prs_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(prs_res.status_int, expected_res_status)
        elif prs_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=prs_res.status_int)

        prs = self.deserialize(self.fmt, prs_res)

        return prs

    def _create_gbp_resource(self, type, expected_res_status, body):
        plural = self._get_resource_plural(type)
        data = {type: body}
        req = self.new_create_request(plural, data, self.fmt)
        res = req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        prs = self.deserialize(self.fmt, res)
        return prs

    def create_external_policy(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'ptg1', 'description': 'test ptg',
                    'provided_policy_rule_sets': {},
                    'consumed_policy_rule_sets': {},
                    'tenant_id': self._tenant_id,
                    'external_segments': []}
        defaults.update(kwargs)
        return self._create_gbp_resource(
            'external_policy', expected_res_status, defaults)

    def create_external_segment(self, expected_res_status=None, **kwargs):
        body = self._get_test_es_attrs()
        body.update(kwargs)
        return self._create_gbp_resource(
            'external_segment', expected_res_status, body)

    def create_nat_pool(self, expected_res_status=None, **kwargs):
        body = self._get_test_np_attrs()
        body.update(kwargs)
        return self._create_gbp_resource(
            'nat_pool', expected_res_status, body)


class GroupPolicyDBTestPlugin(gpdb.GroupPolicyDbPlugin):

        supported_extension_aliases = ['group-policy']


DB_GP_PLUGIN_KLASS = (GroupPolicyDBTestPlugin.__module__ + '.' +
                      GroupPolicyDBTestPlugin.__name__)


class GroupPolicyDbTestCase(GroupPolicyDBTestBase,
                            test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, service_plugins=None,
              ext_mgr=None):
        extensions.append_api_extensions_path(gbp.neutron.extensions.__path__)
        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        self.plugin = importutils.import_object(gp_plugin)
        if not service_plugins:
            service_plugins = {'gp_plugin_name': gp_plugin}
        nattr.PLURALS['nat_pools'] = 'nat_pool'
        super(GroupPolicyDbTestCase, self).setUp(
            plugin=core_plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)


class TestGroupResources(GroupPolicyDbTestCase):

    def _test_show_resource(self, resource, resource_id, attrs):
        resource_plural = self._get_resource_plural(resource)
        req = self.new_show_request(resource_plural, resource_id,
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt,
                               req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res[resource][k], v)

    def test_create_and_show_policy_target(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        attrs = self._get_test_policy_target_attrs(
            policy_target_group_id=ptg_id)

        pt = self.create_policy_target(policy_target_group_id=ptg_id)

        for k, v in attrs.iteritems():
            self.assertEqual(pt['policy_target'][k], v)

        req = self.new_show_request(
            'policy_target_groups', ptg_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        self.assertEqual(res['policy_target_group']['policy_targets'],
                         [pt['policy_target']['id']])

        self._test_show_resource(
            'policy_target', pt['policy_target']['id'], attrs)

    def test_list_policy_targets(self):
        pts = [self.create_policy_target(name='pt1', description='pt'),
               self.create_policy_target(name='pt2', description='pt'),
               self.create_policy_target(name='pt3', description='pt')]
        self._test_list_resources('policy_target', pts,
                                  query_params='description=pt')

    def test_update_policy_target(self):
        name = 'new_policy_target'
        description = 'new desc'
        attrs = self._get_test_policy_target_attrs(name=name,
                                                   description=description)

        pt = self.create_policy_target()

        data = {'policy_target': {'name': name, 'description': description}}
        req = self.new_update_request(
            'policy_targets', data, pt['policy_target']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_target'][k], v)

        self._test_show_resource(
            'policy_target', pt['policy_target']['id'], attrs)

    def test_delete_policy_target(self):
        ctx = context.get_admin_context()

        pt = self.create_policy_target()
        pt_id = pt['policy_target']['id']

        req = self.new_delete_request('policy_targets', pt_id)
        res = req.get_response(self.ext_api)

        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyTargetNotFound,
                          self.plugin.get_policy_target, ctx, pt_id)

    def test_create_and_show_policy_target_group(self):
        name = "ptg1"
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        l2p = self.create_l2_policy(name=name, l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']

        provided_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        consumed_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        attrs = self._get_test_policy_target_group_attrs(
            name, l2_policy_id=l2p_id,
            provided_policy_rule_sets=[provided_prs_id],
            consumed_policy_rule_sets=[consumed_prs_id])

        ptg = self.create_policy_target_group(
            name=name, l2_policy_id=l2p_id,
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})

        for k, v in attrs.iteritems():
            self.assertEqual(ptg['policy_target_group'][k], v)

        self._test_show_resource(
            'policy_target_group', ptg['policy_target_group']['id'], attrs)

    def test_list_policy_target_groups(self):
        ptgs = (
            [self.create_policy_target_group(name='ptg1', description='ptg'),
             self.create_policy_target_group(name='ptg2', description='ptg'),
             self.create_policy_target_group(name='ptg3', description='ptg')])
        self._test_list_resources('policy_target_group', ptgs,
                                  query_params='description=ptg')

    def test_update_policy_target_group(self):
        name = "new_policy_target_group1"
        description = 'new desc'
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        l2p_id = self.create_l2_policy(l3_policy_id=l3p_id)['l2_policy']['id']
        attrs = self._get_test_policy_target_group_attrs(
            name=name, description=description, l2_policy_id=l2p_id)
        ct1_id = self.create_policy_rule_set(
            name='policy_rule_set1')['policy_rule_set']['id']
        ct2_id = self.create_policy_rule_set(
            name='policy_rule_set2')['policy_rule_set']['id']
        ptg = self.create_policy_target_group(
            consumed_policy_rule_sets={ct1_id: 'scope'},
            provided_policy_rule_sets={ct2_id: 'scope'})
        ct3_id = self.create_policy_rule_set(
            name='policy_rule_set3')['policy_rule_set']['id']
        ct4_id = self.create_policy_rule_set(
            name='policy_rule_set4')['policy_rule_set']['id']
        data = {'policy_target_group':
                {'name': name, 'description': description,
                 'l2_policy_id': l2p_id,
                 'provided_policy_rule_sets': {ct3_id: 'scope'},
                 'consumed_policy_rule_sets': {ct4_id: 'scope'}}}
        req = self.new_update_request('policy_target_groups', data,
                                      ptg['policy_target_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        attrs['provided_policy_rule_sets'] = [ct3_id]
        attrs['consumed_policy_rule_sets'] = [ct4_id]
        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_target_group'][k], v)

        self._test_show_resource('policy_target_group',
                                 ptg['policy_target_group']['id'], attrs)

    def test_delete_policy_target_group(self):
        ctx = context.get_admin_context()

        ptg = self.create_policy_target_group()
        ptg_id = ptg['policy_target_group']['id']

        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyTargetGroupNotFound,
                          self.plugin.get_policy_target_group, ctx, ptg_id)

    def test_create_and_show_l2_policy(self):
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        attrs = self._get_test_l2_policy_attrs(l3_policy_id=l3p_id)

        l2p = self.create_l2_policy(l3_policy_id=l3p_id)
        for k, v in attrs.iteritems():
            self.assertEqual(l2p['l2_policy'][k], v)

        self._test_show_resource('l2_policy', l2p['l2_policy']['id'], attrs)

    def test_list_l2_policies(self):
        l2_policies = [self.create_l2_policy(name='l2p1', description='l2p'),
                       self.create_l2_policy(name='l2p2', description='l2p'),
                       self.create_l2_policy(name='l2p3', description='l2p')]
        self._test_list_resources('l2_policy', l2_policies,
                                  query_params='description=l2p')

    def test_update_l2_policy(self):
        name = "new_l2_policy"
        description = 'new desc'
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        attrs = self._get_test_l2_policy_attrs(name=name,
                                               description=description,
                                               l3_policy_id=l3p_id)

        l2p = self.create_l2_policy()
        data = {'l2_policy': {'name': name, 'description': description,
                              'l3_policy_id': l3p_id}}
        req = self.new_update_request('l2_policies', data,
                                      l2p['l2_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['l2_policy'][k], v)

        self._test_show_resource('l2_policy', l2p['l2_policy']['id'], attrs)

    def test_delete_l2_policy(self):
        ctx = context.get_admin_context()

        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']

        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.L2PolicyNotFound, self.plugin.get_l2_policy,
                          ctx, l2p_id)

    def test_create_and_show_l3_policy(self):
        es = self.create_external_segment()['external_segment']
        es_dict = {es['id']: ['172.0.0.2', '172.0.0.3']}
        attrs = self._get_test_l3_policy_attrs(
            external_segments=es_dict)

        l3p = self.create_l3_policy(external_segments=es_dict)

        for k, v in attrs.iteritems():
            self.assertEqual(v, l3p['l3_policy'][k])

        req = self.new_show_request('l3_policies', l3p['l3_policy']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(v, res['l3_policy'][k])

        self._test_show_resource('l3_policy', l3p['l3_policy']['id'], attrs)

    def test_create_l3_policy_with_invalid_subnet_prefix_length(self):
        ctx = context.get_admin_context()
        data = {'l3_policy': {'name': 'l3p1', 'ip_version': 4,
                              'description': '', 'ip_pool': '1.1.1.0/24',
                              'subnet_prefix_length': 32}}

        self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                          self.plugin.create_l3_policy, ctx, data)

    def test_list_l3_policies(self):
        l3_policies = [self.create_l3_policy(name='l3p1', description='l3p'),
                       self.create_l3_policy(name='l3p2', description='l3p'),
                       self.create_l3_policy(name='l3p3', description='l3p')]
        self._test_list_resources('l3_policy', l3_policies,
                                  query_params='description=l3p')

    def test_update_l3_policy(self):
        name = "new_l3_policy"
        description = 'new desc'
        prefix_length = 26
        es = self.create_external_segment()['external_segment']
        es_dict = {es['id']: ['172.0.0.2', '172.0.0.3']}
        attrs = self._get_test_l3_policy_attrs(
            name=name, description=description,
            subnet_prefix_length=prefix_length,
            external_segments=es_dict)

        l3p = self.create_l3_policy()
        data = {'l3_policy': {'name': name, 'description': description,
                              'subnet_prefix_length': prefix_length,
                              'external_segments': es_dict}}

        req = self.new_update_request('l3_policies', data,
                                      l3p['l3_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['l3_policy'][k], v)

        self._test_show_resource('l3_policy', l3p['l3_policy']['id'], attrs)

    def test_update_l3_policy_with_invalid_subnet_prefix_length(self):
        ctx = context.get_admin_context()

        l3p = self.create_l3_policy()

        for prefix_length in [0, 1, 32]:
            data = {'l3_policy': {'subnet_prefix_length': prefix_length}}
            self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                              self.plugin.update_l3_policy, ctx,
                              l3p['l3_policy']['id'], data)

        l3p = self.create_l3_policy(ip_version='6')

        for prefix_length in [0, 1, 128]:
            data = {'l3_policy': {'subnet_prefix_length': prefix_length}}
            self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                              self.plugin.update_l3_policy, ctx,
                              l3p['l3_policy']['id'], data)

    def test_delete_l3_policy(self):
        ctx = context.get_admin_context()

        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        req = self.new_delete_request('l3_policies', l3p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.L3PolicyNotFound, self.plugin.get_l3_policy,
                          ctx, l3p_id)

    def test_create_and_show_network_service_policy(self):
        params = [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]
        attrs = self._get_test_network_service_policy_attrs(
            network_service_params=params)

        nsp = self.create_network_service_policy(network_service_params=params)
        for k, v in attrs.iteritems():
            self.assertEqual(nsp['network_service_policy'][k], v)

        self._test_show_resource('network_service_policy',
                                 nsp['network_service_policy']['id'], attrs)

    def test_list_network_service_policies(self):
        network_service_policies = [
            self.create_network_service_policy(name='nsp1', description='nsp'),
            self.create_network_service_policy(name='nsp2', description='nsp'),
            self.create_network_service_policy(name='nsp3', description='nsp')]
        self._test_list_resources('network_service_policy',
                                  network_service_policies,
                                  query_params='description=nsp')

    def test_update_network_service_policy(self):
        name = "new_network_service_policy"
        description = 'new desc'
        attrs = self._get_test_network_service_policy_attrs(
            name=name, description=description)

        nsp = self.create_network_service_policy()
        data = {'network_service_policy': {'name': name,
                                           'description': description}}
        req = self.new_update_request('network_service_policies', data,
                                      nsp['network_service_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['network_service_policy'][k], v)

        self._test_show_resource('network_service_policy',
                                 nsp['network_service_policy']['id'], attrs)

    def test_delete_network_service_policy(self):
        ctx = context.get_admin_context()

        nsp = self.create_network_service_policy()
        nsp_id = nsp['network_service_policy']['id']

        req = self.new_delete_request('network_service_policies', nsp_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NetworkServicePolicyNotFound,
                          self.plugin.get_network_service_policy,
                          ctx, nsp_id)

    def test_delete_network_service_policy_with_params(self):
        ctx = context.get_admin_context()
        params = [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]

        nsp = self.create_network_service_policy(network_service_params=params)
        nsp_id = nsp['network_service_policy']['id']

        req = self.new_delete_request('network_service_policies', nsp_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NetworkServicePolicyNotFound,
                          self.plugin.get_network_service_policy,
                          ctx, nsp_id)

    def test_create_and_show_policy_classifier(self):
        name = "pc1"
        attrs = self._get_test_policy_classifier_attrs(name=name)

        pc = self.create_policy_classifier(name=name)

        for k, v in attrs.iteritems():
            self.assertEqual(pc['policy_classifier'][k], v)

        req = self.new_show_request('policy_classifiers',
                                    pc['policy_classifier']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_list_policy_classifiers(self):
        policy_classifiers = [
            self.create_policy_classifier(name='pc1', description='pc'),
            self.create_policy_classifier(name='pc2', description='pc'),
            self.create_policy_classifier(name='pc3', description='pc')]
        self._test_list_resources('policy_classifier', policy_classifiers,
                                  query_params='description=pc')

    def test_update_policy_classifier(self):
        name = "new_policy_classifier"
        description = 'new desc'
        protocol = 'tcp'
        port_range = '100:200'
        direction = 'in'
        attrs = self._get_test_policy_classifier_attrs(
            name=name, description=description, protocol=protocol,
            port_range=port_range, direction=direction)

        pc = self.create_policy_classifier()
        data = {'policy_classifier': {'name': name, 'description': description,
                                      'protocol': protocol, 'port_range':
                                      port_range, 'direction': direction}}

        req = self.new_update_request('policy_classifiers', data,
                                      pc['policy_classifier']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_delete_policy_classifier(self):
        ctx = context.get_admin_context()

        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']

        req = self.new_delete_request('policy_classifiers', pc_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyClassifierNotFound,
                          self.plugin.get_policy_classifier, ctx, pc_id)

    def test_create_and_show_policy_action(self):
        name = "pa1"
        attrs = self._get_test_policy_action_attrs(name=name)

        pa = self.create_policy_action(name=name)

        for k, v in attrs.iteritems():
            self.assertEqual(pa['policy_action'][k], v)

        req = self.new_show_request('policy_actions',
                                    pa['policy_action']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_action'][k], v)

        self._test_show_resource('policy_action',
                                 pa['policy_action']['id'], attrs)

    def test_list_policy_actions(self):
        policy_actions = [
            self.create_policy_action(name='pa1', description='pa'),
            self.create_policy_action(name='pa2', description='pa'),
            self.create_policy_action(name='pa3', description='pa')]
        self._test_list_resources('policy_action', policy_actions,
                                  query_params='description=pa')

    def test_update_policy_action(self):
        name = "new_policy_action"
        description = 'new desc'
        action_value = _uuid()
        attrs = self._get_test_policy_action_attrs(
            name=name, description=description, action_value=action_value)

        pa = self.create_policy_action()
        data = {'policy_action': {'name': name, 'description': description,
                                  'action_value': action_value}}

        req = self.new_update_request('policy_actions', data,
                                      pa['policy_action']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_action'][k], v)

        self._test_show_resource('policy_action',
                                 pa['policy_action']['id'], attrs)

    def test_delete_policy_action(self):
        ctx = context.get_admin_context()

        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']

        req = self.new_delete_request('policy_actions', pa_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyActionNotFound,
                          self.plugin.get_policy_action, ctx, pa_id)

    def test_create_and_show_policy_rule(self):
        name = "pr1"
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        attrs = self._get_test_policy_rule_attrs(
            name=name, policy_classifier_id=pc_id)

        pr = self.create_policy_rule(
            name=name, policy_classifier_id=pc_id)

        for k, v in attrs.iteritems():
            self.assertEqual(pr['policy_rule'][k], v)

        req = self.new_show_request('policy_rules', pr['policy_rule']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_rule'][k], v)

        self._test_show_resource('policy_rule',
                                 pr['policy_rule']['id'], attrs)

    def test_list_policy_rules(self):
        pcs = [self.create_policy_classifier()['policy_classifier']['id'],
               self.create_policy_classifier()['policy_classifier']['id'],
               self.create_policy_classifier()['policy_classifier']['id']]
        policy_rules = [
            self.create_policy_rule(name='pr1', description='pr',
                                    policy_classifier_id=pcs[0]),
            self.create_policy_rule(name='pr2', description='pr',
                                    policy_classifier_id=pcs[1]),
            self.create_policy_rule(name='pr3', description='pr',
                                    policy_classifier_id=pcs[2])]
        self._test_list_resources('policy_rule', policy_rules,
                                  query_params='description=pr')

    def test_update_policy_rule(self):
        name = "new_policy_rule"
        description = 'new desc'
        enabled = False
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']
        attrs = self._get_test_policy_rule_attrs(
            name=name, description=description, policy_classifier_id=pc_id,
            policy_actions=[pa_id], enabled=enabled)

        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        data = {'policy_rule': {'name': name, 'description': description,
                                'policy_classifier_id': pc_id,
                                'policy_actions': [pa_id], 'enabled': enabled}}

        req = self.new_update_request('policy_rules', data,
                                      pr['policy_rule']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_rule'][k], v)

        self._test_show_resource('policy_rule',
                                 pr['policy_rule']['id'], attrs)

    def test_delete_policy_rule(self):
        ctx = context.get_admin_context()
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        pr_id = pr['policy_rule']['id']

        req = self.new_delete_request('policy_rules', pr_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyRuleNotFound,
                          self.plugin.get_policy_rule, ctx, pr_id)

    def test_create_and_show_policy_rule_set(self):
        name = "policy_rule_set1"
        attrs = self._get_test_prs_attrs(name=name)

        prs = self.create_policy_rule_set(name=name)

        for k, v in attrs.iteritems():
            self.assertEqual(prs['policy_rule_set'][k], v)

        req = self.new_show_request(
            'policy_rule_sets', prs['policy_rule_set']['id'], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_rule_set'][k], v)

        self._test_show_resource('policy_rule_set',
                                 prs['policy_rule_set']['id'], attrs)

    def test_create_prs_with_multiple_rules_children(self, **kwargs):
        policy_classifiers = [
            self.create_policy_classifier()['policy_classifier']['id'],
            self.create_policy_classifier()['policy_classifier']['id']]
        policy_rules = sorted([
            self.create_policy_rule(
                policy_classifier_id=
                policy_classifiers[0])['policy_rule']['id'],
            self.create_policy_rule(
                policy_classifier_id=
                policy_classifiers[1])['policy_rule']['id']])
        child_policy_rule_sets = sorted(
            [self.create_policy_rule_set()['policy_rule_set']['id'],
             self.create_policy_rule_set()['policy_rule_set']['id']])
        attrs = self._get_test_prs_attrs(
            policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)
        prs = self.create_policy_rule_set(
            policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)

        req = self.new_show_request('policy_rule_sets',
                                    prs['policy_rule_set']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        parent_id = res['policy_rule_set']['id']
        res['policy_rule_set']['policy_rules'] = sorted(
            res['policy_rule_set']['policy_rules'])
        res['policy_rule_set']['child_policy_rule_sets'] = sorted(
            res['policy_rule_set']['child_policy_rule_sets'])
        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_rule_set'][k], v)

        req = self.new_show_request('policy_rule_sets',
                                    child_policy_rule_sets[0],
                                    fmt=self.fmt)
        c1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c1['policy_rule_set']['parent_id'], parent_id)
        req = self.new_show_request('policy_rule_sets',
                                    child_policy_rule_sets[1],
                                    fmt=self.fmt)
        c2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c2['policy_rule_set']['parent_id'], parent_id)

    def test_create_child_prs_fail(self, **kwargs):
        self.create_policy_rule_set(child_policy_rule_sets=[
            '00000000-ffff-ffff-ffff-000000000000'],
            expected_res_status=webob.exc.HTTPNotFound.code)

    def test_list_policy_rule_sets(self):
        policy_rule_sets = [
            self.create_policy_rule_set(name='ct1', description='ct'),
            self.create_policy_rule_set(name='ct2', description='ct'),
            self.create_policy_rule_set(name='ct3', description='ct')]
        self._test_list_resources('policy_rule_set', policy_rule_sets,
                                  query_params='description=ct')

    def test_update_policy_rule_set(self):
        name = "new_policy_rule_set"
        description = 'new desc'
        pc_id = self.create_policy_classifier()['policy_classifier']['id']
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        child_policy_rule_sets = [
            self.create_policy_rule_set()['policy_rule_set']['id']]
        prs = self.create_policy_rule_set(
            child_policy_rule_sets=child_policy_rule_sets,
            policy_rules=policy_rules)
        child_policy_rule_sets = [
            self.create_policy_rule_set()['policy_rule_set']['id']]
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        attrs = self._get_test_prs_attrs(
            name=name, description=description, policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)
        data = {'policy_rule_set':
                {'name': name, 'description': description,
                 'policy_rules': policy_rules,
                 'child_policy_rule_sets': child_policy_rule_sets}}

        req = self.new_update_request('policy_rule_sets', data,
                                      prs['policy_rule_set']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['policy_rule_set'][k], v)

        self._test_show_resource('policy_rule_set',
                                 prs['policy_rule_set']['id'], attrs)

    def test_delete_policy_rule_set(self):
        ctx = context.get_admin_context()
        prs = self.create_policy_rule_set()
        prs_id = prs['policy_rule_set']['id']

        req = self.new_delete_request('policy_rule_sets', prs_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.PolicyRuleSetNotFound,
                          self.plugin.get_policy_rule_set, ctx, prs_id)

    def test_prs_one_hierarchy_children(self):
        child = self.create_policy_rule_set()['policy_rule_set']
        parent = self.create_policy_rule_set(
            child_policy_rule_sets=[child['id']])['policy_rule_set']
        self.create_policy_rule_set(
            child_policy_rule_sets=[parent['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_prs_one_hierarchy_parent(self):
        child = self.create_policy_rule_set()['policy_rule_set']
        # parent
        self.create_policy_rule_set(
            child_policy_rule_sets=[child['id']])['policy_rule_set']
        nephew = self.create_policy_rule_set()['policy_rule_set']
        data = {'policy_rule_set': {'child_policy_rule_sets': [nephew['id']]}}
        req = self.new_update_request('policy_rule_sets', data, child['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_prs_parent_no_loop(self):
        prs = self.create_policy_rule_set()['policy_rule_set']
        data = {'policy_rule_set': {'child_policy_rule_sets': [prs['id']]}}
        req = self.new_update_request('policy_rule_sets', data, prs['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def _test_create_and_show(self, type, attrs, expected=None):
        plural = self._get_resource_plural(type)
        res = self._create_gbp_resource(type, None, attrs)
        expected = expected or attrs
        for k, v in expected.iteritems():
            self.assertEqual(v, res[type][k])

        req = self.new_show_request(plural, res[type]['id'], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        for k, v in expected.iteritems():
            self.assertEqual(v, res[type][k])
        self._test_show_resource(type, res[type]['id'], expected)

    def test_create_and_show_ep(self):
        es = self.create_external_segment()['external_segment']
        prs = self.create_policy_rule_set()['policy_rule_set']
        attrs = {'external_segments': [es['id']],
                 'provided_policy_rule_sets': {prs['id']: None},
                 'consumed_policy_rule_sets': {prs['id']: None}}
        body = self._get_test_ep_attrs()
        body.update(attrs)
        expected = copy.deepcopy(body)
        expected['provided_policy_rule_sets'] = [prs['id']]
        expected['consumed_policy_rule_sets'] = [prs['id']]
        self._test_create_and_show('external_policy', body,
                                   expected=expected)

    def test_create_and_show_es(self):
        route = {'destination': '0.0.0.0/0', 'nexthop': '172.0.0.1'}
        attrs = self._get_test_es_attrs(external_routes=[route])
        self._test_create_and_show('external_segment', attrs)

    def test_create_and_show_np(self):
        es = self.create_external_segment()['external_segment']
        attrs = self._get_test_np_attrs(external_segment_id=es['id'])
        self._test_create_and_show('nat_pool', attrs)

    def test_list_ep(self):
        external_policies = [
            self.create_external_policy(name='ep1', description='ep'),
            self.create_external_policy(name='ep2', description='ep'),
            self.create_external_policy(name='ep3', description='ep')]
        self._test_list_resources('external_policy',
                                  external_policies,
                                  query_params='description=ep')

    def test_list_es(self):
        external_segments = [
            self.create_external_segment(name='es1', description='es'),
            self.create_external_segment(name='es2', description='es'),
            self.create_external_segment(name='es3', description='es')]
        self._test_list_resources('external_segment',
                                  external_segments,
                                  query_params='description=es')

    def test_update_external_policy(self):
        name = 'new_ep'
        description = 'new desc'
        es = self.create_external_segment()['external_segment']
        prs = self.create_policy_rule_set()['policy_rule_set']
        attrs = self._get_test_ep_attrs(
            name=name, description=description,
            external_segments=[es['id']],
            provided_policy_rule_sets={prs['id']: None},
            consumed_policy_rule_sets={prs['id']: None})
        ep = self.create_external_policy()['external_policy']
        data = {'external_policy': {
            'name': name, 'description': description,
            'external_segments': [es['id']],
            'provided_policy_rule_sets': {prs['id']: None},
            'consumed_policy_rule_sets': {prs['id']: None}}}

        req = self.new_update_request('external_policies', data,
                                      ep['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['external_policy']
        for k, v in attrs.iteritems():
            self.assertEqual(v, res[k])

        self._test_show_resource('external_policy', ep['id'], attrs)

    def test_update_external_segment(self):
        name = 'new_es'
        description = 'new desc'
        route = {'destination': '0.0.0.0/0', 'nexthop': '172.0.0.1'}
        attrs = self._get_test_es_attrs(name=name, description=description,
                                        external_routes=[route])
        es = self.create_external_segment()['external_segment']
        data = {'external_segment': {
            'name': name, 'description': description,
            'external_routes': [route]}}

        req = self.new_update_request('external_segments', data,
                                      es['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['external_segment']
        for k, v in attrs.iteritems():
            self.assertEqual(res[k], v)

        self._test_show_resource('external_segment', es['id'], attrs)

    def test_update_nat_pool(self):
        name = 'new_np'
        description = 'new desc'
        es = self.create_external_segment()['external_segment']

        attrs = self._get_test_np_attrs(name=name, description=description,
                                        external_segment_id=es['id'])
        np = self.create_nat_pool()['nat_pool']
        data = {'nat_pool': {
            'name': name, 'description': description,
            'external_segment_id': es['id']}}

        req = self.new_update_request('nat_pools', data,
                                      np['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['nat_pool']
        for k, v in attrs.iteritems():
            self.assertEqual(v, res[k])

        self._test_show_resource('nat_pool', np['id'], attrs)

    def test_delete_ep(self):
        ctx = context.get_admin_context()
        ep = self.create_external_policy()
        ep_id = ep['external_policy']['id']

        req = self.new_delete_request('external_policies', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.ExternalPolicyNotFound,
                          self.plugin.get_external_policy, ctx, ep_id)

    def test_delete_es(self):
        ctx = context.get_admin_context()
        ep = self.create_external_segment()
        ep_id = ep['external_segment']['id']

        req = self.new_delete_request('external_segments', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.ExternalSegmentNotFound,
                          self.plugin.get_external_segment, ctx, ep_id)

    def test_delete_np(self):
        ctx = context.get_admin_context()
        ep = self.create_nat_pool()
        ep_id = ep['nat_pool']['id']

        req = self.new_delete_request('nat_pools', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.NATPoolNotFound,
                          self.plugin.get_nat_pool, ctx, ep_id)
