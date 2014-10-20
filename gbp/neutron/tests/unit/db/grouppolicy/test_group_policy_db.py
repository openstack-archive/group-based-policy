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

import webob.exc

from neutron.api import extensions
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

    def _get_test_endpoint_attrs(self, name='ep1', description='test ep',
                                 endpoint_group_id=None):
        attrs = {'name': name, 'description': description,
                 'endpoint_group_id': endpoint_group_id,
                 'tenant_id': self._tenant_id}

        return attrs

    def _get_test_endpoint_group_attrs(self, name='epg1',
                                       description='test epg',
                                       l2_policy_id=None,
                                       provided_contracts=None,
                                       consumed_contracts=None):
        pc_ids = cc_ids = []
        if provided_contracts:
            pc_ids = [pc_id for pc_id in provided_contracts]
        if consumed_contracts:
            cc_ids = [cc_id for cc_id in consumed_contracts]
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'l2_policy_id': l2_policy_id,
                 'provided_contracts': pc_ids,
                 'consumed_contracts': cc_ids}

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
                                  subnet_prefix_length=24):
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'ip_version': ip_version,
                 'ip_pool': ip_pool,
                 'subnet_prefix_length': subnet_prefix_length}

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

    def _get_test_contract_attrs(self, name='contract1',
                                 description='test contract',
                                 child_contracts=None, policy_rules=None):
        if not child_contracts:
            child_contracts = []
        if not policy_rules:
            policy_rules = []
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'child_contracts': child_contracts,
                 'policy_rules': policy_rules}

        return attrs

    def create_endpoint(self, endpoint_group_id=None,
                        expected_res_status=None, **kwargs):
        defaults = {'name': 'ep1', 'description': 'test ep'}
        defaults.update(kwargs)

        data = {'endpoint': {'endpoint_group_id': endpoint_group_id,
                             'tenant_id': self._tenant_id}}
        data['endpoint'].update(defaults)

        ep_req = self.new_create_request('endpoints', data, self.fmt)
        ep_res = ep_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(ep_res.status_int, expected_res_status)
        elif ep_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=ep_res.status_int)

        ep = self.deserialize(self.fmt, ep_res)

        return ep

    def create_endpoint_group(self, l2_policy_id=None,
                              expected_res_status=None, **kwargs):
        defaults = {'name': 'epg1', 'description': 'test epg',
                    'provided_contracts': {},
                    'consumed_contracts': {}}
        defaults.update(kwargs)

        data = {'endpoint_group': {'tenant_id': self._tenant_id,
                                   'l2_policy_id': l2_policy_id}}
        data['endpoint_group'].update(defaults)

        epg_req = self.new_create_request('endpoint_groups', data, self.fmt)
        epg_res = epg_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(epg_res.status_int, expected_res_status)
        elif epg_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=epg_res.status_int)

        epg = self.deserialize(self.fmt, epg_res)

        return epg

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
                    'subnet_prefix_length': 24}
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

    def create_contract(self, expected_res_status=None, **kwargs):
        defaults = {'name': 'contract1', 'description': 'test contract',
                    'child_contracts': [], 'policy_rules': []}
        defaults.update(kwargs)
        kwargs = defaults

        data = {'contract': {'tenant_id': self._tenant_id}}
        data['contract'].update(kwargs)

        ct_req = self.new_create_request('contracts', data, self.fmt)
        ct_res = ct_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(ct_res.status_int, expected_res_status)
        elif ct_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=ct_res.status_int)

        ct = self.deserialize(self.fmt, ct_res)

        return ct


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

    def test_create_and_show_endpoint(self):
        epg_id = self.create_endpoint_group()['endpoint_group']['id']
        attrs = self._get_test_endpoint_attrs(endpoint_group_id=epg_id)

        ep = self.create_endpoint(endpoint_group_id=epg_id)

        for k, v in attrs.iteritems():
            self.assertEqual(ep['endpoint'][k], v)

        req = self.new_show_request('endpoint_groups', epg_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        self.assertEqual(res['endpoint_group']['endpoints'],
                         [ep['endpoint']['id']])

        self._test_show_resource('endpoint', ep['endpoint']['id'], attrs)

    def test_list_endpoints(self):
        eps = [self.create_endpoint(name='ep1', description='ep'),
               self.create_endpoint(name='ep2', description='ep'),
               self.create_endpoint(name='ep3', description='ep')]
        self._test_list_resources('endpoint', eps,
                                  query_params='description=ep')

    def test_update_endpoint(self):
        name = 'new_endpoint'
        description = 'new desc'
        attrs = self._get_test_endpoint_attrs(name=name,
                                              description=description)

        ep = self.create_endpoint()

        data = {'endpoint': {'name': name, 'description': description}}
        req = self.new_update_request('endpoints', data, ep['endpoint']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['endpoint'][k], v)

        self._test_show_resource('endpoint', ep['endpoint']['id'], attrs)

    def test_delete_endpoint(self):
        ctx = context.get_admin_context()

        ep = self.create_endpoint()
        ep_id = ep['endpoint']['id']

        req = self.new_delete_request('endpoints', ep_id)
        res = req.get_response(self.ext_api)

        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.EndpointNotFound, self.plugin.get_endpoint,
                          ctx, ep_id)

    def test_create_and_show_endpoint_group(self):
        name = "epg1"
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        l2p = self.create_l2_policy(name=name, l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']

        provided_ct_id = self.create_contract()['contract']['id']
        consumed_ct_id = self.create_contract()['contract']['id']
        attrs = self._get_test_endpoint_group_attrs(name,
                                                    l2_policy_id=l2p_id,
                                                    provided_contracts=
                                                    [provided_ct_id],
                                                    consumed_contracts=
                                                    [consumed_ct_id])

        epg = self.create_endpoint_group(name=name, l2_policy_id=l2p_id,
                                         provided_contracts={provided_ct_id:
                                                             None},
                                         consumed_contracts={consumed_ct_id:
                                                             None})

        for k, v in attrs.iteritems():
            self.assertEqual(epg['endpoint_group'][k], v)

        self._test_show_resource('endpoint_group', epg['endpoint_group']['id'],
                                 attrs)

    def test_list_endpoint_groups(self):
        epgs = [self.create_endpoint_group(name='epg1', description='epg'),
                self.create_endpoint_group(name='epg2', description='epg'),
                self.create_endpoint_group(name='epg3', description='epg')]
        self._test_list_resources('endpoint_group', epgs,
                                  query_params='description=epg')

    def test_update_endpoint_group(self):
        name = "new_endpoint_group1"
        description = 'new desc'
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        l2p_id = self.create_l2_policy(l3_policy_id=l3p_id)['l2_policy']['id']
        attrs = self._get_test_endpoint_group_attrs(name=name,
                                                    description=description,
                                                    l2_policy_id=l2p_id)
        ct1_id = self.create_contract(name='contract1')['contract']['id']
        ct2_id = self.create_contract(name='contract2')['contract']['id']
        epg = self.create_endpoint_group(consumed_contracts={ct1_id: 'scope'},
                                         provided_contracts={ct2_id: 'scope'})
        ct3_id = self.create_contract(name='contract3')['contract']['id']
        ct4_id = self.create_contract(name='contract4')['contract']['id']
        data = {'endpoint_group': {'name': name, 'description': description,
                                   'l2_policy_id': l2p_id,
                                   'provided_contracts': {ct3_id: 'scope'},
                                   'consumed_contracts': {ct4_id: 'scope'}}}
        req = self.new_update_request('endpoint_groups', data,
                                      epg['endpoint_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        attrs['provided_contracts'] = [ct3_id]
        attrs['consumed_contracts'] = [ct4_id]
        for k, v in attrs.iteritems():
            self.assertEqual(res['endpoint_group'][k], v)

        self._test_show_resource('endpoint_group',
                                 epg['endpoint_group']['id'], attrs)

    def test_delete_endpoint_group(self):
        ctx = context.get_admin_context()

        epg = self.create_endpoint_group()
        epg_id = epg['endpoint_group']['id']

        req = self.new_delete_request('endpoint_groups', epg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.EndpointGroupNotFound,
                          self.plugin.get_endpoint_group, ctx, epg_id)

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
        attrs = self._get_test_l3_policy_attrs()

        l3p = self.create_l3_policy()

        for k, v in attrs.iteritems():
            self.assertEqual(l3p['l3_policy'][k], v)

        req = self.new_show_request('l3_policies', l3p['l3_policy']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['l3_policy'][k], v)

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
        attrs = self._get_test_l3_policy_attrs(
            name=name, description=description,
            subnet_prefix_length=prefix_length)

        l3p = self.create_l3_policy()
        data = {'l3_policy': {'name': name, 'description': description,
                              'subnet_prefix_length': prefix_length}}

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

    def test_create_and_show_contract(self):
        name = "contract1"
        attrs = self._get_test_contract_attrs(name=name)

        ct = self.create_contract(name=name)

        for k, v in attrs.iteritems():
            self.assertEqual(ct['contract'][k], v)

        req = self.new_show_request('contracts', ct['contract']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['contract'][k], v)

        self._test_show_resource('contract',
                                 ct['contract']['id'], attrs)

    def test_create_contract_with_multiple_rules_children(self, **kwargs):
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
        child_contracts = sorted([self.create_contract()['contract']['id'],
                                  self.create_contract()['contract']['id']])
        attrs = self._get_test_contract_attrs(
            policy_rules=policy_rules, child_contracts=child_contracts)
        ct = self.create_contract(policy_rules=policy_rules,
                                  child_contracts=child_contracts)

        req = self.new_show_request('contracts', ct['contract']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        parent_id = res['contract']['id']
        res['contract']['policy_rules'] = sorted(
            res['contract']['policy_rules'])
        res['contract']['child_contracts'] = sorted(
            res['contract']['child_contracts'])
        for k, v in attrs.iteritems():
            self.assertEqual(res['contract'][k], v)

        req = self.new_show_request('contracts', child_contracts[0],
                                    fmt=self.fmt)
        c1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c1['contract']['parent_id'], parent_id)
        req = self.new_show_request('contracts', child_contracts[1],
                                    fmt=self.fmt)
        c2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c2['contract']['parent_id'], parent_id)

    def test_create_child_contract_fail(self, **kwargs):
        self.create_contract(child_contracts=[
            '00000000-ffff-ffff-ffff-000000000000'],
            expected_res_status=webob.exc.HTTPNotFound.code)

    def test_list_contracts(self):
        contracts = [
            self.create_contract(name='ct1', description='ct'),
            self.create_contract(name='ct2', description='ct'),
            self.create_contract(name='ct3', description='ct')]
        self._test_list_resources('contract', contracts,
                                  query_params='description=ct')

    def test_update_contract(self):
        name = "new_contract"
        description = 'new desc'
        pc_id = self.create_policy_classifier()['policy_classifier']['id']
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        child_contracts = [self.create_contract()['contract']['id']]
        ct = self.create_contract(child_contracts=child_contracts,
                                  policy_rules=policy_rules)
        child_contracts = [self.create_contract()['contract']['id']]
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        attrs = self._get_test_contract_attrs(
            name=name, description=description, policy_rules=policy_rules,
            child_contracts=child_contracts)
        data = {'contract': {'name': name, 'description': description,
                             'policy_rules': policy_rules,
                             'child_contracts': child_contracts}}

        req = self.new_update_request('contracts', data,
                                      ct['contract']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['contract'][k], v)

        self._test_show_resource('contract',
                                 ct['contract']['id'], attrs)

    def test_delete_contract(self):
        ctx = context.get_admin_context()
        ct = self.create_contract()
        ct_id = ct['contract']['id']

        req = self.new_delete_request('contracts', ct_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(gpolicy.ContractNotFound,
                          self.plugin.get_contract, ctx, ct_id)

    def test_contract_one_hierarchy_children(self):
        child = self.create_contract()['contract']
        parent = self.create_contract(
            child_contracts = [child['id']])['contract']
        self.create_contract(
            child_contracts = [parent['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_contract_one_hierarchy_parent(self):
        child = self.create_contract()['contract']
        # parent
        self.create_contract(
            child_contracts = [child['id']])['contract']
        nephew = self.create_contract()['contract']
        data = {'contract': {'child_contracts': [nephew['id']]}}
        req = self.new_update_request('contracts', data, child['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_contract_parent_no_loop(self):
        ct = self.create_contract()['contract']
        data = {'contract': {'child_contracts': [ct['id']]}}
        req = self.new_update_request('contracts', data, ct['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)
