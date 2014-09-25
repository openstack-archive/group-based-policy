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
from neutron.plugins.common import constants
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extensions

from gbp.neutron.db.grouppolicy import group_policy_db as gpdb
import gbp.neutron.extensions
from gbp.neutron.extensions import group_policy as gpolicy


JSON_FORMAT = 'json'


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
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id, 'l2_policy_id': l2_policy_id,
                 'provided_contracts': provided_contracts or {},
                 'consumed_contracts': consumed_contracts or {}}

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


class GroupPolicyDBTestPlugin(gpdb.GroupPolicyDbPlugin):

        supported_extension_aliases = ['group-policy']


DB_GP_PLUGIN_KLASS = (GroupPolicyDBTestPlugin.__module__ + '.' +
                      GroupPolicyDBTestPlugin.__name__)


class GroupPolicyDbTestCase(GroupPolicyDBTestBase,
                            test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, gp_plugin=None, service_plugins=None, ext_mgr=None):
        extensions.append_api_extensions_path(gbp.neutron.extensions.__path__)
        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        self.plugin = importutils.import_object(gp_plugin)
        if not service_plugins:
            service_plugins = {'gp_plugin_name': gp_plugin}

        super(GroupPolicyDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
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
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        l2p_id = self.create_l2_policy(l3_policy_id=l3p_id)['l2_policy']['id']
        attrs = self._get_test_endpoint_group_attrs(l2_policy_id=l2p_id)

        epg = self.create_endpoint_group(l2_policy_id=l2p_id)

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

        epg = self.create_endpoint_group()
        data = {'endpoint_group': {'name': name, 'description': description,
                                   'l2_policy_id': l2p_id,
                                   'provided_contracts': {},
                                   'consumed_contracts': {}}}
        req = self.new_update_request('endpoint_groups', data,
                                      epg['endpoint_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

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
