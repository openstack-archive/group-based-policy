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

import ast
import collections

from neutron import context as n_ctx
from oslo_config import cfg
from oslo_serialization import jsonutils

from gbpservice.neutron.services.servicechain.plugins.msc import (
    plugin as msc_plugin)
from gbpservice.neutron.services.servicechain.plugins.msc import context
from gbpservice.neutron.tests.unit.db.grouppolicy import (
    test_servicechain_db as test_servicechain_db)
from gbpservice.neutron.tests.unit.db.grouppolicy import test_group_policy_db

cfg.CONF.import_opt(
    'servicechain_drivers',
    'gbpservice.neutron.services.servicechain.plugins.msc.config',
    group='servicechain')


class ServiceChainMSCTestPlugin(msc_plugin.ServiceChainPlugin):

    supported_extension_aliases = ['servicechain'] + (
        test_group_policy_db.UNSUPPORTED_REQUIRED_EXTS)
    path_prefix = "/servicechain"


SC_PLUGIN_KLASS = (ServiceChainMSCTestPlugin.__module__ + '.' +
                   ServiceChainMSCTestPlugin.__name__)


class ServiceChainPluginTestCase(test_servicechain_db.ServiceChainDbTestCase):

    def setUp(self, core_plugin=None, sc_plugin=None, gp_plugin=None):
        super(ServiceChainPluginTestCase, self).setUp(core_plugin=core_plugin,
                                                      sc_plugin=sc_plugin or
                                                      SC_PLUGIN_KLASS,
                                                      gp_plugin=gp_plugin)


class TestGroupPolicyPluginGroupResources(
        ServiceChainPluginTestCase,
        test_servicechain_db.TestServiceChainResources):

    def test_spec_shared(self):
        # Shared spec can only point shared nodes
        node = self._create_profiled_servicechain_node(
            'LOADBALANCER', shared=True, shared_profile=True,
            profile_tenant_id='admin', tenant_id='admin')['servicechain_node']
        self.create_servicechain_spec(nodes=[node['id']], shared=True,
                                      expected_res_status=201)
        self.create_servicechain_spec(nodes=[node['id']], shared=False,
                                      tenant_id='admin',
                                      expected_res_status=201)

        node = self._create_profiled_servicechain_node(
            'LOADBALANCER', shared=False, profile_tenant_id='nonadmin',
            tenant_id='nonadmin')['servicechain_node']
        self.create_servicechain_spec(nodes=[node['id']], shared=True,
                                      expected_res_status=404)
        self.create_servicechain_spec(nodes=[node['id']], shared=True,
                                      tenant_id='nonadmin',
                                      expected_res_status=400)
        self.create_servicechain_spec(nodes=[node['id']], shared=False,
                                      tenant_id='nonadmin',
                                      expected_res_status=201)

    def test_node_shared(self):
        # Shared node can only point shared profile
        prof = self.create_service_profile(
            service_type='LOADBALANCER', shared=True,
            tenant_id='admin')['service_profile']
        to_update = self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            expected_res_status=201)['servicechain_node']
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=False, tenant_id='admin',
            expected_res_status=201)

        prof = self.create_service_profile(
            service_type='LOADBALANCER', shared=False,
            tenant_id='admin')['service_profile']
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            expected_res_status=404)
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            tenant_id='admin', expected_res_status=400)
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=False,
            tenant_id='admin', expected_res_status=201)

        self.create_servicechain_spec(nodes=[to_update['id']], shared=True,
                                      tenant_id='nonadmin',
                                      expected_res_status=201)

        data = {'servicechain_node': {'shared': False}}
        req = self.new_update_request('servicechain_nodes', data,
                                      to_update['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)
        res = self.deserialize(self.fmt, res)
        self.assertEqual('InvalidSharedAttributeUpdate',
                         res['NeutronError']['type'])

    def test_profile_shared(self):
        prof = self.create_service_profile(
            service_type='LOADBALANCER', shared=True,
            tenant_id='admin')['service_profile']
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            expected_res_status=201)

        data = {'service_profile': {'shared': False}}
        req = self.new_update_request('service_profiles', data,
                                      prof['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)
        res = self.deserialize(self.fmt, res)
        self.assertEqual('InvalidSharedAttributeUpdate',
                         res['NeutronError']['type'])

        prof = self.create_service_profile(
            service_type='LOADBALANCER', shared=False)['service_profile']
        self.create_servicechain_node(
            service_profile_id=prof['id'], shared=False,
            expected_res_status=201)

        data = {'service_profile': {'shared': True}}
        req = self.new_update_request('service_profiles', data,
                                      prof['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(200, res.status_int)
        res = self.deserialize(self.fmt, res)
        self.assertTrue(res['service_profile']['shared'])

    def test_node_context_profile(self):

        # Current node with profile
        plugin_context = n_ctx.get_admin_context()
        plugin_context.is_admin = plugin_context.is_advsvc = False
        plugin_context.tenant_id = 'test-tenant'

        prof = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']
        current = self.create_servicechain_node(
            service_profile_id=prof['id'],
            expected_res_status=201)['servicechain_node']
        ctx = context.ServiceChainNodeContext(self.plugin, plugin_context,
                                              current)

        self.assertIsNone(ctx.original)
        self.assertIsNone(ctx.original_profile)
        self.assertEqual(ctx.current['id'], current['id'])
        self.assertEqual(ctx.current_profile['id'], prof['id'])

        # Original node with profile

        prof2 = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']
        original = self.create_servicechain_node(
            service_profile_id=prof2['id'],
            expected_res_status=201)['servicechain_node']
        ctx = context.ServiceChainNodeContext(self.plugin, plugin_context,
                                              current, original)

        self.assertEqual(ctx.original['id'], original['id'])
        self.assertEqual(ctx.original_profile['id'], prof2['id'])
        self.assertEqual(ctx.current['id'], current['id'])
        self.assertEqual(ctx.current_profile['id'], prof['id'])

    def test_node_context_no_profile(self):

        plugin_context = n_ctx.get_admin_context()
        plugin_context.is_admin = plugin_context.is_advsvc = False
        plugin_context.tenant_id = 'test_tenant'

        current = self.create_servicechain_node(
            service_type='TEST',
            expected_res_status=201)['servicechain_node']
        ctx = context.ServiceChainNodeContext(self.plugin, plugin_context,
                                              current)

        self.assertIsNone(ctx.original)
        self.assertIsNone(ctx.original_profile)
        self.assertEqual(ctx.current['id'], current['id'])
        self.assertIsNone(ctx.current_profile)

        original = self.create_servicechain_node(
            service_type='TEST',
            expected_res_status=201)['servicechain_node']
        ctx = context.ServiceChainNodeContext(self.plugin, plugin_context,
                                              current, original)

        self.assertEqual(ctx.original['id'], original['id'])
        self.assertIsNone(ctx.original_profile)
        self.assertEqual(ctx.current['id'], current['id'])
        self.assertIsNone(ctx.current_profile)

    def test_spec_parameters(self):
        params_node_1 = ['p1', 'p2', 'p3']
        params_node_2 = ['p4', 'p5', 'p6']
        params_node_3 = ['p7', 'p8', 'p9']

        def params_dict(params):
            return jsonutils.dumps({'Parameters':
                                    dict((x, {}) for x in params)})

        prof = self.create_service_profile(
            service_type='LOADBALANCER', shared=True,
            tenant_id='admin')['service_profile']

        # Create 2 nodes with different parameters
        node1 = self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            config=params_dict(params_node_1),
            expected_res_status=201)['servicechain_node']
        node2 = self.create_servicechain_node(
            service_profile_id=prof['id'], shared=True,
            config=params_dict(params_node_2),
            expected_res_status=201)['servicechain_node']

        # Create SC spec with the nodes assigned
        spec = self.create_servicechain_spec(
            nodes=[node1['id'], node2['id']], shared=True,
            expected_res_status=201)['servicechain_spec']

        # Verify param names correspondence
        self.assertEqual(
            collections.Counter(params_node_1 + params_node_2),
            collections.Counter(ast.literal_eval(spec['config_param_names'])))

        # Update the spec removing one node
        self.update_servicechain_spec(spec['id'], nodes=[node1['id']],
                                      expected_res_status=200)

        spec = self.show_servicechain_spec(spec['id'])['servicechain_spec']
        # Verify param names correspondence
        self.assertEqual(
            collections.Counter(params_node_1),
            collections.Counter(ast.literal_eval(spec['config_param_names'])))

        # Update the spec without modifying the node list
        self.update_servicechain_spec(spec['id'],
                                      name='new_name',
                                      expected_res_status=200)

        spec = self.show_servicechain_spec(spec['id'])['servicechain_spec']
        # Verify param names correspondence
        self.assertEqual(
            collections.Counter(params_node_1),
            collections.Counter(ast.literal_eval(spec['config_param_names'])))

        # Update a node with new config params
        self.update_servicechain_node(node1['id'],
                                      config=params_dict(params_node_3),
                                      expected_res_status=200)

        spec = self.show_servicechain_spec(spec['id'])['servicechain_spec']
        # Verify param names correspondence
        self.assertEqual(
            collections.Counter(params_node_3),
            collections.Counter(ast.literal_eval(spec['config_param_names'])))
