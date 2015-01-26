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

from gbpservice.neutron.db import servicechain_db as svcchain_db
import gbpservice.neutron.extensions
from gbpservice.neutron.extensions import servicechain as service_chain

JSON_FORMAT = 'json'


class ServiceChainDBTestBase(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.SERVICECHAIN])
        for k in service_chain.RESOURCE_ATTRIBUTE_MAP.keys()
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

    def _get_test_servicechain_node_attrs(self, name='scn1',
                                          description='test scn',
                                          service_type=constants.FIREWALL,
                                          config="{}"):
        attrs = {'name': name, 'description': description,
                 'service_type': service_type,
                 'config': config,
                 'tenant_id': self._tenant_id}

        return attrs

    def _get_test_servicechain_spec_attrs(self, name='scs1',
                                          description='test scs',
                                          nodes=None):
        node_ids = []
        if nodes:
            node_ids = [node_id for node_id in nodes]
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'nodes': node_ids}

        return attrs

    def _get_test_servicechain_instance_attrs(self, name='sci1',
                                              description='test sci',
                                              config_param_values="{}",
                                              servicechain_specs=[],
                                              provider_ptg_id=None,
                                              consumer_ptg_id=None,
                                              classifier_id=None):
        attrs = {'name': name, 'description': description,
                 'tenant_id': self._tenant_id,
                 'config_param_values': config_param_values,
                 'servicechain_specs': servicechain_specs,
                 'provider_ptg_id': provider_ptg_id,
                 'consumer_ptg_id': consumer_ptg_id,
                 'classifier_id': classifier_id}

        return attrs

    def create_servicechain_node(self, service_type=constants.FIREWALL,
                                 config="{}", expected_res_status=None,
                                 **kwargs):
        defaults = {'name': 'scn1', 'description': 'test scn'}
        defaults.update(kwargs)

        data = {'servicechain_node': {'service_type': service_type,
                                      'tenant_id': self._tenant_id,
                                      'config': config}}
        data['servicechain_node'].update(defaults)

        scn_req = self.new_create_request('servicechain_nodes', data, self.fmt)
        scn_res = scn_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(scn_res.status_int, expected_res_status)
        elif scn_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=scn_res.status_int)

        scn = self.deserialize(self.fmt, scn_res)

        return scn

    def create_servicechain_spec(self, nodes=None, expected_res_status=None,
                                 **kwargs):
        defaults = {'name': 'scs1', 'description': 'test scs'}
        defaults.update(kwargs)

        data = {'servicechain_spec': {'tenant_id': self._tenant_id,
                                      'nodes': nodes}}
        data['servicechain_spec'].update(defaults)

        scs_req = self.new_create_request('servicechain_specs', data, self.fmt)
        scs_res = scs_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(scs_res.status_int, expected_res_status)
        elif scs_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=scs_res.status_int)

        scs = self.deserialize(self.fmt, scs_res)

        return scs

    def test_create_servicechain_specs_same_node(self):
        template1 = '{"key1":"value1"}'
        scn = self.create_servicechain_node(config=template1)
        scn_id = scn['servicechain_node']['id']
        spec1 = {"servicechain_spec": {'name': 'scs1',
                                       'tenant_id': self._tenant_id,
                                       'nodes': [scn_id]}}
        spec_req = self.new_create_request('servicechain_specs',
                                           spec1,
                                           self.fmt)
        spec_res = spec_req.get_response(self.ext_api)
        self.assertEqual(spec_res.status_int, webob.exc.HTTPCreated.code)
        res = self.deserialize(self.fmt, spec_res)
        self.assertIn('servicechain_spec', res)
        self.assertEqual([scn_id], res['servicechain_spec']['nodes'])
        spec2 = {"servicechain_spec": {'name': 'scs2',
                                       'tenant_id': self._tenant_id,
                                       'nodes': [scn_id]}}
        spec_req = self.new_create_request('servicechain_specs',
                                           spec2,
                                           self.fmt)
        spec_res = spec_req.get_response(self.ext_api)
        self.assertEqual(spec_res.status_int, webob.exc.HTTPCreated.code)
        res = self.deserialize(self.fmt, spec_res)
        self.assertIn('servicechain_spec', res)
        self.assertEqual([scn_id], res['servicechain_spec']['nodes'])

    def create_servicechain_instance(self, servicechain_specs=[],
                                     config_param_values="{}",
                                     provider_ptg_id=None,
                                     consumer_ptg_id=None,
                                     classifier_id=None,
                                     expected_res_status=None, **kwargs):
        defaults = {'name': 'sci1', 'description': 'test sci'}
        defaults.update(kwargs)
        data = {'servicechain_instance':
                {'config_param_values': config_param_values,
                 'servicechain_specs': servicechain_specs,
                 'tenant_id': self._tenant_id,
                 'provider_ptg_id': provider_ptg_id,
                 'consumer_ptg_id': consumer_ptg_id,
                 'classifier_id': classifier_id}}
        data['servicechain_instance'].update(defaults)

        sci_req = self.new_create_request('servicechain_instances',
                                          data, self.fmt)
        sci_res = sci_req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(sci_res.status_int, expected_res_status)
        elif sci_res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=sci_res.status_int)

        sci = self.deserialize(self.fmt, sci_res)

        return sci


class ServiceChainDBTestPlugin(svcchain_db.ServiceChainDbPlugin):

        supported_extension_aliases = ['servicechain']


DB_GP_PLUGIN_KLASS = (ServiceChainDBTestPlugin.__module__ + '.' +
                      ServiceChainDBTestPlugin.__name__)

GP_PLUGIN_KLASS = (
    "gbpservice.neutron.services.grouppolicy.plugin.GroupPolicyPlugin")


class ServiceChainDbTestCase(ServiceChainDBTestBase,
                             test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, sc_plugin=None, service_plugins=None,
              ext_mgr=None):
        extensions.append_api_extensions_path(
            gbpservice.neutron.extensions.__path__)
        if not sc_plugin:
            sc_plugin = DB_GP_PLUGIN_KLASS
        self.plugin = importutils.import_object(sc_plugin)
        if not service_plugins:
            service_plugins = {'gp_plugin_name': GP_PLUGIN_KLASS,
                               'sc_plugin_name': sc_plugin}

        super(ServiceChainDbTestCase, self).setUp(
            plugin=core_plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)


class TestServiceChainResources(ServiceChainDbTestCase):

    def _test_show_resource(self, resource, resource_id, attrs):
        resource_plural = self._get_resource_plural(resource)
        req = self.new_show_request(resource_plural, resource_id,
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt,
                               req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res[resource][k], v)

    def test_create_and_show_servicechain_node(self):
        attrs = self._get_test_servicechain_node_attrs(
            service_type=constants.LOADBALANCER, config="config1")

        scn = self.create_servicechain_node(
            service_type=constants.LOADBALANCER, config="config1")

        for k, v in attrs.iteritems():
            self.assertEqual(scn['servicechain_node'][k], v)

        self._test_show_resource('servicechain_node',
                                 scn['servicechain_node']['id'],
                                 attrs)

    def test_list_servicechain_nodes(self):
        scns = [self.create_servicechain_node(name='scn1', description='scn'),
                self.create_servicechain_node(name='scn2', description='scn'),
                self.create_servicechain_node(name='scn3', description='scn')]
        self._test_list_resources('servicechain_node', scns,
                                  query_params='description=scn')

    def test_update_servicechain_node(self):
        name = 'new_servicechain_node'
        description = 'new desc'
        attrs = self._get_test_servicechain_node_attrs(name=name,
                                                       description=description)

        scn = self.create_servicechain_node()

        data = {'servicechain_node': {'name': name,
                                      'description': description}}
        req = self.new_update_request('servicechain_nodes', data,
                                      scn['servicechain_node']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['servicechain_node'][k], v)

        self._test_show_resource('servicechain_node',
                                 scn['servicechain_node']['id'],
                                 attrs)

    def test_delete_servicechain_node(self):
        ctx = context.get_admin_context()

        scn = self.create_servicechain_node()
        scn_id = scn['servicechain_node']['id']

        scs = self.create_servicechain_spec(nodes=[scn_id])
        scs_id = scs['servicechain_spec']['id']

        # Deleting Service Chain Node in use by a Spec should fail
        self.assertRaises(service_chain.ServiceChainNodeInUse,
                          self.plugin.delete_servicechain_node, ctx, scn_id)

        req = self.new_delete_request('servicechain_specs', scs_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

        # After deleting the Service Chain Spec, node delete should succeed
        req = self.new_delete_request('servicechain_nodes', scn_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(service_chain.ServiceChainNodeNotFound,
                          self.plugin.get_servicechain_node,
                          ctx, scn_id)

    def test_create_and_show_servicechain_spec(self):
        name = "scs1"
        scn = self.create_servicechain_node()
        scn_id = scn['servicechain_node']['id']

        attrs = self._get_test_servicechain_spec_attrs(name, nodes=[scn_id])

        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])

        for k, v in attrs.iteritems():
            self.assertEqual(scs['servicechain_spec'][k], v)

        self._test_show_resource('servicechain_spec',
                                 scs['servicechain_spec']['id'],
                                 attrs)

    def test_create_spec_multiple_nodes(self):
        name = "scs1"
        scn1 = self.create_servicechain_node()
        scn1_id = scn1['servicechain_node']['id']
        scn2 = self.create_servicechain_node()
        scn2_id = scn2['servicechain_node']['id']
        attrs = self._get_test_servicechain_spec_attrs(
                            name, nodes=[scn1_id, scn2_id])
        scs = self.create_servicechain_spec(
                            name=name, nodes=[scn1_id, scn2_id])
        for k, v in attrs.iteritems():
            self.assertEqual(scs['servicechain_spec'][k], v)

    def test_list_servicechain_specs(self):
        scs = [self.create_servicechain_spec(name='scs1', description='scs'),
               self.create_servicechain_spec(name='scs2', description='scs'),
               self.create_servicechain_spec(name='scs3', description='scs')]
        self._test_list_resources('servicechain_spec', scs,
                                  query_params='description=scs')

    def test_node_ordering_list_servicechain_specs(self):
        scn1_id = self.create_servicechain_node()['servicechain_node']['id']
        scn2_id = self.create_servicechain_node()['servicechain_node']['id']
        nodes_list = [scn1_id, scn2_id]
        scs = self.create_servicechain_spec(name='scs1',
                                            nodes=nodes_list)
        self.assertEqual(scs['servicechain_spec']['nodes'], nodes_list)
        res = self._list('servicechain_specs')
        self.assertEqual(len(res['servicechain_specs']), 1)
        self.assertEqual(res['servicechain_specs'][0]['nodes'],
                         nodes_list)

        # Delete the service chain spec and create another with nodes in
        # reverse order and verify that that proper ordering is maintained
        req = self.new_delete_request('servicechain_specs',
                                      scs['servicechain_spec']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

        nodes_list.reverse()
        scs = self.create_servicechain_spec(name='scs1',
                                            nodes=nodes_list)
        self.assertEqual(scs['servicechain_spec']['nodes'], nodes_list)
        res = self._list('servicechain_specs')
        self.assertEqual(len(res['servicechain_specs']), 1)
        self.assertEqual(res['servicechain_specs'][0]['nodes'],
                         nodes_list)

    def test_update_servicechain_spec(self):
        name = "new_servicechain_spec1"
        description = 'new desc'
        scn_id = self.create_servicechain_node()['servicechain_node']['id']
        attrs = self._get_test_servicechain_spec_attrs(name=name,
                                                       description=description,
                                                       nodes=[scn_id])
        scs = self.create_servicechain_spec()
        data = {'servicechain_spec': {'name': name, 'description': description,
                                      'nodes': [scn_id]}}
        req = self.new_update_request('servicechain_specs', data,
                                      scs['servicechain_spec']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in attrs.iteritems():
            self.assertEqual(res['servicechain_spec'][k], v)

        self._test_show_resource('servicechain_spec',
                                 scs['servicechain_spec']['id'], attrs)

    def test_delete_servicechain_spec(self):
        ctx = context.get_admin_context()

        scs = self.create_servicechain_spec()
        scs_id = scs['servicechain_spec']['id']

        req = self.new_delete_request('servicechain_specs', scs_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(service_chain.ServiceChainSpecNotFound,
                          self.plugin.get_servicechain_spec, ctx, scs_id)

    def test_delete_spec_in_use_by_policy_action_rejected(self):
        ctx = context.get_admin_context()
        scs_id = self.create_servicechain_spec()['servicechain_spec']['id']
        data = {'policy_action': {'action_type': 'redirect',
                                  'tenant_id': self._tenant_id,
                                  'action_value': scs_id}}
        pa_req = self.new_create_request('grouppolicy/policy_actions',
                                         data, self.fmt)
        res = pa_req.get_response(self.ext_api)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)

        self.assertRaises(service_chain.ServiceChainSpecInUse,
                          self.plugin.delete_servicechain_spec, ctx, scs_id)

    def test_delete_spec_in_use_by_instance_rejected(self):
        ctx = context.get_admin_context()
        scs_id = self.create_servicechain_spec()['servicechain_spec']['id']

        sci = self.create_servicechain_instance(servicechain_specs=[scs_id])
        sci_id = sci['servicechain_instance']['id']

        # Deleting the Spec used by Instance should not be allowed
        self.assertRaises(service_chain.ServiceChainSpecInUse,
                          self.plugin.delete_servicechain_spec, ctx, scs_id)

        req = self.new_delete_request('servicechain_instances', sci_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(service_chain.ServiceChainInstanceNotFound,
                          self.plugin.get_servicechain_instance,
                          ctx, sci_id)

        # Deleting the spec should succeed after the instance is deleted
        req = self.new_delete_request('servicechain_specs', scs_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(service_chain.ServiceChainSpecNotFound,
                          self.plugin.get_servicechain_spec, ctx, scs_id)

    def test_create_and_show_servicechain_instance(self):
        scs_id = self.create_servicechain_spec()['servicechain_spec']['id']
        policy_target_group_id = uuidutils.generate_uuid()
        classifier_id = uuidutils.generate_uuid()
        config_param_values = "{}"
        attrs = self._get_test_servicechain_instance_attrs(
            servicechain_specs=[scs_id],
            provider_ptg_id=policy_target_group_id,
            consumer_ptg_id=policy_target_group_id,
            classifier_id=classifier_id,
            config_param_values=config_param_values)

        sci = self.create_servicechain_instance(
            servicechain_specs=[scs_id],
            provider_ptg_id=policy_target_group_id,
            consumer_ptg_id=policy_target_group_id,
            classifier_id=classifier_id,
            config_param_values=config_param_values)
        for k, v in attrs.iteritems():
            self.assertEqual(sci['servicechain_instance'][k], v)

        self._test_show_resource('servicechain_instance',
                                 sci['servicechain_instance']['id'],
                                 attrs)
        req = self.new_delete_request('servicechain_instances',
                                      sci['servicechain_instance']['id'])
        req.get_response(self.ext_api)

    def test_list_servicechain_instances(self):
        servicechain_instances = [self.create_servicechain_instance(
            name='sci1', description='sci'),
            self.create_servicechain_instance(name='sci2', description='sci'),
            self.create_servicechain_instance(name='sci3', description='sci')]
        self._test_list_resources('servicechain_instance',
                                  servicechain_instances,
                                  query_params='description=sci')

    def test_spec_ordering_list_servicechain_instances(self):
        scs1_id = self.create_servicechain_spec()['servicechain_spec']['id']
        scs2_id = self.create_servicechain_spec()['servicechain_spec']['id']
        specs_list = [scs1_id, scs2_id]
        sci = self.create_servicechain_instance(name='sci1',
                                                servicechain_specs=specs_list)
        self.assertEqual(sci['servicechain_instance']['servicechain_specs'],
                         specs_list)
        res = self._list('servicechain_instances')
        self.assertEqual(len(res['servicechain_instances']), 1)
        result_instance = res['servicechain_instances'][0]
        self.assertEqual(result_instance['servicechain_specs'], specs_list)

        # Delete the service chain instance and create another with specs in
        # reverse order and verify that that proper ordering is maintained
        req = self.new_delete_request('servicechain_instances',
                                      sci['servicechain_instance']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

        specs_list.reverse()
        sci = self.create_servicechain_instance(name='sci1',
                                                servicechain_specs=specs_list)
        self.assertEqual(sci['servicechain_instance']['servicechain_specs'],
                         specs_list)
        res = self._list('servicechain_instances')
        self.assertEqual(len(res['servicechain_instances']), 1)
        result_instance = res['servicechain_instances'][0]
        self.assertEqual(result_instance['servicechain_specs'], specs_list)

    def test_update_servicechain_instance(self):
        name = "new_servicechain_instance"
        description = 'new desc'
        config_param_values = "{}"
        scs_id = self.create_servicechain_spec()['servicechain_spec']['id']
        provider_ptg_id = uuidutils.generate_uuid()
        consumer_ptg_id = uuidutils.generate_uuid()
        classifier_id = uuidutils.generate_uuid()
        attrs = self._get_test_servicechain_instance_attrs(
            name=name, description=description, servicechain_specs=[scs_id],
            provider_ptg_id=provider_ptg_id, consumer_ptg_id=consumer_ptg_id,
            classifier_id=classifier_id,
            config_param_values=config_param_values)

        sci = self.create_servicechain_instance(
            servicechain_specs=[scs_id], provider_ptg_id=provider_ptg_id,
            consumer_ptg_id=consumer_ptg_id, classifier_id=classifier_id,
            config_param_values=config_param_values)
        data = {'servicechain_instance': {'name': name,
                                          'description': description,
                                          'servicechain_specs': [scs_id]}}
        req = self.new_update_request('servicechain_instances', data,
                                      sci['servicechain_instance']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        for k, v in attrs.iteritems():
            self.assertEqual(res['servicechain_instance'][k], v)

        self._test_show_resource('servicechain_instance',
                                 sci['servicechain_instance']['id'], attrs)
        req = self.new_delete_request('servicechain_instances',
                                      sci['servicechain_instance']['id'])
        req.get_response(self.ext_api)

    def test_delete_servicechain_instance(self):
        ctx = context.get_admin_context()

        sci = self.create_servicechain_instance()
        sci_id = sci['servicechain_instance']['id']

        req = self.new_delete_request('servicechain_instances', sci_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        self.assertRaises(service_chain.ServiceChainInstanceNotFound,
                          self.plugin.get_servicechain_instance,
                          ctx, sci_id)
