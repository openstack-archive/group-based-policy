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

import mock
from neutron.common import config  # noqa
from neutron.common import exceptions as n_exc
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import model_base
from neutron import manager
from neutron.plugins.common import constants as pconst
from oslo.config import cfg
from oslo.serialization import jsonutils

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db  # noqa
from gbpservice.neutron.services.grouppolicy import config as gpconfig  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ncp_context)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
import gbpservice.neutron.services.servicechain.plugins.ncp.config  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp import model
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    dummy_driver as dummy_driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain import (
    test_servicechain_plugin as test_base)

SC_PLUGIN_KLASS = (
    "gbpservice.neutron.services.servicechain.plugins.ncp.plugin."
    "NodeCompositionPlugin")
CORE_PLUGIN = ('gbpservice.neutron.tests.unit.services.grouppolicy.'
               'test_resource_mapping.NoL3NatSGTestPlugin')
GP_PLUGIN_KLASS = (
    "gbpservice.neutron.services.grouppolicy.plugin.GroupPolicyPlugin"
)


class NodeCompositionPluginTestCase(
        test_base.TestGroupPolicyPluginGroupResources):

    DEFAULT_LB_CONFIG = '{}'
    SERVICE_PROFILE_VENDOR = 'dummy'

    def setUp(self, core_plugin=None, gp_plugin=None, node_drivers=None,
              node_plumber=None):
        if node_drivers:
            cfg.CONF.set_override('node_drivers', node_drivers,
                                  group='node_composition_plugin')
        cfg.CONF.set_override('node_plumber', node_plumber or 'dummy_plumber',
                              group='node_composition_plugin')
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'resource_mapping'],
                                     group='group_policy')
        super(NodeCompositionPluginTestCase, self).setUp(
            core_plugin=core_plugin or CORE_PLUGIN,
            gp_plugin=gp_plugin or GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        return servicechain_plugin

    def _create_service_profile(self, **kwargs):
        """Create service profile wrapper that can be used by drivers."""
        return self.create_service_profile(**kwargs)

    def _create_redirect_rule(self, spec_id):
        action = self.create_policy_action(action_type='REDIRECT',
                                           action_value=spec_id)
        classifier = self.create_policy_classifier(
            port_range=80, protocol='tcp', direction='bi')
        rule = self.create_policy_rule(
            policy_actions=[action['policy_action']['id']],
            policy_classifier_id=classifier['policy_classifier']['id'])
        return rule

    def _create_redirect_prs(self, spec_id):
        rule = self._create_redirect_rule(spec_id)['policy_rule']
        prs = self.create_policy_rule_set(policy_rules=[rule['id']])
        return prs

    def _create_simple_service_chain(self, number_of_nodes=1):
        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node_ids = []
        for x in xrange(number_of_nodes):
            node_ids.append(self.create_servicechain_node(
                service_profile_id=prof['id'],
                config=self.DEFAULT_LB_CONFIG,
                expected_res_status=201)['servicechain_node']['id'])

        return self._create_chain_with_nodes(node_ids)

    def _create_chain_with_nodes(self, node_ids=None):
        node_ids = node_ids or []
        spec = self.create_servicechain_spec(
            nodes=node_ids,
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        provider = self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})['policy_target_group']
        consumer = self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})['policy_target_group']
        return provider, consumer, prs

    def _add_node_driver(self, name):
        inst = dummy_driver.NoopNodeDriver()
        inst.initialize(name)
        ext = mock.Mock()
        ext.obj = inst
        self.sc_plugin.driver_manager.ordered_drivers.append(ext)
        self.sc_plugin.driver_manager.drivers[name] = ext

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        return servicechain_plugin

    def test_spec_ordering_list_servicechain_instances(self):
        pass

    def test_context_attributes(self):
        # Verify Context attributes for simple config
        plugin_context = n_context.get_admin_context()
        profile = self._create_service_profile(
            service_type="LOADBALANCER",
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        management = self.create_policy_target_group(
            service_management=True,
            is_admin_context=True)['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']

        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']], classifier_id=classifier['id'])[
                                                    'servicechain_instance']

        # Verify created without errors
        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node)

        self.assertIsNotNone(ctx.gbp_plugin)
        self.assertIsNotNone(ctx.sc_plugin)
        self.assertIsNotNone(ctx.core_plugin)
        self.assertIsNotNone(ctx.plugin_context)
        self.assertIsNotNone(ctx.plugin_session)
        self.assertIsNotNone(ctx.session)
        self.assertIsNotNone(ctx.admin_context)
        self.assertIsNotNone(ctx.admin_session)
        del ctx.current_profile['nodes']
        self.assertEqual(ctx.current_profile, profile)
        self.assertEqual(instance['id'], ctx.instance['id'])
        self.assertEqual(provider['id'], ctx.provider['id'])
        self.assertEqual(consumer['id'], ctx.consumer['id'])
        self.assertEqual(management['id'], ctx.management['id'])
        self.assertEqual([spec['id']], [x['id'] for x in ctx.relevant_specs])
        self.assertIsNone(ctx.original_node)
        self.assertEqual(0, len(ctx.get_service_targets()))

    def test_context_relevant_specs(self):
        plugin_context = n_context.get_admin_context()
        node_used = self._create_profiled_servicechain_node(
            service_type="LOADBALANCER",
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']

        provider = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
            classifier_id=classifier['id'],
            servicechain_specs=[spec_used['id']])['servicechain_instance']

        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node_used)
        self.assertEqual([spec_used['id']],
                         [x['id'] for x in ctx.relevant_specs])

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              dummy_driver.NoopNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)

    def test_spec_parameters(self):
        """Test that config_param_names is empty when using NCP.
        In NCP the config attribute of a node may be something different than
        a HEAT template, therefore config_param_names is not used.
        """

        params_node_1 = ['p1', 'p2', 'p3']
        params_node_2 = ['p4', 'p5', 'p6']
        params_node_3 = ['p7', 'p8', 'p9']

        def params_dict(params):
            return jsonutils.dumps({'Parameters':
                                    dict((x, {}) for x in params)})

        prof = self._create_service_profile(
            service_type='LOADBALANCER', shared=True,
            vendor=self.SERVICE_PROFILE_VENDOR,
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

        # Verify param names is empty
        self.assertIsNone(spec['config_param_names'])

        # Update the spec removing one node
        self.update_servicechain_spec(spec['id'], nodes=[node1['id']],
                                      expected_res_status=200)

        spec = self.show_servicechain_spec(spec['id'])['servicechain_spec']
        # Verify param names is empty
        self.assertIsNone(spec['config_param_names'])

        # Update a node with new config params
        self.update_servicechain_node(node1['id'],
                                      config=params_dict(params_node_3),
                                      expected_res_status=200)

        spec = self.show_servicechain_spec(spec['id'])['servicechain_spec']
        # Verify param names is empty
        self.assertIsNone(spec['config_param_names'])

    def test_create_service_chain(self):
        deploy = self.driver.create = mock.Mock()
        destroy = self.driver.delete = mock.Mock()

        self._create_simple_service_chain(1)
        self.assertEqual(1, deploy.call_count)
        self.assertEqual(0, destroy.call_count)

        deploy.reset_mock()

        provider, _, _ = self._create_simple_service_chain(3)
        self.assertEqual(3, deploy.call_count)
        self.assertEqual(0, destroy.call_count)

        self.update_policy_target_group(provider['id'],
                                        provided_policy_rule_sets={})
        self.assertEqual(3, deploy.call_count)
        self.assertEqual(3, destroy.call_count)

    def test_update_service_chain(self):
        deploy = self.driver.create = mock.Mock()
        update = self.driver.update = mock.Mock()
        destroy = self.driver.delete = mock.Mock()

        provider, _, prs = self._create_simple_service_chain(1)
        self.assertEqual(1, deploy.call_count)
        self.assertEqual(0, destroy.call_count)

        # REVISIT(Magesh): When bug #1446587 is fixed, we should test by
        # performing a classifier or rule update instead of SC instance update
        instances = self._list('servicechain_instances')[
                                            'servicechain_instances']
        self.assertEqual(1, len(instances))
        self.update_servicechain_instance(
            instances[0]['id'],
            expected_res_status=200)
        self.assertEqual(1, update.call_count)
        self.assertEqual(0, destroy.call_count)

    def test_create_service_chain_fails(self):
        deploy = self.driver.create = mock.Mock()
        destroy = self.driver.delete = mock.Mock()

        deploy.side_effect = Exception

        try:
            self._create_simple_service_chain(3)
        except Exception:
            pass

        self.assertEqual(1, deploy.call_count)
        self.assertEqual(3, destroy.call_count)

    def test_update_node_fails(self):
        validate_update = self.driver.validate_update = mock.Mock()
        validate_update.side_effect = exc.NodeCompositionPluginBadRequest(
            resource='node', msg='reason')

        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node_id = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']['id']

        spec = self.create_servicechain_spec(
            nodes=[node_id],
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})

        res = self.update_servicechain_node(node_id,
                                            description='somethingelse',
                                            expected_res_status=400)
        self.assertEqual('NodeCompositionPluginBadRequest',
                         res['NeutronError']['type'])

    def test_update_instantiated_profile_fails(self):
        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node_id = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']['id']

        spec = self.create_servicechain_spec(
            nodes=[node_id], expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})

        res = self.update_service_profile(prof['id'],
                                          vendor='somethingelse',
                                          expected_res_status=400)
        self.assertEqual('ServiceProfileInUseByAnInstance',
                         res['NeutronError']['type'])

    def test_second_driver_scheduled_if_first_fails(self):
        self._add_node_driver('test')
        drivers = [x.obj for x in
                   self.sc_plugin.driver_manager.ordered_drivers]
        create_1 = drivers[0].validate_create = mock.Mock()
        create_1.side_effect = n_exc.NeutronException()

        # This happens without error
        profile = self._create_service_profile(
            service_type="TYPE",
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']], classifier_id=classifier['id'],
            expected_res_status=201)

    def test_chain_fails_if_no_drivers_available(self):
        self._add_node_driver('test')
        drivers = [x.obj for x in
                   self.sc_plugin.driver_manager.ordered_drivers]
        create_1 = drivers[0].validate_create = mock.Mock()
        create_1.side_effect = n_exc.NeutronException()
        create_2 = drivers[1].validate_create = mock.Mock()
        create_2.side_effect = n_exc.NeutronException()

        profile = self._create_service_profile(
            service_type="TYPE",
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']], classifier_id=classifier['id'],
            expected_res_status=400)

    def test_multiple_nodes_update(self):
        update = self.driver.update = mock.Mock()
        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']

        self._create_chain_with_nodes([node['id']])
        self.update_servicechain_node(node['id'], name='somethingelse')
        self.assertEqual(1, update.call_count)

        update.reset_mock()
        self._create_chain_with_nodes([node['id']])
        self._create_chain_with_nodes([node['id']])
        self.update_servicechain_node(node['id'], name='somethingelse')
        self.assertEqual(3, update.call_count)

    def test_update_spec(self):
        prof = self.create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node1 = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        node2 = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']

        spec = self.create_servicechain_spec(
            nodes=[node1['id'], node2['id']],
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})

        res = self.update_servicechain_spec(spec['id'],
                                            nodes=[node1['id']],
                                            expected_res_status=200)
        self.assertEqual([node1['id']], res['servicechain_spec']['nodes'])

    def test_instance_update(self):
        prof = self.create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node1 = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        node2 = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']

        spec = self.create_servicechain_spec(
            nodes=[node1['id'], node2['id']],
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})

        instances = self._list('servicechain_instances')[
                                            'servicechain_instances']
        self.assertEqual(1, len(instances))
        spec2 = self.create_servicechain_spec(
            nodes=[node1['id']],
            expected_res_status=201)['servicechain_spec']
        res = self.update_servicechain_instance(
            instances[0]['id'], servicechain_specs=[spec2['id']],
            expected_res_status=200)
        self.assertEqual([spec2['id']],
                         res['servicechain_instance']['servicechain_specs'])

    def test_relevant_ptg_update(self):
        add = self.driver.update_policy_target_added = mock.Mock()
        rem = self.driver.update_policy_target_removed = mock.Mock()

        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']

        spec = self.create_servicechain_spec(
            nodes=[node['id']],
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        provider = self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})['policy_target_group']
        consumer = self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})['policy_target_group']

        # Verify notification issued for created PT in the provider
        pt = self.create_policy_target(
            policy_target_group_id=provider['id'])['policy_target']
        self.assertEqual(1, add.call_count)
        add.assert_called_with(mock.ANY, pt)

        # Verify notification issued for deleted PT in the provider
        self.delete_policy_target(pt['id'])
        self.assertEqual(1, rem.call_count)
        rem.assert_called_with(mock.ANY, pt)

        # Verify notification issued for created PT in the consumer
        pt = self.create_policy_target(
            policy_target_group_id=consumer['id'])['policy_target']
        self.assertEqual(2, add.call_count)
        add.assert_called_with(mock.ANY, pt)

        # Verify notification issued for deleted PT in the consumer
        self.delete_policy_target(pt['id'])
        self.assertEqual(2, rem.call_count)
        rem.assert_called_with(mock.ANY, pt)

    def test_irrelevant_ptg_update(self):
        add = self.driver.update_policy_target_added = mock.Mock()
        rem = self.driver.update_policy_target_removed = mock.Mock()

        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']

        spec = self.create_servicechain_spec(
            nodes=[node['id']], expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})

        other = self.create_policy_target_group()['policy_target_group']

        # Verify notification issued for created PT in the provider
        pt = self.create_policy_target(
            policy_target_group_id=other['id'])['policy_target']
        self.assertFalse(add.called)

        # Verify notification issued for deleted PT in the provider
        self.delete_policy_target(pt['id'])
        self.assertFalse(rem.called)

    def test_notify_chain_update_hook(self):
        update_hook = self.driver.notify_chain_parameters_updated = mock.Mock()

        prof = self.create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']],
            expected_res_status=201)['servicechain_spec']

        action = self.create_policy_action(action_type='REDIRECT',
                                           action_value=spec['id'])
        classifier = self.create_policy_classifier(
            port_range=80, protocol='tcp', direction='bi')['policy_classifier']
        rule = self.create_policy_rule(
            policy_actions=[action['policy_action']['id']],
            policy_classifier_id=classifier['id'])['policy_rule']
        prs = self.create_policy_rule_set(
            policy_rules=[rule['id']])['policy_rule_set']

        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})['policy_target_group']
        instances = self._list('servicechain_instances')[
            'servicechain_instances']
        self.assertEqual(1, len(instances))

        self.update_policy_classifier(classifier['id'], port_range=22)
        update_hook.assert_called_with(mock.ANY)

    def test_context_no_management(self):
        # Verify Context attributes for simple config
        plugin_context = n_context.get_admin_context()
        plugin_context.is_admin = False
        plugin_context.is_advsvc = False
        plugin_context.tenant_id = 'test-tenant'
        node = self._create_profiled_servicechain_node()['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']

        # Verify admin created SM is None
        management = self.create_policy_target_group(
            service_management=True, tenant_id='admin',
            is_admin_context=True)['policy_target_group']
        pc = self.create_policy_classifier()['policy_classifier']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']],
            classifier_id=pc['id'])['servicechain_instance']
        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node)

        self.assertIsNone(ctx.management)

        self.delete_policy_target_group(management['id'],
                                        is_admin_context=True)
        shared_management = self.create_policy_target_group(
            service_management=True, tenant_id='admin',
            is_admin_context=True, shared=True)['policy_target_group']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']],
            classifier_id=pc['id'])['servicechain_instance']
        # Now admin Service Management PTG is visible
        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node)
        self.assertEqual(shared_management['id'], ctx.management['id'])

        # Private management overrides shared one
        private_management = self.create_policy_target_group(
            service_management=True,
            is_admin_context=True)['policy_target_group']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']],
            classifier_id=pc['id'])['servicechain_instance']
        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node)
        self.assertEqual(private_management['id'], ctx.management['id'])


class AgnosticChainPlumberTestCase(NodeCompositionPluginTestCase):

    def setUp(self):
        cfg.CONF.set_override('policy_drivers', ['implicit_policy',
                                                 'resource_mapping'],
                              group='group_policy')
        cfg.CONF.set_override('allow_overlapping_ips', True)

        super(AgnosticChainPlumberTestCase, self).setUp(
            node_drivers=['node_dummy'], node_plumber='agnostic_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)
        res = mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                         '_check_router_needs_rescheduling').start()
        res.return_value = None
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.driver.get_plumbing_info = mock.Mock()
        self.driver.get_plumbing_info.return_value = {}

    def _create_simple_chain(self):
        node = self._create_profiled_servicechain_node(
            service_type="LOADBALANCER",
            config=self.DEFAULT_LB_CONFIG)['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']

        action = self.create_policy_action(
            action_type='REDIRECT', action_value=spec['id'])['policy_action']
        classifier = self.create_policy_classifier(
            direction='bi', port_range=80, protocol='tcp')['policy_classifier']
        rule = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action['id']])['policy_rule']

        prs = self.create_policy_rule_set(
            policy_rules=[rule['id']])['policy_rule_set']

        provider = self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})['policy_target_group']
        consumer = self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})['policy_target_group']

        return provider, consumer, node

    def test_one_pt_prov_cons(self):
        context = n_context.get_admin_context()
        self.driver.get_plumbing_info.return_value = {'provider': [{}],
                                                      'consumer': [{}]}
        provider, consumer, node = self._create_simple_chain()

        # Verify Service PT created and correctly placed
        prov_cons = {'provider': provider, 'consumer': consumer}
        targets = model.get_service_targets(context.session)
        self.assertEqual(2, len(targets))
        old_relationship = None
        for target in targets:
            self.assertEqual(node['id'], target.servicechain_node_id)
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            self.assertEqual(prov_cons[target.relationship]['id'],
                             pt['policy_target_group_id'])
            self.assertNotEqual(old_relationship, target.relationship)
            old_relationship = target.relationship

        self.update_policy_target_group(
            provider['id'], provided_policy_rule_sets={})
        # With chain deletion, also the Service PTs are deleted
        new_targets = model.get_service_targets(context.session)
        self.assertEqual(0, len(new_targets))
        for target in targets:
            self.show_policy_target(
                target.policy_target_id, expected_res_status=404)

    def test_pt_override(self):
        context = n_context.get_admin_context()
        test_name = 'test_name'
        self.driver.get_plumbing_info.return_value = {
            'provider': [{'name': test_name}]}
        self._create_simple_chain()
        targets = model.get_service_targets(context.session)
        self.assertEqual(1, len(targets))
        pt = self.show_policy_target(
            targets[0].policy_target_id)['policy_target']
        self.assertEqual(test_name, pt['name'])

    def test_ptg_delete(self):
        self.driver.get_plumbing_info.return_value = {'provider': [{}],
                                                      'consumer': [{}]}
        provider, _, _ = self._create_simple_service_chain()
        # Deleting a PTG will fail because of existing PTs
        res = self.delete_policy_target_group(provider['id'],
                                              expected_res_status=400)
        self.assertEqual('PolicyTargetGroupInUse',
                         res['NeutronError']['type'])

        # Removing the PRSs will make the PTG deletable again
        self.update_policy_target_group(provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
        self.delete_policy_target_group(provider['id'],
                                        expected_res_status=204)


class TestQuotasForServiceChain(test_base.ServiceChainPluginTestCase):

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        return servicechain_plugin

    def setUp(self, core_plugin=None, gp_plugin=None, node_drivers=None,
              node_plumber=None):
        if node_drivers:
            cfg.CONF.set_override('node_drivers', node_drivers,
                                  group='node_composition_plugin')
        cfg.CONF.set_override('node_plumber', node_plumber or 'dummy_plumber',
                              group='node_composition_plugin')
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'resource_mapping'],
                                     group='group_policy')
        super(TestQuotasForServiceChain, self).setUp(
            core_plugin=core_plugin or CORE_PLUGIN,
            gp_plugin=gp_plugin or GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        cfg.CONF.set_override('quota_servicechain_node', 1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_servicechain_spec', 1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_servicechain_instance', 1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_service_profile', 1,
                              group='QUOTAS')

    def tearDown(self):
        cfg.CONF.set_override('quota_servicechain_node', -1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_servicechain_spec', -1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_servicechain_instance', -1,
                              group='QUOTAS')
        cfg.CONF.set_override('quota_service_profile', -1,
                              group='QUOTAS')
        super(TestQuotasForServiceChain, self).tearDown()

    def test_quota_implicit_service_instance(self):
        prof = self.create_service_profile(
            service_type='LOADBALANCER',
            vendor="vendor")['service_profile']

        node1_id = self.create_servicechain_node(
            service_profile_id=prof['id'], config="{}",
            expected_res_status=201)['servicechain_node']['id']

        spec = self.create_servicechain_spec(
            nodes=[node1_id],
            expected_res_status=201)['servicechain_spec']
        action = self.create_policy_action(action_type='REDIRECT',
                                           action_value=spec['id'])
        classifier = self.create_policy_classifier(
            port_range=80, protocol='tcp', direction='bi')
        rule = self.create_policy_rule(
            policy_actions=[action['policy_action']['id']],
            policy_classifier_id=classifier['policy_classifier']['id'])
        prs = self.create_policy_rule_set(
            policy_rules=[rule['policy_rule']['id']])['policy_rule_set']
        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: ''})
        # Second service instance creation should fail now
        # sice service instance quota is 1, resulting in PTG
        # creation error
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_target_group,
                          consumed_policy_rule_sets={prs['id']: ''})
