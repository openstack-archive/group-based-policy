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

import mock
from neutron.common import config  # noqa
from neutron.common import exceptions as n_exc
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import model_base
from neutron import manager
from neutron.plugins.common import constants as pconst
from oslo_config import cfg
from oslo_serialization import jsonutils

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db  # noqa
from gbpservice.neutron.services.grouppolicy import config as gpconfig  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ncp_context)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
import gbpservice.neutron.services.servicechain.plugins.ncp.config  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    dummy_driver as dummy_driver)
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

    def setUp(self, core_plugin=None, gp_plugin=None, node_drivers=None):
        if node_drivers:
            cfg.CONF.set_override('node_drivers', node_drivers,
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
        prof = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']

        node_ids = []
        for x in xrange(number_of_nodes):
            node_ids.append(self.create_servicechain_node(
                service_profile_id=prof['id'],
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

    def test_spec_ordering_list_servicechain_instances(self):
        pass

    def test_context_attributes(self):
        # Verify Context attributes for simple config
        plugin_context = n_context.get_admin_context()
        profile = self.create_service_profile(
            service_type="TYPE")['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'], config='{}')['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        management = self.create_policy_target_group()['policy_target_group']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']])['servicechain_instance']

        # Verify created without errors
        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node,
            management_group=management)

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
            service_type="TYPE", config='{}')['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']

        provider = self.create_policy_target_group()['policy_target_group']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
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

        # Verify param names is empty
        self.assertIsNone(spec['config_param_names'])

        # Update the spec removing one node
        self.update_servicechain_spec(spec['id'], nodes=[node1['id']],
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

        prof = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']

        node_id = self.create_servicechain_node(
            service_profile_id=prof['id'],
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
        prof = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']

        node_id = self.create_servicechain_node(
            service_profile_id=prof['id'],
            expected_res_status=201)['servicechain_node']['id']

        spec = self.create_servicechain_spec(
            nodes=[node_id],
            expected_res_status=201)['servicechain_spec']
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
        profile = self.create_service_profile(
            service_type="TYPE")['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'], config='{}')['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']], expected_res_status=201)

    def test_chain_fails_if_no_drivers_available(self):
        self._add_node_driver('test')
        drivers = [x.obj for x in
                   self.sc_plugin.driver_manager.ordered_drivers]
        create_1 = drivers[0].validate_create = mock.Mock()
        create_1.side_effect = n_exc.NeutronException()
        create_2 = drivers[1].validate_create = mock.Mock()
        create_2.side_effect = n_exc.NeutronException()

        profile = self.create_service_profile(
            service_type="TYPE")['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=profile['id'], config='{}')['servicechain_node']
        spec = self.create_servicechain_spec(
            nodes=[node['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        consumer = self.create_policy_target_group()['policy_target_group']
        self.create_servicechain_instance(
            provider_ptg_id=provider['id'], consumer_ptg_id=consumer['id'],
            servicechain_specs=[spec['id']], expected_res_status=400)

    def test_multiple_nodes_update(self):
        update = self.driver.update = mock.Mock()
        prof = self.create_service_profile(
            service_type='LOADBALANCER')['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'], config='{}')['servicechain_node']

        self._create_chain_with_nodes([node['id']])
        self.update_servicechain_node(node['id'], name='somethingelse')
        self.assertEqual(1, update.call_count)

        update.reset_mock()
        self._create_chain_with_nodes([node['id']])
        self._create_chain_with_nodes([node['id']])
        self.update_servicechain_node(node['id'], name='somethingelse')
        self.assertEqual(3, update.call_count)