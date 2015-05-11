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
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import model_base
from neutron import manager
from neutron.plugins.common import constants as pconst
from oslo_config import cfg

from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ncp_context)
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

    def setUp(self, core_plugin=None, gp_plugin=None, node_drivers=None,
              node_plumber=None):
        if node_drivers:
            cfg.CONF.set_override('node_drivers', node_drivers,
                                  group='node_composition_plugin')
        cfg.CONF.set_override('node_plumber', node_plumber or 'dummy_plumber',
                              group='node_composition_plugin')
        super(NodeCompositionPluginTestCase, self).setUp(
            core_plugin=core_plugin or CORE_PLUGIN,
            gp_plugin=gp_plugin or GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

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
        node = self._create_profiled_servicechain_node(
            service_type="TYPE", config='{}')['servicechain_node']
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
        self.assertIsNotNone(ctx.plugin_context)
        self.assertIsNotNone(ctx.plugin_session)
        self.assertIsNotNone(ctx.session)
        self.assertIsNotNone(ctx.admin_context)
        self.assertIsNotNone(ctx.admin_session)
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


class AngnosticChainPlumberTestCase(NodeCompositionPluginTestCase):

    def setUp(self):
        cfg.CONF.set_override('policy_drivers', ['implicit_policy',
                                                 'resource_mapping'],
                              group='group_policy')
        cfg.CONF.set_override('allow_overlapping_ips', True)

        super(AngnosticChainPlumberTestCase, self).setUp(
            node_drivers=['node_dummy'], node_plumber='agnostic_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)
        res = mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                         '_check_router_needs_rescheduling').start()
        res.return_value = None
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.driver.get_plumbing_info = mock.Mock()
        self.driver.get_plumbing_info.return_value = {}

    def _create_simple_chain(self):
        node = self._create_profiled_servicechain_node()['servicechain_node']
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