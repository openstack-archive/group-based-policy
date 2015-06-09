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

from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import model_base
from oslo.config import cfg

from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ncp_context)
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
                                  group='node_composition_chain')
        super(NodeCompositionPluginTestCase, self).setUp(
            core_plugin=core_plugin or CORE_PLUGIN,
            gp_plugin=gp_plugin or GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

    def test_node_shared(self):
        pass

    def test_profile_shared(self):
        pass

    def test_spec_shared(self):
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
        self.assertEqual(ctx.instance, instance)
        self.assertEqual(ctx.provider, provider)
        self.assertEqual(ctx.consumer, consumer)
        self.assertEqual(ctx.management, management)
        self.assertEqual(ctx.management, management)
        self.assertEqual(ctx.relevant_specs, [spec])
        del ctx.current_profile['nodes']
        self.assertEqual(ctx.current_profile, profile)
        self.assertIsNone(ctx.original_node)
        self.assertIsNone(ctx.service_targets)

    def test_context_relevant_specs(self):
        plugin_context = n_context.get_admin_context()
        node_used = self._create_profiled_servicechain_node(
            service_type="TYPE", config='{}')['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']

        node_unused = self._create_profiled_servicechain_node(
            service_type="TYPE", config='{}')['servicechain_node']
        spec_unused = self.create_servicechain_spec(
            nodes=[node_unused['id']])['servicechain_spec']

        provider = self.create_policy_target_group()['policy_target_group']
        instance = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
            servicechain_specs=[spec_used['id'],
                                spec_unused['id']])['servicechain_instance']
        self.assertEqual(len(instance['servicechain_specs']), 2)

        ctx = ncp_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node_used)
        self.assertEqual(ctx.relevant_specs, [spec_used])


class TestNcpNodeDriverManager(NodeCompositionPluginTestCase):

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              dummy_driver.NoopNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)
