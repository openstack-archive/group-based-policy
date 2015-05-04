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

from neutron.api import extensions
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.plugins.common import constants
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2
from oslo_config import cfg
from oslo_utils import importutils

from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.extensions import servicechain as service_chain
from gbpservice.neutron.services.servicechain.plugins.ncc import (
    context as ncc_context)
from gbpservice.neutron.services.servicechain.plugins.ncc.node_drivers import (
    dummy_driver as dummy_driver)
from gbpservice.neutron.tests.unit import common as cm
from gbpservice.neutron.tests.unit.db.grouppolicy import (
    test_servicechain_db as base)
from gbpservice.neutron.tests.unit.db.grouppolicy import test_group_policy_db


cfg.CONF.import_opt(
    'node_drivers',
    'gbpservice.neutron.services.servicechain.plugins.ncc.config',
    group='node_centric_chain')
SC_PLUGIN_KLASS = (
    "gbpservice.neutron.services.servicechain.plugins.ncc.plugin."
    "NodeCentricChainPlugin")
CORE_PLUGIN = ('gbpservice.neutron.tests.unit.services.grouppolicy.'
               'test_resource_mapping.NoL3NatSGTestPlugin')
GP_PLUGIN_KLASS = (
    "gbpservice.neutron.services.grouppolicy.plugin.GroupPolicyPlugin"
)


class GbpAndChainTestMixin(test_group_policy_db.ApiManagerMixin):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.SERVICECHAIN])
        for k in service_chain.RESOURCE_ATTRIBUTE_MAP.keys())
    resource_prefix_map.update(dict(
        (k, constants.COMMON_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    ))

    fmt = test_group_policy_db.JSON_FORMAT

    def __getattr__(self, item):
        # Verify is an update of a proper GBP object

        def _is_sc_resource(plural):
            return plural in service_chain.RESOURCE_ATTRIBUTE_MAP

        def _is_gbp_resource(plural):
            return plural in gpolicy.RESOURCE_ATTRIBUTE_MAP

        def _is_valid_resource(plural):
            return _is_gbp_resource(plural) or _is_sc_resource(plural)
        # Update Method
        if item.startswith('update_'):
            resource = item[len('update_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def update_wrapper(id, **kwargs):
                    return self._update_resource(id, resource, **kwargs)
                return update_wrapper
        # Show Method
        if item.startswith('show_'):
            resource = item[len('show_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def show_wrapper(id, **kwargs):
                    return self._show_resource(id, plural, **kwargs)
                return show_wrapper
        # Create Method
        if item.startswith('create_'):
            resource = item[len('create_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def create_wrapper(**kwargs):
                    return self._create_resource(resource, **kwargs)
                return create_wrapper
        # Delete Method
        if item.startswith('delete_'):
            resource = item[len('delete_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def delete_wrapper(id, **kwargs):
                    return self._delete_resource(id, plural, **kwargs)
                return delete_wrapper

        raise AttributeError

    def _create_profiled_servicechain_node(
            self, service_type=constants.LOADBALANCER, **kwargs):
        prof = self.create_service_profile(
            service_type=service_type)['service_profile']
        return self.create_servicechain_node(
            service_profile_id=prof['id'], **kwargs)


class TestGroupPolicyPluginGroupResources(base.TestServiceChainResources):

    def setUp(self, core_plugin=None, sc_plugin=None):
        if not sc_plugin:
            sc_plugin = SC_PLUGIN_KLASS
        super(TestGroupPolicyPluginGroupResources, self).setUp(
            core_plugin=core_plugin, sc_plugin=sc_plugin)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)


class GbpAndChainTestCase(GbpAndChainTestMixin,
                          test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, sc_plugin=None,
              service_plugins=None, ext_mgr=None):
        if not service_plugins:
            service_plugins = {'gp_plugin_name': gp_plugin,
                               'sc_plugin_name': sc_plugin}

        super(GbpAndChainTestCase, self).setUp(
            plugin=core_plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )
        self.plugin = importutils.import_object(sc_plugin)
        if not ext_mgr:
            ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        test_policy_file = test_group_policy_db.ETCDIR + "/test-policy.json"
        cfg.CONF.set_override('policy_file', test_policy_file)


class NodeCentricChainPluginTestCase(GbpAndChainTestCase):
    def setUp(self, core_plugin=None, gp_plugin=None, node_drivers=None):
        if node_drivers:
            cfg.CONF.set_override('node_drivers', node_drivers,
                                  group='node_centric_chain')
        super(NodeCentricChainPluginTestCase, self).setUp(
            core_plugin=core_plugin or CORE_PLUGIN,
            gp_plugin=gp_plugin or GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)


class TestNccPluginContext(NodeCentricChainPluginTestCase):

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
        ctx = ncc_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node,
            management_group=management)

        self.assertIsNotNone(ctx.gbp_plugin)
        self.assertIsNotNone(ctx.sc_plugin)
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

        ctx = ncc_context.get_node_driver_context(
            self.plugin, plugin_context, instance, node_used)
        self.assertEqual(ctx.relevant_specs, [spec_used])


class TestNccNodeDriverManager(NodeCentricChainPluginTestCase):

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              dummy_driver.NoopNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)
