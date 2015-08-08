#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
from neutron.common import config  # noqa
from neutron import context as n_context
from neutron import manager
from oslo_config import cfg

from gbpservice.neutron.services.servicechain.plugins.ncp import model
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as base)


GATEWAY = 'gateway'
TRANSPARENT = 'transparent'
ENDPOINT = 'endpoint'

info_mapping = {
    GATEWAY: {'plumbing_type': GATEWAY, 'provider': [{}], 'consumer': [{}]},
    TRANSPARENT: {'plumbing_type': TRANSPARENT, 'provider': [{}],
                  'consumer': [{}]},
    ENDPOINT: {'plumbing_type': ENDPOINT, 'provider': [{}]},
}
info_mapping['FIREWALL'] = info_mapping[GATEWAY]
info_mapping['TRANSPARENT_FIREWALL'] = info_mapping[TRANSPARENT]
info_mapping['LOADBALANCER'] = info_mapping[ENDPOINT]


class TrafficStitchingPlumberTestCase(base.NodeCompositionPluginTestCase):

    def setUp(self):
        cfg.CONF.set_override('policy_drivers', ['implicit_policy',
                                                 'resource_mapping'],
                              group='group_policy')
        cfg.CONF.set_override('allow_overlapping_ips', True)
        cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        super(TrafficStitchingPlumberTestCase, self).setUp(
            node_drivers=['node_dummy'], node_plumber='stitching_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)
        res = mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                         '_check_router_needs_rescheduling').start()
        res.return_value = None
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.driver.get_plumbing_info = mock.Mock()
        self.driver.get_plumbing_info.return_value = {}

    def test_one_gateway_pt_prov_cons(self):
        context = n_context.get_admin_context()
        self.driver.get_plumbing_info.return_value = {
            'provider': [{}], 'consumer': [{}], 'plumbing_type': 'gateway'}
        provider, consumer, node = self._create_simple_chain()
        provider = self.show_policy_target_group(
            provider['id'])['policy_target_group']
        # Verify Service PT created and correctly placed
        targets = model.get_service_targets(context.session)
        self.assertEqual(2, len(targets))
        old_relationship = None
        for target in targets:
            self.assertEqual(node['id'], target.servicechain_node_id)
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            if target.relationship == 'provider':
                self.assertEqual(provider['id'],
                                 pt['policy_target_group_id'])
                self.assertTrue(pt['group_default_gateway'])
                self.assertFalse(pt['proxy_gateway'])
            else:
                # Consumer side a proxy group exists
                self.assertEqual(provider['proxy_group_id'],
                                 pt['policy_target_group_id'])
                self.assertFalse(pt['group_default_gateway'])
                self.assertTrue(pt['proxy_gateway'])

            self.assertNotEqual(old_relationship, target.relationship)
            old_relationship = target.relationship
            port = self._get_object('ports', pt['port_id'], self.api)['port']
            self.assertTrue(port['name'].startswith('pt_service_target_'),
                            "Port name doesn't start with 'pt_service_target_"
                            "'.\nport:\n%s\n" % port)

        self.update_policy_target_group(
            provider['id'], provided_policy_rule_sets={})
        # With chain deletion, also the Service PTs are deleted
        new_targets = model.get_service_targets(context.session)
        self.assertEqual(0, len(new_targets))
        for target in targets:
            self.show_policy_target(
                target.policy_target_id, expected_res_status=404)
        provider = self.show_policy_target_group(
            provider['id'])['policy_target_group']
        self.assertIsNone(provider['proxy_group_id'])

    def test_ptg_delete(self):
        self.driver.get_plumbing_info.return_value = {
            'provider': [{}], 'consumer': [{}],
            'plumbing_type': 'transparent'}
        provider, _, _ = self._create_simple_service_chain()
        # Deleting a PTG will fail because of existing PTs
        self.delete_policy_target_group(provider['id'],
                                        expected_res_status=204)


class ResourceMappingStitchingPlumberGBPTestCase(
        test_gp_driver.ResourceMappingTestCase):

    def setUp(self):
        cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        cfg.CONF.set_override('node_plumber', 'stitching_plumber',
                              group='node_composition_plugin')
        ml2_opts = {'mechanism_drivers': ['stitching_gbp']}
        host_agents = mock.patch('neutron.plugins.ml2.driver_context.'
                                 'PortContext.host_agents').start()
        host_agents.return_value = [self.agent_conf]
        super(ResourceMappingStitchingPlumberGBPTestCase, self).setUp(
            sc_plugin=base.SC_PLUGIN_KLASS, ml2_options=ml2_opts)

        def get_plumbing_info(context):
            return info_mapping.get(context.current_profile['service_type'])

        self.node_driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.node_driver.get_plumbing_info = get_plumbing_info

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get('SERVICECHAIN')
        return servicechain_plugin


class TestPolicyRuleSet(ResourceMappingStitchingPlumberGBPTestCase,
                        test_gp_driver.TestPolicyRuleSet):

    def test_parent_ruleset_update_for_redirect(self):
        # NCP doesn't support multiple SPECs per instance
        pass

    def test_enforce_parent_redirect_after_ptg_create(self):
        # NCP doesn't support multiple SPECs per instance
        pass

    def test_hierarchical_redirect(self):
        # NCP doesn't support multiple SPECs per instance
        pass

    def test_redirect_multiple_ptgs_single_prs(self):
        # REVISIT(ivar): This test is doing a mock patching that breaks the
        # workflow
        pass

    def test_action_spec_value_update(self):
        # NCP doesn't support multiple SPECs per instance
        pass

    def test_rule_update_hierarchial_prs(self):
        # NCP doesn't support multiple SPECs per instance
        pass

    def test_rule_update_updates_chain(self):
        # NCP doesn't support multiple SPECs per instance
        pass


class TestPolicyAction(ResourceMappingStitchingPlumberGBPTestCase,
                       test_gp_driver.TestPolicyAction):
    pass


class TestPolicyRule(ResourceMappingStitchingPlumberGBPTestCase,
                     test_gp_driver.TestPolicyRule):
    pass


class TestExternalSegment(ResourceMappingStitchingPlumberGBPTestCase,
                          test_gp_driver.TestExternalSegment):
    def test_update(self):
        super(TestExternalSegment, self).test_update(
            proxy_ip_pool1='182.169.0.0/16',
            proxy_ip_pool2='172.169.0.0/16')


class TestExternalPolicy(ResourceMappingStitchingPlumberGBPTestCase,
                         test_gp_driver.TestExternalPolicy):
    pass


class TestImplicitServiceChains(ResourceMappingStitchingPlumberGBPTestCase,
                                base.NodeCompositionPluginTestMixin):

    def test_service_targets_vif_details(self):
        context = n_context.get_admin_context()
        self._create_simple_service_chain(service_type='TRANSPARENT_FIREWALL')
        targets = model.get_service_targets(context.session)
        self.assertTrue(len(targets) > 0)
        for target in targets:
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            # Being service targets, port filter and hybrid plug will be false
            port = self._bind_port_to_host(pt['port_id'], 'host')['port']
            self.assertFalse(port['binding:vif_details']['port_filter'])
            self.assertFalse(port['binding:vif_details']['ovs_hybrid_plug'])

    def test_endpoint_target_vif_details(self):
        context = n_context.get_admin_context()
        self._create_simple_service_chain(service_type='LOADBALANCER')
        targets = model.get_service_targets(context.session)
        self.assertTrue(len(targets) > 0)
        for target in targets:
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            # Being service targets, port filter and hybrid plug will be false
            port = self._bind_port_to_host(pt['port_id'], 'host')['port']
            self.assertTrue(port['binding:vif_details']['port_filter'])
            self.assertTrue(port['binding:vif_details']['ovs_hybrid_plug'])
