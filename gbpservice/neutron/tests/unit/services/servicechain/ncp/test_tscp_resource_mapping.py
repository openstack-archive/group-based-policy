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
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_config import cfg

from gbpservice.neutron.services.grouppolicy import (
    policy_driver_manager as pdm)
from gbpservice.neutron.services.servicechain.plugins.ncp import model
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as base)


GATEWAY = 'gateway'
GATEWAY_HA = 'gateway_ha'
TRANSPARENT = 'transparent'
ENDPOINT = 'endpoint'

info_mapping = {
    GATEWAY: {'plumbing_type': GATEWAY, 'provider': [{}], 'consumer': [{}]},
    GATEWAY_HA: {'plumbing_type': GATEWAY, 'provider': [{}, {}, {}],
                 'consumer': [{}, {}, {}]},
    TRANSPARENT: {'plumbing_type': TRANSPARENT, 'provider': [{}],
                  'consumer': [{}]},
    ENDPOINT: {'plumbing_type': ENDPOINT, 'provider': [{}]},

}
info_mapping['FIREWALL'] = info_mapping[GATEWAY]
info_mapping['FIREWALL_HA'] = info_mapping[GATEWAY_HA]
info_mapping['TRANSPARENT_FIREWALL'] = info_mapping[TRANSPARENT]
info_mapping['LOADBALANCERV2'] = info_mapping[ENDPOINT]


class ResourceMappingStitchingPlumberGBPTestCase(
        test_gp_driver.ResourceMappingTestCase):

    def setUp(self):
        cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        cfg.CONF.set_override('node_plumber', 'stitching_plumber',
                              group='node_composition_plugin')
        ml2_opts = {'mechanism_drivers': ['stitching_gbp'],
                    'extension_drivers': ['qos']}
        host_agents = mock.patch('neutron.plugins.ml2.driver_context.'
                                 'PortContext.host_agents').start()
        host_agents.return_value = [self.agent_conf]
        qos_plugin = 'qos'
        super(ResourceMappingStitchingPlumberGBPTestCase, self).setUp(
            sc_plugin=base.SC_PLUGIN_KLASS, ml2_options=ml2_opts,
            qos_plugin=qos_plugin)

        def get_plumbing_info(context):
            return info_mapping.get(context.current_profile['service_type'])

        self.node_driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.node_driver.get_plumbing_info = get_plumbing_info
        pdm.PolicyDriverManager.get_policy_target_group_status = (
                mock.MagicMock({}))

    @property
    def sc_plugin(self):
        return directory.get_plugin('SERVICECHAIN')


class TestPolicyRuleSet(ResourceMappingStitchingPlumberGBPTestCase,
                        test_gp_driver.TestPolicyRuleSet):
    pass


class TestServiceChain(ResourceMappingStitchingPlumberGBPTestCase,
                       test_gp_driver.TestServiceChain):

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


class TestServiceChainAdminOwner(ResourceMappingStitchingPlumberGBPTestCase,
                                 test_gp_driver.TestServiceChainAdminOwner):

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
        self._create_simple_service_chain(service_type='LOADBALANCERV2')
        targets = model.get_service_targets(context.session)
        self.assertTrue(len(targets) > 0)
        for target in targets:
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            port = self._bind_port_to_host(pt['port_id'], 'host')['port']
            self.assertTrue(port['binding:vif_details']['port_filter'])
            # This change sets hybrid VIF plugging to True by default again
            # https://github.com/openstack/neutron/commit/
            # eca893be5b770c41cfc570dc016a41c30c2cdf23
            self.assertTrue(port['binding:vif_details']['ovs_hybrid_plug'])
