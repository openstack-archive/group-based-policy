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
import netaddr
from neutron.common import config  # noqa
from neutron import manager
from oslo_config import cfg

from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_apic_mapping as test_apic)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as base)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_tscp_resource_mapping as test_tscp_rmd)


class ApicMappingStitchingPlumberGBPTestCase(
        test_apic.ApicMappingTestCase):

    def setUp(self):
        cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        cfg.CONF.set_override('node_plumber', 'stitching_plumber',
                              group='node_composition_plugin')
        super(ApicMappingStitchingPlumberGBPTestCase, self).setUp(
            sc_plugin=base.SC_PLUGIN_KLASS)

        def get_plumbing_info(context):
            return test_tscp_rmd.info_mapping.get(
                context.current_profile['service_type'])

        self.node_driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.node_driver.get_plumbing_info = get_plumbing_info
        self.mgr = self.driver.apic_manager

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get('SERVICECHAIN')
        return servicechain_plugin


class TestPolicyRuleSet(ApicMappingStitchingPlumberGBPTestCase,
                        test_apic.TestPolicyRuleSet):

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


class TestPolicyRule(ApicMappingStitchingPlumberGBPTestCase,
                     test_apic.TestPolicyRule):
    pass


class TestExternalSegment(ApicMappingStitchingPlumberGBPTestCase,
                          test_apic.TestExternalSegment):
    pass


class TestExternalPolicy(ApicMappingStitchingPlumberGBPTestCase,
                         test_apic.TestExternalPolicy):
    pass


class TestImplicitServiceChains(ApicMappingStitchingPlumberGBPTestCase,
                                base.NodeCompositionPluginTestMixin):
    pass


class TestProxyGroup(ApicMappingStitchingPlumberGBPTestCase):

    def test_proxy_group_same_l2p(self):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        l2p = self.create_l2_policy()['l2_policy']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'],
            l2_policy_id=l2p['id'])['policy_target_group']
        # The used L2P will be ignored, and the proxy will be put on the
        # proxied group's L2P
        self.assertEqual(ptg1['l2_policy_id'], proxy['l2_policy_id'])

    def test_l2_proxy_group_subnets(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            proxy_type='l2')['policy_target_group']
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg['subnets'], proxy['subnets'])
        self.assertEqual(1, len(proxy['subnets']))

    def test_l3_proxy_group_subnets(self):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        original_subnet = ptg1['subnets'][0]
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'],
            proxy_type='l3')['policy_target_group']
        ptg1 = self.show_policy_target_group(ptg1['id'])['policy_target_group']
        self.assertEqual(set(ptg1['subnets']), set(proxy['subnets']))
        self.assertEqual(2, len(proxy['subnets']))
        proxy['subnets'].remove(original_subnet)
        new_subnet = proxy['subnets'][0]

        # Verify subnet from proxy pool
        l2p = self.show_l2_policy(ptg1['l2_policy_id'])['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        subnet = self._get_object('subnets', new_subnet, self.api)['subnet']
        self.assertTrue(netaddr.IPNetwork(subnet['cidr']) in
                        netaddr.IPNetwork(l3p['proxy_ip_pool']))

    def test_proxy_shadow_created(self):
        l2p = self.create_l2_policy()['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.mgr.reset_mock()
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'])['policy_target_group']
        l2p = self.show_l2_policy(ptg['l2_policy_id'])['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        # Shadow BD created
        self.mgr.ensure_bd_created_on_apic.assert_called_once_with(
            ptg['tenant_id'], 'Shd-' + ptg['id'], ctx_owner=l3p['tenant_id'],
            ctx_name=l3p['id'], allow_broadcast=False, unicast_route=False,
            transaction=mock.ANY)
        # Proxied PTG moved
        expected_calls = [
            # Proxy created on L2P
            mock.call(
                ptg['tenant_id'], proxy['id'], bd_owner=l2p['tenant_id'],
                bd_name=l2p['id']),
            # Proxied moved on shadow BD
            mock.call(
                ptg['tenant_id'], ptg['id'], bd_owner=ptg['tenant_id'],
                bd_name='Shd-' + ptg['id'], transaction=mock.ANY)]
        self._check_call_list(expected_calls,
                              self.mgr.ensure_epg_created.call_args_list)

    def test_proxy_shadow_deleted(self):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'])['policy_target_group']
        self.mgr.reset_mock()
        self.delete_policy_target_group(proxy['id'], expected_res_status=204)
        # Proxied PTG moved back
        self.mgr.ensure_epg_created.assert_called_once_with(
            ptg1['tenant_id'], ptg1['id'], bd_owner=ptg1['tenant_id'],
            bd_name=ptg1['l2_policy_id'])
        # Shadow BD deleted
        self.mgr.delete_bd_on_apic.assert_called_once_with(
            ptg1['tenant_id'], 'Shd-' + ptg1['id'])