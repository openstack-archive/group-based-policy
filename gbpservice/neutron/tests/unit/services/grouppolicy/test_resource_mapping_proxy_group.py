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

import neutron.common  # noqa

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_group_proxy_extension as test_gp_ext)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_resource_mapping)


class ResourceMappingProxyGroupGBPTestCase(
        test_resource_mapping.ResourceMappingTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     ['proxy_group'],
                                     group='group_policy')
        super(ResourceMappingProxyGroupGBPTestCase, self).setUp()


class TestProxyGroupRMD(ResourceMappingProxyGroupGBPTestCase,
                        test_gp_ext.ExtensionDriverTestCaseMixin):

    def test_proxy_group_extension(self):
        l3p = self.create_l3_policy(ip_pool='11.0.0.0/8')['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(29, l3p['proxy_subnet_prefix_length'])

        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.assertIsNone(ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])
        self.assertIsNone(ptg['proxy_type'])

        # Verify Default L3P pool mapping on show
        l3p = self.show_l3_policy(l3p['id'])['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(29, l3p['proxy_subnet_prefix_length'])

        l2p2 = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            l2_policy_id=l2p2['id'])['policy_target_group']
        self.assertIsNone(ptg_proxy['proxy_group_id'])
        self.assertEqual(ptg['id'], ptg_proxy['proxied_group_id'])
        self.assertEqual('l3', ptg_proxy['proxy_type'])

        # Verify relationship added
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg_proxy['id'], ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])

        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'])['policy_target']
        self.assertFalse(pt['proxy_gateway'])
        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'],
            proxy_gateway=True)['policy_target']
        self.assertTrue(pt['proxy_gateway'])
        pt = self.show_policy_target(pt['id'])['policy_target']
        self.assertTrue(pt['proxy_gateway'])


class TestPolicyTarget(ResourceMappingProxyGroupGBPTestCase,
                       test_resource_mapping.TestPolicyTarget):
    pass


class TestPolicyTargetGroup(ResourceMappingProxyGroupGBPTestCase,
                            test_resource_mapping.TestPolicyTargetGroup):
    pass


class TestL2Policy(ResourceMappingProxyGroupGBPTestCase,
                   test_resource_mapping.TestL2Policy):
    pass


class TestL3Policy(ResourceMappingProxyGroupGBPTestCase,
                   test_resource_mapping.TestL3Policy):

    def test_implicit_l3p_proxy_pool(self):
        default_proxy_pool = '192.168.0.0/16'
        default_proxy_subnet_prefix_length = 29
        l2p = self.create_l2_policy()['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        self.assertEqual(default_proxy_pool, l3p['proxy_ip_pool'])
        self.assertEqual(default_proxy_subnet_prefix_length,
                         l3p['proxy_subnet_prefix_length'])


class TestPolicyRuleSet(ResourceMappingProxyGroupGBPTestCase,
                        test_resource_mapping.TestPolicyRuleSet):
    pass


class TestPolicyAction(ResourceMappingProxyGroupGBPTestCase,
                       test_resource_mapping.TestPolicyAction):
    pass


class TestPolicyRule(ResourceMappingProxyGroupGBPTestCase,
                     test_resource_mapping.TestPolicyRule):
    pass


class TestExternalSegment(ResourceMappingProxyGroupGBPTestCase,
                          test_resource_mapping.TestExternalSegment):
    pass


class TestExternalPolicy(ResourceMappingProxyGroupGBPTestCase,
                         test_resource_mapping.TestExternalPolicy):
    pass
