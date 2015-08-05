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

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_resource_mapping)


class ResourceMappingProxyGroupGBPTestCase(
        test_resource_mapping.ResourceMappingTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     ['proxy_group'],
                                     group='group_policy')
        super(ResourceMappingProxyGroupGBPTestCase, self).setUp()


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
    pass


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
