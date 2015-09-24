# Copyright 2014 Alcatel-Lucent USA Inc.
#
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

from gbpservice.neutron.services.grouppolicy.drivers.oneconvergence import (
    nvsd_gbp_api as api)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_resource_mapping)


class MockNVSDApiClient(object):

    def create_endpoint(self, context, endpoint):
        pass

    def update_endpoint(self, context, updated_endpoint):
        pass

    def delete_endpoint(self, context, endpoint_id):
        pass

    def create_endpointgroup(self, context, endpointgroup):
        pass

    def update_endpointgroup(self, context, endpointgroup):
        pass

    def delete_endpointgroup(self, context, endpointgroup_id):
        pass

    def create_policy_classifier(self, context, policy_classifier):
        pass

    def update_policy_classifier(self, context, policy_classifier):
        pass

    def delete_policy_classifier(self, context, policy_classifier_id):
        pass


class OneConvergenceGBPDriverTestCase(
                    test_resource_mapping.ResourceMappingTestCase):

    def setUp(self):
        policy_drivers = ['implicit_policy', 'oneconvergence_gbp_driver',
                          'chain_mapping']
        with mock.patch.object(
                    api, 'NVSDServiceApi',
                    new=MockNVSDApiClient) as self.mockNVSDApi:
            super(OneConvergenceGBPDriverTestCase, self).setUp(
                                            policy_drivers=policy_drivers)


class TestPolicyTarget(OneConvergenceGBPDriverTestCase,
                       test_resource_mapping.TestPolicyTarget):

    # Functionality tests and api results are covered by the base class tests
    def test_oneconvergence_controller_api_invoked(self):
        with mock.patch.object(MockNVSDApiClient,
                               'create_endpoint') as create_ep:
            with mock.patch.object(MockNVSDApiClient,
                                   'update_endpoint') as update_ep:
                with mock.patch.object(MockNVSDApiClient,
                                       'delete_endpoint') as delete_ep:
                    ptg = self.create_policy_target_group(name="ptg1")
                    ptg_id = ptg['policy_target_group']['id']

                    # Create policy_target with implicit port.
                    pt = self.create_policy_target(
                            name="pt1",
                            policy_target_group_id=ptg_id)['policy_target']
                    create_ep.assert_called_once_with(mock.ANY, pt)
                    pt = self.update_policy_target(
                            pt['id'], name="new_pt")['policy_target']
                    update_ep.assert_called_once_with(mock.ANY, pt)
                    self.delete_policy_target(pt['id'])
                    delete_ep.assert_called_once_with(mock.ANY, pt['id'])


class TestPolicyTargetGroup(OneConvergenceGBPDriverTestCase,
                            test_resource_mapping.TestPolicyTargetGroup):

    def test_subnet_allocation(self):
        ptg1 = self.create_policy_target_group(name="ptg1")
        subnet1 = ptg1['policy_target_group']['subnets']
        ptg2 = self.create_policy_target_group(name="ptg2")
        subnet2 = ptg2['policy_target_group']['subnets']
        self.assertEqual(subnet1, subnet2)

    def test_no_extra_subnets_created(self):
        count = len(self._get_all_subnets())
        self.create_policy_target_group()
        self.create_policy_target_group()
        new_count = len(self._get_all_subnets())
        # One Convergence driver shares the same implicit subnet
        self.assertEqual(count + 1, new_count)

    def test_ip_pool_exhaustion(self):
        # One Convergence driver shares the same implicit subnet
        pass

    def test_oneconvergence_controller_api_invoked(self):
        with mock.patch.object(MockNVSDApiClient,
                               'create_endpointgroup') as create_epg:
            with mock.patch.object(MockNVSDApiClient,
                                   'update_endpointgroup') as update_epg:
                with mock.patch.object(MockNVSDApiClient,
                                       'delete_endpointgroup') as delete_epg:
                    ptg = self.create_policy_target_group(
                                    name="ptg1")['policy_target_group']
                    create_epg.assert_called_once_with(mock.ANY, ptg)
                    ptg = self.update_policy_target_group(
                                    ptg['id'],
                                    name="new_ptg")['policy_target_group']
                    update_epg.assert_called_once_with(mock.ANY, ptg)
                    self.delete_policy_target_group(ptg['id'])
                    delete_epg.assert_called_once_with(mock.ANY, ptg['id'])


class TestPolicyClassifier(OneConvergenceGBPDriverTestCase):

    def test_oneconvergence_controller_api_invoked(self):
        with mock.patch.object(
                MockNVSDApiClient,
                'create_policy_classifier') as create_classifier:
            with mock.patch.object(
                    MockNVSDApiClient,
                    'update_policy_classifier') as update_classifier:
                with mock.patch.object(
                        MockNVSDApiClient,
                        'delete_policy_classifier') as delete_classifier:
                    classifier = self.create_policy_classifier(
                        name="classifier1")
                    classifier = classifier['policy_classifier']
                    classifier.update({"policy_rules": []})
                    create_classifier.assert_called_once_with(mock.ANY,
                                                              classifier)
                    classifier = self.update_policy_classifier(
                        classifier['id'],
                        name="new_classifier")['policy_classifier']
                    classifier.update({"policy_rules": []})
                    update_classifier.assert_called_once_with(mock.ANY,
                                                              classifier)
                    self.delete_policy_classifier(classifier['id'])
                    delete_classifier.assert_called_once_with(
                                            mock.ANY, classifier['id'])


class TestL2Policy(OneConvergenceGBPDriverTestCase,
                   test_resource_mapping.TestL2Policy):
    pass


class TestL3Policy(OneConvergenceGBPDriverTestCase,
                   test_resource_mapping.TestL3Policy):
    pass


class TestPolicyRuleSet(OneConvergenceGBPDriverTestCase,
                        test_resource_mapping.TestPolicyRuleSet):
    pass


class TestServiceChain(OneConvergenceGBPDriverTestCase,
                       test_resource_mapping.TestServiceChain):
    pass


class TestServiceChainAdminOwner(
        OneConvergenceGBPDriverTestCase,
        test_resource_mapping.TestServiceChainAdminOwner):
    pass


class TestPolicyAction(OneConvergenceGBPDriverTestCase,
                       test_resource_mapping.TestPolicyAction):
    pass


class TestPolicyRule(OneConvergenceGBPDriverTestCase,
                     test_resource_mapping.TestPolicyRule):
    pass


class TestExternalSegment(OneConvergenceGBPDriverTestCase,
                          test_resource_mapping.TestExternalSegment):
    pass


class TestExternalPolicy(OneConvergenceGBPDriverTestCase,
                         test_resource_mapping.TestExternalPolicy):
    pass
