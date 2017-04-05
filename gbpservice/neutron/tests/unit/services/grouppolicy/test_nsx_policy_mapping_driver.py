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
from mock import call
import webob.exc

from neutron.db import api as db_api
from neutron_lib.db import model_base
from oslo_config import cfg
from vmware_nsx.common import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

from gbpservice.neutron.services.grouppolicy.\
     drivers.vmware.nsx_policy import nsx_policy_mapping as driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)


TEST_PROJECT = 'test-project'

GET_RESPONSE_EMPTY = {}
GET_RESPONSE_DOMAIN_EXISTS = {'id': TEST_PROJECT}


class NsxPolicyMappingTestCase(test_rmd.ResourceMappingTestCase):

    def setUp(self):
        self.set_up_mocks()
        self.set_up_config()

        super(NsxPolicyMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'nsx_policy'])
        # REVISIT (annak): currently run with ML2 plugin
        # core_plugin='vmware_nsx.plugin.NsxV3Plugin'

        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

        self.driver = self._gbp_plugin.policy_driver_manager.policy_drivers[
               'nsx_policy'].obj
        self.nsx_policy = self.driver.nsx_policy
        self._tenant_id = TEST_PROJECT

    def tearDown(self):
        super(NsxPolicyMappingTestCase, self).tearDown()

    def set_up_config(self):
        cfg.CONF.register_opts(driver.policy_opts, driver.DRIVER_OPT_GROUP)
        cfg.CONF.register_opts(config.nsx_v3_opts, group="nsx_v3")
        cfg.CONF.set_override('nsx_policy_manager', '1.1.1.1',
                              driver.DRIVER_OPT_GROUP)
        cfg.CONF.set_override('nsx_api_managers', '1.1.1.1',
                              driver.NSX_V3_GROUP)

    def set_up_mocks(self):
        mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()

    def _mock_existing_domain(self):
        return mock.patch.object(self.nsx_policy.domain, 'get',
                                 return_value=GET_RESPONSE_DOMAIN_EXISTS)

    def _mock_missing_domain(self):
        return mock.patch.object(self.nsx_policy.domain, 'get',
                                 side_effect=nsxlib_exc.ResourceNotFound)

    def _mock_domain_create(self):
        return mock.patch.object(self.nsx_policy.domain, 'create')

    def _mock_service_create(self):
        return mock.patch.object(self.nsx_policy.service, 'create')

    def _mock_profile_create(self):
        return mock.patch.object(self.nsx_policy.comm_profile, 'create')

    def _mock_profile_list(self, profile_ids):
        return mock.patch.object(self.nsx_policy.comm_profile, 'list',
                                 return_value=[{'id': p}
                                               for p in profile_ids])

    def _mock_group_create(self):
        return mock.patch.object(self.nsx_policy.group, 'create')

    def _mock_group_create_fails(self):
        return mock.patch.object(self.nsx_policy.group, 'create',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_group_delete(self):
        return mock.patch.object(self.nsx_policy.group, 'delete')

    def _mock_map_update(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'update')

    def _mock_map_update_fails(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'update',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_create_fails(self):
        return mock.patch.object(self.policy_api, 'create',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_create_with_parent_fails(self):
        return mock.patch.object(self.policy_api, 'create_with_parent',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_delete(self):
        return mock.patch.object(self.policy_api, 'delete')


class TestPolicyClassifier(NsxPolicyMappingTestCase):

    def test_policy_classifier_create_first(self):
        # Create first classifier within tenant
        # Should trigger domain generation on backend
        with self._mock_missing_domain(),\
            self._mock_domain_create() as domain_create_call,\
            self._mock_service_create() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi')

            # verify API call to create domain to represent the tenant
            domain_create_call.assert_called_with(domain_id=self._tenant_id)

            # verify API call to create service
            service_create_call.assert_called_with(
                name='test',
                description=mock.ANY,
                protocol='tcp',
                dest_ports=['80'],
                service_id=mock.ANY)

    def test_policy_classifier_create_non_first(self):
        # Create non-first classifier within tenant
        # Should not trigger domain generation on backend
        with self._mock_existing_domain(),\
            self._mock_service_create() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi')

            # verify API call to create the service
            service_create_call.assert_called_with(
                name='test',
                description=mock.ANY,
                protocol='tcp',
                dest_ports=['80'],
                service_id=mock.ANY)


class TestPolicyTargetGroup(NsxPolicyMappingTestCase):

    def _prepare_rule_set(self):
        with self._mock_existing_domain(),\
             self._mock_service_create(),\
             self._mock_profile_create():

            rule = self._create_simple_policy_rule()
            return self.create_policy_rule_set(
                    name='test', policy_rules=[rule['id']])['policy_rule_set']

    def assert_neutron_resources(self, net_count, subnet_count, port_count):
        networks = self._plugin.get_networks(self._context)
        self.assertEqual(net_count, len(networks))

        subnets = self._plugin.get_subnets(self._context)
        self.assertEqual(subnet_count, len(subnets))

        ports = self._plugin.get_ports(self._context)
        self.assertEqual(port_count, len(ports))

    def assert_neutron_rollback(self):
        self.assert_neutron_resources(0, 0, 0)

    def _test_policy_group_create_with_single_rule(self,
                                                   direction_in=True,
                                                   direction_out=True):
        '''Create consumer and producer group pair with single rule.

        Verify backend group and rule creation calls.
        Verify spawned neutron resources.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_in = driver.in_name(policy_rule_set['id'])
        profile_out = driver.out_name(policy_rule_set['id'])
        profile_ids = []
        if direction_in:
            profile_ids.append(profile_in)
        if direction_out:
            profile_ids.append(profile_out)

        with self._mock_existing_domain(),\
            self._mock_group_create() as group_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_map_update() as map_create:

            provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs(
                    policy_rule_set['id'])

            # validate group creation on backend
            calls = [call(domain_id=TEST_PROJECT,
                          name='ptg1',
                          description=mock.ANY,
                          cond_val=provider_ptg,
                          group_id=provider_ptg),
                     call(domain_id=TEST_PROJECT,
                          name='ptg2',
                          description=mock.ANY,
                          cond_val=consumer_ptg,
                          group_id=consumer_ptg)]
            group_create.assert_has_calls(calls)

            # validate communication map creation on backend
            calls = []
            if direction_in:
                calls.append(call(
                    domain_id=TEST_PROJECT,
                    profile_id=driver.in_name(policy_rule_set['id']),
                    map_id=mock.ANY,
                    description=mock.ANY,
                    source_groups=[consumer_ptg],
                    dest_groups=[provider_ptg]))

            if direction_out:
                calls.append(call(
                    domain_id=TEST_PROJECT,
                    profile_id=driver.out_name(policy_rule_set['id']),
                    map_id=mock.ANY,
                    description=mock.ANY,
                    source_groups=[provider_ptg],
                    dest_groups=[consumer_ptg]))

            map_create.assert_has_calls(calls)

            # validate neutron resources
            self.assert_neutron_resources(2, 2, 2)

    def test_policy_group_create_with_single_rule_in(self):
        self._test_policy_group_create_with_single_rule(True, False)

    def test_policy_group_create_with_single_rule_out(self):
        self._test_policy_group_create_with_single_rule(False, True)

    def test_policy_group_create_with_single_rule_bi(self):
        self._test_policy_group_create_with_single_rule(True, True)

    def test_policy_group_create_fail_isolated(self):
        '''Verify integrity when backend fails on isolated group creation.

        Verify backend receives a group delete call.
        Verify spawned neutron resources are cleaned up.
        '''

        policy_rule_set = self._prepare_rule_set()

        with self._mock_existing_domain(),\
            self._mock_group_create_fails(),\
            self._mock_group_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_with(self._tenant_id,
                                            mock.ANY)

            self.assert_neutron_rollback()

    def test_policy_group_create_fail_connected(self):
        '''Verify integrity when backend fails on connectivity map creation

        This test creates a pair of groups. First group creation succeeds,
        while second fails on connectivity enforcement.
        Verify backend receives a group delete call for second group.
        Verify spawned neutron resources are cleaned up for second group.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_ids = [driver.in_name(policy_rule_set['id']),
                       driver.out_name(policy_rule_set['id'])]

        with self._mock_existing_domain(),\
            self._mock_group_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_map_update_fails(),\
            self._mock_group_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_once()
            group_delete.assert_called_with(self._tenant_id, mock.ANY)

            self.assert_neutron_resources(1, 1, 1)


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    def test_policy_rule_set_create_bidirectional(self):
        with self._mock_profile_create() as profile_create:

            rule = self._create_simple_policy_rule()
            rule_set = self.create_policy_rule_set(
                name='test', policy_rules=[rule['id']])['policy_rule_set']

            calls = [call(name=driver.in_name('test'),
                          description=mock.ANY,
                          profile_id=driver.in_name(rule_set['id']),
                          services=[rule['policy_classifier_id']]),
                     call(name=driver.out_name('test'),
                          description=mock.ANY,
                          profile_id=driver.out_name(rule_set['id']),
                          services=[rule['policy_classifier_id']])]

            profile_create.assert_has_calls(calls)
