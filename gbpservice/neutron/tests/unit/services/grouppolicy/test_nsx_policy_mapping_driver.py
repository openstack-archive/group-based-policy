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
import webob.exc

from neutron.db import api as db_api
from neutron_lib.db import model_base
from oslo_config import cfg
from vmware_nsx.common import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs

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
        self.policy_api = self.driver.policy_api
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
        return mock.patch.object(self.policy_api, 'get',
                                 return_value=GET_RESPONSE_DOMAIN_EXISTS)

    def _mock_missing_domain(self):
        return mock.patch.object(self.policy_api, 'get',
                                 side_effect=nsxlib_exc.ResourceNotFound)

    def _mock_policy_create(self):
        return mock.patch.object(self.policy_api, 'create')

    def _mock_policy_create_with_parent(self):
        return mock.patch.object(self.policy_api, 'create_with_parent')

    def _mock_policy_create_fails(self):
        return mock.patch.object(self.policy_api, 'create',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_create_with_parent_fails(self):
        return mock.patch.object(self.policy_api, 'create_with_parent',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_delete(self):
        return mock.patch.object(self.policy_api, 'delete')

    def _compare_policy_def(self, expected_def, actual_def):
        self.assertEqual(expected_def.__class__, actual_def.__class__)
        self.assertEqual(expected_def.tenant, actual_def.tenant)
        expected_dict = expected_def.get_obj_dict()
        actual_dict = actual_def.get_obj_dict()
        for key in expected_dict.keys():
            if expected_dict[key]:
                self.assertEqual(expected_dict[key], actual_dict[key])

    def assert_api_call(self, api_call, expected_def1, expected_def2=None,
                        call_number=0):
        api_call.assert_called()
        actual_def = api_call.call_args_list[call_number][0][0]
        self._compare_policy_def(expected_def1, actual_def)

        if expected_def2:
            actual_def = api_call.call_args_list[call_number][0][1]
            if isinstance(expected_def2, list):
                self.assertIsInstance(actual_def, list)
                for index, entry in enumerate(expected_def2):
                    self._compare_policy_def(entry, actual_def[index])
            else:
                self._compare_policy_def(expected_def2, actual_def)


class TestPolicyClassifier(NsxPolicyMappingTestCase):

    def test_policy_classifier_create_first(self):
        # Create first classifier within tenant
        # Should trigger domain generation on backend
        with self._mock_missing_domain(),\
            self._mock_policy_create() as domain_create_call,\
            self._mock_policy_create_with_parent() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi')

            # verify API call to create domain to represent the tenant
            domain_def = policy_defs.DomainDef(TEST_PROJECT)
            self.assert_api_call(domain_create_call, domain_def)

            # verify API call to create service
            classifier_def = policy_defs.ServiceDef()
            entry_def = policy_defs.L4ServiceEntryDef(
                    protocol=policy_constants.TCP,
                    dest_ports=['80'])

            self.assert_api_call(service_create_call,
                                 classifier_def, entry_def)

    def test_policy_classifier_create_non_first(self):
        # Create non-first classifier within tenant
        # Should not trigger domain generation on backend
        with self._mock_existing_domain(),\
            self._mock_policy_create_with_parent() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi')
            # verify API call to create the service
            classifier_def = policy_defs.ServiceDef()
            entry_def = policy_defs.L4ServiceEntryDef(
                    protocol=policy_constants.TCP,
                    dest_ports=['80'])

            self.assert_api_call(service_create_call,
                                 classifier_def, entry_def)


class TestPolicyTargetGroup(NsxPolicyMappingTestCase):

    def _prepare_rule_set(self):
        with self._mock_existing_domain(),\
             mock.patch.object(self.policy_api, 'create'),\
             mock.patch.object(self.policy_api, 'create_with_parent'):

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

    def test_policy_group_create_with_single_rule(self):
        '''Create consumer and producer group pair with single rule.

        Verify backend group and rule creation calls.
        Verify spawned neutron resources.
        '''

        policy_rule_set = self._prepare_rule_set()

        with self._mock_existing_domain(),\
            self._mock_policy_create() as group_create,\
            self._mock_policy_create_with_parent() as map_create:

            provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs(
                    policy_rule_set['id'])

            # validate group creation on backend
            group1_def = policy_defs.GroupDef(TEST_PROJECT, name='ptg1')
            group2_def = policy_defs.GroupDef(TEST_PROJECT, name='ptg2')

            self.assert_api_call(group_create, group1_def, call_number=0)
            self.assert_api_call(group_create, group2_def, call_number=1)

            # validate communication map creation on backend
            parent = policy_defs.CommunicationMapDef(TEST_PROJECT)
            entries = []
            entries.append(policy_defs.CommunicationMapEntryDef(
                TEST_PROJECT,
                profile_id=driver.in_name(policy_rule_set['id']),
                source_groups=[consumer_ptg],
                dest_groups=[provider_ptg]))

            entries.append(policy_defs.CommunicationMapEntryDef(
                TEST_PROJECT,
                profile_id=driver.out_name(policy_rule_set['id']),
                source_groups=[provider_ptg],
                dest_groups=[consumer_ptg]))

            self.assert_api_call(map_create, parent, entries)

            self.assert_neutron_resources(2, 2, 2)

    def test_policy_group_create_fail_isolated(self):
        '''Verify integrity when backend fails on isolated group creation.

        Verify backend receives a group delete call.
        Verify spawned neutron resources are cleaned up.
        '''

        policy_rule_set = self._prepare_rule_set()

        with self._mock_existing_domain(),\
            self._mock_policy_create_fails(),\
            self._mock_policy_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            self.assert_api_call(group_delete, policy_defs.GroupDef())
            self.assert_neutron_rollback()

    def test_policy_group_create_fail_connected(self):
        '''Verify integrity when backend fails on connectivity map creation

        This test creates a pair of groups. First group creation succeeds,
        while second fails on connectivity enforcement.
        Verify backend receives a group delete call for second group.
        Verify spawned neutron resources are cleaned up for second group.
        '''

        policy_rule_set = self._prepare_rule_set()

        with self._mock_existing_domain(),\
            self._mock_policy_create(),\
            self._mock_policy_create_with_parent_fails(),\
            self._mock_policy_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_once()
            self.assert_api_call(group_delete, policy_defs.GroupDef())

            self.assert_neutron_resources(1, 1, 1)


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    def test_policy_rule_set_create_bidirectional(self):
        with self._mock_policy_create() as api_calls:

            rule = self._create_simple_policy_rule()
            self.create_policy_rule_set(name='test',
                                        policy_rules=[rule['id']])

            profile = policy_defs.CommunicationProfileDef()
            entry = policy_defs.CommunicationProfileEntryDef(
                    services=[rule['policy_classifier_id']])

            # we expect 4 create calls:
            # for contract and contract entry for each direction
            for i in (0, 1):
                self.assert_api_call(api_calls, profile, call_number=i * 2)
                self.assert_api_call(api_calls, entry, call_number=i * 2 + 1)
