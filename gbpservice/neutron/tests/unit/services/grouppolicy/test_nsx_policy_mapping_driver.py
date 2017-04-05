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

from neutron.db import api as db_api
from neutron_lib.db import model_base
from oslo_config import cfg
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
        self.set_up_config()
        self.set_up_mocks()

        super(NsxPolicyMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'nsx_policy'])
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

        self.driver = self._gbp_plugin.policy_driver_manager.policy_drivers[
               'nsx_policy'].obj
        self.policy_api = self.driver.policy_api

    def tearDown(self):
        super(NsxPolicyMappingTestCase, self).tearDown()

    def set_up_config(self):
        cfg.CONF.register_opts(driver.policy_opts, driver.DRIVER_OPT_GROUP)
        cfg.CONF.register_opts(driver.nsx_opts, driver.NSX_V3_GROUP)
        cfg.CONF.set_override('nsx_policy_manager', '1.1.1.1',
                              driver.DRIVER_OPT_GROUP)
        cfg.CONF.set_override('nsx_api_managers', '1.1.1.1',
                              driver.NSX_V3_GROUP)

    def set_up_mocks(self):
        mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()

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
            self._compare_policy_def(expected_def2, actual_def)


class TestPolicyClassifier(NsxPolicyMappingTestCase):

    def test_policy_classifier_create_first(self):
        # Create first classifier within tenant
        # Should trigger domain generation on backend
        with mock.patch.object(self.policy_api, 'get',
                               side_effect=nsxlib_exc.ResourceNotFound),\
            mock.patch.object(self.policy_api,
                              'create') as domain_create_call,\
            mock.patch.object(self.policy_api,
                              'create_with_parent') as service_create_call:
            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi',
                                          tenant_id=TEST_PROJECT)

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
        with mock.patch.object(self.policy_api, 'get',
                               return_value=GET_RESPONSE_DOMAIN_EXISTS),\
            mock.patch.object(self.policy_api,
                              'create_with_parent') as service_create_call:
            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi',
                                          tenant_id=TEST_PROJECT)
            # verify API call to create the service
            classifier_def = policy_defs.ServiceDef()
            entry_def = policy_defs.L4ServiceEntryDef(
                    protocol=policy_constants.TCP,
                    dest_ports=['80'])

            self.assert_api_call(service_create_call,
                                 classifier_def, entry_def)


class TestPolicyTargetGroup(NsxPolicyMappingTestCase):

    def test_policy_target_group_create(self):
        with mock.patch.object(self.policy_api, 'create') as api_call:
            rule = self._create_simple_policy_rule()
            policy_rule_set = self.create_policy_rule_set(
                    name='test', policy_rules=[rule['id']])['policy_rule_set']

            provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs(
                    policy_rule_set['id'])

            api_call.assert_called()

        # TODO(annak): verify neutron objects and mock calls


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    def test_policy_rule_set_create_bidirectional(self):
        with mock.patch.object(self.policy_api, 'create') as api_calls:
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
