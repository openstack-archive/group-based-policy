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

import heatclient
import mock
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
import webob

from gbpservice.neutron.services.servicechain.plugins.ncp import config
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    openstack_heat_api_client as heatClient)
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    template_node_driver as template_node_driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as test_ncp_plugin)


STACK_ACTION_WAIT_TIME = 15


class MockStackObject(object):
    def __init__(self, status):
        self.stack_status = status


class MockHeatClientFunctionsDeleteNotFound(object):
    def delete(self, stack_id):
        raise heatclient.exc.HTTPNotFound()

    def create(self, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}

    def get(self, stack_id):
        return MockStackObject('DELETE_COMPLETE')


class MockHeatClientFunctions(object):
    def delete(self, stack_id):
        pass

    def create(self, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}

    def get(self, stack_id):
        return MockStackObject('DELETE_COMPLETE')


class MockHeatClientDeleteNotFound(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctionsDeleteNotFound()


class MockHeatClient(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctions()


class TemplateNodeDriverTestCase(
        test_ncp_plugin.NodeCompositionPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('stack_action_wait_time',
                                     STACK_ACTION_WAIT_TIME,
                                     group='servicechain')
        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClient).start()
        super(TemplateNodeDriverTestCase, self).setUp(
            node_drivers=['template_node_driver'],
            node_plumber='agnostic_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              template_node_driver.TemplateNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)


class TestServiceChainInstance(TemplateNodeDriverTestCase):

    def test_invalid_service_type_rejected(self):
        node_used = self._create_profiled_servicechain_node(
            service_type="test", config='{}')['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        res = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
            servicechain_specs=[spec_used['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NoDriverAvailableForAction',
                         res['NeutronError']['type'])

    def test_chain_node_create_success(self):
        res = self._create_profiled_servicechain_node(
                    service_type=constants.FIREWALL, config='{}',
                    expected_res_status=webob.exc.HTTPCreated.code)
        self.assertEqual('{}', res['servicechain_node']['config'])

    def test_chain_node_create_success_service_type(self):
        res = self.create_servicechain_node(
            service_type=constants.FIREWALL, config='{}',
            expected_res_status=webob.exc.HTTPCreated.code)
        self.assertEqual('{}', res['servicechain_node']['config'])

    def test_node_create(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            self._create_simple_service_chain()
            expected_stack_name = mock.ANY
            stack_create.assert_called_once_with(
                                    expected_stack_name, mock.ANY, mock.ANY)

    def test_node_update(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prof = self.create_service_profile(
                            service_type='LOADBALANCER')['service_profile']

            node = self.create_servicechain_node(
                            service_profile_id=prof['id'],
                            expected_res_status=201)['servicechain_node']

            self._create_chain_with_nodes(node_ids=[node['id']])
            with mock.patch.object(heatClient.HeatClient,
                                   'update') as stack_update:
                self.update_servicechain_node(
                                        node['id'],
                                        name='newname',
                                        #config="{}",
                                        expected_res_status=200)
                stack_update.assert_called_once_with(
                                    mock.ANY, mock.ANY, mock.ANY)

    def test_node_delete(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            provider, _, _ = self._create_simple_service_chain()
            with mock.patch.object(heatClient.HeatClient,
                                   'delete'):
                self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)

    def test_wait_stack_delete_for_instance_delete(self):

        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            provider, _, _ = self._create_simple_service_chain()

            # Verify that as part of delete service chain instance we call
            # get method for heat stack 5 times before giving up if the state
            # does not become DELETE_COMPLETE
            with mock.patch.object(heatClient.HeatClient,
                                   'delete') as stack_delete:
                with mock.patch.object(heatClient.HeatClient,
                                       'get') as stack_get:
                    stack_get.return_value = MockStackObject('PENDING_DELETE')
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)
                    stack_delete.assert_called_once_with(mock.ANY)
                    self.assertEqual(STACK_ACTION_WAIT_TIME / 5,
                                     stack_get.call_count)

            # Create and delete another service chain instance and verify that
            # we call get method for heat stack only once if the stack state
            # is DELETE_COMPLETE
            provider, _, _ = self._create_simple_service_chain()
            with mock.patch.object(heatClient.HeatClient,
                                   'delete') as stack_delete:
                with mock.patch.object(heatClient.HeatClient,
                                       'get') as stack_get:
                    stack_get.return_value = MockStackObject(
                        'DELETE_COMPLETE')
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)
                    stack_delete.assert_called_once_with(mock.ANY)
                    self.assertEqual(1, stack_get.call_count)

    def test_stack_not_found_ignored(self):
        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClientDeleteNotFound).start()

        provider, _, _ = self._create_simple_service_chain()

        # Removing the PRSs will make the PTG deletable again
        self.update_policy_target_group(provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
        self.delete_policy_target_group(provider['id'],
                                        expected_res_status=204)
