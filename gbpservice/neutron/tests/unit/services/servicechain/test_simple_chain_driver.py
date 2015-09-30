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

import contextlib
import heatclient
import mock
from neutron.openstack.common import jsonutils
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
import webob

from gbpservice.neutron.services.servicechain.plugins.msc import config
from gbpservice.neutron.services.servicechain.plugins.msc.drivers import (
    simplechain_driver as simplechain_driver)
from gbpservice.neutron.tests.unit.services.servicechain import (
    test_servicechain_plugin as test_servicechain_plugin)


STACK_DELETE_RETRIES = 5
STACK_DELETE_RETRY_WAIT = 3


class MockStackObject(object):
    def __init__(self, status):
        self.stack_status = status


class MockHeatClientFunctions(object):
    def delete(self, stack_id):
        raise heatclient.exc.HTTPNotFound()

    def create(self, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}

    def get(self, stack_id):
        return MockStackObject('DELETE_COMPLETE')

    def update(self, *args, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}


class MockHeatClient(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctions()


class SimpleChainDriverTestCase(
        test_servicechain_plugin.ServiceChainPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('servicechain_drivers',
                                     ['simplechain_driver'],
                                     group='servicechain')
        config.cfg.CONF.set_override('stack_delete_retries',
                                     STACK_DELETE_RETRIES,
                                     group='simplechain')
        config.cfg.CONF.set_override('stack_delete_retry_wait',
                                     STACK_DELETE_RETRY_WAIT,
                                     group='simplechain')
        super(SimpleChainDriverTestCase, self).setUp()
        key_client = mock.patch(
            'gbpservice.neutron.services.servicechain.plugins.msc.drivers.'
            'simplechain_driver.HeatClient._get_auth_token').start()
        key_client.return_value = 'mysplendidtoken'


class TestServiceChainInstance(SimpleChainDriverTestCase):

    def test_invalid_service_type_rejected(self):
        res = self.create_service_profile(
                    service_type="test",
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('InvalidServiceTypeForReferenceDriver',
                         res['NeutronError']['type'])

    def test_chain_node_create_success(self):
        res = self._create_profiled_servicechain_node(
                    service_type=constants.FIREWALL, config='{}',
                    expected_res_status=webob.exc.HTTPCreated.code)
        self.assertEqual('{}', res['servicechain_node']['config'])

    def test_in_use_node_config_update_rejected(self):
        node = self.create_servicechain_node(
            service_type=constants.FIREWALL, config='{}',
            expected_res_status=webob.exc.HTTPCreated.code)[
                                                'servicechain_node']
        self.assertEqual('{}', node['config'])
        spec = self.create_servicechain_spec(
            nodes=[node['id']],
            expected_res_status=webob.exc.HTTPCreated.code)[
                                                'servicechain_spec']
        with mock.patch.object(simplechain_driver.HeatClient,
                              'create') as stack_create:
            stack_create.return_value = {'stack': {
                                            'id': uuidutils.generate_uuid()}}
            self.create_servicechain_instance(servicechain_specs=[spec['id']])
            res = self.update_servicechain_node(
                    node['id'],
                    config='{"key": "value"}',
                    expected_res_status=webob.exc.HTTPBadRequest.code)
            self.assertEqual('NodeUpdateNotSupported',
                             res['NeutronError']['type'])

    def test_chain_spec_update(self):
        template1 = '{"key1":"value1"}'
        scn = self._create_profiled_servicechain_node(config=template1)
        scn1_name = scn['servicechain_node']['name']
        scn_id = scn['servicechain_node']['id']
        name = "scs1"
        template2 = '{"key2":"value2"}'
        scn2 = self._create_profiled_servicechain_node(config=template2)
        scn2_id = scn2['servicechain_node']['id']
        scn2_name = scn2['servicechain_node']['name']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        stack1 = {'stack': {'id': uuidutils.generate_uuid()}}
        stack2 = {'stack': {'id': uuidutils.generate_uuid()}}
        stack3 = {'stack': {'id': uuidutils.generate_uuid()}}
        expected_create_calls = []
        expected_delete_calls = []
        with contextlib.nested(
            mock.patch.object(simplechain_driver.HeatClient,
                              'create'),
            mock.patch.object(simplechain_driver.HeatClient,
                              'delete'),
        ) as (stack_create, stack_delete):
            stack_create.return_value = stack1
            instance1_name = "sc_instance_1"
            sc_instance1 = self.create_servicechain_instance(
                                        name=instance1_name,
                                        servicechain_specs=[sc_spec_id])
            sci1_id = sc_instance1['servicechain_instance']['id']
            self.assertEqual([sc_spec_id],
                sc_instance1['servicechain_instance'][
                    'servicechain_specs'])
            stack_name = ("stack_" + instance1_name + scn1_name +
                          sci1_id[:8])
            expected_create_calls.append(
                        mock.call(stack_name,
                                  jsonutils.loads(template1), {}))
            stack_create.return_value = stack2
            instance2_name = "sc_instance_2"
            sc_instance2 = self.create_servicechain_instance(
                                        name=instance2_name,
                                        servicechain_specs=[sc_spec_id])
            sci2_id = sc_instance2['servicechain_instance']['id']
            self.assertEqual(
                [sc_spec_id],
                sc_instance2['servicechain_instance'][
                    'servicechain_specs'])
            stack_name = ("stack_" + instance2_name + scn1_name +
                          sci2_id[:8])
            expected_create_calls.append(
                mock.call(stack_name, jsonutils.loads(template1), {}))

            #Now perform an update of the spec
            new_spec = {'servicechain_spec': {'nodes': [scn2_id]}}
            stack_create.return_value = stack3
            req = self.new_update_request(
                        'servicechain_specs', new_spec, sc_spec_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPOk.code, res.status_int)
            # The two existing stacks will be deleted and two new stacks
            # will be created
            expected_delete_calls.append(mock.call(stack1['stack']['id']))
            expected_delete_calls.append(mock.call(stack2['stack']['id']))
            stack_name = ("stack_" + instance1_name + scn2_name +
                          sci1_id[:8])
            expected_create_calls.append(
                mock.call(stack_name, jsonutils.loads(template2), {}))
            stack_name = ("stack_" + instance2_name + scn2_name +
                          sci2_id[:8])
            expected_create_calls.append(
                mock.call(stack_name, jsonutils.loads(template2), {}))
            self.assertEqual(expected_delete_calls,
                             stack_delete.call_args_list)
            self.assertEqual(expected_create_calls,
                             stack_create.call_args_list)

    def test_chain_instance_create(self):
        name = "scs1"
        scn = self._create_profiled_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        with mock.patch.object(simplechain_driver.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_specs=[sc_spec_id])
            expected_stack_name = (
                "stack_" + "sc_instance_1" +
                scn['servicechain_node']['name'] +
                sc_instance['servicechain_instance']['id'][:8])
            self.assertEqual(
                [sc_spec_id],
                sc_instance['servicechain_instance']['servicechain_specs'])
            stack_create.assert_called_once_with(
                                    expected_stack_name, mock.ANY, mock.ANY)

    def test_chain_instance_delete(self):
        name = "scs1"
        scn = self._create_profiled_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        with mock.patch.object(simplechain_driver.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_specs=[sc_spec_id])
            self.assertEqual([sc_spec_id],
                sc_instance['servicechain_instance']['servicechain_specs'])
            with mock.patch.object(simplechain_driver.HeatClient,
                                   'delete'):
                req = self.new_delete_request(
                                    'servicechain_instances',
                                    sc_instance['servicechain_instance']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)

    def test_wait_stack_delete_for_instance_delete(self):
        name = "scs1"
        scn = self._create_profiled_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        with mock.patch.object(simplechain_driver.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_specs=[sc_spec_id])
            self.assertEqual([sc_spec_id],
                sc_instance['servicechain_instance']['servicechain_specs'])

            # Verify that as part of delete service chain instance we call
            # get method for heat stack 5 times before giving up if the state
            # does not become DELETE_COMPLETE
            with contextlib.nested(
                mock.patch.object(simplechain_driver.HeatClient, 'delete'),
                mock.patch.object(simplechain_driver.HeatClient, 'get')) as (
                                                    stack_delete, stack_get):
                stack_get.return_value = MockStackObject('PENDING_DELETE')
                req = self.new_delete_request(
                                    'servicechain_instances',
                                    sc_instance['servicechain_instance']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                stack_delete.assert_called_once_with(mock.ANY)
                self.assertEqual(STACK_DELETE_RETRIES, stack_get.call_count)

            # Create and delete another service chain instance and verify that
            # we call get method for heat stack only once if the stack state
            # is DELETE_COMPLETE
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_specs=[sc_spec_id])
            self.assertEqual([sc_spec_id],
                sc_instance['servicechain_instance']['servicechain_specs'])
            with contextlib.nested(
                mock.patch.object(simplechain_driver.HeatClient, 'delete'),
                mock.patch.object(simplechain_driver.HeatClient, 'get')) as (
                                                    stack_delete, stack_get):
                stack_get.return_value = MockStackObject('DELETE_COMPLETE')
                req = self.new_delete_request(
                                    'servicechain_instances',
                                    sc_instance['servicechain_instance']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
                stack_delete.assert_called_once_with(mock.ANY)
                self.assertEqual(1, stack_get.call_count)

    def test_stack_not_found_ignored(self):
        name = "scs1"
        scn = self._create_profiled_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClient).start()
        sc_instance = self.create_servicechain_instance(
                                    name="sc_instance_1",
                                    servicechain_specs=[sc_spec_id])
        req = self.new_delete_request(
                            'servicechain_instances',
                            sc_instance['servicechain_instance']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
