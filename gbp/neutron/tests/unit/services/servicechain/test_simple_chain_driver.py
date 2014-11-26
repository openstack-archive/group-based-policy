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
import mock
from neutron.openstack.common import uuidutils
import webob

from gbp.neutron.services.servicechain import config
import gbp.neutron.services.servicechain.drivers.simplechain_driver as\
                                                simplechain_driver
from gbp.neutron.tests.unit.services.servicechain import \
                                    test_servicechain_plugin


class SimpleChainDriverTestCase(
        test_servicechain_plugin.ServiceChainPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('servicechain_drivers',
                                     ['simplechain_driver'],
                                     group='servicechain')
        super(SimpleChainDriverTestCase, self).setUp()


class TestServiceChainInstance(SimpleChainDriverTestCase):

    def test_chain_spec_update(self):
        name = "scs1"
        scn = self.create_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        name = "scs2"
        scn2 = self.create_servicechain_node()
        scn2_id = scn2['servicechain_node']['id']
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
            sc_instance1 = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_spec=sc_spec_id)
            self.assertEqual(
                sc_instance1['servicechain_instance']['servicechain_spec'],
                sc_spec_id)
            expected_create_calls.append(
                                mock.call(mock.ANY, mock.ANY, mock.ANY))
            stack_create.return_value = stack2
            sc_instance2 = self.create_servicechain_instance(
                                        name="sc_instance_2",
                                        servicechain_spec=sc_spec_id)
            self.assertEqual(
                sc_instance2['servicechain_instance']['servicechain_spec'],
                sc_spec_id)
            expected_create_calls.append(
                                mock.call(mock.ANY, mock.ANY, mock.ANY))

            #Now perform an update of the spec
            new_spec = {'servicechain_spec': {'nodes': [scn2_id]}}
            stack_create.return_value = stack3
            req = self.new_update_request(
                        'servicechain_specs', new_spec, sc_spec_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
            # The two existing stacks will be deleted and two new stacks
            # will be created
            expected_delete_calls.append(mock.call(stack1['stack']['id']))
            expected_delete_calls.append(mock.call(stack2['stack']['id']))
            expected_create_calls.append(
                                mock.call(mock.ANY, mock.ANY, mock.ANY))
            expected_create_calls.append(
                                mock.call(mock.ANY, mock.ANY, mock.ANY))
            self.assertEqual(expected_delete_calls,
                             stack_delete.call_args_list)
            self.assertEqual(expected_create_calls,
                             stack_create.call_args_list)

    def test_chain_instance_create(self):
        name = "scs1"
        scn = self.create_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        with mock.patch.object(simplechain_driver.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_spec=sc_spec_id)
            self.assertEqual(
                sc_instance['servicechain_instance']['servicechain_spec'],
                sc_spec_id)
            stack_create.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)

    def test_chain_instance_delete(self):
        name = "scs1"
        scn = self.create_servicechain_node()
        scn_id = scn['servicechain_node']['id']
        scs = self.create_servicechain_spec(name=name, nodes=[scn_id])
        sc_spec_id = scs['servicechain_spec']['id']

        with mock.patch.object(simplechain_driver.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            sc_instance = self.create_servicechain_instance(
                                        name="sc_instance_1",
                                        servicechain_spec=sc_spec_id)
            self.assertEqual(
                sc_instance['servicechain_instance']['servicechain_spec'],
                sc_spec_id)
            with mock.patch.object(simplechain_driver.HeatClient,
                                   'delete'):
                req = self.new_delete_request(
                                    'servicechain_instances',
                                    sc_instance['servicechain_instance']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
