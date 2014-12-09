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
                                        servicechain_spec=[sc_spec_id])
            self.assertEqual(
                sc_instance['servicechain_instance']['servicechain_spec'],
                [sc_spec_id])
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
                                        servicechain_spec=[sc_spec_id])
            self.assertEqual(
                sc_instance['servicechain_instance']['servicechain_spec'],
                [sc_spec_id])
            with mock.patch.object(simplechain_driver.HeatClient,
                                   'delete'):
                req = self.new_delete_request(
                                    'servicechain_instances',
                                    sc_instance['servicechain_instance']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
