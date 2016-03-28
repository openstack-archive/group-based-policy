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

import ast
import unittest

import oslo_serialization.jsonutils as jsonutils
import pecan
from pecan import rest
import webtest

from gbpservice.nfp.base_configurator.api import root_controller

ERROR = 'error'
UNHANDLED = 'unhandled'
FAILURE = 'failure'

"""This class contains  unittest cases for REST server of configurator.

This class tests success and failure cases for all the HTTP requests which
are implemented in REST server. run_tests.sh file is used for running all
the tests in this class. All the methods of this class started with test
prefix called and on success it will print ok and on failure it will
print the error trace.

"""


class ControllerTestCase(unittest.TestCase, rest.RestController):

    def setUp(self):
        """Standard method of TestCase to setup environment before each test.

        This method set the value of required variables that is used in
        test cases before execution of each test case.


        """
        RootController = root_controller.RootController()
        self.app = webtest.TestApp(pecan.make_app(RootController))
        self.data = {'info': {'service_type': 'firewall',
                              'service_vendor': '',
                              'context': {'foo': 'foo'}},
                     'config': [{'resource': 'heat',
                                 'resource_data': {'some_data': 'some_value'}}]
                     }
        self.data_error = {'info': {'service_type': 'firewall',
                                    'service_vendor': '',
                                    'context': {'foo': 'foo'}},
                           'config': [{'resource': 'non-heat',
                                       'resource_data': {
                                            'some_data': 'some_value'}}]
                           }

    def post_create_network_function_config_with_heat(self):
        """Tests HTTP post request create_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/create_network_function_config',
                jsonutils.dumps(self.data))
        self.assertEqual(response.status_code, 204)

    def post_create_network_function_config_with_others(self):
        """Tests HTTP post request create_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/create_network_function_config',
                jsonutils.dumps(self.data_error))
        self.assertEqual(response.status_code, 204)

    def post_delete_network_function_config_with_heat(self):
        """Tests HTTP post request delete_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                jsonutils.dumps(self.data))
        self.assertEqual(response.status_code, 204)

    def post_delete_network_function_config_with_others(self):
        """Tests HTTP post request delete_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                jsonutils.dumps(self.data_error))
        self.assertEqual(response.status_code, 204)

    def test_get_notifications(self):
        """Tests HTTP get request get_notifications.

        Returns: none

        """
        config_data = self.data['config'][0]
        info_data = self.data['info']
        service_type = info_data['service_type']
        notification_context = self.data['info']['context']
        resource = config_data['resource']
        response_unhandled = {'info': {'service_type': service_type,
                                       'context': notification_context},
                              'notification': [{
                                        'resource': resource,
                                        'data': {
                                            'status_code': UNHANDLED}}]
                              }
        response_error = {'info': {'service_type': service_type,
                                   'context': notification_context},
                          'notification': [{
                                    'resource': 'non-heat',
                                    'data': {
                                        'status_code': FAILURE,
                                        'error_msg': (
                                            'Unsupported resource type')}}]
                          }
        self.post_create_network_function_config_with_heat()
        self.post_delete_network_function_config_with_heat()
        self.post_create_network_function_config_with_others()
        self.post_delete_network_function_config_with_others()
        response = self.app.get(
                '/v1/nfp/get_notifications')
        response_expected = ast.literal_eval(response.text)
        self.assertEqual(response_expected[0], response_unhandled)
        self.assertEqual(response_expected[1], response_unhandled)
        self.assertEqual(response_expected[2], response_error)
        self.assertEqual(response_expected[3], response_error)
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
