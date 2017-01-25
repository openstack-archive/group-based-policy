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

from neutron.tests import base
import oslo_serialization.jsonutils as jsonutils
import pecan
from pecan import rest
import webtest
import zlib

from gbpservice.nfp.pecan import constants

setattr(pecan, 'mode', constants.base)


ERROR = 'error'
UNHANDLED = 'unhandled'
FAILURE = 'failure'


class ControllerTestCase(base.BaseTestCase, rest.RestController):

    """This class contains  unittest cases for REST server of configurator.

    This class tests success and failure cases for all the HTTP requests which
    are implemented in REST server. run_tests.sh file is used for running all
    the tests in this class. All the methods of this class started with test
    prefix called and on success it will print ok and on failure it will
    print the error trace.

    """

    def setUp(self):
        """Standard method of TestCase to setup environment before each test.

        This method set the value of required variables that is used in
        test cases before execution of each test case.
        """
        super(ControllerTestCase, self).setUp()
        from gbpservice.nfp.pecan.api import root_controller
        reload(root_controller)
        RootController = root_controller.RootController()
        self.app = webtest.TestApp(pecan.make_app(RootController))
        self.data = {'info': {'service_type': 'firewall',
                              'service_vendor': '',
                              'context': {'foo': 'foo'}},
                     'config': [{'resource': 'heat',
                                 'resource_data': {'some_data': 'some_value'}}]
                     }
        self.data_non_heat = {'info': {'service_type': 'firewall',
                                       'service_vendor': '',
                                       'context': {'foo': 'foo'}},
                              'config': [{'resource': 'non-heat',
                                          'resource_data': {
                                                'some_data': 'some_value'}}]
                              }

    def post_create_network_function_config_with_heat(self,
            operation='create'):
        """Tests HTTP post request create_network_function_device_config.

        Returns: none

        """

        self.data['info']['context']['operation'] = operation
        response = self.app.post(
                '/v1/nfp/create_network_function_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

    def post_create_network_function_config_with_others(self,
            operation='create'):
        """Tests HTTP post request create_network_function_device_config.

        Returns: none

        """

        self.data_non_heat['info']['context']['operation'] = operation
        response = self.app.post(
                '/v1/nfp/create_network_function_config',
                zlib.compress(jsonutils.dumps(self.data_non_heat)),
                content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

    def post_delete_network_function_config_with_heat(self,
            operation='delete'):
        """Tests HTTP post request delete_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

    def post_delete_network_function_config_with_others(self,
            operation='delete'):
        """Tests HTTP post request delete_network_function_device_config.

        Returns: none

        """

        response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                zlib.compress(jsonutils.dumps(self.data_non_heat)),
                content_type='application/octet-stream')
        self.assertEqual(response.status_code, 200)

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
        self.post_create_network_function_config_with_heat(operation='create')
        self.post_delete_network_function_config_with_heat(operation='delete')
        self.post_create_network_function_config_with_others(
                operation='create')
        self.post_delete_network_function_config_with_others(
                operation='delete')
        response = self.app.get(
                '/v1/nfp/get_notifications')
        response_str = zlib.decompress(response.body)
        response_expected = ast.literal_eval(response_str)
        self.assertEqual(response_expected[0], response_unhandled)
        self.assertEqual(response_expected[1], response_unhandled)
        self.assertEqual(response_expected[2], response_error)
        self.assertEqual(response_expected[3], response_error)
        self.assertEqual(response.status_code, 200)
