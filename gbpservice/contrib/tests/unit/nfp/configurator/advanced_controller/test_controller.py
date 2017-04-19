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
import os
import oslo_serialization.jsonutils as jsonutils
import pecan
import pika
PECAN_CONFIG_FILE = (os.getcwd() +
                     "/gbpservice/nfp/pecan/api/config.py")

pecan.set_config(PECAN_CONFIG_FILE, overwrite=True)

import webtest
import zlib

from neutron.tests import base
from pecan import rest

from gbpservice.nfp.pecan import constants

setattr(pecan, 'mode', constants.advanced)

from gbpservice.contrib.nfp.configurator.advanced_controller import controller
from gbpservice.nfp.pecan.api import root_controller
reload(root_controller)
pika.BlockingConnection = mock.MagicMock(return_value=None)


class ControllerTestCase(base.BaseTestCase, rest.RestController):
    """
    This class contains all the unittest cases for REST server of configurator.

    This class tests success and failure cases for all the HTTP requests which
    are implemented in REST server. run_tests.sh file is used for running all
    the tests in this class. All the methods of this class started with test
    prefix called and on success it will print ok and on failure it will
    print the error trace.

    """
    @classmethod
    def setUpClass(cls):
        """A class method called before tests in an individual class run

        """
        rootController = root_controller.RootController()
        ControllerTestCase.app = webtest.TestApp(
                                            pecan.make_app(rootController))
        ControllerTestCase.data = {'info': {'service_type': 'firewall',
                                            'service_vendor': 'vyos',
                                            'context': {}},
                                   'config': [{'resource': 'firewall',
                                               'resource_data': {}}]
                                   }

    def test_get_notifications(self):
        """Tests HTTP get request get_notifications.

        Returns: none

        """
        with mock.patch.object(
                controller.RMQConsumer, 'pull_notifications') as mock_pn:
            response = self.app.get('/v1/nfp/get_notifications')
        mock_pn.assert_called_with()
        self.assertEqual(response.status_code, 200)

    def test_post_create_network_function_device_config(self):
        """Tests HTTP post request create_network_function_device_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.post(
                '/v1/nfp/create_network_function_device_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'create_network_function_device_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_post_create_network_function_config(self):
        """Tests HTTP post request create_network_function_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.post(
                '/v1/nfp/create_network_function_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'create_network_function_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_post_delete_network_function_device_config(self):
        """Tests HTTP post request delete_network_function_device_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.post(
                '/v1/nfp/delete_network_function_device_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'delete_network_function_device_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_post_delete_network_function_config(self):
        """Tests HTTP post request delete_network_function_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'delete_network_function_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_put_update_network_function_device_config(self):
        """Tests HTTP put request update_network_function_device_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.put(
                '/v1/nfp/update_network_function_device_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'update_network_function_device_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_put_update_network_function_config(self):
        """Tests HTTP put request update_network_function_config.

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            response = self.app.put(
                '/v1/nfp/update_network_function_config',
                zlib.compress(jsonutils.dumps(self.data)),
                content_type='application/octet-stream')
        rpc_mock.assert_called_with(
            'update_network_function_config', self.data)
        self.assertEqual(response.status_code, 200)

    def test_post_create_network_function_device_config_fail(self):
        """Tests failure case of HTTP post request
        create_network_function_device_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/create_network_function_device_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)

    def test_post_create_network_function_config_fail(self):
        """Tests failure case of HTTP post request
        create_network_function_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/create_network_function_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)

    def test_post_delete_network_function_device_config_fail(self):
        """Tests failure case of HTTP post request
        delete_network_function_device_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/delete_network_function_device_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)

    def test_post_delete_network_function_config_fail(self):
        """Tests failure case of HTTP post request
        delete_network_function_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/delete_network_function_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)

    def test_put_update_network_function_device_config_fail(self):
        """Tests failure case of HTTP put request
        update_network_function_device_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/update_network_function_device_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)

    def test_put_update_network_function_config_fail(self):
        """Tests failure case of HTTP put request
        update_network_function_config

        Returns: none

        """

        with mock.patch.object(
                controller.RPCClient, 'cast') as rpc_mock:
            rpc_mock.return_value = Exception
            response = self.app.post(
                '/v1/nfp/update_network_function_config',
                expect_errors=True)
            self.assertEqual(response.status_code, 400)
