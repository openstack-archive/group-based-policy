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
import unittest2

from neutronclient.v2_0 import client as clientv20

from gbpservice.network.neutronv2 import api as nc_api
from gbpservice.network.neutronv2 import client as nc_client


ATTRIBUTES = 'fake_attributes'
CONTEXT = 'fake_context'
FILTERS = {'fake_key1': 'fake_value1', 'fake_key2': 'fake_value2'}
ID = 'fake_id'
INTERFACE = 'fake_interface'
VALUE = 'fake_value'


class NeutronV2ApiTestCase(unittest2.TestCase):
    """ Test case for Neutron V2 API testing.

    Provide a set of mocked methods for the neutron v2 API testing.
    """

    def setUp(self):
        self.neutron_api = nc_api.API()
        self.mock_client = mock.Mock(clientv20.Client)

    def _test_create_resource(self, resource):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            action = 'create_' + resource
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client, action)
            mock_client_action.return_value = {resource: VALUE}

            method_to_test = getattr(self.neutron_api, action)
            method_to_test(CONTEXT, ATTRIBUTES)
            mock_client_action.assert_called_once_with(ATTRIBUTES)

    def _test_show_resource(self, resource):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            action = 'show_' + resource
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client, action)
            mock_client_action.return_value = {resource: VALUE}

            method_to_test = getattr(self.neutron_api, action)
            method_to_test(CONTEXT, ID)
            mock_client_action.assert_called_once_with(ID)

    def _test_list_resources(self, resource):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            resources = resource + 's'
            action = 'list_' + resources
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client, action)
            mock_client_action.return_value = {resources: VALUE}

            method_to_test = getattr(self.neutron_api, action)
            method_to_test(CONTEXT, FILTERS)
            mock_client_action.assert_called_once_with(**FILTERS)

    def _test_update_resource(self, resource):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            action = 'update_' + resource
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client, action)
            mock_client_action.return_value = {resource: VALUE}

            method_to_test = getattr(self.neutron_api, action)
            method_to_test(CONTEXT, ID, ATTRIBUTES)
            mock_client_action.assert_called_once_with(ID, ATTRIBUTES)

    def _test_delete_resource(self, resource):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            action = 'delete_' + resource
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client, action)
            mock_client_action.return_value = {resource: VALUE}

            method_to_test = getattr(self.neutron_api, action)
            method_to_test(CONTEXT, ID)
            mock_client_action.assert_called_once_with(ID)

    def _test_router_interface(self, action):
        with mock.patch.object(nc_client, 'get_client') as mock_get_client:
            mock_get_client.return_value = self.mock_client
            mock_client_action = getattr(self.mock_client,
                                         action + '_interface_router')
            mock_client_action.return_value = VALUE

            method_to_test = getattr(self.neutron_api,
                                     action + '_router_interface')
            method_to_test(CONTEXT, ID, INTERFACE)
            mock_client_action.assert_called_once_with(ID, INTERFACE)

    def test_create_network(self):
        self._test_create_resource('network')

    def test_show_network(self):
        self._test_show_resource('network')

    def test_list_networks(self):
        self._test_list_resources('network')

    def test_update_network(self):
        self._test_update_resource('network')

    def test_delete_network(self):
        self._test_delete_resource('network')

    def test_create_subnet(self):
        self._test_create_resource('subnet')

    def test_show_subnet(self):
        self._test_show_resource('subnet')

    def test_list_subnets(self):
        self._test_list_resources('subnet')

    def test_update_subnet(self):
        self._test_update_resource('subnet')

    def test_delete_subnet(self):
        self._test_delete_resource('subnet')

    def test_create_port(self):
        self._test_create_resource('port')

    def test_show_port(self):
        self._test_show_resource('port')

    def test_list_ports(self):
        self._test_list_resources('port')

    def test_update_port(self):
        self._test_update_resource('port')

    def test_delete_port(self):
        self._test_delete_resource('port')

    def test_create_security_group(self):
        self._test_create_resource('security_group')

    def test_show_security_group(self):
        self._test_show_resource('security_group')

    def test_list_security_groups(self):
        self._test_list_resources('security_group')

    def test_update_security_group(self):
        self._test_update_resource('security_group')

    def test_delete_security_group(self):
        self._test_delete_resource('security_group')

    def test_create_security_group_rule(self):
        self._test_create_resource('security_group_rule')

    def test_show_security_group_rule(self):
        self._test_show_resource('security_group_rule')

    def test_list_security_group_rules(self):
        self._test_list_resources('security_group_rule')

    # REVISIT(yi): update_security_group_rule not supported in neutron yet
    # def test_update_security_group_rule(self):
    #     self._test_update_resource('security_group_rule')

    def test_delete_security_group_rule(self):
        self._test_delete_resource('security_group_rule')

    def test_create_router(self):
        self._test_create_resource('router')

    def test_show_router(self):
        self._test_show_resource('router')

    def test_list_routers(self):
        self._test_list_resources('router')

    def test_update_router(self):
        self._test_update_resource('router')

    def test_delete_router(self):
        self._test_delete_resource('router')

    def test_add_router_interface(self):
        self._test_router_interface('add')

    def test_remove_router_interface(self):
        self._test_router_interface('remove')
