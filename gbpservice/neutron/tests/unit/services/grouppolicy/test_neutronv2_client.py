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
#

import mock
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron_lib import context
from neutronclient.common import exceptions
from neutronclient.v2_0 import client
from oslo_config import cfg

from gbpservice.network.neutronv2 import client as neutronclient


CONF = cfg.CONF

# NOTE: Neutron client raises Exception which is discouraged by HACKING.
#       We set this variable here and use it for assertions below to avoid
#       the hacking checks until we can make neutron client throw a custom
#       exception class instead.
NEUTRON_CLIENT_EXCEPTION = Exception


class TestNeutronClient(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(TestNeutronClient, self).setUp()

    def test_withtoken(self):
        CONF.set_override('neutron_server_url',
                          'http://anyhost',
                          group='neutron')
        CONF.set_override('url_timeout',
                          30,
                          group='neutron')
        my_context = context.ContextBase('userid',
                                         'my_tenantid',
                                         auth_token='token')
        cl = neutronclient.get_client(my_context)

        self.assertEqual(CONF.neutron.neutron_server_url,
                         cl.httpclient.endpoint_url)
        self.assertEqual(my_context.auth_token,
                         cl.httpclient.auth_token)
        self.assertEqual(CONF.neutron.url_timeout, cl.httpclient.timeout)

    def test_withouttoken(self):
        my_context = context.ContextBase('userid', 'my_tenantid')
        self.assertRaises(exceptions.Unauthorized,
                          neutronclient.get_client,
                          my_context)

    def test_withtoken_context_is_admin(self):
        CONF.set_override('neutron_server_url',
                          'http://anyhost',
                          group='neutron')
        CONF.set_override('url_timeout',
                          30,
                          group='neutron')
        my_context = context.ContextBase('userid',
                                         'my_tenantid',
                                         auth_token='token',
                                         is_admin=True)
        cl = neutronclient.get_client(my_context)

        self.assertEqual(CONF.neutron.neutron_server_url,
                         cl.httpclient.endpoint_url)
        self.assertEqual(my_context.auth_token,
                         cl.httpclient.auth_token)
        self.assertEqual(CONF.neutron.url_timeout, cl.httpclient.timeout)

    def test_withouttoken_keystone_connection_error(self):
        CONF.set_override('neutron_server_url',
                          'http://anyhost',
                          group='neutron')
        CONF.set_override('auth_strategy',
                          'keystone',
                          group='neutron')
        my_context = context.ContextBase('userid', 'my_tenantid')
        self.assertRaises(NEUTRON_CLIENT_EXCEPTION,
                          neutronclient.get_client,
                          my_context)

    def test_reuse_admin_token(self):
        CONF.set_override('neutron_server_url',
                          'http://anyhost',
                          group='neutron')
        CONF.set_override('url_timeout',
                          30,
                          group='neutron')
        token_store = neutronclient.AdminTokenStore.get()
        token_store.admin_auth_token = 'new_token'
        my_context = context.ContextBase('userid', 'my_tenantid',
                                         auth_token='token')
        with mock.patch.object(client.Client, "list_networks",
                               side_effect=mock.Mock):
            with mock.patch.object(client.Client, 'get_auth_info',
                                   return_value={'auth_token': 'new_token1'}):
                client1 = neutronclient.get_client(my_context, True)
                client1.list_networks(retrieve_all=False)
                self.assertEqual('new_token1', token_store.admin_auth_token)
                client1 = neutronclient.get_client(my_context, True)
                client1.list_networks(retrieve_all=False)
                self.assertEqual('new_token1', token_store.admin_auth_token)

    def test_admin_token_updated(self):
        CONF.set_override('neutron_server_url',
                          'http://anyhost',
                          group='neutron')
        CONF.set_override('url_timeout',
                          30,
                          group='neutron')
        token_store = neutronclient.AdminTokenStore.get()
        token_store.admin_auth_token = 'new_token'
        tokens = [{'auth_token': 'new_token1'}, {'auth_token': 'new_token'}]
        my_context = context.ContextBase('userid', 'my_tenantid',
                                         auth_token='token')
        with mock.patch.object(client.Client, "list_networks",
                               side_effect=mock.Mock):
            with mock.patch.object(client.Client, 'get_auth_info',
                                   side_effect=tokens.pop):
                client1 = neutronclient.get_client(my_context, True)
                client1.list_networks(retrieve_all=False)
                self.assertEqual('new_token', token_store.admin_auth_token)
                client1 = neutronclient.get_client(my_context, True)
                client1.list_networks(retrieve_all=False)
                self.assertEqual('new_token1', token_store.admin_auth_token)
