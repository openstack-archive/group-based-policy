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

from gbpservice.nfp.lib import transport
import mock
from neutron.common import rpc as n_rpc
from neutron_lib import context as ctx
from oslo_config import cfg
from oslo_serialization import jsonutils
import six
import unittest2

"""
Common class used to create configuration mapping
"""


class Map(dict):

    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in six.iteritems(arg):
                    self[k] = v

        if kwargs:
            for k, v in six.iteritems(kwargs):
                self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]


class TestContext(object):

    def get_context(self):
        try:
            context = ctx.Context(user_id='some_user',
                    tenant_id='some_tenant', is_advsvc=True)
        except Exception:
            context = ctx.Context(user_id='admin',
                    tenant_id='admin', is_advsvc=True, is_admin=True)
        return context

    def get_test_context(self):
        # creating a test context
        variables = {}
        variables['context'] = self.get_context()
        variables['body'] = {'info': {'context': {}},
                             'config': []}
        variables['method_type'] = 'CREATE'
        variables['device_config'] = True
        return variables


class CommonLibraryTest(unittest2.TestCase):

    def setUp(self):
        n_rpc.init(cfg.CONF)
        self.imprt_rc = 'gbpservice.nfp.lib.rest_client_over_unix'

    def _cast(self, context, method, **kwargs):
        return

    def _call(self, context, method, **kwargs):
        return []

    def _get(self, path):

        class MockResponse(object):

            def __init__(self):
                self.content = {'success': '200'}
        return MockResponse()

    def _uget(self, path):
        return(200, "")

    def _post(self, path, body, method_type):
        return (200, "")

    def _upost(self, path, body, delete=False):
        return (200, "")

    def test_rpc_send_request_to_configurator(self):

        with mock.patch('oslo_messaging.rpc.client._CallContext.cast') as cast:
            cast.side_effect = self._cast

            test_context = TestContext().get_test_context()
            conf = Map(backend='rpc', RPC=Map(topic='topic'))

            transport.send_request_to_configurator(
                conf,
                test_context['context'],
                test_context['body'],
                test_context['method_type'],
                test_context['device_config'])

    def test_tcp_rest_send_request_to_configurator(self):

        with mock.patch.object(transport.RestApi, 'post') as mock_post:
            mock_post.side_effect = self._post

            test_context = TestContext().get_test_context()
            conf = Map(backend='tcp_rest', RPC=Map(topic='topic'),
                       REST=Map(rest_server_ip='0.0.0.0',
                                rest_server_port=5672))

            transport.send_request_to_configurator(
                conf,
                test_context['context'],
                test_context['body'],
                test_context['method_type'],
                test_context['device_config'])

    def test_unix_rest_send_request_to_configurator(self):

        with mock.patch(self.imprt_rc + '.post') as mock_post:
            mock_post.side_effect = self._upost

            test_context = TestContext().get_test_context()
            conf = Map(backend='unix_rest')

            transport.send_request_to_configurator(
                conf,
                test_context['context'],
                test_context['body'],
                test_context['method_type'],
                test_context['device_config'])

    def test_tcp_rest_get_response_from_configurator(self):

        with mock.patch.object(transport.RestApi, 'get') as (
            mock_get), mock.patch.object(jsonutils, 'loads') as (
            mock_loads):
            mock_get.side_effect = self._get
            mock_loads.return_value = True

            conf = Map(backend='tcp_rest', RPC=Map(topic='topic'),
                       REST=Map(rest_server_ip='0.0.0.0',
                                rest_server_port=5672))

            transport.get_response_from_configurator(conf)

    def test_unix_rest_get_response_from_configurator(self):

        with mock.patch(self.imprt_rc + '.get') as (
            mock_get), mock.patch.object(jsonutils, 'loads') as (
            mock_loads):
            mock_get.side_effect = self._uget
            mock_loads.return_value = True

            conf = Map(backend='unix_rest')

            transport.get_response_from_configurator(conf)

if __name__ == '__main__':
    unittest2.main()
