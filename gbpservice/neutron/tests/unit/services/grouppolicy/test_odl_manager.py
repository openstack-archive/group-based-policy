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

import requests
import unittest

import mock
from oslo_serialization import jsonutils

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.odl import odl_manager


HOST = 'fake_host'
PORT = 'fake_port'
USERNAME = 'fake_username'
PASSWORD = 'fake_password'
HEADER = {
    'Content-type': 'application/yang.data+json',
    'Accept': 'application/yang.data+json',
}

VALUE = 'fake_value'
TENANT_ID = 'fake_tenant_id'
TENANT = {
    'id': TENANT_ID,
    'value': VALUE
}
ENDPOINT = 'fake_endpoint'
ACTION_NAME = 'fake_action_name'
ACTION = {
    'name': ACTION_NAME,
    'value': VALUE
}
CLASSIFIER_NAME = 'fake_classifier_name'
CLASSIFIER = {
    'name': CLASSIFIER_NAME,
    'value': VALUE
}
L3CTX_ID = 'fake_l3ctx_id'
L3CTX = {
    'id': L3CTX_ID,
    'value': VALUE
}
L2BD_ID = 'fake_l2bd_id'
L2BD = {
    'id': L2BD_ID,
    'value': VALUE
}
L2FD_ID = 'fake_l2bd_id'
L2FD = {
    'id': L2FD_ID,
    'value': VALUE
}
EPG_ID = 'fake_epg_id'
EPG = {
    'id': EPG_ID,
    'value': VALUE
}
SUBNET_ID = 'fake_subnet_id'
SUBNET = {
    'id': SUBNET_ID,
    'value': VALUE
}
CONTRACT_ID = 'fake_contract_id'
CONTRACT = {
    'id': CONTRACT_ID,
    'value': VALUE
}

URL_BASE = ("http://%(host)s:%(port)s/restconf" %
            {'host': HOST, 'port': PORT})
URL_REG_EP = (URL_BASE +
              '/operations/endpoint:register-endpoint')
URL_UNREG_EP = (URL_BASE +
                '/operations/endpoint:unregister-endpoint')
URL_TENANT = (URL_BASE +
              '/config/policy:tenants/policy:tenant/%s' %
              TENANT_ID)
URL_ACTION = (URL_TENANT +
              '/subject-feature-instances/action-instance/%s' %
              ACTION_NAME)
URL_CLASSIFIER = (URL_TENANT +
                  '/subject-feature-instances/classifier-instance/%s' %
                  CLASSIFIER_NAME)
URL_L3CTX = (URL_TENANT + '/l3-context/%s' % L3CTX_ID)
URL_L2BD = (URL_TENANT + '/l2-bridge-domain/%s' % L2BD_ID)
URL_L2FD = (URL_TENANT + '/l2-flood-domain/%s' % L2FD_ID)
URL_EPG = (URL_TENANT + '/policy:endpoint-group/%s' % EPG_ID)
URL_SUBNET = (URL_TENANT + '/subnet/%s' % SUBNET_ID)
URL_CONTRACT = (URL_TENANT + '/policy:contract/%s' % CONTRACT_ID)


class AuthMatcher(object):
    """ A customized class to check if authentication object is matched or not

    AS authentication is passed as an object reference, we cannot test the
    object directly, instead, we check if the correct username and password
    is used
    """

    def __eq__(self, obj):
        return (obj.username == USERNAME and obj.password == PASSWORD)


class DataMatcher(object):
    """ A customized class to check if data is matched or not

    As data is passed as a string for HTTP request in ODL manager, we cannot
    directly test the data object. Instead, we have to convert the data to
    the string in the same format
    """

    def __init__(self, obj):
        self._data = jsonutils.dumps(
            obj,
            indent=4,
            sort_keys=True
        )

    def __eq__(self, obj):
        return (self._data == obj)


class OdlManagerTestCase(unittest.TestCase):
    """ Test case for ODL manager testing

    Set up the testing environment
    """

    def setUp(self):
        config.cfg.CONF.set_override('odl_username',
                                     USERNAME,
                                     group='odl_driver')
        config.cfg.CONF.set_override('odl_password',
                                     PASSWORD,
                                     group='odl_driver')
        config.cfg.CONF.set_override('odl_host',
                                     HOST,
                                     group='odl_driver')
        config.cfg.CONF.set_override('odl_port',
                                     PORT,
                                     group='odl_driver')

        self.manager = odl_manager.OdlManager()

    # test a single HTTP request
    def _test_single_request_operation(
            self,
            http_method,
            tested_method,
            *args,
            **kwargs
    ):
        with mock.patch('requests.request') as mock_request:
            tested_method(*args)
            mock_request.assert_called_once_with(
                http_method,
                **kwargs
            )

    # In some ODL manager operations, ODL manager needs to check if a tenant
    # is existing or not, if not, the ODL manager needs to create the tenant
    # first -- such a scenario needs to be tested with this method
    def _test_multi_request_operations(
            self,
            http_method,
            tested_method,
            *args,
            **kwargs
    ):
        with mock.patch.object(odl_manager.OdlManager,
                               '_is_tenant_created') as mock_is_tenant_created:
            with mock.patch('requests.request') as mock_request:
                mock_is_tenant_created.return_value = True
                tested_method(*args)
                mock_request.assert_called_once_with(
                    http_method,
                    **kwargs
                )

                mock_is_tenant_created.return_value = False
                mock_request.reset_mock()
                tested_method(*args)
                mock_request.assert_any_call(
                    'put',
                    url=URL_TENANT,
                    headers=HEADER,
                    data=DataMatcher({'tenant': {'id': TENANT_ID}}),
                    auth=AuthMatcher()
                )
                mock_request.assert_any_call(
                    http_method,
                    **kwargs
                )

    @mock.patch.object(requests, 'request')
    def test_is_tenant_created(self, mock_request):

        mock_request.return_value = mock.Mock(
            status_code=200
        )
        assert self.manager._is_tenant_created(TENANT_ID)
        mock_request.assert_called_once_with(
            'get',
            url=URL_TENANT,
            headers=HEADER,
            auth=AuthMatcher()
        )

        mock_request.reset_mock()
        mock_request.return_value = mock.Mock(
            status_code=404
        )
        assert not self.manager._is_tenant_created(TENANT_ID)
        mock_request.assert_called_once_with(
            'get',
            url=URL_TENANT,
            headers=HEADER,
            auth=AuthMatcher()
        )

    def test_register_endpoints(self):
        method = getattr(self.manager, 'register_endpoints')
        self._test_single_request_operation(
            'post',
            method,
            [ENDPOINT],
            url=URL_REG_EP,
            headers=HEADER,
            data=DataMatcher({'input': ENDPOINT}),
            auth=AuthMatcher()
        )

    def test_unregister_endpoints(self):
        method = getattr(self.manager, 'unregister_endpoints')
        self._test_single_request_operation(
            'post',
            method,
            [ENDPOINT],
            url=URL_UNREG_EP,
            headers=HEADER,
            data=DataMatcher({'input': ENDPOINT}),
            auth=AuthMatcher()
        )

    def test_create_update_tenant(self):
        method = getattr(self.manager, 'create_update_tenant')
        self._test_single_request_operation(
            'put',
            method,
            TENANT_ID,
            TENANT,
            url=URL_TENANT,
            headers=HEADER,
            data=DataMatcher({'tenant': TENANT}),
            auth=AuthMatcher()
        )

    def test_create_action(self):
        method = getattr(self.manager, 'create_action')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            ACTION,
            url=URL_ACTION,
            headers=HEADER,
            data=DataMatcher({'action-instance': ACTION}),
            auth=AuthMatcher()
        )

    def test_delete_action(self):
        method = getattr(self.manager, 'delete_action')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            ACTION,
            url=URL_ACTION,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_classifier(self):
        method = getattr(self.manager, 'create_classifier')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            CLASSIFIER,
            url=URL_CLASSIFIER,
            headers=HEADER,
            data=DataMatcher({'classifier-instance': CLASSIFIER}),
            auth=AuthMatcher()
        )

    def test_delete_classifier(self):
        method = getattr(self.manager, 'delete_classifier')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            CLASSIFIER,
            url=URL_CLASSIFIER,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_l3_context(self):
        method = getattr(self.manager, 'create_update_l3_context')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            L3CTX,
            url=URL_L3CTX,
            headers=HEADER,
            data=DataMatcher({'l3-context': L3CTX}),
            auth=AuthMatcher()
        )

    def test_delete_l3_context(self):
        method = getattr(self.manager, 'delete_l3_context')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            L3CTX,
            url=URL_L3CTX,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_l2_bridge_domain(self):
        method = getattr(self.manager, 'create_update_l2_bridge_domain')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            L2BD,
            url=URL_L2BD,
            headers=HEADER,
            data=DataMatcher({'l2-bridge-domain': L2BD}),
            auth=AuthMatcher()
        )

    def test_delete_l2_bridge_domain(self):
        method = getattr(self.manager, 'delete_l2_bridge_domain')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            L2BD,
            url=URL_L2BD,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_l2_flood_domain(self):
        method = getattr(self.manager, 'create_update_l2_flood_domain')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            L2FD,
            url=URL_L2FD,
            headers=HEADER,
            data=DataMatcher({'l2-flood-domain': L2FD}),
            auth=AuthMatcher()
        )

    def test_delete_l2_flood_domain(self):
        method = getattr(self.manager, 'delete_l2_flood_domain')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            L2FD,
            url=URL_L2FD,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_endpoint_group(self):
        method = getattr(self.manager, 'create_update_endpoint_group')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            EPG,
            url=URL_EPG,
            headers=HEADER,
            data=DataMatcher({'endpoint-group': EPG}),
            auth=AuthMatcher()
        )

    def test_delete_endpoint_group(self):
        method = getattr(self.manager, 'delete_endpoint_group')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            EPG,
            url=URL_EPG,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_subnet(self):
        method = getattr(self.manager, 'create_update_subnet')
        self._test_multi_request_operations(
            'put',
            method,
            TENANT_ID,
            SUBNET,
            url=URL_SUBNET,
            headers=HEADER,
            data=DataMatcher({'subnet': SUBNET}),
            auth=AuthMatcher()
        )

    def test_delete_subnet(self):
        method = getattr(self.manager, 'delete_subnet')
        self._test_single_request_operation(
            'delete',
            method,
            TENANT_ID,
            SUBNET,
            url=URL_SUBNET,
            headers=HEADER,
            data=None,
            auth=AuthMatcher()
        )

    def test_create_update_contract(self):
        method = getattr(self.manager, 'create_update_contract')
        self._test_single_request_operation(
            'put',
            method,
            TENANT_ID,
            CONTRACT,
            url=URL_CONTRACT,
            headers=HEADER,
            data=DataMatcher({'contract': CONTRACT}),
            auth=AuthMatcher()
        )
