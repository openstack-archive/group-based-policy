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

import requests

import json
import mock

from gbpservice.contrib.nfp.configurator.agents import vpn
from gbpservice.contrib.nfp.configurator.drivers.base import base_driver
from gbpservice.contrib.nfp.configurator.drivers.vpn.vyos import (
    vyos_vpn_driver)
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
    vpn_test_data)

from neutron.tests import base

from oslo_serialization import jsonutils


bdobj = base_driver.BaseDriver('conf')
bdobj.register_agent_object_with_driver(
    'agent',
    vpn.VpnaasRpcSender(vpn_test_data.VPNTestData().sc))


class VpnaasIpsecDriverTestCase(base.BaseTestCase):
    """
    Implements test cases for driver methods
    of vpn.

    """
    def __init__(self, *args, **kwargs):
        super(VpnaasIpsecDriverTestCase, self).__init__(*args, **kwargs)
        self.conf = 'conf'
        self.test_dict = vpn_test_data.VPNTestData()
        self.context = self.test_dict.make_service_context()
        self.headers = self.test_dict.get_header()
        self.plugin_rpc = vpn.VpnaasRpcSender(self.test_dict.sc)
        self.driver = vyos_vpn_driver.VpnaasIpsecDriver(self.conf)
        self.svc_validate = (
            vyos_vpn_driver.VPNServiceValidator(self.plugin_rpc))
        self.resp = mock.Mock()
        self.fake_resp_dict = {'status': True}

    def test_create_vpn_service(self):
        """
        Implements method to test the vpn driver's create vpn service.
        """

        context = self.test_dict.make_service_context(operation_type='vpn')

        kwargs = self.test_dict.make_resource_data(operation='create',
                                                   service_type='vpn')
        with mock.patch.object(bdobj.agent, 'update_status') as (
                mock_update_status):
            self.driver.vpnservice_updated(context, kwargs)
            mock_update_status.assert_called_with(
                self.context,
                self.test_dict.vpn_vpnsvc_active)

    def test_create_ipsec_site_conn(self):
        """
        Implements method to test the vpn driver's create ipsec site conn
        """
        self.resp = mock.Mock(status_code=200)
        context = self.test_dict.make_service_context()
        kwargs = self.test_dict.make_resource_data(operation='create',
                                                   service_type='ipsec')
        with mock.patch.object(
                bdobj.agent, 'update_status') as mock_update_status, (
            mock.patch.object(jsonutils, 'loads')) as mock_resp, (
            mock.patch.object(requests, 'post')) as mock_post, (
            mock.patch.object(
                self.driver.agent, 'get_vpn_servicecontext',
                return_value=[self.test_dict.svc_context])):
            mock_resp.return_value = self.fake_resp_dict
            mock_post.return_value = self.resp
            self.driver.vpnservice_updated(context, kwargs)

            mock_post.assert_called_with(
                self.test_dict.url_create_ipsec_conn,
                data=jsonutils.dumps(self.test_dict.svc_context),
                headers=self.headers,
                timeout=self.test_dict.timeout)
            mock_update_status.assert_called_with(
                context,
                self.test_dict.ipsec_vpnsvc_status)

    def _dict_to_query_str(self, args):
        return '&'.join([str(k) + '=' + str(v) for k, v in args.iteritems()])

    def test_delete_ipsec_site_conn(self):
        """
        Implements method to test the vpn driver's create ipsec site conn
        """

        self.resp = mock.Mock(status_code=200)
        kwargs = self.test_dict.make_resource_data(operation='delete',
                                                   service_type='ipsec')
        with mock.patch.object(self.plugin_rpc, 'ipsec_site_conn_deleted'), (
                mock.patch.object(json, 'loads')) as mock_resp, (
                mock.patch.object(requests, 'delete')) as (
                mock_delete):
            mock_resp.return_value = self.fake_resp_dict
            mock_delete.return_value = self.resp
            self.driver.vpnservice_updated(self.context, kwargs)
            resource = kwargs['resource']
            svc_desc = resource['description']
            tokens = svc_desc.split(';')
            cidr = tokens[1].split('=')[1]

            tunnel = {}
            tunnel['peer_address'] = resource['peer_address']
            tunnel['local_cidr'] = cidr
            tunnel['peer_cidrs'] = resource['peer_cidrs']

            url = self.test_dict.url_delete_ipsec_conn

            mock_delete.assert_called_with(
                url.encode('ascii', 'ignore'),
                timeout=self.test_dict.timeout,
                headers=self.headers,
                data=None)

    def test_check_status(self):
        """
        Implements method to test the vpn driver's check status
        """

        self.resp = mock.Mock(status_code=200)
        svc_context = self.test_dict.svc_context
        with mock.patch.object(self.plugin_rpc, 'update_status'), (
                mock.patch.object(self.resp, 'json')) as mock_json, (
                mock.patch.object(requests, 'get')) as mock_get:
            mock_get.return_value = self.resp
            mock_json.return_value = {'state': 'DOWN'}
            state = self.driver.check_status(self.context, svc_context)
            self.assertEqual(state, None)


class VpnGenericConfigDriverTestCase(base.BaseTestCase):
    """
    Implements test cases for driver methods
    of generic config.

    """
    def __init__(self, *args, **kwargs):
        super(VpnGenericConfigDriverTestCase, self).__init__(*args, **kwargs)
        self.conf = 'conf'
        self.test_dict = vpn_test_data.VPNTestData()
        self.context = self.test_dict.make_service_context()
        self.headers = self.test_dict.get_header()
        self.plugin_rpc = vpn.VpnaasRpcSender(self.test_dict.sc)
        self.rest_apt = vyos_vpn_driver.RestApi(self.test_dict.vm_mgmt_ip)
        self.driver = vyos_vpn_driver.VpnGenericConfigDriver()
        self.resp = mock.Mock()
        self.fake_resp_dict = {'status': True}
        self.kwargs = self.test_dict.fake_resource_data()

    def setUp(self):
        super(VpnGenericConfigDriverTestCase, self).setUp()
        self.resp = mock.Mock(status_code=200)

    def tearDown(self):
        super(VpnGenericConfigDriverTestCase, self).tearDown()
        self.resp = mock.Mock(status_code=200)

    def test_configure_interfaces(self):
        """
        Implements test case for configure interfaces method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(self.resp,
                              'json',
                              return_value=self.fake_resp_dict)):
            self.driver.configure_interfaces(self.test_dict.context_device,
                                             self.kwargs)

            mock_post.assert_called_with(
                self.test_dict.url_for_add_inte,
                jsonutils.dumps(
                    self.test_dict.data_for_interface),
                headers=self.headers,
                timeout=self.test_dict.timeout)

    def test_clear_interfaces(self):
        """
        Implements test case for clear interfaces method
        of generic config driver.

        Returns: none

        """

        self.resp = mock.Mock(status_code=200)
        with mock.patch.object(
                requests, 'delete', return_value=self.resp) as mock_delete, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            self.driver.clear_interfaces(self.test_dict.context_device,
                                         self.kwargs)

            mock_delete.assert_called_with(
                self.test_dict.url_for_del_inte,
                data=jsonutils.dumps(
                    self.test_dict.data_for_interface),
                headers=self.headers,
                timeout=self.test_dict.timeout)

    def test_configure_source_routes(self):
        """
        Implements test case for configure routes method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(jsonutils, 'loads',
                              return_value=self.fake_resp_dict)):
            self.driver.configure_routes(self.test_dict.context_device,
                                         self.kwargs)

            mock_post.assert_called_with(
                self.test_dict.url_for_add_src_route,
                data=jsonutils.dumps(
                    self.test_dict.data_for_add_src_route),
                headers=self.headers,
                timeout=self.test_dict.timeout)

    def test_delete_source_routes(self):
        """
        Implements test case for clear routes method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(requests, 'post', return_value=self.resp), (
            mock.patch.object(
                requests, 'delete', return_value=self.resp)) as mock_delete:
            self.driver.clear_routes(
                self.test_dict.context_device, self.kwargs)

            mock_delete.assert_called_with(
                self.test_dict.url_for_del_src_route,
                data=jsonutils.dumps(
                    self.test_dict.data_for_del_src_route),
                headers=self.headers,
                timeout=self.test_dict.timeout)


class VPNSvcValidatorTestCase(base.BaseTestCase):

    def __init__(self, *args, **kwargs):
        super(VPNSvcValidatorTestCase, self).__init__(*args, **kwargs)
        self.test_dict = vpn_test_data.VPNTestData()
        self.plugin_rpc = vpn.VpnaasRpcSender(self.test_dict.sc)
        self.valid_obj = vyos_vpn_driver.VPNServiceValidator(self.plugin_rpc)

    def test_validate_active(self):
        """
        Implements testcase for vpn driver's validate method to test in
        success condition while making call to the service VM
        """

        context = self.test_dict.make_service_context()
        svc = self.test_dict._create_vpnservice_obj()
        description = str(svc['resource']['description'])
        description = description.split(';')
        description[1] = 'tunnel_local_cidr=12.0.6.0/24'
        description = ";".join(description)
        svc.update({'description': description})

        with mock.patch.object(self.plugin_rpc, "update_status") as mock_valid:
            self.valid_obj.validate(context, svc)
            mock_valid.assert_called_with(context,
                                          self.test_dict.vpn_vpnsvc_active)

    def test_validate_error(self):
        """
        Implements testcase for vpn driver's validate method to test in
        fail condition while making call to the service VM
        """

        context = self.test_dict.make_service_context()
        with mock.patch.object(self.plugin_rpc, "update_status") as mock_valid:
            self.valid_obj.validate(
                context,
                self.test_dict._create_vpnservice_obj())
            mock_valid.assert_called_with(
                context,
                self.test_dict.vpn_vpnsvc_active)


class RestApiTestCase(base.BaseTestCase):
    """
    Class which implements the testcases to test the vpn RestApi calls.
    """

    def __init__(self, *args, **kwargs):
        super(RestApiTestCase, self).__init__(*args, **kwargs)
        self.rest_obj = vyos_vpn_driver.RestApi((
            vpn_test_data.VPNTestData().vm_mgmt_ip))
        self.resp = mock.Mock()
        self.resp = mock.Mock(status_code=200)
        self.test_dict = vpn_test_data.VPNTestData()
        self.headers = self.test_dict.get_header()
        self.args = {'peer_address': '1.103.2.2'}
        self.fake_resp_dict = {'status': None}
        self.timeout = self.rest_obj.timeout
        self.data = {'data': 'data'}
        self.j_data = jsonutils.dumps(self.data)

    def test_post_success(self):
        """
        Implements testcase for vpn drivers post method to test in
        success condition while making call to the service VM
        """

        self.resp = mock.Mock(status_code=200)
        self.fake_resp_dict.update({'status': True})
        with mock.patch.object(requests, 'post', return_value=self.resp) as (
            mock_post), (
            mock.patch.object(jsonutils, 'loads',
                              return_value=self.fake_resp_dict)):
            self.rest_obj.post('create-ipsec-site-conn',
                               self.data, self.headers)
            mock_post.assert_called_with(
                self.test_dict.url_create_ipsec_conn,
                data=self.j_data,
                headers=self.headers,
                timeout=self.timeout)

    def test_put_success(self):
        """
        Implements testcase for vpn drivers put method to test in
        success condition while making call to the service VM
        """

        self.resp = mock.Mock(status_code=200)
        with mock.patch.object(requests, 'put', return_value=self.resp) as (
                mock_put):
            self.rest_obj.put('create-ipsec-site-conn',
                              self.data, self.headers)
            mock_put.assert_called_with(
                self.test_dict.url_create_ipsec_conn,
                data=self.j_data,
                headers=self.headers,
                timeout=self.timeout)

    def test_put_fail(self):
        """
        Implements testcase for vpn drivers put method to test in
        fail condition while making call to the service VM
        """

        self.resp = mock.Mock(status_code=404)
        with mock.patch.object(requests, 'put', return_value=self.resp) as (
                mock_put):

            self.rest_obj.put('create-ipsec-site-conn',
                              self.data, self.headers)
            mock_put.assert_called_with(
                self.test_dict.url_create_ipsec_conn,
                data=jsonutils.dumps(self.data),
                headers=self.headers,
                timeout=self.timeout)

    def test_delete_success(self):
        """
        Implements testcase for vpn drivers delete method to test in
        success condition while making call to the service VM
        """
        self.resp = mock.Mock(status_code=200)
        self.fake_resp_dict.update({'status': True})
        with mock.patch.object(requests, 'delete', return_value=self.resp) as (
            mock_delete), (
            mock.patch.object(jsonutils, 'loads',
                              return_value=self.fake_resp_dict)):
            self.rest_obj.delete('delete-ipsec-site-conn',
                                 self.args,
                                 self.headers)
            mock_delete.assert_called_with(
                self.test_dict.url_delete_ipsec_conn,
                timeout=self.timeout,
                data=None,
                headers=self.headers)

    def test_get_success(self):
        """
        Implements testcase for vpn drivers get methode to test in
        fail condition while making call to the service VM
        """

        self.resp = mock.Mock(status_code=200)
        with mock.patch.object(requests, 'get', return_value=self.resp) as (
                mock_get):
            self.rest_obj.get('create-ipsec-site-tunnel',
                              self.data, self.headers)
            mock_get.assert_called_with(
                self.test_dict.url_create_ipsec_tunnel,
                params=self.data,
                headers=self.headers,
                timeout=self.timeout)

    def test_get_fail(self):
        """
        Implements testcase for vpn drivers get methode to test in
        fail condition
        """

        self.resp = mock.Mock(status_code=404)
        with mock.patch.object(requests, 'get', return_value=self.resp) as (
                mock_get):
            self.rest_obj.get('create-ipsec-site-tunnel',
                              self.data, self.headers)
            mock_get.assert_called_with(
                self.test_dict.url_create_ipsec_tunnel,
                params=self.data,
                headers=self.headers,
                timeout=self.timeout)
