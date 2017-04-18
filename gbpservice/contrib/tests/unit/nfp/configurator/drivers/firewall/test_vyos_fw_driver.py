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
import requests

from neutron.tests import base
from oslo_config import cfg
from oslo_serialization import jsonutils

from gbpservice.contrib.nfp.configurator.drivers.firewall.vyos import (
                                                    vyos_fw_driver as fw_dvr)
from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                        fw_test_data as fo)


class FwGenericConfigDriverTestCase(base.BaseTestCase):
    """ Implements test cases for driver methods
    of generic config.

    """

    def __init__(self, *args, **kwargs):
        super(FwGenericConfigDriverTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()
        with mock.patch.object(cfg, 'CONF') as mock_cfg:
            mock_cfg.configure_mock(rest_timeout=120, host='foo')
            self.driver = fw_dvr.FwaasDriver(mock_cfg)
        self.resp = mock.Mock()
        self.fake_resp_dict = {'status': True, 'reason': 'not found!'}
        self.kwargs = self.fo._fake_resource_data()

    def test_configure_static_ip(self):
        """ Implements test case for configure static ip method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)), (
            mock.patch.object(
                self.driver, '_configure_log_forwarding',
                return_value=const.STATUS_SUCCESS)):
            self.driver.configure_interfaces(self.fo.context, self.kwargs)

            data = jsonutils.dumps(self.fo.static_ip_data())
            mock_post.assert_called_with(
                self.fo.get_url_for_api('add_static_ip'),
                data=data, headers=self.fo.fake_header,
                timeout=self.fo.timeout)

    def test_configure_interfaces(self):
        """ Implements test case for configure interfaces method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)), (
            mock.patch.object(
                self.driver, '_configure_log_forwarding',
                return_value=const.STATUS_SUCCESS)), (
            mock.patch.object(
                self.driver, '_configure_static_ips',
                return_value=const.STATUS_SUCCESS)):
            self.driver.configure_interfaces(self.fo.context, self.kwargs)

            data = jsonutils.dumps(self.fo.data_for_interface)
            mock_post.assert_called_with(self.fo.get_url_for_api('add_inte'),
                                         data=data,
                                         headers=self.fo.fake_header,
                                         timeout=self.fo.timeout)

    def test_clear_interfaces(self):
        """ Implements test case for clear interfaces method
        of generic config driver.

        Returns: none

        """
        self.resp = mock.Mock(status_code=200)
        with mock.patch.object(
                requests, 'delete', return_value=self.resp) as mock_delete, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            self.driver.clear_interfaces(self.fo.context, self.kwargs)

            data = jsonutils.dumps(self.fo.data_for_interface)
            mock_delete.assert_called_with(
                                self.fo.get_url_for_api('del_inte'),
                                data=data, headers=self.fo.fake_header,
                                timeout=self.fo.timeout)

    def test_configure_source_routes(self):
        """ Implements test case for configure routes method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):

            self.driver.configure_routes(self.fo.context, self.kwargs)

            data = list()
            data.append(self.fo.data_for_add_src_route[0])
            data.append(self.fo.data_for_add_src_route[1])
            data = jsonutils.dumps(data)
            mock_post.assert_called_with(
                self.fo.get_url_for_api('add_src_route'),
                data=data, headers=self.fo.fake_header,
                timeout=self.fo.timeout)

    def test_delete_source_routes(self):
        """ Implements test case for clear routes method
        of generic config driver.

        Returns: none

        """

        with mock.patch.object(
                requests, 'delete', return_value=self.resp) as mock_delete, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            self.driver.clear_routes(
                self.fo.context, self.kwargs)

            data = list()
            data.append(self.fo.data_for_del_src_route[0])
            data.append(self.fo.data_for_del_src_route[1])
            data = jsonutils.dumps(data)
            mock_delete.assert_called_with(
                self.fo.get_url_for_api('del_src_route'),
                data=data, headers=self.fo.fake_header,
                timeout=self.fo.timeout)


class FwaasDriverTestCase(base.BaseTestCase):
    """ Implements test cases for driver methods
    of firewall.

    """

    def __init__(self, *args, **kwargs):
        super(FwaasDriverTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()
        with mock.patch.object(cfg, 'CONF') as mock_cfg:
            mock_cfg.configure_mock(rest_timeout=self.fo.timeout, host='foo')
            self.driver = fw_dvr.FwaasDriver(mock_cfg)
        self.resp = mock.Mock()
        self.fake_resp_dict = {'status': True,
                               'message': 'something',
                               'config_success': True,
                               'delete_success': True}
        self.fo.firewall = self.fo._fake_firewall_obj()
        self.firewall = jsonutils.dumps(self.fo.firewall)

    def test_create_firewall_fwaasdriver(self):
        """ Implements test case for create firewall method
        of firewall's drivers.

        Returns: none

        """

        with mock.patch.object(
                requests, 'post', return_value=self.resp) as mock_post, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            mock_post.configure_mock(status_code=200)
            self.driver.create_firewall(self.fo.firewall_api_context(),
                                        self.fo.firewall, self.fo.host)
            mock_post.assert_called_with(self.fo.get_url_for_api('config_fw'),
                                         data=self.firewall,
                                         headers=self.fo.fake_header,
                                         timeout=self.fo.timeout)

    def test_update_firewall_fwaasdriver(self):
        """ Implements test case for update firewall method
        of firewall's drivers.

        Returns: none

        """

        with mock.patch.object(
                requests, 'put', return_value=self.resp) as mock_put, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            self.driver.update_firewall(self.fo.firewall_api_context(),
                                        self.fo.firewall, self.fo.host)
            mock_put.assert_called_with(self.fo.get_url_for_api('update_fw'),
                                        data=self.firewall,
                                        headers=self.fo.fake_header,
                                        timeout=self.fo.timeout)

    def test_delete_firewall_fwaasdriver(self):
        """ Implements test case for delete firewall method
        of firewall's drivers.

        Returns: none

        """

        with mock.patch.object(
                requests, 'delete', return_value=self.resp) as mock_delete, (
            mock.patch.object(
                self.resp, 'json', return_value=self.fake_resp_dict)):
            self.driver.delete_firewall(self.fo.firewall_api_context(),
                                        self.fo.firewall, self.fo.host)
            mock_delete.assert_called_with(
                self.fo.get_url_for_api('delete_fw'),
                data=self.firewall, headers=self.fo.fake_header,
                timeout=self.fo.timeout)
