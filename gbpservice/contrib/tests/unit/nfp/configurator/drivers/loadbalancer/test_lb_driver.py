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

from gbpservice.contrib.nfp.configurator.agents import loadbalancer_v1 as lb
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v1.\
    haproxy import (haproxy_lb_driver as lb_driver)
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v1.\
    haproxy import (haproxy_rest_client as _rest_client)
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
    lb_test_data as test_data)
from neutron.tests import base
from oslo_serialization import jsonutils


class HaproxyOnVmDriverTestCase(base.BaseTestCase):
    """ Implements test cases for haproxy loadbalancer driver. """

    def __init__(self, *args, **kwargs):
        super(HaproxyOnVmDriverTestCase, self).__init__(*args, **kwargs)
        self.fo = test_data.FakeObjects()
        self.data = test_data.AssertionData()
        self.driver = lb_driver.HaproxyOnVmDriver()
        self.resp = mock.Mock()
        self.fake_resp_dict = {'status': True,
                               'config_success': True,
                               'delete_success': True}
        self.fo.vip = self.fo._get_vip_object()[0]
        self.fo.old_vip = self.fo._get_vip_object()[0]
        self.fo.pool = self.fo._get_pool_object()[0]
        self.fo.old_pool = self.fo._get_pool_object()[0]
        self.fo.hm = self.fo._get_hm_object()
        self.fo.old_hm = self.fo._get_hm_object()
        self.fo.member = self.fo._get_member_object()
        self.fo.old_member = self.fo._get_member_object()
        self.vip = self.fo.vip
        self.resp.status_code = 200
        self.get_resource = {
            'server': {
                'resource': [],
                'srvr:4910851f-4af7-4592-ad04-08b508c6fa21': []},
            'timeout': {}}

    @mock.patch(__name__ + '.test_data.FakeObjects.rpcmgr')
    @mock.patch(__name__ + '.test_data.FakeObjects.drivers')
    @mock.patch(__name__ + '.test_data.FakeObjects.sc')
    def _get_lb_handler_objects(self, sc, drivers, rpcmgr):
        """ Retrieves EventHandler object of loadbalancer agent.

        :param sc: mocked service controller object of process model framework
        :param drivers: mocked drivers object of loadbalancer object
        :param rpcmgr: mocked RPC manager object loadbalancer object

        Returns: objects of LBaaSEventHandler of loadbalancer agent

        """

        agent = lb.LBaaSEventHandler(sc, drivers, rpcmgr)
        return agent

    def _test_lbaasdriver(self, method_name):
        """ Tests all create/update/delete operation of loadbalancer driver.

        Returns: none

        """
        agent = self._get_lb_handler_objects()
        driver = lb_driver.HaproxyOnVmDriver(agent.plugin_rpc)
        rest_client = _rest_client.HttpRequests(
            self.data.url, self.data.port)
        logical_device_return_value = {
            'vip': self.fo.vip,
            'old_vip': self.fo.old_vip,
            'pool': self.fo.pool,
            'healthmonitors': self.fo.hm,
            'members': self.fo.member}
        with mock.patch.object(
                agent.plugin_rpc, 'get_logical_device',
                return_value=logical_device_return_value), (
            mock.patch.object(
                driver, '_get_rest_client', return_value=rest_client)), (
            mock.patch.object(
                rest_client.pool, 'request',
                return_value=self.resp)) as mock_request, (
            mock.patch.object(
                rest_client, 'get_resource',
                return_value=self.get_resource)) as mock_get_resource:

            mock_request.status_code = 200
            if method_name == 'DELETE_VIP':
                driver.delete_vip(self.fo.vip, self.fo.context)
                mock_request.assert_called_with(
                    'DELETE',
                    data=None,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.delete_vip_url)
            elif method_name == 'CREATE_VIP':
                driver.create_vip(self.fo.vip, self.fo.context)
                data = jsonutils.dumps(self.data.create_vip_data)
                mock_request.assert_called_with(
                    'POST',
                    data=data,
                    headers=self.data.header,
                    timeout=30,
                    url=self.data.create_vip_url)
                mock_get_resource.assert_called_with(
                    self.data.create_vip_resources)
            elif method_name == 'UPDATE_VIP':
                driver.update_vip(
                    self.fo.old_vip,
                    self.fo.vip,
                    self.fo.context)
                data = jsonutils.dumps(self.data.update_vip_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.update_vip_url)
            elif method_name == 'CREATE_POOL':
                driver.create_pool(self.fo.pool, self.fo.context)
            elif method_name == 'DELETE_POOL':
                driver.delete_pool(self.fo.pool, self.fo.context)
            elif method_name == 'UPDATE_POOL':
                driver.update_pool(
                    self.fo.old_pool,
                    self.fo.pool,
                    self.fo.context)
                data = jsonutils.dumps(self.data.update_pool_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.update_pool_url)
            elif method_name == 'CREATE_MEMBER':
                driver.create_member(self.fo.member[0], self.fo.context)
                data = jsonutils.dumps(self.data.create_member_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.create_member_url)
            elif method_name == 'DELETE_MEMBER':
                driver.delete_member(self.fo.member[0], self.fo.context)
                data = jsonutils.dumps(self.data.delete_member_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.delete_member_url)
            elif method_name == 'UPDATE_MEMBER':
                driver.update_member(
                    self.fo.old_member[0],
                    self.fo.member[0],
                    self.fo.context)
                data = jsonutils.dumps(self.data.update_member_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.update_member_url)
            elif method_name == 'CREATE_POOL_HEALTH_MONITOR':
                driver.create_pool_health_monitor(
                    self.fo.hm[0], self.fo._get_pool_object()[0]['id'],
                    self.fo.context)
                data = jsonutils.dumps(self.data.create_hm_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.create_hm_url)
            elif method_name == 'DELETE_POOL_HEALTH_MONITOR':
                driver.delete_pool_health_monitor(
                    self.fo.hm[0], self.fo._get_pool_object()[0]['id'],
                    self.fo.context)
                data = jsonutils.dumps(self.data.delete_hm_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.delete_hm_url)
            elif method_name == 'UPDATE_POOL_HEALTH_MONITOR':
                driver.update_pool_health_monitor(
                    self.fo.old_hm[0],
                    self.fo.hm[0], self.fo._get_pool_object()[0]['id'],
                    self.fo.context)
                data = jsonutils.dumps(self.data.update_hm_data)
                mock_request.assert_called_with(
                    'PUT',
                    data=data,
                    headers=self.data.header,
                    timeout=self.data.timeout,
                    url=self.data.update_hm_url)

    def test_vip_create_lbaasdriver(self):
        """Implements test case for create vip method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('CREATE_VIP')

    def test_vip_delete_lbaasdriver(self):
        """Implements test case for delete vip method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('DELETE_VIP')

    def test_vip_update_lbaasdriver(self):
        """Implements test case for update vip method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('UPDATE_VIP')

    def test_pool_create_lbaasdriver(self):
        """Implements test case for create pool method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('CREATE_POOL')

    def test_pool_delete_lbaasdriver(self):
        """Implements test case for delete vip method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('DELETE_POOL')

    def test_pool_update_lbaasdriver(self):
        """Implements test case for update vip method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('UPDATE_POOL')

    def test_member_create_lbaasdriver(self):
        """Implements test case for create member method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('CREATE_MEMBER')

    def test_member_delete_lbaasdriver(self):
        """Implements test case for delete member method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('DELETE_MEMBER')

    def test_member_update_lbaasdriver(self):
        """Implements test case for update member method of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('UPDATE_MEMBER')

    def test_pool_health_monitor_create_lbaasdriver(self):
        """Implements test case for create pool_health_monitor method of
        loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('CREATE_POOL_HEALTH_MONITOR')

    def test_pool_health_monitor_delete_lbaasdriver(self):
        """Implements test case for delete pool_health_monitor method
        of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('DELETE_POOL_HEALTH_MONITOR')

    def test_pool_health_monitor_update_lbaasdriver(self):
        """Implements test case for update pool_health_monitor method
        of loadbalancer driver.

        Returns: none

        """

        self._test_lbaasdriver('UPDATE_POOL_HEALTH_MONITOR')
