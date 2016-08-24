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
from gbpservice.contrib.nfp.configurator.lib import demuxer
from gbpservice.contrib.nfp.configurator.modules import configurator
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
    lb_test_data as test_data)
from neutron.tests import base


class LBaasRpcSenderTest(base.BaseTestCase):
    """Implements test cases for LBaasRpcSender class methods of
       loadbalancer agent.
    """

    @mock.patch(__name__ + '.test_data.FakeObjects.conf')
    @mock.patch(__name__ + '.test_data.FakeObjects.sc')
    def _get_configurator_rpc_manager_object(self, sc, conf):
        """ Retrieves RPC manager object of configurator.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of RPC manager of configurator, and mock object of
                 service controller and oslo configurator.

        """

        cm = configurator.ConfiguratorModule(sc)
        dmx = demuxer.ServiceAgentDemuxer()
        rpc_mgr = configurator.ConfiguratorRpcManager(sc, cm, conf, dmx)
        return sc, conf, rpc_mgr

    def test_update_status(self):
        """Implements test case for update_status method
        of loadbalancer agent's LBaasRpcSender class.

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_configurator_rpc_manager_object()
        agent = lb.LBaasRpcSender(sc)
        agent_info = {'context': 'context', 'resource': 'pool'}
        agent.update_status('pool', 'object_id',
                            'status', agent_info, 'pool')

    def test_update_pool_stats(self):
        """Implements test case for update_pool_stats method
        of loadbalancer agent's LBaasRpcSender class.

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_configurator_rpc_manager_object()
        agent = lb.LBaasRpcSender(sc)
        context = test_data.Context()
        agent.update_pool_stats('pool_id', 'stats', context)

    def test_get_logical_device(self):
        """Implements test case for get_logical_device method
        of loadbalancer agent's LBaasRpcSender class.

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_configurator_rpc_manager_object()
        agent = lb.LBaasRpcSender(sc)
        agent.get_logical_device(
            '6350c0fd-07f8-46ff-b797-62acd23760de',
            test_data.FakeObjects()._get_context_logical_device())


class LBaaSRpcManagerTest(base.BaseTestCase):
    """Implements test cases for LBaaSRpcManager class methods of
       loadbalancer agent.
    """

    def __init__(self, *args, **kwargs):
        super(LBaaSRpcManagerTest, self).__init__(*args, **kwargs)
        self.fo = test_data.FakeObjects()
        self.foo = test_data.Foo()
        self.arg_dict_vip = {
            'context': self.fo.context,
            'vip': self.fo._get_vip_object()[0],
        }
        self.arg_dict_vip_update = {
            'context': self.fo.context,
            'vip': self.fo._get_vip_object()[0],
            'old_vip': self.fo._get_vip_object()[0],
        }
        self.arg_dict_pool_create = {
            'context': self.fo.context,
            'pool': self.fo._get_pool_object()[0],
            'driver_name': 'loadbalancer',
        }
        self.arg_dict_pool_update = {
            'context': self.fo.context,
            'pool': self.fo._get_pool_object()[0],
            'old_pool': self.fo._get_pool_object()[0]}
        self.arg_dict_pool_delete = {
            'context': self.fo.context,
            'pool': self.fo._get_pool_object()[0],
        }
        self.arg_dict_member = {
            'context': self.fo.context,
            'member': self.fo._get_member_object()[0],
        }
        self.arg_dict_member_update = {
            'context': self.fo.context,
            'member': self.fo._get_member_object()[0],
            'old_member': self.fo._get_member_object()[0],
        }
        self.arg_dict_health_monitor = {
            'context': self.fo.context,
            'health_monitor': self.fo._get_hm_object()[0],
            'pool_id': self.fo._get_pool_object()[0]['id'],
        }
        self.arg_dict_health_monitor_update = {
            'context': self.fo.context,
            'health_monitor': self.fo._get_hm_object()[0],
            'old_health_monitor': self.fo._get_hm_object()[0],
            'pool_id': self.fo._get_pool_object()[0]['id'],
        }

    @mock.patch(__name__ + '.test_data.FakeObjects.conf')
    @mock.patch(__name__ + '.test_data.FakeObjects.sc')
    def _get_configurator_rpc_manager_object(self, sc, conf):
        """ Retrieves RPC manager object of configurator.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of RPC manager of configurator, and mock object of
                 service controller and oslo configurator.

        """

        cm = configurator.ConfiguratorModule(sc)
        dmx = demuxer.ServiceAgentDemuxer()
        rpc_mgr = configurator.ConfiguratorRpcManager(sc, cm, conf, dmx)
        return sc, conf, rpc_mgr

    def _get_lbaas_rpc_manager_object(self, conf, sc):
        """ Retrieves RPC manager object of loadbalancer agent.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: objects of RPC manager, service controller of
                 loadbalancer agent

        """

        agent = lb.LBaaSRpcManager(sc, conf)
        return agent, sc

    def _test_rpc_manager(self, operation, request_data, args):
        """ Tests all create/update/delete operation of RPC manager of
        loadbalancer agent.

        Returns: none

        """
        sc, conf, rpc_mgr = self._get_configurator_rpc_manager_object()
        agent, sc = self._get_lbaas_rpc_manager_object(conf, sc)
        method = self.fo.method

        with mock.patch.object(
                sc, 'new_event', return_value=self.foo) as mock_sc_new_event, (
            mock.patch.object(
                sc, 'post_event')) as mock_sc_post_event, (
            mock.patch.object(
                rpc_mgr, '_get_service_agent_instance', return_value=agent)):

            getattr(rpc_mgr, method[operation])(self.fo.context, request_data)
            mock_sc_new_event.assert_called_with(id=operation, data=args)
            mock_sc_post_event.assert_called_with(self.foo)

    def test_create_vip_rpc_manager(self):
        """Implements test case for create vip method
        of loadbalancer agent's RPC manager.

        Returns: none

        """
        self._test_rpc_manager(
            'CREATE_VIP',
            self.fo.get_request_data_for_vip(),
            self.arg_dict_vip)

    def test_delete_vip_rpc_manager(self):
        """Implements test case for delete vip method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'DELETE_VIP',
            self.fo.get_request_data_for_vip(),
            self.arg_dict_vip)

    def test_update_vip_rpc_manager(self):
        """Implements test case for update vip method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'UPDATE_VIP',
            self.fo.get_request_data_for_vip_update(),
            self.arg_dict_vip_update)

    def test_create_pool_rpc_manager(self):
        """Implements test case for create pool method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'CREATE_POOL',
            self.fo.get_request_data_for_create_pool(),
            self.arg_dict_pool_create)

    def test_delete_pool_rpc_manager(self):
        """Implements test case for delete pool method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'DELETE_POOL',
            self.fo.get_request_data_for_delete_pool(),
            self.arg_dict_pool_delete)

    def test_update_pool_rpc_manager(self):
        """Implements test case for update pool method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'UPDATE_POOL',
            self.fo.get_request_data_for_update_pool(),
            self.arg_dict_pool_update)

    def test_create_member_rpc_manager(self):
        """Implements test case for create member method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'CREATE_MEMBER',
            self.fo.get_request_data_for_member(),
            self.arg_dict_member)

    def test_delete_member_rpc_manager(self):
        """Implements test case for delete member method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'DELETE_MEMBER',
            self.fo.get_request_data_for_member(),
            self.arg_dict_member)

    def test_update_member_rpc_manager(self):
        """Implements test case for update member method
        of loadbalancer agent's RPC manager.

        Returns: none

        """
        self._test_rpc_manager(
            'UPDATE_MEMBER',
            self.fo.get_request_data_for_update_member(),
            self.arg_dict_member_update)

    def test_CREATE_POOL_HEALTH_MONITOR_rpc_manager(self):
        """Implements test case for create pool_health_monitor method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'CREATE_POOL_HEALTH_MONITOR',
            self.fo.get_request_data_for_pool_hm(),
            self.arg_dict_health_monitor)

    def test_DELETE_POOL_HEALTH_MONITOR_rpc_manager(self):
        """Implements test case for delete pool_health_monitor method
        of loadbalancer agent's RPC manager.

        Returns: none

        """

        self._test_rpc_manager(
            'DELETE_POOL_HEALTH_MONITOR',
            self.fo.get_request_data_for_pool_hm(),
            self.arg_dict_health_monitor)

    def test_UPDATE_POOL_HEALTH_MONITOR_rpc_manager(self):
        """Implements test case for update pool_health_monitor method
        of loadbalancer agent's RPC manager.

        Returns: none

        """
        self._test_rpc_manager(
            'UPDATE_POOL_HEALTH_MONITOR',
            self.fo.get_request_data_for_update_pool_hm(),
            self.arg_dict_health_monitor_update)


class LBaasEventHandlerTestCase(base.BaseTestCase):
    """Implement test cases for LBaaSEventHandler class methods of
       loadbalancer agent.
    """

    def __init__(self, *args, **kwargs):
        super(LBaasEventHandlerTestCase, self).__init__(*args, **kwargs)
        self.fo = test_data.FakeObjects()
        self.ev = test_data.FakeEvent()
        self.drivers = {'loadbalancer': mock.Mock()}

    def _get_lb_handler_objects(self, sc, drivers, rpcmgr):
        """ Retrieves EventHandler object of loadbalancer agent.

        :param sc: mocked service controller object of process model framework
        :param drivers: mocked drivers object of loadbalancer object
        :param rpcmgr: mocked RPC manager object loadbalancer object

        Returns: objects of LBaaSEventHandler of loadbalancer agent

        """

        agent = lb.LBaaSEventHandler(sc, drivers, rpcmgr)
        return agent

    @mock.patch(__name__ + '.test_data.FakeObjects.rpcmgr')
    @mock.patch(__name__ + '.test_data.FakeObjects.sc')
    def _test_handle_event(self, sc, rpcmgr):
        """ Tests all create/update/delete operation of LBaaSEventHandler of
        loadbalancer agent.

        Returns: none

        """

        agent = self._get_lb_handler_objects(sc, self.drivers, rpcmgr)
        driver = self.drivers['loadbalancer']

        with mock.patch.object(
                agent, '_get_driver', return_value=driver), (
            mock.patch.object(
                driver, 'create_vip')) as mock_create_vip, (
            mock.patch.object(
                driver, 'delete_vip')) as mock_delete_vip, (
            mock.patch.object(
                driver, 'update_vip')) as mock_update_vip, (
            mock.patch.object(
                driver, 'create_pool')) as mock_create_pool, (
            mock.patch.object(
                driver, 'delete_pool')) as mock_delete_pool, (
            mock.patch.object(
                driver, 'update_pool')) as mock_update_pool, (
            mock.patch.object(
                driver, 'create_member')) as mock_create_member, (
            mock.patch.object(
                driver, 'delete_member')) as mock_delete_member, (
            mock.patch.object(
                driver, 'update_member')) as mock_update_member, (
            mock.patch.object(
                driver, 'create_pool_health_monitor')) as mock_create_poolhm, (
            mock.patch.object(
                driver, 'delete_pool_health_monitor')) as mock_delete_poolhm, (
            mock.patch.object(
                driver, 'update_pool_health_monitor')) as mock_update_poolhm:

            vip = self.fo._get_vip_object()[0]
            old_vip = self.fo._get_vip_object()[0]
            pool = self.fo._get_pool_object()[0]
            old_pool = self.fo._get_pool_object()[0]
            member = self.fo._get_member_object()[0]
            old_member = self.fo._get_member_object()[0]
            hm = self.fo._get_hm_object()[0]
            old_hm = self.fo._get_hm_object()[0]
            pool_id = '6350c0fd-07f8-46ff-b797-62acd23760de'
            agent.handle_event(self.ev)

            if self.ev.id == 'CREATE_VIP':
                mock_create_vip.assert_called_with(vip, self.fo.vip_context)
            elif self.ev.id == 'DELETE_VIP':
                mock_delete_vip.assert_called_with(vip, self.fo.vip_context)
            elif self.ev.id == 'UPDATE_VIP':
                mock_update_vip.assert_called_with(
                    old_vip, vip, self.fo.vip_context)
            elif self.ev.id == 'CREATE_POOL':
                mock_create_pool.assert_called_with(
                    pool, self.fo.vip_context)
            elif self.ev.id == 'DELETE_POOL':
                mock_delete_pool.assert_called_with(
                    pool, self.fo.vip_context)
            elif self.ev.id == 'UPDATE_POOL':
                mock_update_pool.assert_called_with(
                    old_pool, pool, self.fo.vip_context)
            elif self.ev.id == 'CREATE_MEMBER':
                mock_create_member.assert_called_with(
                    member, self.fo.context_test)
            elif self.ev.id == 'DELETE_MEMBER':
                mock_delete_member.assert_called_with(
                    member, self.fo.context_test)
            elif self.ev.id == 'UPDATE_MEMBER':
                mock_update_member.assert_called_with(
                    old_member, member, self.fo.context_test)
            elif self.ev.id == 'CREATE_POOL_HEALTH_MONITOR':
                mock_create_poolhm.assert_called_with(
                    hm, pool_id, self.fo.context_test)
            elif self.ev.id == 'DELETE_POOL_HEALTH_MONITOR':
                mock_delete_poolhm.assert_called_with(
                    hm, pool_id, self.fo.context_test)
            elif self.ev.id == 'UPDATE_POOL_HEALTH_MONITOR':
                mock_update_poolhm.assert_called_with(
                    old_hm, hm, pool_id, self.fo.context_test)

    def test_create_vip_event_handler(self):
        """Implements test case for create vip method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'CREATE_VIP'
        self._test_handle_event()

    def test_delete_vip_event_handler(self):
        """Implements test case for delete vip method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'DELETE_VIP'
        self._test_handle_event()

    def test_update_vip_event_handler(self):
        """Implements test case for update vip method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'UPDATE_VIP'
        self._test_handle_event()

    def test_create_pool_event_handler(self):
        """Implements test case for create pool method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """
        self.ev.id = 'CREATE_POOL'
        self._test_handle_event()

    def test_delete_pool_event_handler(self):
        """Implements test case for delete pool method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'DELETE_POOL'
        self._test_handle_event()

    def test_update_pool_event_handler(self):
        """Implements test case for update pool method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'UPDATE_POOL'
        self._test_handle_event()

    def test_create_member_event_handler(self):
        """Implements test case for create member method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'CREATE_MEMBER'
        self._test_handle_event()

    def test_delete_member_event_handler(self):
        """Implements test case for delete member method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'DELETE_MEMBER'
        self._test_handle_event()

    def test_update_member_event_handler(self):
        """Implements test case for update member method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'UPDATE_MEMBER'
        self._test_handle_event()

    def test_create_pool_hm_event_handler(self):
        """Implements test case for create pool_health_monitor method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'CREATE_POOL_HEALTH_MONITOR'
        self._test_handle_event()

    def test_delete_pool_hm_event_handler(self):
        """Implements test case for delete pool_health_monitor method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'DELETE_POOL_HEALTH_MONITOR'
        self._test_handle_event()

    def test_update_pool_hm_event_handler(self):
        """Implements test case for update pool_health_monitor method
        of loadbalancer agent's LBaaSEventHandler class.

        Returns: none

        """

        self.ev.id = 'UPDATE_POOL_HEALTH_MONITOR'
        self._test_handle_event()
