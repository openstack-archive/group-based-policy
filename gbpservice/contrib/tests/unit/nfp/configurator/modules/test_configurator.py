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
import unittest

from oslo_log import log as logging

from gbpservice.contrib.nfp.configurator.agents import firewall as fw
from gbpservice.contrib.nfp.configurator.agents import generic_config as gc
from gbpservice.contrib.nfp.configurator.lib import demuxer as demuxer_lib
from gbpservice.contrib.nfp.configurator.modules import configurator as cfgr
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                        fw_test_data as fo)

LOG = logging.getLogger(__name__)

STATUS_ACTIVE = "ACTIVE"

""" Tests RPC manager class of configurator

"""


class ConfiguratorRpcManagerTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(ConfiguratorRpcManagerTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()

    @mock.patch(__name__ + '.fo.FakeObjects.conf')
    @mock.patch(__name__ + '.fo.FakeObjects.sc')
    def _get_ConfiguratorRpcManager_object(self, sc, conf):
        """ Retrieves RPC manager object of configurator.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of configurator's RPC manager.

        """

        cm = cfgr.ConfiguratorModule(sc)
        demuxer = demuxer_lib.ServiceAgentDemuxer()
        rpc_mgr = cfgr.ConfiguratorRpcManager(sc, cm, conf, demuxer)
        return sc, conf, rpc_mgr

    def _get_GenericConfigRpcManager_object(self, conf, sc):
        """ Retrieves RPC manager object of generic config agent.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of generic config's RPC manager
        and service controller.

        """

        agent = gc.GenericConfigRpcManager(sc, conf)
        return agent, sc

    @mock.patch(__name__ + '.fo.FakeObjects.drivers')
    def _get_GenericConfigEventHandler_object(self, sc, rpcmgr, drivers):
        """ Retrieves event handler object of generic configuration.

        :param sc: mocked service controller object of process model framework
        :param rpcmgr: object of configurator's RPC manager
        :param drivers: list of driver objects for firewall agent

        Returns: object of generic config's event handler

        """

        agent = gc.GenericConfigEventHandler(sc, drivers, rpcmgr)
        return agent

    def _get_FWaasRpcManager_object(self, conf, sc):
        """ Retrieves RPC manager object of firewall agent.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of firewall's RPC manager and service controller

        """

        agent = fw.FWaasRpcManager(sc, conf)
        return agent, sc

    def _test_network_device_config(self, operation, method, batch=False):
        """ Tests generic config APIs

        :param operation: create/delete
        :param method: CONFIGURE_ROUTES/CLEAR_ROUTES/
        CONFIGURE_INTERFACES/CLEAR_INTERFACES
        :param batch: True or False. Indicates if the
        request is a batch request

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_ConfiguratorRpcManager_object()
        agent, sc = self._get_GenericConfigRpcManager_object(conf, sc)

        request_data = {'batch': {
                'request_data_actual': (
                            self.fo.fake_request_data_generic_bulk()),
                'request_data_expected': (
                            self.fo.fake_request_data_generic_bulk())},
                        'single': {
                'request_data_actual': (
                            (self.fo.fake_request_data_generic_single(
                                                                routes=True)
                             if 'ROUTES' in method
                             else self.fo.fake_request_data_generic_single())),
                'request_data_expected': (
                            (self.fo.fake_request_data_generic_single(
                                                                routes=True)
                             if 'ROUTES' in method
                             else self.fo.fake_request_data_generic_single()))}
                        }
        if batch:
            request_data_actual, request_data_expected = (
                                            request_data['batch'].values())
        else:
            request_data_actual, request_data_expected = (
                                            request_data['single'].values())

        with mock.patch.object(
                    sc, 'new_event', return_value='foo') as mock_sc_event, \
            mock.patch.object(sc, 'post_event') as mock_sc_rpc_event, \
            mock.patch.object(rpc_mgr,
                              '_get_service_agent_instance',
                              return_value=agent):

            if operation == 'create':
                rpc_mgr.create_network_function_device_config(
                                    self.fo.context, request_data_actual)
            elif operation == 'delete':
                rpc_mgr.delete_network_function_device_config(
                                    self.fo.context, request_data_actual)

            context = request_data_expected['info']['context']

            agent_info = {}
            agent_info.update(
                    {'resource': request_data_expected['config'][0][
                                                                'resource'],
                     'resource_type': request_data_expected['info'][
                                                            'service_type'],
                     'service_vendor': request_data_expected['info'][
                                                            'service_vendor'],
                     'context': context,
                     'notification_data': {}
                     })
            resource_data = request_data_expected['config'][0]['resource_data']
            if batch:
                sa_req_list = self.fo.fake_sa_req_list()
                if operation == 'delete':
                    sa_req_list[0]['method'] = 'clear_interfaces'
                    sa_req_list[1]['method'] = 'clear_routes'
                args_dict = {
                         'sa_req_list': sa_req_list,
                         'notification_data': {}
                        }
            else:
                args_dict = {'context': agent_info,
                             'resource_data': resource_data}
            mock_sc_event.assert_called_with(id=method,
                                             data=args_dict, key=None)
            mock_sc_rpc_event.assert_called_with('foo')

    def _test_fw_event_creation(self, operation):
        """ Tests firewall APIs

        :param operation: CREATE_FIREWALL/UPDATE_FIREWALL/DELETE_FIREWALL

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_ConfiguratorRpcManager_object()
        agent, sc = self._get_FWaasRpcManager_object(conf, sc)
        arg_dict = {'context': self.fo.fw_context,
                    'firewall': self.fo._fake_firewall_obj(),
                    'host': self.fo.host}
        method = {'CREATE_FIREWALL': 'create_network_function_config',
                  'UPDATE_FIREWALL': 'update_network_function_config',
                  'DELETE_FIREWALL': 'delete_network_function_config'}
        request_data = self.fo.fake_request_data_fw()
        with mock.patch.object(sc, 'new_event', return_value='foo') as (
                                                        mock_sc_event), \
            mock.patch.object(sc, 'post_event') as mock_sc_rpc_event, \
            mock.patch.object(rpc_mgr,
                              '_get_service_agent_instance',
                              return_value=agent):
            getattr(rpc_mgr, method[operation])(self.fo.fw_context,
                                                request_data)

            mock_sc_event.assert_called_with(id=operation,
                                             data=arg_dict, key=None)
            mock_sc_rpc_event.assert_called_with('foo')

    def _test_notifications(self):
        """ Tests response path notification  APIs

        Returns: none

        """

        sc, conf, rpc_mgr = self._get_ConfiguratorRpcManager_object()
        agent = self._get_GenericConfigEventHandler_object(sc, rpc_mgr)

        data = "PUT ME IN THE QUEUE!"
        with mock.patch.object(sc, 'new_event', return_value='foo') as (
                                                            mock_new_event),\
                mock.patch.object(sc, 'stash_event') as mock_poll_event:

            agent.notify._notification(data)

            mock_new_event.assert_called_with(id='STASH_EVENT',
                                              key='STASH_EVENT',
                                              data=data)
            mock_poll_event.assert_called_with('foo')

    def test_configure_routes_configurator_api(self):
        """ Implements test case for configure routes API

        Returns: none

        """

        method = "CONFIGURE_ROUTES"
        operation = 'create'
        self._test_network_device_config(operation, method)

    def test_clear_routes_configurator_api(self):
        """ Implements test case for clear routes API

        Returns: none

        """

        method = "CLEAR_ROUTES"
        operation = 'delete'
        self._test_network_device_config(operation, method)

    def test_configure_interfaces_configurator_api(self):
        """ Implements test case for configure interfaces API

        Returns: none

        """

        method = "CONFIGURE_INTERFACES"
        operation = 'create'
        self._test_network_device_config(operation, method)

    def test_clear_interfaces_configurator_api(self):
        """ Implements test case for clear interfaces API

        Returns: none

        """

        method = "CLEAR_INTERFACES"
        operation = 'delete'
        self._test_network_device_config(operation, method)

    def test_configure_bulk_configurator_api(self):
        """ Implements test case for bulk configure request API

        Returns: none

        """

        method = "PROCESS_BATCH"
        operation = 'create'
        self._test_network_device_config(operation, method, True)

    def test_clear_bulk_configurator_api(self):
        """ Implements test case for bulk clear request API

        Returns: none

        """

        method = "PROCESS_BATCH"
        operation = 'delete'
        self._test_network_device_config(operation, method, True)

    def test_create_firewall_configurator_api(self):
        """ Implements test case for create firewall API

        Returns: none

        """

        self._test_fw_event_creation('CREATE_FIREWALL')

    def test_update_firewall_configurator_api(self):
        """ Implements test case for update firewall API

        Returns: none

        """

        self._test_fw_event_creation('UPDATE_FIREWALL')

    def test_delete_firewall_configurator_api(self):
        """ Implements test case for delete firewall API

        Returns: none

        """

        self._test_fw_event_creation('DELETE_FIREWALL')

    def test_get_notifications_generic_configurator_api(self):
        """ Implements test case for get notifications API
        of configurator

        Returns: none

        """

        self._test_notifications()


if __name__ == '__main__':
    unittest.main()
