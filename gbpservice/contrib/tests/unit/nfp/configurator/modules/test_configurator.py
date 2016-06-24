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

from neutron.tests import base

from gbpservice.contrib.nfp.configurator.lib import demuxer as demuxer_lib
from gbpservice.contrib.nfp.configurator.modules import configurator as cfgr
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                        fw_test_data as fo)


class ConfiguratorRpcManagerTestCase(base.BaseTestCase):
    """ Tests RPC manager class of configurator

    """

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
        return sc, rpc_mgr

    def _test_network_function_device_config(self, operation,
                                             method, batch=False):
        """ Tests generic config APIs

        :param operation: create/delete
        :param method: CONFIGURE_ROUTES/CLEAR_ROUTES/
        CONFIGURE_INTERFACES/CLEAR_INTERFACES
        :param batch: True or False. Indicates if the
        request is a batch request

        Returns: none

        """

        sc, rpc_mgr = self._get_ConfiguratorRpcManager_object()
        agent = mock.Mock()

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

        with mock.patch.object(rpc_mgr,
                               '_get_service_agent_instance',
                               return_value=agent), (
             mock.patch.object(agent, 'process_request')) as mock_request:

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
            notification_data = dict()
            sa_req_list = self.fo.fake_sa_req_list()

            response_data = {'single': {'routes': [sa_req_list[1]],
                                        'interfaces': [sa_req_list[0]]},
                             'batch': sa_req_list}

            if batch:
                data = response_data['batch']
                if operation == 'delete':
                    data[0]['method'] = 'clear_interfaces'
                    data[1]['method'] = 'clear_routes'
            else:
                data = response_data['single'][method.split('_')[1].lower()]
                if operation == 'delete':
                    data[0]['method'] = data[0]['method'].replace(
                                                    'configure', 'clear', 1)
            mock_request.assert_called_with(data,
                                            notification_data)

    def _test_network_function_config(self, operation):
        """ Tests firewall APIs

        :param operation: CREATE_FIREWALL/UPDATE_FIREWALL/DELETE_FIREWALL

        Returns: none

        """

        sc, rpc_mgr = self._get_ConfiguratorRpcManager_object()
        agent = mock.Mock()
        method = {'CREATE': 'create_network_function_config',
                  'UPDATE': 'update_network_function_config',
                  'DELETE': 'delete_network_function_config'}
        request_data = self.fo.fake_request_data_fw()
        with mock.patch.object(rpc_mgr,
                               '_get_service_agent_instance',
                               return_value=agent), (
             mock.patch.object(agent, 'process_request')) as mock_request:

            getattr(rpc_mgr, method[operation.split('_')[0]])(
                                                        self.fo.fw_context,
                                                        request_data)

            notification_data = dict()
            data = self.fo.fake_sa_req_list_fw()
            if 'UPDATE' in operation:
                data[0]['method'] = data[0]['method'].replace(
                                                    'create', 'update', 1)
            elif 'DELETE' in operation:
                data[0]['method'] = data[0]['method'].replace(
                                                    'create', 'delete', 1)

            mock_request.assert_called_with(data,
                                            notification_data)

    def _test_notifications(self):
        """ Tests response path notification  APIs

        Returns: none

        """

        sc, rpc_mgr = self._get_ConfiguratorRpcManager_object()

        events = fo.FakeEventGetNotifications()
        with mock.patch.object(sc, 'get_stashed_events',
                               return_value=[events]):

            return_value = rpc_mgr.get_notifications('context')

            expected_value = [events.data]
            self.assertEqual(return_value, expected_value)

    def test_configure_routes_generic_api(self):
        """ Implements test case for configure routes API

        Returns: none

        """

        method = "CONFIGURE_ROUTES"
        operation = 'create'
        self._test_network_function_device_config(operation, method)

    def test_clear_routes_generic_api(self):
        """ Implements test case for clear routes API

        Returns: none

        """

        method = "CLEAR_ROUTES"
        operation = 'delete'
        self._test_network_function_device_config(operation, method)

    def test_configure_interfaces_generic_api(self):
        """ Implements test case for configure interfaces API

        Returns: none

        """

        method = "CONFIGURE_INTERFACES"
        operation = 'create'
        self._test_network_function_device_config(operation, method)

    def test_clear_interfaces_generic_api(self):
        """ Implements test case for clear interfaces API

        Returns: none

        """

        method = "CLEAR_INTERFACES"
        operation = 'delete'
        self._test_network_function_device_config(operation, method)

    def test_configure_bulk_generic_api(self):
        """ Implements test case for bulk configure request API

        Returns: none

        """

        method = "PROCESS_BATCH"
        operation = 'create'
        self._test_network_function_device_config(operation, method, True)

    def test_clear_bulk_generic_api(self):
        """ Implements test case for bulk clear request API

        Returns: none

        """

        method = "PROCESS_BATCH"
        operation = 'delete'
        self._test_network_function_device_config(operation, method, True)

    def test_network_function_create_api(self):
        """ Implements test case for create firewall API

        Returns: none

        """

        self._test_network_function_config('CREATE_FIREWALL')

    def test_network_function_update_api(self):
        """ Implements test case for update firewall API

        Returns: none

        """

        self._test_network_function_config('UPDATE_FIREWALL')

    def test_network_function_delete_api(self):
        """ Implements test case for delete firewall API

        Returns: none

        """

        self._test_network_function_config('DELETE_FIREWALL')

    def test_get_notifications_generic_configurator_api(self):
        """ Implements test case for get notifications API
        of configurator

        Returns: none

        """

        self._test_notifications()
