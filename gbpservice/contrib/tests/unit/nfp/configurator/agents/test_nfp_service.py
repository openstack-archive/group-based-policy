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

from gbpservice.contrib.nfp.configurator.agents import nfp_service as ns
from gbpservice.contrib.nfp.configurator.lib import (
                                        nfp_service_constants as const)
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                nfp_service_test_data as fo)


class NfpServiceRpcManagerTestCase(base.BaseTestCase):
    """ Implement test cases for RPC manager methods of nfp service agent.

    """

    def __init__(self, *args, **kwargs):
        super(NfpServiceRpcManagerTestCase, self).__init__(
                                                        *args, **kwargs)
        self.fo = fo.FakeObjects()

    @mock.patch(__name__ + '.fo.FakeObjects.sc')
    @mock.patch(__name__ + '.fo.FakeObjects.conf')
    def _get_NfpServiceRpcManager_object(self, conf, sc):
        """ Retrieves RPC manager object of nfp service agent.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of nfp service's RPC manager
        and service controller.
        """

        agent = ns.ConfigScriptRpcManager(sc, conf)
        return agent, sc

    def _test_event_creation(self, method):
        """ Tests event creation and enqueueing for create/delete
        operation of generic config agent's RPC manager.

        :param method: CREATE_NFP_SERVICE

        Returns: none
        """

        agent, sc = self._get_NfpServiceRpcManager_object()
        arg_dict = {'context': self.fo.context,
                    'resource_data': self.fo.kwargs}
        with mock.patch.object(
                    sc, 'new_event', return_value='foo') as mock_sc_event, (
             mock.patch.object(sc, 'post_event')) as mock_sc_rpc_event:
            actual_call = agent.run_nfp_service(self.fo.context,
                                                self.fo.kwargs)

            expected_cal = mock_sc_event.assert_called_with(
                                id=method, data=arg_dict, key=None)
            self.assertEqual(actual_call, expected_cal)
            mock_sc_rpc_event.assert_called_with('foo')

    def test_nfp_service_rpcmanager(self):
        """ Implements test case for run_nfp_service method
        of nfp service RPC manager.

        Returns: none
        """

        self._test_event_creation(const.CREATE_NFP_SERVICE_EVENT)


class NfpServiceEventHandlerTestCase(base.BaseTestCase):
    """ Implements test cases for event handler methods
    of nfp service agent.

    """

    def __init__(self, *args, **kwargs):
        super(NfpServiceEventHandlerTestCase, self).__init__(
                                                        *args, **kwargs)
        self.fo = fo.FakeObjects()
        self.context = {'notification_data': {},
                        'resource': 'interfaces'}

    @mock.patch(__name__ + '.fo.FakeObjects.rpcmgr')
    @mock.patch(__name__ + '.fo.FakeObjects.drivers')
    @mock.patch(__name__ + '.fo.FakeObjects.sc')
    def _get_nfp_service_event_handler_object(self, sc, drivers, rpcmgr):
        """ Retrieves event handler object of nfp service.

        :param sc: mocked service controller object of process model framework
        :param rpcmgr: object of configurator's RPC manager
        :param drivers: list of driver objects for nfp service agent

        Returns: object of nfp service's event handler
        """

        agent = ns.ConfigScriptEventHandler(sc, drivers, rpcmgr)
        return agent, sc

    def _test_handle_event(self, ev, result=const.UNHANDLED_RESULT):
        """ Test handle event method of nfp service agent.

        :param ev: event data which has to be actually sent by
        process framework.

        Returns: None
        """

        agent, sc = self._get_nfp_service_event_handler_object()
        driver = mock.Mock()

        with mock.patch.object(
                driver, 'run_heat', return_value=result) as mock_config_inte, (
             mock.patch.object(
                agent, '_get_driver', return_value=driver)):

            agent.handle_event(ev)

            mock_config_inte.assert_called_with(
                ev.data['context']['context'], ev.data['resource_data'])

    def test_create_nfp_service_handle_event_success(self):
        """ Implements positive test case for create_nfp_service method
        of nfp service event handler.

        Returns: none
        """

        ev = fo.FakeEventNfpService()
        ev.id = const.CREATE_NFP_SERVICE_EVENT
        self._test_handle_event(ev)

    def test_create_nfp_service_handle_event_failure(self):
        """ Implements negative test case for create_nfp_service method
        of nfp service event handler.

        Returns: none
        """

        ev = fo.FakeEventNfpService()
        ev.id = const.CREATE_NFP_SERVICE_EVENT
        self._test_handle_event(ev, const.FAILURE)
