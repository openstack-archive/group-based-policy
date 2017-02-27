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
from oslo_config import cfg

from gbpservice.contrib.nfp.configurator.agents import firewall as fw
from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.contrib.nfp.configurator.lib import fw_constants as fw_const
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
    fw_test_data as fo)


class FWaasRpcManagerTestCase(base.BaseTestCase):
    """ Implements test cases for RPC manager methods of firewall agent.

    """

    def __init__(self, *args, **kwargs):
        super(FWaasRpcManagerTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()

    @mock.patch(__name__ + '.fo.FakeObjects.sc')
    @mock.patch(__name__ + '.fo.FakeObjects.conf')
    def _get_FWaasRpcManager_object(self, conf, sc):
        """ Retrieves RPC manager object of firewall agent.

        :param sc: mocked service controller object of process model framework
        :param conf: mocked OSLO configuration file

        Returns: object of firewall's RPC manager and service controller

        """

        agent = fw.FWaasRpcManager(sc, conf)
        return agent, sc

    def _test_event_creation(self, method):
        """ Tests event creation and enqueueing for create/update/delete
        operation of firewall agent's RPC manager.

        Returns: none

        """

        agent, sc = self._get_FWaasRpcManager_object()
        context = {}
        arg_dict = {'context': context,
                    'firewall': self.fo.firewall,
                    'host': self.fo.host}
        with mock.patch.object(sc, 'new_event', return_value='foo') as (
                mock_sc_event), (
                mock.patch.object(sc, 'post_event')) as mock_sc_rpc_event:
            call_method = getattr(agent, method.lower())
            call_method(context, self.fo.firewall, self.fo.host)

            result_dict = arg_dict
            result_dict['firewall'] = {
                'file_path': "/tmp/%s" % (self.fo.firewall['id'])}
            mock_sc_event.assert_called_with(id=method,
                                             data=result_dict, key=None)
            mock_sc_rpc_event.assert_called_with('foo')

    def test_create_firewall_fwaasrpcmanager(self):
        """ Implements test case for create firewall method
        of firewall agent's RPC manager.

        Returns: none

        """

        self._test_event_creation(fw_const.FIREWALL_CREATE_EVENT)

    def test_update_firewall_fwaasrpcmanager(self):
        """ Implements test case for update firewall method
        of firewall agent's RPC manager.

        Returns: none

        """

        self._test_event_creation(fw_const.FIREWALL_UPDATE_EVENT)

    def test_delete_firewall_fwaasrpcmanager(self):
        """ Implements test case for delete firewall method
        of firewall agent's RPC manager.

        Returns: none

        """

        self._test_event_creation(fw_const.FIREWALL_DELETE_EVENT)


class FwaasHandlerTestCase(base.BaseTestCase):
    """ Implements test cases for event handler methods
    of firewall agent.

    """

    def __init__(self, *args, **kwargs):
        super(FwaasHandlerTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()
        self.ev = fo.FakeEventFirewall()
        self.firewall_rule = {
            'id': 'rule-id', 'action': 'allow',
            'destination_ip_address': '',
            'destination_port': '80',
            'enabled': 'enabled', 'ip_version': 'v4',
            'protocol': 'tcp', 'source_ip_address': '',
            'source_port': '', 'shared': False,
            'position': 1
        }

        self.ev.data['context']['agent_info']['resource'] = 'firewall'

    @mock.patch(__name__ + '.fo.FakeObjects.rpcmgr')
    @mock.patch(__name__ + '.fo.FakeObjects.drivers')
    @mock.patch(__name__ + '.fo.FakeObjects.sc')
    def _get_FwHandler_objects(self, sc, drivers, rpcmgr):
        """ Retrieves event handler object of firewall agent.

        :param sc: mocked service controller object of process model framework
        :param drivers: list of driver objects for firewall agent
        :param rpcmgr: object of configurator's RPC manager

        Returns: object of firewall agents's event handler

        """

        with mock.patch.object(cfg, 'CONF') as mock_cfg:
            mock_cfg.configure_mock(host='foo')
            agent = fw.FWaasEventHandler(sc, drivers, rpcmgr, mock_cfg)
        return agent

    def _test_handle_event(self, rule_list_info=True):
        """ Test handle event method of firewall agent for various
        device configuration operations.

        :param rule_list_info: an atrribute of firewall resource object
        sent from plugin which contains the firewall rules.

        Returns: None

        """

        agent = self._get_FwHandler_objects()
        driver = mock.Mock()

        with mock.patch.object(
            agent.plugin_rpc, 'set_firewall_status') as (
            mock_set_fw_status), (
            mock.patch.object(
                agent.plugin_rpc, 'firewall_deleted')) as (mock_fw_deleted), (
            mock.patch.object(
                driver, fw_const.FIREWALL_CREATE_EVENT.lower())) as (
            mock_create_fw), (
            mock.patch.object(
                driver, fw_const.FIREWALL_UPDATE_EVENT.lower())) as (
            mock_update_fw), (
            mock.patch.object(
                driver, fw_const.FIREWALL_DELETE_EVENT.lower())) as (
            mock_delete_fw), (
            mock.patch.object(
                agent, '_get_driver', return_value=driver)):

            firewall = self.fo._fake_firewall_obj()
            if not rule_list_info:
                firewall_rule_list = []
            else:
                firewall_rule_list = [self.firewall_rule]
            firewall.update({'firewall_rule_list': firewall_rule_list})
            self.ev.data.get('firewall').update(
                {'firewall_rule_list': firewall_rule_list})

            agent_info = self.ev.data['context']['agent_info']
            agent.handle_event(self.ev)
            context = self.fo.neutron_context

            if 'service_info' in self.fo.context:
                self.fo.context.pop('service_info')
            if not rule_list_info:
                if self.ev.id == fw_const.FIREWALL_CREATE_EVENT:
                    mock_set_fw_status.assert_called_with(
                        agent_info,
                        firewall['id'], const.STATUS_ACTIVE, firewall)
                elif self.ev.id == fw_const.FIREWALL_UPDATE_EVENT:
                    mock_set_fw_status.assert_called_with(
                        agent_info,
                        const.STATUS_ACTIVE, firewall)
                elif self.ev.id == fw_const.FIREWALL_DELETE_EVENT:
                    mock_fw_deleted.assert_called_with(
                        agent_info, firewall['id'], firewall)
            else:
                if self.ev.id == fw_const.FIREWALL_CREATE_EVENT:
                    mock_create_fw.assert_called_with(
                        context,
                        firewall, self.fo.host)
                elif self.ev.id == fw_const.FIREWALL_UPDATE_EVENT:
                    mock_update_fw.assert_called_with(
                        context,
                        firewall, self.fo.host)
                elif self.ev.id == fw_const.FIREWALL_DELETE_EVENT:
                    mock_delete_fw.assert_called_with(
                        context,
                        firewall, self.fo.host)

    def test_create_firewall_with_rule_list_info_true(self):
        """ Implements test case for create firewall method
        of firewall agent's event handler with firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_CREATE_EVENT
        self._test_handle_event()

    def test_update_firewall_with_rule_list_info_true(self):
        """ Implements test case for update firewall method
        of firewall agent's event handler with firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_UPDATE_EVENT
        self._test_handle_event()

    def test_delete_firewall_with_rule_list_info_true(self):
        """ Implements test case for delete firewall method
        of firewall agent's event handler with firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_DELETE_EVENT
        self._test_handle_event()

    def test_create_firewall_with_rule_list_info_false(self):
        """ Implements test case for create firewall method
        of firewall agent's event handler without firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_CREATE_EVENT
        self._test_handle_event(False)

    def test_update_firewall_with_rule_list_info_false(self):
        """ Implements test case for update firewall method
        of firewall agent's event handler without firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_UPDATE_EVENT
        self._test_handle_event(False)

    def test_delete_firewall_with_rule_list_info_false(self):
        """ Implements test case for delete firewall method
        of firewall agent's event handler without firewall rules.

        Returns: none

        """

        self.ev.id = fw_const.FIREWALL_DELETE_EVENT
        self._test_handle_event(False)
