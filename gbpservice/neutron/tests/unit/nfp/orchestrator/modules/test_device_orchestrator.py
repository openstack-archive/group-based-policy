# Copyright (c) 2016 OpenStack Foundation.
#
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

import copy
from gbpservice.nfp.orchestrator.db import nfp_db as nfpdb
from gbpservice.nfp.orchestrator.modules import (
    device_orchestrator)

from gbpservice.nfp.lib import transport
import mock
from mock import patch
from oslo_config import cfg
import unittest


class DummyEvent(object):
    def __init__(self, data, status, ref_count=0):
        self.data = {}
        self.data['status'] = status
        self.data['id'] = 'vm-id'

        self.data['network_function_id'] = 'network_function_id'
        self.data['network_function_device_id'] = 'network_function_device_id'
        self.data['network_function_instance_id'] = (
            'network_function_instance_id')
        self.data['ports'] = [{'id': 'myid1',
                     'port_model': 'neutron',
                     'port_classification': 'management',
                     'port_role': 'active'}]
        self.data['mgmt_port_id'] = [
                        {'id': 'myid1',
                         'port_model': 'neutron',
                         'port_classification': 'management',
                         'port_role': 'active'},
                                    ]
        self.data['interfaces_in_use'] = 1
        self.data['reference_count'] = ref_count
        self.data['service_details'] = {'service_vendor': 'vyos'}
        self.context = {}


class HaproxyDummyDriver(object):
    def get_network_function_device_status(self):
        pass


class DummyExtensionManager(object):
    drivers = 'dummy-driver'


param_req = {'param1': 'value1', 'param2': 'value2'}

cfg.CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')
orchestration_driver = HaproxyDummyDriver()
NDO_CLASS_PATH = ('gbpservice.nfp.orchestrator'
                  '.modules.device_orchestrator')
ORCHESTRATOR_LIB_PATH = ('gbpservice.nfp.orchestrator.lib')


class NDOModuleTestCase(unittest.TestCase):
    @mock.patch.object(device_orchestrator, 'events_init')
    @mock.patch.object(device_orchestrator, 'rpc_init')
    def test_module_init(self, mock_rpc_init, mock_events_init):
        controller = "dummy-controller"
        config = "dummy-config"
        device_orchestrator.DeviceOrchestrator = mock.Mock()
        device_orchestrator.nfp_module_init(controller, config)
        mock_events_init.assert_called_once_with(controller, config,
                                   device_orchestrator.DeviceOrchestrator())
        mock_rpc_init.assert_called_once_with(controller, config)

    def test_rpc_init(self):
        controller = mock.Mock()
        config = mock.Mock()
        device_orchestrator.rpc_init(controller, config)
        controller.register_rpc_agents.assert_called_once_with(mock.ANY)
        call_args, call_kwargs = controller.register_rpc_agents.call_args
        self.assertEqual(1, len(call_args[0]))
        self.assertIsInstance(call_args[0][0],
                              device_orchestrator.RpcAgent)

    def test_events_init(self):
        controller = mock.Mock()
        config = mock.Mock()
        device_orchestrator.events_init(
            controller, config, device_orchestrator)
        controller.register_events.assert_called_once_with(mock.ANY)


class NDORpcHandlerTestCase(object):

    def setUp(self):
        super(NDORpcHandlerTestCase, self).setUp()
        self.controller = mock.Mock()
        self.config = mock.Mock()
        self.rpc_handler = device_orchestrator.RpcHandler(self.config,
                                                          self.controller)

    @mock.patch.object(device_orchestrator.DeviceOrchestrator,
                       "get_network_function_config_info")
    def test_rpc_create_network_function(self,
                                        mock_get_network_function_config_info):
        self.rpc_response = {'notification_data': {
                                    'kwargs': [{'resource': 'healthmonitor',
                                                'kwargs': {'result': 'success',
                                                'device_id': 'dev-id'}}]
                            }}
        self.rpc_handler.get_network_function_config_info("context",
                                                          self.rpc_response)
        event_id = 'DEVICE_HEALTHY'
        event_data = {'device_id': 'dev-id'}
        self.controller._create_event.assert_called_once_with(
            event_id=event_id,
            event_data=event_data)
        self.rpc_handler.get_network_function_config_info.\
            assert_called_once_with("context", self.rpc_response)


@patch(NDO_CLASS_PATH + '.NDOConfiguratorRpcApi.__init__',
       mock.MagicMock(return_value=None))
class NDORpcApiTestCase(unittest.TestCase):

    def setUp(self):
        super(NDORpcApiTestCase, self).setUp()
        self.controller = mock.Mock()
        self.config = mock.Mock()

    def test_create_network_function_device_config(self):
        context = 'context'
        conf = {'info': 'info'}
        self.rpc_handler = device_orchestrator.NDOConfiguratorRpcApi(
            context, conf)
        self.rpc_handler.conf = mock.MagicMock(return_value=conf)
        self.rpc_handler.context = mock.MagicMock(return_value=context)
        self.rpc_handler.rpc_api = mock.MagicMock(return_value=True)
        device_data = {'id': 'network_function_id',
             'network_function_id': 'network_function_id',
             'network_function_instance_id': 'network_function_instance_id',
             'network_function_device_id': 'network_function_instance_id',
             'mgmt_ip_address': 'mgmt-ip',
             'service_details': {'service_type': 'service_type',
                                 'service_vendor': 'service_vendor'}}
        config_params = {'info': {'service_type': ''},
                         'config': [{'kwargs': {}}]}
        transport.send_request_to_configurator = mock.MagicMock(
            return_value=True)
        self.rpc_handler.create_network_function_device_config(device_data,
                                                               config_params)

        transport.send_request_to_configurator.assert_called_once_with(
            self.rpc_handler.conf, self.rpc_handler.context,
            config_params, 'CREATE', True)

    def test_delete_network_function_device_config(self):
        context = 'context'
        conf = 'config'
        self.rpc_handler = device_orchestrator.NDOConfiguratorRpcApi(
            context, conf)
        self.rpc_handler.conf = mock.MagicMock(return_value=conf)
        self.rpc_handler.context = mock.MagicMock(return_value=context)
        self.rpc_handler.rpc_api = mock.MagicMock(return_value=True)
        device_data = {'id': 'network_function_id',
             'network_function_id': 'network_function_id',
             'network_function_instance_id': 'network_function_instance_id',
             'network_function_device_id': 'network_function_instance_id',
             'mgmt_ip_address': 'mgmt-ip',
             'service_details': {'service_type': 'service_type',
                                 'service_vendor': 'service_vendor'}}
        config_params = {'info': {'service_type': ''},
                         'config': [{'kwargs': {}}]}
        transport.send_request_to_configurator = mock.MagicMock(
            return_value=True)
        self.rpc_handler.delete_network_function_device_config(device_data,
                                                               config_params)
        transport.send_request_to_configurator.assert_called_once_with(
            self.rpc_handler.conf, self.rpc_handler.context,
            config_params, 'DELETE', True)


@patch(NDO_CLASS_PATH + '.DeviceOrchestrator._create_event',
       mock.MagicMock(return_value=True))
@patch(NDO_CLASS_PATH + '.DeviceOrchestrator.db_session',
       mock.MagicMock(return_value=True))
@patch(NDO_CLASS_PATH +
       '.DeviceOrchestrator._get_orchestration_driver',
       mock.MagicMock(return_value=orchestration_driver))
@patch(NDO_CLASS_PATH + '.NDOConfiguratorRpcApi.__init__',
       mock.MagicMock(return_value=None))
@patch(ORCHESTRATOR_LIB_PATH + '.extension_manager.ExtensionManager',
       mock.MagicMock(return_value=DummyExtensionManager()))
class DeviceOrchestratorTestCase(unittest.TestCase):

    def _initialize_ndo_handler(self):
        ndo_handler = device_orchestrator.DeviceOrchestrator(
                object, cfg.CONF)
        #ndo_handler.db_session = mock.MagicMock()
        self.event = DummyEvent(100, 'PENDING_CREATE')
        return ndo_handler

    @unittest.skip('skipping')
    @mock.patch.object(device_orchestrator.DeviceOrchestrator,
            'device_configuration_complete')
    def test_handle_event(self, mock_device_configuration_complete):
        ndo_mgr = device_orchestrator.DeviceOrchestrator(object, cfg.CONF)
        mock_device_configuration_complete.return_value = True
        self.event = DummyEvent(100, 'DEVICE_CONFIGURED')
        self.event.id = 'DEVICE_CONFIGURED'

        ndo_mgr.handle_event(self.event)
        mock_device_configuration_complete.assert_called_with(self.event)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_check_device_up(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        ndo_handler._controller = mock.MagicMock(return_value='')
        mock_update_nsd.return_value = 100
        orig_event_data = copy.deepcopy(self.event.data)

        orchestration_driver.get_network_function_device_status = (
                mock.MagicMock(return_value='ACTIVE'))
        status = 'DEVICE_UP'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]

        ndo_handler.check_device_is_up(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

        orchestration_driver.get_network_function_device_status = (
                mock.MagicMock(return_value='ERROR'))
        status = 'DEVICE_NOT_UP'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]

        ndo_handler.check_device_is_up(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_health_check(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        mock_update_nsd.return_value = 100
        orig_event_data = copy.deepcopy(self.event.data)

        ndo_handler.configurator_rpc.create_network_function_device_config = (
            mock.MagicMock(return_value=101))
        orchestration_driver.get_network_function_device_healthcheck_info = (
            mock.MagicMock(return_value=param_req))

        status = 'HEALTH_CHECK_PENDING'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]

        ndo_handler.perform_health_check(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)
        ndo_handler.configurator_rpc.create_network_function_device_config.\
            assert_called_with(orig_event_data, param_req)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_plug_interfaces(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()

        mock_update_nsd.return_value = 100
        orig_event_data = copy.deepcopy(self.event.data)
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=orig_event_data)
        orig_event_data['status_description'] = ''

        orchestration_driver.plug_network_function_device_interfaces = (
            mock.MagicMock(return_value=True))
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        orig_event_data['interfaces_in_use'] += len(orig_event_data['ports'])

        ndo_handler.plug_interfaces(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

        orchestration_driver.plug_network_function_device_interfaces = (
            mock.MagicMock(return_value=False))
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        event_id = 'DEVICE_CONFIGURATION_FAILED'

        ndo_handler.plug_interfaces(self.event)
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=orig_event_data,
                                             is_internal_event=True)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_create_device_configuration(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        device = self.event.data
        config_params = {'param1': 'value1', 'parama2': 'value2'}
        orchestration_driver.get_network_function_device_config_info = (
            mock.MagicMock(return_value=config_params))
        ndo_handler.configurator_rpc.create_network_function_device_config = (
                mock.MagicMock(return_value=True))

        ndo_handler.create_device_configuration(self.event)
        ndo_handler.configurator_rpc.create_network_function_device_config.\
            assert_called_with(device, config_params)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_device_configuration_complete(self,
                                           mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        device = self.event.data

        ndo_handler._prepare_device_data = mock.MagicMock(return_value=device)
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        orig_event_data = copy.deepcopy(self.event.data)
        status = 'ACTIVE'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]
        orig_event_data['reference_count'] += 1

        ndo_handler.device_configuration_complete(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

        event_id = 'DEVICE_ACTIVE'
        device_created_data = {
                'network_function_id': orig_event_data['network_function_id'],
                'network_function_instance_id': (
                    orig_event_data['network_function_instance_id']),
                'network_function_device_id': orig_event_data['id'],
                              }
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=device_created_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'get_network_function')
    @mock.patch.object(nfpdb.NFPDbBase, 'get_port_info')
    def test_delete_network_function_device(self, mock_get_port, mock_get_nf,
                                            mock_update_nsd, mock_get_nsd):
        ndo_handler = self._initialize_ndo_handler()
        delete_event_req = DummyEvent(100, 'ACTIVE')
        delete_event_req.data = {'network_function_device_id': 'device-id',
                'network_function_instance': {'id': 'nfi-id', 'port_info': []},
                'network_function_id': 'network_function_id'
                                 }
        mgmt_port_id = {'id': 'port-id', 'port_model': 'port-policy'}
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=delete_event_req.data)
        ndo_handler._get_service_type = mock.MagicMock(
            return_value='service-type')
        ndo_handler._get_port = mock.MagicMock(return_value=mgmt_port_id)

        mock_get_port.return_value = mgmt_port_id
        mock_get_nsd.return_value = {'id': 'device-id',
                                     'mgmt_port_id': ['mgmt-data-port-id']}

        event_id = 'DELETE_CONFIGURATION'
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.delete_network_function_device(delete_event_req)
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=delete_event_req.data,
                                             is_internal_event=True)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_delete_device_configuration(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        config_params = {'param1': 'value1', 'parama2': 'value2'}
        self.event = DummyEvent(101, 'ACTIVE')
        orchestration_driver.get_network_function_device_config_info = (
            mock.MagicMock(return_value=config_params))
        ndo_handler.configurator_rpc.delete_network_function_device_config = (
                mock.MagicMock(return_value=True))

        ndo_handler.delete_device_configuration(self.event)
        ndo_handler.configurator_rpc.delete_network_function_device_config.\
            assert_called_with(self.event.data, config_params)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_unplug_interfaces(self, mock_update_nsd):

        ndo_handler = self._initialize_ndo_handler()
        self.event = DummyEvent(101, 'ACTIVE')
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=self.event.data)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = (
            ndo_handler.status_map['ACTIVE'])
        orchestration_driver.unplug_network_function_device_interfaces = (
            mock.MagicMock(return_value=True))

        ndo_handler.unplug_interfaces(self.event)

        orig_event_data['interfaces_in_use'] -= len(orig_event_data['ports'])
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

        self.event = DummyEvent(101, 'ACTIVE')
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['interfaces_in_use'] -= len(orig_event_data['ports'])
        orig_event_data['status_description'] = (
            ndo_handler.status_map['ACTIVE'])

        orchestration_driver.unplug_network_function_device_interfaces = (
            mock.MagicMock(return_value=False))

        ndo_handler.unplug_interfaces(self.event)
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'delete_network_function_device')
    def test_device_delete(self, mock_delete_nsd):
        ndo_handler = self._initialize_ndo_handler()
        self.event = DummyEvent(101, 'ACTIVE', 1)
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=self.event.data)
        orig_event_data = copy.deepcopy(self.event.data)
        orchestration_driver.delete_network_function_device = (
            mock.MagicMock(return_value=True))
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.delete_device(self.event)

        event_id = 'DEVICE_BEING_DELETED'
        orig_event_data['reference_count'] -= 1

        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=orig_event_data,
                                             is_poll_event=True,
                                             original_event=self.event)

    def test_handle_device_create_error(self):
        ndo_handler = self._initialize_ndo_handler()
        event_id = status = 'DEVICE_CREATE_FAILED'
        self.event = DummyEvent(101, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_create_error(self.event)
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_not_up(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        status = 'ERROR'
        desc = 'Device not became ACTIVE'
        self.event = DummyEvent(101, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = desc
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_not_up(self.event)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_not_reachable(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        status = 'ERROR'
        self.event = DummyEvent(101, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        desc = 'Device not reachable, Health Check Failed'
        orig_event_data['status_description'] = desc
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_not_reachable(self.event)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_config_failed(self, mock_update_nsd):
        ndo_handler = self._initialize_ndo_handler()
        status = 'ERROR'
        desc = 'Configuring Device Failed.'
        self.event = DummyEvent(101, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = desc
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_config_failed(self.event)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        mock_update_nsd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)


def main():
    unittest.main()

if __name__ == '__main__':
    main()
