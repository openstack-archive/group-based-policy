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


from gbpservice.nfp.lib import transport
import mock
from mock import patch
from oslo_config import cfg
import unittest

import uuid as pyuuid

dummy_data = {}

with mock.patch('oslo_config.cfg.CONF.register_opts') as opt:
    from gbpservice.nfp.orchestrator.modules import (
        device_orchestrator)


class DummyController(object):
    def event_complete(self, event, result=None, return_value=None):
        return

    def new_event(self, id, data, key):
        return


class DummyDesc(object):
    def to_dict(self):
        return {}


class DummyEvent(object):

    def __init__(self, data, status, ref_count=0):
        self.id = ''
        self.key = str(pyuuid.uuid4())
        self.data = {}
        self.data['status'] = status
        self.data['id'] = 'vm-id'

        self.data['network_function_id'] = 'network_function_id'
        self.data['network_function_device_id'] = 'vm-id'
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
        self.data['network_function'] = {'id': 'network_function_id'}
        self.data['network_function_device'] = {'id': 'vm-id'}
        self.data['network_function_instance'] = {
            'id': 'network_function_instance_id'}
        self.data['resource_owner_context'] = {'admin_token': str(
            pyuuid.uuid4()), 'tenant_id': str(pyuuid.uuid4()),
            'admin_tenant_id': str(pyuuid.uuid4())}
        self.data['admin_token'] = str(pyuuid.uuid4())
        self.data['provider'] = {'ptg': None}
        self.data['consumer'] = {'ptg': None}
        self.binding_key = self.data['service_details'][
                                'service_vendor'] + self.data[
                                            'network_function']['id']
        self.context = {}
        self.desc = DummyDesc()

        self.context = self.data


class Desc(object):

    def __init__(self):
        uuid = pyuuid.uuid4()
        id = ''
        self.uuid = str(uuid) + ':' + id
        self.type = ''
        self.flag = ''
        self.worker = ''
        self.poll_desc = None

    def to_dict(self):
        return {'uuid': self.uuid,
                'type': self.type,
                'flag': self.flag,
                'worker': self.worker,
                'poll_desc': self.poll_desc
                }


class HaproxyDummyDriver(object):

    def get_network_function_device_status(self):
        pass

    def get_network_function_device_config(self, device, config,
                                           is_delete=False):
        pass


class DummyExtensionManager(object):
    drivers = 'dummy-driver'


param_req = {'param1': 'value1', 'param2': 'value2'}

cfg.CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')
orchestration_driver = HaproxyDummyDriver()
NDO_CLASS_PATH = ('gbpservice.nfp.orchestrator'
                  '.modules.device_orchestrator')


class NDOModuleTestCase(unittest.TestCase):

    @mock.patch.object(device_orchestrator, 'events_init')
    @mock.patch.object(device_orchestrator, 'rpc_init')
    def test_module_init(self, mock_rpc_init, mock_events_init):
        controller = "dummy-controller"
        config = "dummy-config"
        device_orchestrator.DeviceOrchestrator = mock.Mock()
        device_orchestrator.nfp_module_init(controller, config)
        mock_events_init.assert_called_once_with(
            controller, config, device_orchestrator.DeviceOrchestrator())
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
    def test_rpc_create_network_function(
            self,
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
        device_data =\
            {'id': 'network_function_id',
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
        device_data =\
            {'id': 'network_function_id',
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
class DeviceOrchestratorTestCase(unittest.TestCase):

    def _initialize_ndo_handler(self):
        ndo_handler = device_orchestrator.DeviceOrchestrator(
            DummyController, cfg.CONF)
        self.event = DummyEvent(dummy_data, 'PENDING_CREATE')
        return ndo_handler

    @unittest.skip('skipping')
    @mock.patch.object(device_orchestrator.DeviceOrchestrator,
                       'device_configuration_complete')
    def test_handle_event(self, mock_device_configuration_complete):
        ndo_mgr = device_orchestrator.DeviceOrchestrator(object, cfg.CONF)
        mock_device_configuration_complete.return_value = True
        self.event = DummyEvent(dummy_data, 'DEVICE_CONFIGURED')
        self.event.id = 'DEVICE_CONFIGURED'

        ndo_mgr.handle_event(self.event)
        mock_device_configuration_complete.assert_called_with(self.event)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_check_device_up(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        ndo_handler._controller = mock.MagicMock(return_value='')
        mock_update_nfd.return_value = 100
        orig_event_data = {}
        orchestration_driver.get_network_function_device_status = (
            mock.MagicMock(return_value='ACTIVE'))
        status = 'DEVICE_UP'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]
        orig_event_data['id'] = self.event.data['id']
        poll_status = ndo_handler.check_device_is_up(self.event)
        self.assertEqual(poll_status, {'poll': False})
        orchestration_driver.get_network_function_device_status = (
            mock.MagicMock(return_value='ERROR'))
        status = 'DEVICE_NOT_UP'
        orig_event_data['status'] = status
        orig_event_data['status_description'] = ndo_handler.status_map[status]
        orig_event_data['network_function_id'] = self.event.data[
            'network_function']['id']
        orig_event_data['binding_key'] = None
        orig_event_data['network_function_instance_id'] = self.event.data[
            'network_function_instance']['id']
        orig_event_data['network_function_device_id'] = self.event.data[
            'network_function_device']['id']
        poll_status = ndo_handler.check_device_is_up(self.event)
        self.assertEqual(poll_status, {'poll': False})

        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)
        ndo_handler._controller.reset_mock()

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_health_check(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        mock_update_nfd.return_value = 100

        ndo_handler.configurator_rpc.create_network_function_device_config = (
            mock.MagicMock(return_value=101))
        orchestration_driver.get_network_function_device_config = (
            mock.MagicMock(return_value=param_req))

        self.event.data['management'] = {'port': {'ip_address': '127.0.0.1'}}
        self.event.desc = Desc()
        orig_event_data = {}
        orig_event_data['id'] = self.event.data['id']
        orig_event_data['mgmt_ip_address'] = self.event.data[
            'management']['port']['ip_address']
        orig_event_data['service_details'] = self.event.data['service_details']
        orig_event_data['network_function_id'] = self.event.data[
            'network_function']['id']
        orig_event_data['network_function_instance_id'] = self.event.data[
            'network_function_instance']['id']
        event_desc = self.event.desc.to_dict()
        orig_event_data['nfp_context'] = {'event_desc': event_desc,
                                          'id': self.event.id,
                                          'key': self.event.key}
        orig_event_data['tenant_id'] = self.event.data[
                'resource_owner_context']['admin_tenant_id']
        orig_event_data['periodicity'] = 'initial'
        ndo_handler.perform_initial_health_check(self.event)
        ndo_handler.configurator_rpc.create_network_function_device_config.\
            assert_called_with(orig_event_data, param_req)

    @mock.patch.object(nfpdb.NFPDbBase, '_get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_plug_interfaces(self, mock_update_nfd, mock_get_nfd):
        ndo_handler = self._initialize_ndo_handler()

        mock_update_nfd.return_value = 100
        orig_event_data = copy.deepcopy(self.event.data)
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=orig_event_data)
        orig_event_data['status_description'] = ''

        orchestration_driver.plug_network_function_device_interfaces = (
            mock.MagicMock(return_value=(True)))
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        orig_event_data['interfaces_in_use'] += len(orig_event_data['ports'])

        mock_get_nfd.return_value = {
            'id': 'device_id',
            'interfaces_in_use': 2
        }
        ndo_handler.plug_interfaces(self.event)
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           {'interfaces_in_use': (
                                               orig_event_data[
                                                   'interfaces_in_use'])})

        orchestration_driver.plug_network_function_device_interfaces = (
            mock.MagicMock(return_value=(False)))
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        event_id = 'DEVICE_CONFIGURATION_FAILED'

        ndo_handler.plug_interfaces(self.event)
        ndo_handler._create_event.assert_called_with(
            event_id=event_id,
            event_data=orig_event_data,
            is_internal_event=True)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_create_device_configuration(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        config_params = {
            'param1': 'value1',
            'parama2': 'value2',
            'config': [{'resource_data': {'forward_route': True}}]}
        orchestration_driver.get_network_function_device_config = (
            mock.MagicMock(return_value=config_params))
        ndo_handler.configurator_rpc.create_network_function_device_config = (
            mock.MagicMock(return_value=True))
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        ndo_handler._controller.event_complete = mock.MagicMock(
                            return_value=None)
        self._update_event()
        device = self._get_device()
        ndo_handler.create_device_configuration(self.event)
        event_id = "UPDATE_DEVICE_CONFIG_PARAMETERS"
        nfp_context = copy.deepcopy(device['nfp_context'])
        nfp_context.update(resource_owner_context=self.event.data[
            'resource_owner_context'],
                           management=self.event.data['management'],
                           admin_token=self.event.data['admin_token'],
                           service_chain_specs=self.event.data[
                               'service_chain_specs'],
                           network_function_device_id=self.event.data[
                               'network_function_device_id'],
                           provider=self.event.data['provider'],
                           id=self.event.data['network_function_device_id'],
                           reference_count=self.event.data['reference_count'],
                           network_function_instance=self.event.data[
                               'network_function_instance'],
                           mgmt_port_id=[{'port_role': 'active',
                                          'port_model': 'neutron',
                                          'id': 'myid1',
                                          'port_classification': (
                                              'management')}],
                           network_function=self.event.data[
                               'network_function'],
                           network_function_id='network_function_id',
                           service_details=self.event.data['service_details'],
                           network_function_instance_id=(
                               'network_function_instance_id'),
                           consumer=self.event.data['consumer'],
                           ports=self.event.data['ports'],
                           interfaces_in_use=self.event.data[
                               'interfaces_in_use'],
                           status='PENDING_CREATE')
        nfp_context.pop('binding_key', None)
        nfp_context.pop('key', None)
        event_data = {'device': device, 'nfp_context': nfp_context,
                      'config_params': config_params}
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                                     event_data=event_data)

    def _update_event(self):
        self.event.data['management'] = {'port': {'ip_address': '127.0.0.1'}}
        self.event.data['provider']['port'] = {
            'ip_address': '127.0.0.1', 'mac_address': 'xx:xx:xx:xx'}
        self.event.data['consumer']['port'] = {
            'ip_address': '127.0.0.1', 'mac_address': 'xx:xx:xx:xx'}
        self.event.data['provider']['subnet'] = {
            'cidr': '11.0.0.0/24', 'gateway_ip': '11.0.0.1'}
        self.event.data['consumer']['subnet'] = {
            'cidr': '11.0.0.0/24', 'gateway_ip': '11.0.0.1'}
        self.event.data['network_function_device'][
            'mgmt_ip_address'] = self.event.data['management']['port'][
            'ip_address']
        self.event.data['service_chain_specs'] = []
        self.event.desc = Desc()

    def _get_device(self):
        device = {}
        device['mgmt_ip_address'] = self.event.data[
            'management']['port']['ip_address']
        device['consumer_gateway_ip'] = self.event.data[
            'consumer']['subnet']['gateway_ip']
        device['mgmt_ip'] = self.event.data['management']['port']['ip_address']
        device['provider_gateway_ip'] = self.event.data[
            'provider']['subnet']['gateway_ip']
        device['consumer_mac'] = self.event.data[
            'consumer']['port']['mac_address']
        device['id'] = self.event.data['id']
        device['nfp_context'] = {'event_desc': self.event.desc.to_dict(),
                                 'binding_key': self.event.binding_key,
                                 'id': self.event.id, 'key': self.event.key,
                                 'network_function_device': self.event.data[
                                     'network_function_device']}
        device['tenant_id'] = self.event.data[
            'resource_owner_context']['admin_tenant_id']
        device.update({
            'provider_mac': self.event.data['provider']['port']['mac_address'],
            'network_function_instance_id': self.event.data[
                'network_function_instance']['id'],
            'provider_ip': self.event.data['provider']['port']['ip_address'],
            'network_function_id': self.event.data['network_function']['id'],
            'service_details': self.event.data['service_details'],
            'consumer_ip': self.event.data['consumer']['port']['ip_address'],
            'consumer_cidr': self.event.data['consumer']['subnet']['cidr'],
            'provider_cidr': self.event.data['provider']['subnet']['cidr']})
        return device

    def test_update_config_params(self):
        ndo_handler = self._initialize_ndo_handler()
        ndo_handler._controller.event_complete = mock.MagicMock(
                return_value=None)
        ndo_handler.update_config_params(self.event)
        ndo_handler._create_event.assert_called_with(
                event_id='DEVICE_CONFIG_PARAMETERS_UPDATED',
                event_data=self.event.data, is_internal_event=True)

    def test_device_configuration_updated(self):
        ndo_handler = self._initialize_ndo_handler()
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        ndo_handler._controller.event_complete = mock.MagicMock(
                            return_value=None)
        ndo_handler.configurator_rpc.create_network_function_device_config = (
            mock.MagicMock(return_value=True))

        config_params = {
            'param1': 'value1',
            'param2': 'value2',
            'config': [{'resource_data': {'forward_route': True}}]}
        orchestration_driver.get_network_function_device_config = (
            mock.MagicMock(return_value=config_params))
        self._update_event()
        device = self._get_device()
        self.event.data['device'] = device
        self.event.data['nfp_context'] = {'service_chain_specs': []}
        self.event.data['config_params'] = config_params
        ndo_handler.device_configuration_updated(self.event)
        ndo_handler.configurator_rpc.create_network_function_device_config.\
            assert_called_with(device, config_params)

    @mock.patch.object(nfpdb.NFPDbBase, '_get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_device_configuration_complete(self,
                                           mock_update_nfd, mock_get_nfd):
        ndo_handler = self._initialize_ndo_handler()
        device = self.event.data
        status = 'ACTIVE'
        device = {'nfp_context': device}
        device['nfp_context']['network_function_device']['reference_count'] = 0
        device['nfp_context']['network_function_device']['status'] = status
        device['nfp_context']['network_function_device'][
            'status_description'] = ndo_handler.status_map[status]
        reference_count = device['nfp_context']['network_function_device'][
            'reference_count'] + 1
        event_desc = Desc()
        device['nfp_context']['event_desc'] = event_desc.to_dict()
        device['nfp_context']['key'] = self.event.key
        device['nfp_context']['binding_key'] = self.event.binding_key
        ndo_handler._prepare_device_data = mock.MagicMock(return_value=device)
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        ndo_handler.nsf_db.get_network_function_device = (
            mock.MagicMock(return_value={'reference_count': (
                reference_count - 1)}))
        self.event.data = device
        ndo_handler._controller = mock.MagicMock(return_value=True)
        mock_get_nfd.return_value = {
            'id': 'device_id',
            'reference_count': 0
        }

        ndo_handler.device_configuration_complete(self.event)
        ndo_handler._controller.reset_mock()

    @mock.patch.object(nfpdb.NFPDbBase, 'get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'get_network_function')
    @mock.patch.object(nfpdb.NFPDbBase, 'get_port_info')
    def test_delete_network_function_device(self, mock_get_port, mock_get_nf,
                                            mock_update_nfd, mock_get_nfd):
        ndo_handler = self._initialize_ndo_handler()
        delete_event_req = DummyEvent(dummy_data, 'ACTIVE')
        delete_event_req.data = \
            {'network_function_device_id': 'device-id',
             'network_function_instance': {'id': 'nfi-id',
                                           'port_info': []},
             'network_function_device': {'id': 'device-id'}}
        mgmt_port_id = {'id': 'port-id', 'port_model': 'port-policy'}
        ndo_handler._prepare_device_data_fast = mock.MagicMock(
            return_value=delete_event_req.data)
        ndo_handler._get_service_type = mock.MagicMock(
            return_value='service-type')
        ndo_handler._get_port = mock.MagicMock(return_value=mgmt_port_id)

        mock_get_port.return_value = mgmt_port_id
        mock_get_nfd.return_value = {'id': 'device-id',
                                     'mgmt_port_id': ['mgmt-data-port-id']}
        delete_event_req.data.update(
            {'event_desc': delete_event_req.desc.to_dict()})
        event_id = 'DELETE_CONFIGURATION'
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        delete_event_req.context = delete_event_req.data
        ndo_handler.delete_network_function_device(delete_event_req)
        ndo_handler._create_event.assert_called_with(
            event_id=event_id,
            event_data=delete_event_req.data,
            is_internal_event=True)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_delete_device_configuration(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        config_params = {'param1': 'value1', 'parama2': 'value2'}
        self.event = DummyEvent(dummy_data, 'ACTIVE')
        orchestration_driver.get_network_function_device_config = (
            mock.MagicMock(return_value=config_params))
        ndo_handler.configurator_rpc.delete_network_function_device_config = (
            mock.MagicMock(return_value=True))

        ndo_handler.delete_device_configuration(self.event)
        ndo_handler.configurator_rpc.delete_network_function_device_config.\
            assert_called_with(self.event.data, config_params)

    @mock.patch.object(nfpdb.NFPDbBase, '_get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_unplug_interfaces(self, mock_update_nfd, mock_get_nfd):

        ndo_handler = self._initialize_ndo_handler()
        self.event = DummyEvent(dummy_data, 'ACTIVE')
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=self.event.data)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = (
            ndo_handler.status_map['ACTIVE'])
        orchestration_driver.unplug_network_function_device_interfaces = (
            mock.MagicMock(return_value=(True, [])))

        ndo_handler._controller.event_complete = mock.MagicMock(
            return_value=None)

        mock_get_nfd.return_value = {
            'id': 'device_id',
            'interfaces_in_use': 1,
            'reference_count': 1,
        }
        ndo_handler.unplug_interfaces(self.event)

        orig_event_data['interfaces_in_use'] -= len(orig_event_data['ports'])
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'], mock.ANY)

        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = (
            ndo_handler.status_map['ACTIVE'])
        orchestration_driver.unplug_network_function_device_interfaces = (
            mock.MagicMock(return_value=(False, [])))

        ndo_handler.unplug_interfaces(self.event)
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           {'interfaces_in_use': (
                                               orig_event_data[
                                                   'interfaces_in_use'])})

    """
    @mock.patch.object(nfpdb.NFPDbBase, 'delete_network_function_device')
    def test_device_delete(self, mock_delete_nfd):
        ndo_handler = self._initialize_ndo_handler()
        self.event = DummyEvent(101, 'ACTIVE', 1)
        ndo_handler._prepare_device_data = mock.MagicMock(
            return_value=self.event.data)
        orig_event_data = copy.deepcopy(self.event.data)
        orchestration_driver.delete_network_function_device = (
            mock.MagicMock(return_value=True))
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.delete_device(self.event)

        event_id = 'DEVICE_DELETED'
        orig_event_data['reference_count'] -= 1

        mock_delete_nfd.assert_called_with(ndo_handler.db_session,
                                           self.event.data['id'])
        ndo_handler._create_event.assert_called_with(event_id=event_id,
                                             event_data=orig_event_data)
    """

    def test_handle_device_create_error(self):
        ndo_handler = self._initialize_ndo_handler()
        event_id = status = 'DEVICE_CREATE_FAILED'
        self.event = DummyEvent(dummy_data, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_create_error(self.event)
        ndo_handler._create_event.assert_called_with(
            event_id=event_id,
            event_data=orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_not_up(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        ndo_handler._controller.new_event = mock.MagicMock(
                    return_value=self.event)
        ndo_handler._controller.event_complete = mock.MagicMock(
                    return_value=None)
        status = 'ERROR'
        desc = 'Device not became ACTIVE'
        self.event = DummyEvent(dummy_data, status, 1)
        orig_event_data = copy.deepcopy(self.event.data)
        orig_event_data['status_description'] = desc
        orig_event_data.pop('interfaces_in_use', None)
        orig_event_data.pop('reference_count', None)
        ndo_handler._create_event = mock.MagicMock(return_value=True)

        ndo_handler.handle_device_not_up(self.event)
        orig_event_data['network_function_device_id'] = orig_event_data['id']
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           orig_event_data['id'],
                                           orig_event_data)

    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_not_reachable(self, mock_update_nfd):
        ndo_handler = self._initialize_ndo_handler()
        status = 'ERROR'
        self.event = DummyEvent(dummy_data, status, 1)
        desc = 'Device not reachable, Health Check Failed'
        tmp_data = copy.deepcopy(self.event.data)
        device = self.event.data
        device = {'nfp_context': device,
                  'id': self.event.data['network_function_device']['id'],
                  'network_function_device_id': (
                      self.event.data['network_function_device']['id'])}
        device['nfp_context']['network_function_device']['reference_count'] = 0
        device['nfp_context']['network_function_device']['status'] = status
        device['nfp_context']['network_function_device'][
            'status_description'] = desc
        device['nfp_context']['network_function_device'][
            'reference_count'] += 1
        event_desc = Desc()
        device['nfp_context']['event_desc'] = event_desc.to_dict()
        device['nfp_context']['key'] = self.event.key
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        ndo_handler._controller = mock.MagicMock(return_value=True)
        self.event.data = device
        ndo_handler.handle_device_not_reachable(self.event)
        device['nfp_context']['network_function_device'].pop(
            'reference_count', None)
        device['nfp_context']['network_function_device'].pop(
            'interfaces_in_use', None)
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           device['nfp_context'][
                                               'network_function_device'][
                                                   'id'],
                                           device)
        ndo_handler._controller.reset_mock()

        self.event.data = tmp_data

    @mock.patch.object(nfpdb.NFPDbBase, '_get_network_function_device')
    @mock.patch.object(nfpdb.NFPDbBase, 'update_network_function_device')
    def test_handle_device_config_failed(self, mock_update_nfd, mock_get_nfd):
        ndo_handler = self._initialize_ndo_handler()
        status = 'ERROR'
        self.event = DummyEvent(dummy_data, status, 1)
        desc = 'Configuring Device Failed.'
        tmp_data = copy.deepcopy(self.event.data)
        device = self.event.data
        device = {'nfp_context': device,
                  'id': self.event.data['network_function_device']['id']}
        device['nfp_context']['network_function_device']['reference_count'] = 0
        device['nfp_context']['network_function_device']['status'] = status
        device['nfp_context']['network_function_device'][
            'status_description'] = desc
        reference_count = device['nfp_context']['network_function_device'][
            'reference_count'] + 1
        event_desc = Desc()
        device['nfp_context']['event_desc'] = event_desc.to_dict()
        device['nfp_context']['key'] = self.event.key
        device['nfp_context']['binding_key'] = self.event.binding_key
        ndo_handler._create_event = mock.MagicMock(return_value=True)
        ndo_handler._controller = mock.MagicMock(return_value=True)
        ndo_handler.nsf_db.get_network_function_device = (
            mock.MagicMock(return_value={'reference_count': (
                reference_count - 1)}))
        self.event.data = device
        mock_get_nfd.return_value = {
            'id': 'device_id',
            'reference_count': 0
        }
        ndo_handler.handle_device_config_failed(self.event)
        mock_update_nfd.assert_called_with(ndo_handler.db_session,
                                           device['nfp_context'][
                                               'network_function_device'][
                                                   'id'],
                                           {'status': 'ERROR',
                                            'status_description':
                                                'Configuring Device Failed.',
                                            'id': 'vm-id'})
        ndo_handler._controller.reset_mock()

        self.event.data = tmp_data


def main():
    unittest.main()

if __name__ == '__main__':
    main()
