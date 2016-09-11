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

import mock

from keystoneclient.v2_0 import client as identity_client

from oslo_config import cfg

from gbpservice.neutron.tests.unit.nfp.orchestrator.db import test_nfp_db
from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions as nfp_exc
from gbpservice.nfp.core import context as nfp_core_context
from gbpservice.nfp.core import controller  # noqa
from gbpservice.nfp.core.event import Event as NFP_EVENT
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.modules import (
    service_orchestrator as nso)
from gbpservice.nfp.orchestrator.openstack import openstack_driver

import uuid as pyuuid


def Event(**kwargs):
    data = kwargs.get('data')
    key = pyuuid.uuid4()
    return NFP_EVENT(key=key,
                     id='',
                     data=data)


class NSOModuleTestCase(test_nfp_db.NFPDBTestCase):

    def setUp(self):
        super(NSOModuleTestCase, self).setUp()

    @mock.patch.object(nso, 'events_init')
    @mock.patch.object(nso, 'rpc_init')
    def test_module_init(self, mock_rpc_init, mock_events_init):
        controller = mock.Mock()
        with mock.patch.object(identity_client, "Client"):
            nso.nfp_module_init(controller, cfg.CONF)
            mock_events_init.assert_called_once_with(
                controller, cfg.CONF, mock.ANY)
            call_args, call_kwargs = mock_events_init.call_args
            self.assertIsInstance(call_args[2],
                                  nso.ServiceOrchestrator)
            mock_rpc_init.assert_called_once_with(controller, cfg.CONF)

    def test_rpc_init(self):
        controller = mock.Mock()
        nso.rpc_init(controller, cfg.CONF)
        controller.register_rpc_agents.assert_called_once_with(mock.ANY)
        call_args, call_kwargs = controller.register_rpc_agents.call_args
        self.assertEqual(2, len(call_args[0]))
        self.assertIsInstance(call_args[0][0], nso.RpcAgent)

    def test_events_init(self):
        controller = mock.Mock()
        with mock.patch.object(identity_client, "Client"):
            nso.events_init(
                controller, cfg.CONF,
                nso.ServiceOrchestrator(controller, cfg.CONF))
            controller.register_events.assert_called_once_with(mock.ANY)


class NSORpcHandlerTestCase(NSOModuleTestCase):

    def setUp(self):
        super(NSORpcHandlerTestCase, self).setUp()
        self.controller = mock.Mock()
        self.rpc_handler = nso.RpcHandler(cfg.CONF, self.controller)

    @mock.patch.object(nso.ServiceOrchestrator,
                       "create_network_function")
    def test_rpc_create_network_function(self, mock_create_network_function):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.create_network_function(
                "context", "network_function")
            mock_create_network_function.assert_called_once_with(
                "context", "network_function")

    @mock.patch.object(nso.ServiceOrchestrator,
                       "get_network_function")
    def test_rpc_get_network_function(self, mock_get_network_function):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.get_network_function(
                "context", "network_function_id")
            mock_get_network_function.assert_called_once_with(
                "context", "network_function_id")

    @mock.patch.object(nso.ServiceOrchestrator,
                       "get_network_functions")
    def test_rpc_get_network_functions(self, mock_get_network_functions):
        with mock.patch.object(identity_client, "Client"):
            filters = {'id': ['myuuid']}
            self.rpc_handler.get_network_functions("context", filters=filters)
            mock_get_network_functions.assert_called_once_with(
                "context", filters)

    @mock.patch.object(nso.ServiceOrchestrator,
                       "delete_network_function")
    def test_rpc_delete_network_function(self, mock_delete_network_function):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.delete_network_function(
                "context", "network_function_id")
            mock_delete_network_function.assert_called_once_with(
                "context", "network_function_id")

    @mock.patch.object(nso.ServiceOrchestrator,
                       "update_network_function")
    def test_rpc_update_network_function(self, mock_update_network_function):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.update_network_function(
                "context", "network_function_id", "updated_network_function")
            mock_update_network_function.assert_called_once_with(
                "context", "network_function_id", "updated_network_function")

    @mock.patch.object(nso.ServiceOrchestrator,
                       "handle_policy_target_added")
    def test_rpc_policy_target_added_notification(
            self, mock_handle_policy_target_added):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.policy_target_added_notification(
                "context", "network_function_id", "policy_target")
            mock_handle_policy_target_added.assert_called_once_with(
                "context", "network_function_id", "policy_target")

    @mock.patch.object(nso.ServiceOrchestrator,
                       "handle_policy_target_removed")
    def test_rpc_policy_target_removed_notification(
            self, mock_handle_policy_target_removed):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.policy_target_removed_notification(
                "context", "network_function_id", "policy_target")
            mock_handle_policy_target_removed.assert_called_once_with(
                "context", "network_function_id", "policy_target")

    @mock.patch.object(
        nso.ServiceOrchestrator, "handle_consumer_ptg_added")
    def test_rpc_consumer_ptg_added_notification(
            self, mock_handle_consumer_ptg_added):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.consumer_ptg_added_notification(
                "context", "network_function_id", "policy_target_group")
            mock_handle_consumer_ptg_added.assert_called_once_with(
                "context", "network_function_id", "policy_target_group")

    @mock.patch.object(
        nso.ServiceOrchestrator, "handle_consumer_ptg_removed")
    def test_rpc_consumer_ptg_removed_notification(
            self, mock_handle_consumer_ptg_removed):
        with mock.patch.object(identity_client, "Client"):
            self.rpc_handler.consumer_ptg_removed_notification(
                "context", "network_function_id", "policy_target_group")
            mock_handle_consumer_ptg_removed.assert_called_once_with(
                "context", "network_function_id", "policy_target_group")


class ServiceOrchestratorTestCase(NSOModuleTestCase):

    def setUp(self):
        super(ServiceOrchestratorTestCase, self).setUp()
        self.controller = mock.Mock()
        self.context = mock.Mock()
        cfg.CONF.set_override("auth_version", "v1", group="keystone_authtoken")
        with mock.patch.object(identity_client, "Client"):
            self.service_orchestrator = nso.ServiceOrchestrator(
                self.controller,
                cfg.CONF)
            self.service_orchestrator.config_driver.\
                parse_template_config_string = (mock.Mock(return_value=(
                    'heat_config',
                    'template')))

    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_tenant_id")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "create_network_function_user_config")
    def test_create_network_function(self, mock_rpc, mock_create_event,
                                     mock_get_service_profile,
                                     mock_get_admin_token,
                                     mock_get_admin_tenant_id):
        network_function_info = {
            'tenant_id': 'tenant_id',
            'service_chain_id': 'sc_instance_id',
            'service_id': 'sc_node_id',
            'service_profile_id': 'service_profile_id',
            'management_ptg_id': 'mgmt_ptg_id',
            'service_cfg.CONF': '',
            'port_info': {
                'id': 'provider_port_id',
                'port_model': nfp_constants.GBP_PORT,
                'port_classification': nfp_constants.PROVIDER
            },
            'network_function_mode': nfp_constants.GBP_MODE,
            'provider': None,
            'consumer': None,
            'resource_owner_context': {'admin_token': str(pyuuid.uuid4()),
                                       'admin_tenant_id': str(pyuuid.uuid4())},
            'service_chain_instance': {'id': str(pyuuid.uuid4())},
            'service_chain_node': {'id': str(pyuuid.uuid4())},
            'service_profile': {'id': str(pyuuid.uuid4()),
                                'service_flavor': None,
                                'service_type': 'xyz'},
            'service_config': None,
            'network_function_mode': 'gbp'
        }
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'None',
                          'service_vendor': 'vyos'})
        self.service_orchestrator.config_driver.\
            parse_template_config_string = mock.MagicMock(
                return_value=('heat_config', '{}'))
        network_function = self.service_orchestrator.create_network_function(
            self.context, network_function_info)
        self.assertIsNotNone(network_function)
        db_network_function = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual(network_function, db_network_function)

    def test_validate_create_service_input(self):
        network_function = {}
        self.assertRaises(
            nfp_exc.RequiredDataNotProvided,
            self.service_orchestrator._validate_create_service_input,
            self.context, network_function)

        network_function = {
            "tenant_id": "test",
            "service_id": "test",
            "service_chain_id": "test",
            "service_profile_id": "test",
            "network_function_mode": "test",
            'network_function_mode': nfp_constants.GBP_MODE,
            'provider': None,
            'consumer': None,
            'resource_owner_context': {'admin_token': str(pyuuid.uuid4()),
                                       'admin_tenant_id': str(pyuuid.uuid4())},
            'service_chain_instance': {'id': str(pyuuid.uuid4())},
            'service_chain_node': {'id': str(pyuuid.uuid4())},
            'service_profile': {'id': str(pyuuid.uuid4()),
                                'service_flavor': None, 'service_type': 'xyz'},
            'service_config': None,
            'network_function_mode': 'gbp',
            'management_ptg_id': None
        }
        return_value = (
            self.service_orchestrator._validate_create_service_input(
                self.context, network_function))
        self.assertIsNone(return_value)

    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "delete_network_function_user_config")
    def test_delete_network_function_without_nfi(self, mock_rpc,
                                                 mock_get_service_profile,
                                                 mock_get_admin_token):
        network_function = self.create_network_function()
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        self.service_orchestrator.delete_network_function(
            self.context, network_function['id'])
        self.assertRaises(nfp_exc.NetworkFunctionNotFound,
                          self.nfp_db.get_network_function,
                          self.session, network_function['id'])
        self.assertFalse(self.controller.event.called)
        self.assertFalse(self.controller.rpc_event.called)

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "delete_network_function_user_config")
    def test_delete_network_function_with_nfi(self, mock_rpc,
                                              mock_get_service_profile,
                                              mock_get_admin_token,
                                              mock_create_event):
        network_function_instance = self.create_network_function_instance()
        network_function_id = network_function_instance['network_function_id']
        network_function = self.nfp_db.get_network_function(
            self.session, network_function_id)
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        tag_str = 'heat_config'
        self.service_orchestrator.delete_network_function(
            self.context, network_function_id)
        network_function = self.nfp_db.get_network_function(
            self.session, network_function_id)
        self.assertEqual('PENDING_DELETE', network_function['status'])
        network_function_details = (
            self.service_orchestrator.get_network_function_details(
                network_function['id']))
        del network_function_details['service_type']
        service_config = network_function['service_config']
        network_function_data = {
            'service_type': mock.ANY,
            'network_function_details': network_function_details
        }
        mock_rpc.assert_called_once_with(
            network_function_data, service_config, tag_str)

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    def test_event_create_network_function_instance(self, mock_create_event):
        network_function = self.create_network_function()
        network_function_port_info = [
            {
                'id': 'provider_port_id',
                'port_model': nfp_constants.GBP_PORT,
                'port_classification': nfp_constants.PROVIDER
            },
            {
                'id': 'consumer_port_id',
                'port_model': nfp_constants.GBP_PORT,
                'port_classification': nfp_constants.CONSUMER
            }
        ]
        management_network_info = {
            'id': 'management_ptg_id',
            'port_model': nfp_constants.GBP_PORT
        }

        create_nfi_request = {
            'network_function': network_function,
            'network_function_port_info': network_function_port_info,
            'management_network_info': management_network_info,
            'service_type': 'service_type',
            'service_details': {'service_vendor': 'vendor',
                                'service_type': 'xyz'},
            'service_vendor': 'vendor',
            'share_existing_device': True,
            'service_profile': None,
            'consumer': {'pt': None},
            'provider': {'pt': None}
        }
        test_event = Event(data=create_nfi_request)
        self.assertEqual([], network_function['network_function_instances'])
        self.service_orchestrator.create_network_function_instance(
            test_event)
        db_network_function = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual(
            1, len(db_network_function['network_function_instances']))
        # The value of port_info in network_function_instance is a list
        # when we do a DB get, the order changes resulting in test failing
        # if we validate the event data
        mock_create_event.assert_called_once_with(
            'CREATE_NETWORK_FUNCTION_DEVICE', event_data=mock.ANY)

    def test_event_handle_device_created(self):
        nfd = self.create_network_function_device()
        nfi = self.create_network_function_instance(create_nfd=False)
        request_data = {
            'network_function_instance_id': nfi['id'],
            'network_function_device_id': nfd['id']
        }
        test_event = Event(data=request_data)
        self.assertIsNone(nfi['network_function_device_id'])
        self.service_orchestrator.handle_device_created(
            test_event)
        db_nfi = self.nfp_db.get_network_function_instance(
            self.session, nfi['id'])
        self.assertEqual(nfd['id'], db_nfi['network_function_device_id'])

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "create_network_function_user_config")
    def test_event_handle_device_active(self, mock_create_rpc,
                                        mock_service_profile,
                                        mock_admin_token,
                                        mock_create_event):
        nfd = self.create_network_function_device()
        nfi = self.create_network_function_instance(create_nfd=False)
        request_data = {
            'network_function_instance_id': nfi['id'],
            'network_function_device_id': nfd['id']
        }
        test_event = Event(data=request_data)
        self.assertIsNone(nfi['network_function_device_id'])
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "apply_config") as mock_apply_user_config:
            mock_apply_user_config.return_value = "stack_id"
            self.service_orchestrator.handle_device_active(
                test_event)
        db_nfi = self.nfp_db.get_network_function_instance(
            self.session, nfi['id'])
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        self.assertEqual(nfd['id'], db_nfi['network_function_device_id'])
        self.assertIsNotNone(db_nf['heat_stack_id'])

    def test_event_handle_device_create_failed(self):
        nfd = self.create_network_function_device()
        nfi = self.create_network_function_instance(create_nfd=False)
        request_data = {
            'network_function_instance_id': nfi['id'],
            'network_function_device_id': nfd['id']
        }
        test_event = Event(data=request_data)
        self.assertIsNone(nfi['network_function_device_id'])
        self.service_orchestrator.handle_device_create_failed(
            test_event)
        db_nfi = self.nfp_db.get_network_function_instance(
            self.session, nfi['id'])
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        self.assertEqual(nfp_constants.ERROR, db_nfi['status'])
        self.assertEqual(nfp_constants.ERROR, db_nf['status'])

    def test_event_check_for_user_config_complete(self):
        network_function = self.create_network_function()
        network_function_details = (
            self.service_orchestrator.get_network_function_details(
                network_function['id']))
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "check_config_complete") as mock_is_config_complete,\
                mock.patch.object(identity_client, "Client"):
            # Verify return status IN_PROGRESS from cfg.CONF driver
            mock_is_config_complete.return_value = "IN_PROGRESS"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id'],
                'network_function_details': network_function_details,
                'network_function': {'id': network_function['id']},
                'event_desc': {'poll_desc': None, 'worker': None,
                               'flag': None, 'type': None,
                               'uuid': 'a1251c79-f661-440e-aab2-a1f401865daf:'}
            }
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_complete(
                test_event)
            mock_is_config_complete.assert_called_once_with(
                request_data)
            self.nfp_db.get_network_function(
                self.session, network_function['id'])
            self.assertEqual(status, nso.CONTINUE_POLLING)

            # Verify return status ERROR from cfg.CONF driver
            mock_is_config_complete.reset_mock()
            mock_is_config_complete.return_value = "ERROR"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id'],
                'network_function_details': network_function_details,
                'network_function': {'id': network_function['id']},
                'event_desc': {'poll_desc': None, 'worker': None,
                               'flag': None, 'type': None,
                               'uuid': 'a1251c79-f661-440e-aab2-a1f401865daf:'}
            }
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_complete(
                test_event)
            mock_is_config_complete.assert_called_once_with(
                request_data)
            self.nfp_db.get_network_function(
                self.session, network_function['id'])
            self.assertEqual(status, nso.STOP_POLLING)

            # Verify return status COMPLETED from cfg.CONF driver
            self.controller.poll_event_done.reset_mock()
            mock_is_config_complete.reset_mock()
            mock_is_config_complete.return_value = "COMPLETED"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id'],
                'network_function_details': network_function_details,
                'network_function': {'id': network_function['id']},
                'event_desc': {'poll_desc': None, 'worker': None,
                               'flag': None, 'type': None,
                               'uuid': 'a1251c79-f661-440e-aab2-a1f401865daf:'}
            }
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_complete(
                test_event)
            mock_is_config_complete.assert_called_once_with(
                request_data)
            self.nfp_db.get_network_function(
                self.session, network_function['id'])
            self.assertEqual(status, nso.STOP_POLLING)

    def test_event_handle_user_config_applied(self):
        network_function = self.create_network_function()
        request_data = {
            'heat_stack_id': 'heat_stack_id',
            'network_function_id': network_function['id']
        }
        test_event = Event(data=request_data)
        self.service_orchestrator.handle_user_config_applied(test_event)
        db_nf = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual('ACTIVE', db_nf['status'])

    def test_event_handle_user_config_failed(self):
        network_function = self.create_network_function()
        request_data = {
            'heat_stack_id': 'heat_stack_id',
            'network_function_id': network_function['id']
        }
        test_event = Event(data=request_data)
        self.service_orchestrator.handle_user_config_failed(test_event)
        db_nf = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual('ERROR', db_nf['status'])

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    def test_event_check_for_user_config_deleted(self, mock_create_event):
        network_function = self.create_network_function()
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "is_config_delete_complete") as mock_is_config_delete_complete:
            # Verify return status IN_PROGRESS from cfg.CONF driver
            mock_is_config_delete_complete.return_value = "IN_PROGRESS"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id']}
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_deleted(
                test_event)
            mock_is_config_delete_complete.assert_called_once_with(
                request_data['heat_stack_id'], network_function['tenant_id'],
                network_function)
            db_nf = self.nfp_db.get_network_function(
                self.session, network_function['id'])
            self.assertEqual(network_function['status'], db_nf['status'])
            self.assertEqual(network_function['heat_stack_id'],
                             db_nf['heat_stack_id'])
            self.assertEqual(status, nso.CONTINUE_POLLING)

            # Verify return status ERROR from cfg.CONF driver
            mock_is_config_delete_complete.reset_mock()
            mock_is_config_delete_complete.return_value = "ERROR"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id']}
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_deleted(
                test_event)
            mock_is_config_delete_complete.assert_called_once_with(
                request_data['heat_stack_id'], network_function['tenant_id'],
                network_function)
            event_data = {
                'network_function_id': network_function['id']
            }
            mock_create_event.assert_called_once_with(
                'USER_CONFIG_DELETE_FAILED', event_data=event_data,
                is_internal_event=True)
            self.assertEqual(status, nso.STOP_POLLING)

            # Verify return status COMPLETED from cfg.CONF driver
            self.controller.poll_event_done.reset_mock()
            mock_is_config_delete_complete.reset_mock()
            mock_create_event.reset_mock()
            mock_is_config_delete_complete.return_value = "COMPLETED"
            request_data = {
                'tenant_id': network_function['tenant_id'],
                'heat_stack_id': 'heat_stack_id',
                'network_function_id': network_function['id'],
                'action': 'update'}
            test_event = Event(data=request_data)
            status = self.service_orchestrator.check_for_user_config_deleted(
                test_event)
            mock_is_config_delete_complete.assert_called_once_with(
                request_data['heat_stack_id'], network_function['tenant_id'],
                network_function)
            db_nf = self.nfp_db.get_network_function(
                self.session, network_function['id'])
            self.assertEqual(None, db_nf['heat_stack_id'])
            mock_create_event.assert_called_once_with(
                'UPDATE_USER_CONFIG_IN_PROGRESS', event_data=request_data,
                original_event=test_event)
            self.assertEqual(status, nso.STOP_POLLING)

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "delete_network_function_user_config")
    def test_event_handle_user_config_deleted(self, mock_delete_rpc,
                                              mock_get_admin_token,
                                              mock_get_service_profile,
                                              mock_create_event):
        nfi = self.create_network_function_instance()
        request_data = {
            'network_function_id': nfi['network_function_id']
        }
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        test_event = Event(data=request_data)
        # test_event.status = 'PTG_ADD_IN_PROGRESS'
        test_event.data['status'] = 'status'
        self.service_orchestrator.handle_user_config_deleted(test_event)
        mock_create_event.assert_called_once_with(
            'DELETE_NETWORK_FUNCTION_INSTANCE', event_data=nfi['id'],
            is_internal_event=True)

    def test_event_handle_user_config_delete_failed(self):
        network_function = self.create_network_function()
        request_data = {
            'network_function_id': network_function['id']
        }
        test_event = Event(data=request_data)
        self.service_orchestrator.handle_user_config_delete_failed(test_event)
        db_nf = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual('ERROR', db_nf['status'])

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "delete_network_function_user_config")
    def test_delete_network_function(self, mock_rpc, mock_get_service_profile,
                                     mock_get_admin_token,
                                     mock_create_event):
        nfi = self.create_network_function_instance()
        network_function = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        tag_str = 'heat_config'
        self.assertEqual([nfi['id']],
                         network_function['network_function_instances'])
        self.service_orchestrator.delete_network_function(
            self.context, network_function['id'])
        db_nf = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        self.assertEqual('PENDING_DELETE', db_nf['status'])
        network_function_details = (
            self.service_orchestrator.get_network_function_details(
                network_function['id']))
        del network_function_details['service_type']
        service_config = network_function['service_config']
        network_function_data = {
            'service_type': mock.ANY,
            'network_function_details': network_function_details
        }
        mock_rpc.assert_called_once_with(
            network_function_data, service_config, tag_str)

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    def test_event_delete_network_function_instance(self, mock_create_event):
        nfi = self.create_network_function_instance()
        network_function = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        self.assertEqual([nfi['id']],
                         network_function['network_function_instances'])
        test_event = Event(data=nfi['id'])
        self.service_orchestrator.delete_network_function_instance(
            test_event)
        db_nfi = self.nfp_db.get_network_function_instance(
            self.session, nfi['id'])
        self.assertEqual(nfp_constants.PENDING_DELETE, db_nfi['status'])
        delete_event_data = {
            'network_function_id': nfi['network_function_id'],
            'network_function_device_id': nfi['network_function_device_id'],
            'network_function_instance': db_nfi
        }
        mock_create_event.assert_called_once_with(
            'DELETE_NETWORK_FUNCTION_DEVICE',
            event_data=delete_event_data)

    def test_event_handle_device_deleted(self):
        nfi = self.create_network_function_instance()
        ns_id = nfi['network_function_id']
        request_data = {'network_function_instance_id': nfi['id']}
        test_event = Event(data=request_data)
        self.service_orchestrator.handle_device_deleted(
            test_event)
        self.assertRaises(nfp_exc.NetworkFunctionInstanceNotFound,
                          self.nfp_db.get_network_function_instance,
                          self.session,
                          nfi['id'])
        self.assertRaises(nfp_exc.NetworkFunctionNotFound,
                          self.nfp_db.get_network_function,
                          self.session,
                          ns_id)

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "policy_target_add_user_config")
    def test_handle_policy_target_added(self, mock_create_rpc,
                                        mock_get_service_profile,
                                        mock_get_admin_token,
                                        mock_create_event):
        nfi = self.create_network_function_instance()
        network_function_id = nfi['network_function_id']
        policy_target = mock.Mock()
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "handle_policy_target_operations") as\
                mock_handle_policy_target_operations:
            mock_handle_policy_target_operations.return_value = 'stack_id'
            self.service_orchestrator.handle_policy_target_added(
                self.context, network_function_id, policy_target)
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        self.assertIsNotNone(db_nf['heat_stack_id'])

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "policy_target_remove_user_config")
    def test_handle_policy_target_removed(self, mock_delete_rpc,
                                          mock_get_service_profile,
                                          mock_get_admin_token,
                                          mock_create_event):
        nfi = self.create_network_function_instance()
        network_function_id = nfi['network_function_id']
        policy_target = mock.Mock()
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "handle_policy_target_operations") as mock_handle_pt_removed:
            mock_handle_pt_removed.return_value = 'stack_id'
            self.service_orchestrator.handle_policy_target_removed(
                self.context, network_function_id, policy_target)
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        self.assertIsNotNone(db_nf['heat_stack_id'])

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "consumer_add_user_config")
    def test_handle_consumer_ptg_added(self, mock_create_rpc,
                                       mock_get_service_profile,
                                       mock_get_admin_token,
                                       mock_create_event):
        nfi = self.create_network_function_instance()
        network_function_id = nfi['network_function_id']
        policy_target_group = mock.Mock()
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        nfp_core_context.get_nfp_context = mock.MagicMock(
            return_value={})
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "handle_consumer_ptg_operations") as\
                mock_handle_consumer_ptg_added:
            mock_handle_consumer_ptg_added.return_value = 'stack_id'
            self.service_orchestrator.handle_consumer_ptg_added(
                self.context, network_function_id, policy_target_group)
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        tag_str = 'heat_config'
        self.assertIsNotNone(db_nf['heat_stack_id'])
        service_config = db_nf['service_config']
        network_function_details = (
            self.service_orchestrator.get_network_function_details(
                db_nf['id']))
        network_function_details['network_function'][
            'status'] = 'status'
        network_function_data = {
            'service_type': mock.ANY,
            'network_function_details': network_function_details,
            'consumer_ptg': policy_target_group
        }
        mock_create_rpc.assert_called_once_with(
            network_function_data, service_config, tag_str
        )

    @mock.patch.object(
        nso.ServiceOrchestrator, "_create_event")
    @mock.patch.object(
        openstack_driver.KeystoneClient, "get_admin_token")
    @mock.patch.object(
        openstack_driver.GBPClient, "get_service_profile")
    @mock.patch.object(
        nso.NSOConfiguratorRpcApi, "consumer_remove_user_config")
    def test_handle_consumer_ptg_removed(self, mock_delete_rpc,
                                         mock_get_service_profile,
                                         mock_get_admin_token,
                                         mock_create_event):
        nfi = self.create_network_function_instance()
        network_function_id = nfi['network_function_id']
        policy_target_group = mock.Mock()
        transport.parse_service_flavor_string = mock.MagicMock(
            return_value={'device_type': 'VM',
                          'service_vendor': 'vyos'})
        nfp_core_context.get_nfp_context = mock.MagicMock(
            return_value={})
        with mock.patch.object(
                self.service_orchestrator.config_driver,
                "handle_consumer_ptg_operations") as\
                mock_handle_consumer_ptg_removed:
            mock_handle_consumer_ptg_removed.return_value = 'stack_id'
            self.service_orchestrator.handle_consumer_ptg_removed(
                self.context, network_function_id, policy_target_group)
        db_nf = self.nfp_db.get_network_function(
            self.session, nfi['network_function_id'])
        tag_str = 'heat_config'
        self.assertIsNotNone(db_nf['heat_stack_id'])
        service_config = db_nf['service_config']
        network_function_details = (
            self.service_orchestrator.get_network_function_details(
                db_nf['id']))
        network_function_details['network_function'][
            'status'] = 'status'
        network_function_data = {
            'service_type': mock.ANY,
            'network_function_details': network_function_details,
            'consumer_ptg': policy_target_group
        }
        mock_delete_rpc.assert_called_once_with(
            network_function_data, service_config, tag_str
        )
