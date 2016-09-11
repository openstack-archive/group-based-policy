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

from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.db import api as db_api
from oslo_log import helpers as log_helpers
import oslo_messaging

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions as nfp_exc
from gbpservice.nfp.common import topics as nfp_rpc_topics
from gbpservice.nfp.core import context as nfp_core_context
from gbpservice.nfp.core.event import Event
from gbpservice.nfp.core import module as nfp_api
from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.config_drivers import heat_driver
from gbpservice.nfp.orchestrator.db import nfp_db as nfp_db
from gbpservice.nfp.orchestrator.openstack import openstack_driver

import sys
import traceback

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)

STOP_POLLING = {'poll': False}
CONTINUE_POLLING = {'poll': True}


def rpc_init(controller, config):
    rpcmgr = RpcHandler(config, controller)
    agent = RpcAgent(controller,
                     host=config.host,
                     topic=nfp_rpc_topics.NFP_NSO_TOPIC,
                     manager=rpcmgr)
    configurator_rpcmgr = RpcHandlerConfigurator(config, controller)
    configurator_agent = RpcAgent(
        controller,
        host=config.host,
        topic=nfp_rpc_topics.NFP_NSO_CONFIGURATOR_TOPIC,
        manager=configurator_rpcmgr)
    controller.register_rpc_agents([agent, configurator_agent])


def events_init(controller, config, service_orchestrator):
    events = ['DELETE_NETWORK_FUNCTION',
              'CREATE_NETWORK_FUNCTION_INSTANCE',
              'DELETE_NETWORK_FUNCTION_INSTANCE',
              'DEVICE_CREATED', 'DEVICE_ACTIVE', 'DEVICE_DELETED',
              'DEVICE_CREATE_FAILED', 'SEND_HEAT_CONFIG',
              'CHECK_HEAT_CONFIG_RESULT', 'APPLY_USER_CONFIG',
              'APPLY_USER_CONFIG_BASEMODE',
              'DELETE_USER_CONFIG', 'UPDATE_USER_CONFIG',
              'POLICY_TARGET_ADD', 'POLICY_TARGET_REMOVE',
              'CONSUMER_ADD', 'CONSUMER_REMOVE',
              'APPLY_USER_CONFIG_IN_PROGRESS',
              'UPDATE_USER_CONFIG_PREPARING_TO_START',
              'UPDATE_USER_CONFIG_IN_PROGRESS',
              'UPDATE_USER_CONFIG_STILL_IN_PROGRESS',
              'DELETE_USER_CONFIG_IN_PROGRESS',
              'CONFIG_APPLIED', 'USER_CONFIG_APPLIED', 'USER_CONFIG_DELETED',
              'USER_CONFIG_DELETE_FAILED', 'USER_CONFIG_UPDATE_FAILED',
              'USER_CONFIG_FAILED', 'CHECK_USER_CONFIG_COMPLETE',
              'SERVICE_CONFIGURED']
    events_to_register = []
    for event in events:
        events_to_register.append(
            Event(id=event, handler=service_orchestrator))
    controller.register_events(events_to_register)


def nfp_module_init(controller, config):
    events_init(controller, config, ServiceOrchestrator(controller, config))
    rpc_init(controller, config)


class RpcHandler(object):

    """RPC Handler for Node Driver to NFP.

    Network Function methods are invoked in an RPC Call by the
    node driver and data has to be returned by the orchestrator.
    """

    RPC_API_VERSION = '1.0'
    target = oslo_messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, controller):
        super(RpcHandler, self).__init__()
        self.conf = conf
        self._controller = controller
        # REVISIT (mak): Can a ServiceOrchestrator object be
        # initialized here and used for each rpc ?

    @log_helpers.log_method_call
    def create_network_function(self, context, network_function):
        '''Create Network Function.

        Invoked in an RPC Call. Return the Network function DB object
        created. Results in an Event for async processing of Network
        Function Instance
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.create_network_function(
            context, network_function)

    @log_helpers.log_method_call
    def get_network_function(self, context, network_function_id):
        '''Invoked in an RPC Call. Return the Network function DB object'''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function(
            context, network_function_id)

    @log_helpers.log_method_call
    def get_network_functions(self, context, filters=None):
        '''Invoked in an RPC Call.

        Returns the Network functions from DB
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_functions(
            context, filters)

    @log_helpers.log_method_call
    def update_network_function(self, context, network_function_id,
                                config):
        '''Update Network Function Configuration.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.

        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.update_network_function(
            context, network_function_id, config)

    @log_helpers.log_method_call
    def delete_network_function(self, context, network_function_id):
        '''Delete the network Function.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.delete_network_function(
            context, network_function_id)

    @log_helpers.log_method_call
    def policy_target_added_notification(self, context, network_function_id,
                                         policy_target):
        '''Update Configuration to react to member addition.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.handle_policy_target_added(
            context, network_function_id, policy_target)

    @log_helpers.log_method_call
    def policy_target_removed_notification(self, context, network_function_id,
                                           policy_target):
        '''Update Configuration to react to member deletion.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.handle_policy_target_removed(
            context, network_function_id, policy_target)

    @log_helpers.log_method_call
    def consumer_ptg_added_notification(self, context, network_function_id,
                                        policy_target_group):
        '''Update Configuration to react to consumer PTG creation.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.handle_consumer_ptg_added(
            context, network_function_id, policy_target_group)

    @log_helpers.log_method_call
    def consumer_ptg_removed_notification(self, context, network_function_id,
                                          policy_target_group):
        '''Update Configuration to react to consumer PTG deletion.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.handle_consumer_ptg_removed(
            context, network_function_id, policy_target_group)

    @log_helpers.log_method_call
    def get_network_function_details(self, context, network_function_id):
        '''Invoked in an RPC Call.

        Return the Network function Details object
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function_details(
            network_function_id)

    @log_helpers.log_method_call
    def get_port_info(self, context, port_id):
        '''Invoked in an RPC Call. Return the Port Info Details object'''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_port_info(port_id)

    @log_helpers.log_method_call
    def get_network_function_context(self, context, network_function_id):
        '''Invoked in an RPC Call.
        Return the Network function context
        '''
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function_context(
            network_function_id)


class RpcHandlerConfigurator(object):

    """RPC Handler for notificationrpcs from
       Configurator to orchestrator.
    """

    RPC_API_VERSION = '1.0'
    target = oslo_messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, controller):
        super(RpcHandlerConfigurator, self).__init__()
        self.conf = conf
        self._controller = controller
        self.rpc_event_mapping = {
            'heat': ['CHECK_HEAT_CONFIG_RESULT',
                     'DELETE_USER_CONFIG',
                     'UPDATE_USER_CONFIG',
                     'POLICY_TARGET_ADD',
                     'POLICY_TARGET_REMOVE',
                     'CONSUMER_ADD',
                     'CONSUMER_REMOVE']
        }

    def _log_event_created(self, event_id, event_data):
        LOG.debug("Service Orchestrator, RPC Handler for configurator,"
            "Created event, %s(event_name)s with "
            "event data: %(event_data)s",
            {'event_name': event_id, 'event_data': event_data})

    def _create_event(self, event_id, event_data=None,
                      is_poll_event=False, original_event=None,
                      serialize=False):
        if is_poll_event:
            ev = self._controller.new_event(
                id=event_id, data=event_data,
                serialize=original_event.sequence,
                binding_key=original_event.binding_key,
                key=original_event.key)
            LOG.debug("poll event started for %s" % (ev.id))
            self._controller.poll_event(ev, max_times=10)
        else:
            if serialize:
                network_function_id = event_data['network_function_id']
                ev = self._controller.new_event(
                    id=event_id, data=event_data,
                    binding_key=network_function_id,
                    key=network_function_id,
                    serialize=True)
            else:
                ev = self._controller.new_event(
                    id=event_id,
                    data=event_data)
            self._controller.post_event(ev)
        self._log_event_created(event_id, event_data)

    @log_helpers.log_method_call
    def network_function_notification(self, context, notification_data):
        info = notification_data.get('info')
        responses = notification_data.get('notification')
        request_info = info.get('context')
        operation = request_info.get('operation')
        logging_context = request_info.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)
        serialize = False

        for response in responses:
            resource = response.get('resource')
            data = response.get('data')
            result = data.get('status_code')

            if result.lower() != 'success':
                if operation == 'create':
                    event_id = self.rpc_event_mapping[resource][0]
                elif operation == 'delete':
                    event_id = self.rpc_event_mapping[resource][1]
                elif operation == 'update':
                    serialize = True
                    event_id = self.rpc_event_mapping[resource][2]
                elif operation == 'pt_add':
                    serialize = True
                    event_id = self.rpc_event_mapping[resource][3]
                elif operation == 'pt_remove':
                    serialize = True
                    event_id = self.rpc_event_mapping[resource][4]
                elif operation == 'consumer_add':
                    serialize = True
                    event_id = self.rpc_event_mapping[resource][5]
                else:
                    serialize = True
                    event_id = self.rpc_event_mapping[resource][6]
                break
            else:
                if operation == 'delete':
                    event_id = 'USER_CONFIG_DELETED'
                else:
                    event_id = 'CONFIG_APPLIED'
        nf_id = request_info.pop('nf_id')
        nfi_id = request_info.pop('nfi_id')
        nfd_id = request_info.pop('nfd_id')
        request_info['network_function_id'] = nf_id
        request_info['network_function_instance_id'] = nfi_id
        request_info['network_function_device_id'] = nfd_id
        event_data = request_info
        self._create_event(event_id=event_id,
                           event_data=event_data, serialize=serialize)
        nfp_logging.clear_logging_context()


class ServiceOrchestrator(nfp_api.NfpEventHandler):

    """Orchestrator For Network Services

    This class handles the orchestration of Network Function lifecycle.
    It deals with logical service resources - Network Functions and Network
    Function Instances. There is a one-to-many mapping between Network
    Functions and Network Function instances. For eg. a Network Function in
    HA mode might have two Network Function Instances - Active, Standby
    whereas a Network Function in Cluster mode might have more than 2 Network
    Function Instances. This module interacts with Device Orchestrator and
    Config driver.

    Workflow for create:
    1) create_network_function is called in the context of an RPC call. This
    method generates an event CREATE_NETWORK_FUNCTION_INSTANCE
    2) Event handler for CREATE_NETWORK_FUNCTION_INSTANCE. Here a DB entry is
    created and generates an event CREATE_NETWORK_FUNCTION_DEVICE.
    3) The Device Orchestrator module handles this event and generates an event
    DEVICE_CREATED or DEVICE_CREATE_FAILED
    4) Event handler for DEVICE_CREATED event updates the Network Function
    Instance DB object with the created Network Function Device ID
    5) Event handler for DEVICE_CREATE_FAILED event updates the Network
    Function Instance and Network Function DB with status ERROR
    6) Device orchestrator could then generate DEVICE_ACTIVE or
    DEVICE_CREATE_FAILED based on the device being healthy or it being not
    reachable
    7) Event handler for DEVICE_ACTIVE updates Network Function Instance to
    Active, invokes config driver (heat) to apply user provided service config.
    A poll event APPLY_USER_CONFIG_IN_PROGRESS is then created.
    8) Event handler for poll event APPLY_USER_CONFIG_IN_PROGRESS checks
    whether the configuration is applied successfully
    9) If the config driver returns COMPLETED or ERROR, the poll event is
    stopped and the Network Function is updated to Active or Error. If it
    returns IN_PROGRESS, the poll event is continued.
    """

    # REVISIT(ashu): Split this into multiple manageable classes
    def __init__(self, controller, config):
        self._controller = controller
        self.db_handler = nfp_db.NFPDbBase()
        self.gbpclient = openstack_driver.GBPClient(config)
        self.keystoneclient = openstack_driver.KeystoneClient(config)
        self.config_driver = heat_driver.HeatDriver(config)
        neutron_context = n_context.get_admin_context()
        self.configurator_rpc = NSOConfiguratorRpcApi(neutron_context, config)
        self.status_map = {
            'pt_add': {'status': 'PT_ADD_IN_PROGRESS',
                       'status_description': 'pt addition is in progress'},
            'pt_remove': {'status': 'PT_REMOVE_IN_PROGRESS',
                          'status_description': 'pt deletion is in progress'},
            'ptg_add': {'status': 'PTG_ADD_IN_PROGRESS',
                        'status_description': 'ptg addition is in progress'},
            'ptg_remove': {'status': 'PTG_REMOVE_IN_PROGRESS',
                           'status_description': (
                               'ptg deletion is in progress')},
        }

    @property
    def db_session(self):
        return db_api.get_session()

    def event_method_mapping(self, event_id):
        event_handler_mapping = {
            "DELETE_NETWORK_FUNCTION": self.delete_network_function,
            "CREATE_NETWORK_FUNCTION_INSTANCE": (
                self.create_network_function_instance),
            "DELETE_NETWORK_FUNCTION_INSTANCE": (
                self.delete_network_function_instance),
            "DEVICE_CREATED": self.handle_device_created,
            "DEVICE_ACTIVE": self.handle_device_active,
            "SEND_HEAT_CONFIG": self.send_heat_config,
            "DEVICE_DELETED": self.handle_device_deleted,
            "DEVICE_CREATE_FAILED": self.handle_device_create_failed,
            "APPLY_USER_CONFIG": self.apply_user_config,
            "APPLY_USER_CONFIG_BASEMODE": self.apply_user_config_basemode,
            "CHECK_HEAT_CONFIG_RESULT": self.check_heat_config_result,
            "DELETE_USER_CONFIG": self.delete_user_config,
            "UPDATE_USER_CONFIG": self.handle_update_user_config,
            "POLICY_TARGET_ADD": self.policy_target_add_user_config,
            "POLICY_TARGET_REMOVE": self.policy_target_remove_user_config,
            "CONSUMER_ADD": self.consumer_ptg_add_user_config,
            "CONSUMER_REMOVE": self.consumer_ptg_remove_user_config,
            "APPLY_USER_CONFIG_IN_PROGRESS": (
                self.apply_user_config_in_progress),
            "CHECK_USER_CONFIG_COMPLETE": (
                self.check_for_user_config_complete),
            "UPDATE_USER_CONFIG_PREPARING_TO_START": (
                self.check_for_user_config_deleted),
            "UPDATE_USER_CONFIG_IN_PROGRESS": (
                self.handle_continue_update_user_config),
            "UPDATE_USER_CONFIG_STILL_IN_PROGRESS": (
                self.apply_user_config_in_progress),
            "DELETE_USER_CONFIG_IN_PROGRESS": (
                self.check_for_user_config_deleted),
            "CONFIG_APPLIED": self.handle_config_applied,
            "USER_CONFIG_APPLIED": self.handle_user_config_applied,
            "USER_CONFIG_DELETED": self.handle_user_config_deleted,
            "USER_CONFIG_DELETE_FAILED": self.handle_user_config_delete_failed,
            "USER_CONFIG_UPDATE_FAILED": self.handle_update_user_config_failed,
            "USER_CONFIG_FAILED": self.handle_user_config_failed,
            "SERVICE_CONFIGURED": self.handle_service_configured
        }
        if event_id not in event_handler_mapping:
            raise Exception("Invalid Event ID")
        else:
            return event_handler_mapping[event_id]

    def handle_event(self, event):
        LOG.info(_LI("NSO: received event %(id)s"),
                 {'id': event.id})
        try:
            event_handler = self.event_method_mapping(event.id)
            event_handler(event)
        except Exception as e:
            LOG.exception(_LE("Error in processing event: %(event_id)s for "
                              "event data %(event_data)s. Error: %(error)s"),
                          {'event_id': event.id, 'event_data': event.data,
                           'error': e})
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)

    def handle_poll_event(self, event):
        LOG.info(_LI("Service Orchestrator received poll event %(id)s"),
                 {'id': event.id})
        try:
            event_handler = self.event_method_mapping(event.id)
            return event_handler(event)
        except Exception:
            LOG.exception(_LE("Error in processing poll event: "
                              "%(event_id)s"), {'event_id': event.id})

    def event_cancelled(self, event, reason):
        if event.id == 'CHECK_USER_CONFIG_COMPLETE':
            nfp_context = event.data
            network_function = nfp_context['network_function']
            LOG.info(_LI("NSO: applying user config failed for "
                         "network function %(network_function_id)s data "
                         "%(data)s with reason %(reason)s"
                         ""), {'data': nfp_context,
                               'network_function_id': network_function[
                                   'id'],
                               'reason': str(reason)})

            updated_network_function = {'status': nfp_constants.ERROR}
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                updated_network_function)

            event_desc = nfp_context.pop('event_desc')
            apply_config_event = self._controller.new_event(
                id='APPLY_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            self._controller.event_complete(
                apply_config_event, result="FAILED")

        elif event.id == 'APPLY_USER_CONFIG_IN_PROGRESS' or (
                event.id == 'UPDATE_USER_CONFIG_STILL_IN_PROGRESS'):
            request_data = event.data
            LOG.info(_LI("NSO: applying user config failed for "
                         "network function %(network_function_id)s data "
                         "%(data)s with reason %(reason)s"
                         ""), {'data': request_data,
                               'network_function_id': request_data[
                                   'network_function_id'],
                               'reason': str(reason)})

            updated_network_function = {'status': nfp_constants.ERROR}
            self.db_handler.update_network_function(
                self.db_session,
                request_data['network_function_id'],
                updated_network_function)

        elif event.id == 'DELETE_USER_CONFIG_IN_PROGRESS' or (
                event.id == 'UPDATE_USER_CONFIG_PREPARING_TO_START'):
            event_data = {
                'network_function_id': request_data['network_function_id']
            }
            request_data = event.data
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=event_data, is_internal_event=True)

    def _log_event_created(self, event_id, event_data):
        LOG.debug("Created event %s(event_name)s with event "
            "data: %(event_data)s",
            {'event_name': event_id, 'event_data': event_data})

    # REVISIT(ashu): Merge this _create_event, and above one to have
    # single function.
    def _create_event(self, event_id, event_data=None,
                      key=None, binding_key=None, serialize=False,
                      is_poll_event=False, original_event=None,
                      is_internal_event=False):
        if not is_internal_event:
            if is_poll_event:
                ev = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid)
                LOG.debug("poll event started for %s" % (ev.id))
                # REVISIT(ashu): Currently increased poll event to run
                # max 40 times, need to come up with proper value.
                self._controller.poll_event(ev, max_times=40)
            else:
                if original_event:
                    ev = self._controller.new_event(
                        id=event_id, data=event_data,
                        serialize=original_event.sequence,
                        binding_key=original_event.binding_key,
                        key=original_event.desc.uuid)
                else:
                    ev = self._controller.new_event(
                        id=event_id,
                        data=event_data)
                self._controller.post_event(ev)
            self._log_event_created(event_id, event_data)
        else:
            if original_event:
                event = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid)
            else:
                # Same module API, so calling corresponding function
                # directly.
                event = self._controller.new_event(
                    id=event_id,
                    data=event_data)
            self.handle_event(event)

    def _get_base_mode_support(self, service_profile_id):
        admin_token = self.keystoneclient.get_admin_token()
        service_profile = self.gbpclient.get_service_profile(
            admin_token, service_profile_id)
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)
        return base_mode_support

    def _get_service_type(self, service_profile_id):
        admin_token = self.keystoneclient.get_admin_token()
        service_profile = self.gbpclient.get_service_profile(
            admin_token, service_profile_id)
        service_type = service_profile['service_type']
        return service_type

    def update_network_function_user_config(self, network_function_id,
                                            service_config_str,
                                            operation):
        tag_str, config_str = self.config_driver.parse_template_config_string(
            service_config_str)
        if not config_str:
            LOG.error(_LE('Exception while parsing config string, config '
                          'string: %(config_str)s is improper for '
                          'network_function id: %(network_function_id)s'),
                      {'config_str': service_config_str,
                       'network_function_id': network_function_id})
            self.handle_driver_error(network_function_id)
            return None

        if tag_str != nfp_constants.CONFIG_INIT_TAG:
            network_function_details = self.get_network_function_details(
                network_function_id)
            service_type = network_function_details.pop('service_type')
            if not service_type:
                service_type = self._get_service_type(
                    network_function_details['network_function'][
                        'service_profile_id'])
            network_function_data = {
                'network_function_details': network_function_details,
                'service_type': service_type
            }
            rpc_method = getattr(self.configurator_rpc, operation +
                                 '_network_function_user_config')
            rpc_method(network_function_data, service_config_str, tag_str)
        else:
            # Place holder for calling config_init API
            pass

    def update_consumer_ptg(self, network_function_data,
                            service_config_str, operation):
        tag_str, config_str = self.config_driver.parse_template_config_string(
            service_config_str)
        network_function_id = network_function_data[
            'network_function_details']['network_function']['id']
        if not config_str:
            LOG.error(_LE('Exception while parsing config string, config '
                          'string: %(config_str)s is improper for '
                          'network_function id: %(network_function_id)s'),
                      {'config_str': service_config_str,
                       'network_function_id': network_function_id})
            self.handle_driver_error(network_function_id)
            return None

        if tag_str != nfp_constants.CONFIG_INIT_TAG:
            rpc_method = getattr(self.configurator_rpc, operation +
                                 '_user_config')
            rpc_method(network_function_data, service_config_str, tag_str)
        else:
            # Place holder for calling config_init API
            pass

    def create_network_function_user_config(self, network_function_id,
                                            service_config_str):
        self.update_network_function_user_config(network_function_id,
                                                 service_config_str,
                                                 operation='create')

    def delete_network_function_user_config(self, network_function_id,
                                            service_config_str):
        self.update_network_function_user_config(network_function_id,
                                                 service_config_str,
                                                 operation='delete')

    def consumer_add_user_config(self, network_function_data,
                                 service_config_str):
        self.update_consumer_ptg(network_function_data,
                                 service_config_str,
                                 operation='consumer_add')

    def consumer_remove_user_config(self, network_function_data,
                                    service_config_str):
        self.update_consumer_ptg(network_function_data,
                                 service_config_str,
                                 operation='consumer_remove')

    def pt_add_user_config(self, network_function_data,
                           service_config_str):
        self.update_consumer_ptg(network_function_data,
                                 service_config_str,
                                 operation='policy_target_add')

    def pt_remove_user_config(self, network_function_data,
                              service_config):
        self.update_consumer_ptg(network_function_data,
                                 service_config,
                                 operation='policy_target_remove')

    def _report_logging_info(self, nf, nfi, service_type,
                             service_vendor):
        LOG.info(_LI("[TenantID:%(tenant_id)s, "
                     "ServiceChainID:%(service_chain_id)s, "
                     "ServiceInstanceID:%(service_instance_id)s, "
                     "ServiceType:%(service_type)s, "
                     "ServiceProvider:%(service_provider)s]"),
                 {'tenant_id': nf['tenant_id'],
                  'service_chain_id': nf['service_chain_id'],
                  'service_instance_id': nfi['id'],
                  'service_type': service_type,
                  'service_provider': service_vendor})

    def create_network_function(self, context, network_function_info):
        self._validate_create_service_input(context, network_function_info)

        admin_token = self.keystoneclient.get_admin_token()
        admin_tenant_id = self.keystoneclient.get_admin_tenant_id(admin_token)

        network_function_info['resource_owner_context'][
            'admin_token'] = admin_token
        network_function_info['resource_owner_context'][
            'admin_tenant_id'] = admin_tenant_id

        tenant_id = network_function_info['tenant_id']

        # GBP or Neutron
        # mode = network_function_info['network_function_mode']
        service_profile = network_function_info['service_profile']
        service_profile_id = service_profile['id']
        service_id = network_function_info['service_chain_node']['id']
        service_chain_id = network_function_info[
            'service_chain_instance']['id']
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)
        service_vendor = service_details['service_vendor']
        # REVISIT(ashu): take the first few characters just like neutron does
        # with ovs interfaces inside the name spaces..
        name = "%s_%s_%s" % (service_profile['service_type'],
                             service_vendor,
                             service_chain_id or service_id)
        service_config_str = network_function_info.get('service_config')
        network_function = {
            'name': name,
            'description': '',
            'tenant_id': tenant_id,
            'service_id': service_id,  # GBP Service Node or Neutron Service ID
            'service_chain_id': service_chain_id,  # GBP SC instance ID
            'service_profile_id': service_profile_id,
            'service_config': service_config_str,
            'status': nfp_constants.PENDING_CREATE
        }
        network_function = self.db_handler.create_network_function(
            self.db_session, network_function)

        nfp_logging.store_logging_context(
            meta_id=network_function['id'],
            auth_token=context.auth_token)

        if (not service_details.get('service_vendor') or
                not service_details.get('device_type')):
            LOG.error(_LE("service_vendor or device_type not provided in "
                          "service profile's service flavor field. Setting "
                          "network function to ERROR, Provided service "
                          "profile: %(service_profile)s"),
                      {'service_profile': service_profile})
            network_function_status = {'status': nfp_constants.ERROR}
            self.db_handler.update_network_function(
                self.db_session, network_function['id'],
                network_function_status)
            return None

        nfp_context = network_function_info

        service_details['service_type'] = service_profile['service_type']
        service_details['network_mode'] = nfp_context['network_function_mode']
        nfp_context['network_function'] = network_function
        nfp_context['service_details'] = service_details
        nfp_context['share_existing_device'] = False
        nfp_context['base_mode'] = base_mode_support

        if base_mode_support:
            # Store the context in current thread
            nfp_core_context.store_nfp_context(nfp_context)
            # In base mode support, create user config directly, no need to
            # create network function instance, network function device first.
            self.create_network_function_user_config(network_function['id'],
                                                     service_config_str)
        else:
            # Create and event to perform Network service instance
            self._create_event('CREATE_NETWORK_FUNCTION_INSTANCE',
                               event_data=nfp_context,
                               is_internal_event=True)

        nfp_logging.clear_logging_context()
        return network_function

    def update_network_function(self, context, network_function_id,
                                user_config):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        # Handle config update
        self.db_handler.update_network_function(
            self.db_session, network_function_id,
            {'service_config': user_config,
             'status': nfp_constants.PENDING_UPDATE})
        self.update_network_function_user_config(network_function_id,
                                                 user_config,
                                                 operation='update')

    def delete_network_function(self, context, network_function_id):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        network_function_info = self.db_handler.get_network_function(
            self.db_session, network_function_id)
        service_profile_id = network_function_info['service_profile_id']
        base_mode_support = self._get_base_mode_support(service_profile_id)
        if (not base_mode_support and
                not network_function_info['network_function_instances']):
            self.db_handler.delete_network_function(
                self.db_session, network_function_id)
            return
        network_function = {
            'status': nfp_constants.PENDING_DELETE
        }
        network_function = self.db_handler.update_network_function(
            self.db_session, network_function_id, network_function)
        heat_stack_id = network_function['heat_stack_id']
        LOG.info(_LI("[Event:DeleteService]"))
        if heat_stack_id:
            service_config = network_function_info['service_config']
            self.delete_network_function_user_config(network_function_id,
                                                     service_config)
        else:
            for nfi_id in network_function['network_function_instances']:
                self._create_event('DELETE_NETWORK_FUNCTION_INSTANCE',
                                   event_data=nfi_id, is_internal_event=True)
        nfp_logging.clear_logging_context()

    def delete_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        network_function_info = network_function_details['network_function']
        if not network_function_info['heat_stack_id']:
            event_data = {
                'network_function_id': network_function_info['id']
            }
            self._create_event('USER_CONFIG_DELETED',
                               event_data=event_data, is_internal_event=True)
            return

        heat_stack_id = self.config_driver.delete_config(
            network_function_info['heat_stack_id'],
            network_function_info['tenant_id'],
            network_function_info)
        request_data = {
            'heat_stack_id': network_function_info['heat_stack_id'],
            'tenant_id': network_function_info['tenant_id'],
            'network_function_id': network_function_info['id'],
            'action': 'delete'
        }
        if not heat_stack_id:
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        self._create_event('DELETE_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_poll_event=True, original_event=event)

    def create_network_function_instance(self, event):
        nfp_context = event.data

        network_function = nfp_context['network_function']
        # service_profile = nfp_context['service_profile']
        service_details = nfp_context['service_details']
        consumer = nfp_context['consumer']
        provider = nfp_context['provider']

        port_info = []
        for ele in [consumer, provider]:
            if ele['pt']:
                # REVISIT(ashu): Only pick few chars from id
                port_info.append(
                    {'id': ele['pt']['id'],
                     'port_model': ele['port_model'],
                     'port_classification': ele['port_classification']
                     })

        # REVISIT(ashu): Only pick few chars from id
        name = '%s_%s' % (network_function['name'],
                          network_function['id'])
        create_nfi_request = {
            'name': name,
            'tenant_id': network_function['tenant_id'],
            'status': nfp_constants.PENDING_CREATE,
            'network_function_id': network_function['id'],
            'service_type': service_details['service_type'],
            'service_vendor': service_details['service_vendor'],
            'share_existing_device': nfp_context['share_existing_device'],
            'port_info': port_info,
        }
        nfi_db = self.db_handler.create_network_function_instance(
            self.db_session, create_nfi_request)
        # Sending LogMeta Details to visibility
        self._report_logging_info(network_function,
                                  nfi_db,
                                  service_details['service_type'],
                                  service_details['service_vendor'])

        nfp_context['network_function_instance'] = nfi_db

        LOG.info(_LI("[Event:CreateService]"))
        self._create_event('CREATE_NETWORK_FUNCTION_DEVICE',
                           event_data=nfp_context)

    def handle_device_created(self, event):
        request_data = event.data
        nfi = {
            'network_function_device_id': request_data[
                'network_function_device_id']
        }
        nfi = self.db_handler.update_network_function_instance(
            self.db_session, request_data['network_function_instance_id'], nfi)
        return

    def send_heat_config(self, event):
        nfp_context = event.data

        network_function_instance = nfp_context['network_function_instance']
        network_function_device = nfp_context['network_function_device']
        network_function = nfp_context['network_function']

        request_data = {
            'network_function_device_id': network_function_device['id'],
            'network_function_instance_id': network_function_instance['id']}

        nfi = {
            'status': nfp_constants.ACTIVE,
            'network_function_device_id': request_data[
                'network_function_device_id']
        }
        nfi = self.db_handler.update_network_function_instance(
            self.db_session, request_data['network_function_instance_id'], nfi)
        network_function_instance['status'] = nfp_constants.ACTIVE
        network_function_instance[
            'network_function_device_id'] = network_function_device['id']

        service_config = network_function['service_config']
        nfp_context['event_desc'] = event.desc.to_dict()
        nfp_context['key'] = event.key
        nfp_context['id'] = event.id
        nfp_core_context.store_nfp_context(nfp_context)
        self.create_network_function_user_config(network_function['id'],
                                                 service_config)

    def handle_device_active(self, event):
        request_data = event.data
        nfi = {
            'status': nfp_constants.ACTIVE,
            'network_function_device_id': request_data[
                'network_function_device_id']
        }
        nfi = self.db_handler.update_network_function_instance(
            self.db_session, request_data['network_function_instance_id'], nfi)
        network_function = self.db_handler.get_network_function(
            self.db_session, nfi['network_function_id'])
        service_config = network_function['service_config']

        self.create_network_function_user_config(network_function['id'],
                                                 service_config)

    def check_heat_config_result(self, event):
        nfp_context = event.data['nfp_context']

        base_mode = nfp_context['base_mode']
        if base_mode:
            # Create and event to apply user config
            self._create_event('APPLY_USER_CONFIG_BASEMODE',
                               event_data=event.data,
                               is_internal_event=True)
        else:
            event_desc = nfp_context['event_desc']
            key = nfp_context['key']
            id = nfp_context['id']

            # Complete the original event here
            event = self._controller.new_event(id=id, key=key,
                                               desc_dict=event_desc)
            self._controller.event_complete(event, result='SUCCESS')

    def apply_user_config_basemode(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        request_data['heat_stack_id'] = self.config_driver.apply_config(
            network_function_details)  # Heat driver to launch stack
        network_function = network_function_details['network_function']
        request_data['network_function_id'] = network_function['id']
        if not request_data['heat_stack_id']:
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        request_data['tenant_id'] = network_function['tenant_id']
        request_data['network_function_details'] = network_function_details
        LOG.debug("handle_device_active heat_stack_id: %s"
                  % (request_data['heat_stack_id']))
        self.db_handler.update_network_function(
            self.db_session, network_function['id'],
            {'heat_stack_id': request_data['heat_stack_id'],
             'description': network_function['description']})
        self._create_event('APPLY_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_poll_event=True,
                           original_event=event)

    def apply_user_config(self, event):
        event_results = event.graph.get_leaf_node_results(event)
        for c_event in event_results:
            if c_event.id == "SEND_HEAT_CONFIG" and (
                    c_event.result.upper() == "HANDLED"):
                self._controller.event_complete(
                    event, result="SUCCESS")
                return
        nfp_context = event.data
        nfp_core_context.store_nfp_context(nfp_context)
        network_function = nfp_context['network_function']
        network_function['description'] = str(network_function['description'])
        nfp_context['heat_stack_id'] = self.config_driver.apply_heat_config(
            nfp_context)  # Heat driver to launch stack
        nfp_context['network_function_id'] = network_function['id']

        if not nfp_context['heat_stack_id']:
            self._create_event('USER_CONFIG_FAILED',
                               event_data=nfp_context, is_internal_event=True)
            self._controller.event_complete(event, result='FAILED')
            return

        LOG.debug("handle_device_active heat_stack_id: %s"
                  % (nfp_context['heat_stack_id']))

        nfp_context['network_function'].update({
            'heat_stack_id': nfp_context['heat_stack_id'],
            'description': network_function['description']})

        nfp_context['event_desc'] = event.desc.to_dict()
        self._create_event('CHECK_USER_CONFIG_COMPLETE',
                           event_data=nfp_context,
                           is_poll_event=True,
                           original_event=event)

        self.db_handler.update_network_function(
            self.db_session, network_function['id'],
            {'heat_stack_id': nfp_context['heat_stack_id'],
             'description': network_function['description']})

    def handle_update_user_config(self, event):
        '''
        Handler to apply any updates in user config.
        Initially checks with config driver whether upadte supported for
        service type or not. If not supported first deletes the config(checks
        for user config deletion via UPDATE_USER_CONFIG_PREPARING_TO_START
        event) and then recreates the config with new changes via
        UPDATE_USER_CONFIG_STILL_IN_PROGRESS event.
        If update supported, update/create corresponding user config in
        UPDATE_USER_CONFIG_IN_PROGRESS event.

        '''
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        stack_id = network_function_details['network_function'
                                            ]['heat_stack_id']
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        if not self.config_driver.is_update_config_supported(service_type):
            service_chain_id = network_function['service_chain_id']
            admin_token = self.keystoneclient.get_admin_token()
            servicechain_instance = self.gbpclient.get_servicechain_instance(
                admin_token,
                service_chain_id)
            provider_ptg_id = servicechain_instance['provider_ptg_id']
            provider_ptg = self.gbpclient.get_policy_target_group(
                admin_token,
                provider_ptg_id)
            provider_tenant_id = provider_ptg['tenant_id']
            stack_id = self.config_driver.delete_config(stack_id,
                                                        provider_tenant_id)
            request_data = {
                'heat_stack_id': stack_id,
                'network_function_id': network_function['id'],
                'tenant_id': provider_tenant_id,
                'action': 'update',
                'operation': request_data['operation']
            }
            self._create_event('UPDATE_USER_CONFIG_PREPARING_TO_START',
                               event_data=request_data,
                               is_poll_event=True, original_event=event)
        else:
            self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                               event_data=event.data,
                               is_internal_event=True,
                               original_event=event)

    def handle_continue_update_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        network_function = network_function_details['network_function']

        if request_data['operation'] == 'update':
            config_id = self.config_driver.update_config(
                network_function_details,
                network_function_details['network_function']['heat_stack_id'])
        elif request_data['operation'] == 'consumer_add':
            config_id = self.config_driver.handle_consumer_ptg_operations(
                network_function_details, request_data['consumer_ptg'],
                "add")
        elif request_data['operation'] == 'consumer_remove':
            config_id = self.config_driver.handle_consumer_ptg_operations(
                network_function_details, request_data['consumer_ptg'],
                "remove")
        else:
            return

        request_data = {
            'heat_stack_id': config_id,
            'tenant_id': network_function['tenant_id'],
            'network_function_id': network_function['id'],
            'network_function_details': network_function_details
        }
        if not config_id:
            event_id = ('USER_CONFIG_UPDATE_FAILED'
                        if request_data['operation'] == 'update'
                        else 'USER_CONFIG_FAILED')
            self._create_event(event_id,
                               event_data=request_data,
                               is_internal_event=True)
            if event.binding_key:
                self._controller.event_done(event)
            return
        self.db_handler.update_network_function(
            self.db_session,
            network_function['id'],
            {'heat_stack_id': config_id})
        self._create_event('UPDATE_USER_CONFIG_STILL_IN_PROGRESS',
                           event_data=request_data,
                           is_poll_event=True, original_event=event)

    def handle_device_create_failed(self, event):
        request_data = event.data
        nfi = {
            'status': nfp_constants.ERROR,
            'network_function_device_id': request_data.get(
                'network_function_device_id')
        }
        nfi = self.db_handler.update_network_function_instance(
            self.db_session, request_data['network_function_instance_id'], nfi)
        network_function = {'status': nfp_constants.ERROR}
        self.db_handler.update_network_function(
            self.db_session, nfi['network_function_id'], network_function)
        # Trigger RPC to notify the Create_Service caller with status

    def handle_driver_error(self, network_function_id):
        network_function_details = self.get_network_function_details(
            network_function_id)
        network_function_id = network_function_details.get(
            'network_function')['id']
        network_function = {'status': nfp_constants.ERROR}
        self.db_handler.update_network_function(
            self.db_session, network_function_id, network_function)

        if network_function_details.get('network_function_instance'):
            network_function_instance_id = network_function_details[
                'network_function_instance']['id']
            nfi = {
                'status': nfp_constants.ERROR,
            }
            nfi = self.db_handler.update_network_function_instance(
                self.db_session, network_function_instance_id, nfi)

    def _update_network_function_instance(self):
        pass

    def delete_network_function_instance(self, event):
        nfi_id = event.data
        nfi = {'status': nfp_constants.PENDING_DELETE}
        nfi = self.db_handler.update_network_function_instance(
            self.db_session, nfi_id, nfi)
        if nfi['network_function_device_id']:
            delete_nfd_request = {
                'network_function_device_id': nfi[
                    'network_function_device_id'],
                'network_function_instance': nfi,
                'network_function_id': nfi['network_function_id']
            }
            self._create_event('DELETE_NETWORK_FUNCTION_DEVICE',
                               event_data=delete_nfd_request)
        else:
            device_deleted_event = {
                'network_function_instance_id': nfi['id']
            }
            self._create_event('DEVICE_DELETED',
                               event_data=device_deleted_event,
                               is_internal_event=True)

    # FIXME: Add all possible validations here
    def _validate_create_service_input(self, context, create_service_request):
        required_attributes = ["resource_owner_context",
                               "service_chain_instance",
                               "service_chain_node", "service_profile",
                               "service_config", "provider", "consumer",
                               "network_function_mode"]
        if (set(required_attributes) & set(create_service_request.keys()) !=
                set(required_attributes)):
            missing_keys = (set(required_attributes) -
                            set(create_service_request.keys()))
            raise nfp_exc.RequiredDataNotProvided(
                required_data=", ".join(missing_keys),
                request="Create Network Function")
        if create_service_request['network_function_mode'].lower() == "gbp":
            gbp_required_attributes = ["management_ptg_id"]
            if (set(gbp_required_attributes) &
                    set(create_service_request.keys()) !=
                    set(gbp_required_attributes)):
                missing_keys = (set(gbp_required_attributes) -
                                set(create_service_request.keys()))
                raise nfp_exc.RequiredDataNotProvided(
                    required_data=", ".join(missing_keys),
                    request="Create Network Function")

    def apply_user_config_in_progress(self, event):
        request_data = event.data
        config_status = self.config_driver.is_config_complete(
            request_data['heat_stack_id'], request_data['tenant_id'],
            request_data['network_function_details'])
        if config_status == nfp_constants.ERROR:
            LOG.info(_LI("NSO: applying user config failed for "
                         "network function %(network_function_id)s data "
                         "%(data)s"), {'data': request_data,
                                       'network_function_id':
                                       request_data['network_function_id']})
            updated_network_function = {'status': nfp_constants.ERROR}
            self.db_handler.update_network_function(
                self.db_session,
                request_data['network_function_id'],
                updated_network_function)
            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            updated_network_function = {'status': nfp_constants.ACTIVE}
            LOG.info(_LI("NSO: applying user config is successfull moving "
                         "network function %(network_function_id)s to ACTIVE"),
                     {'network_function_id':
                      request_data['network_function_id']})
            self.db_handler.update_network_function(
                self.db_session,
                request_data['network_function_id'],
                updated_network_function)
            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    def handle_service_configured(self, event):
        nfp_context = event.data
        network_function = nfp_context['network_function']
        updated_network_function = {'status': nfp_constants.ACTIVE}
        LOG.info(_LI("NSO: applying user config is successfull moving "
                     "network function %(network_function_id)s to ACTIVE"),
                 {'network_function_id': network_function['id']})
        self.db_handler.update_network_function(
            self.db_session,
            network_function['id'],
            updated_network_function)
        self._controller.event_complete(event)
        nfp_core_context.clear_nfp_context()

    def check_for_user_config_complete(self, event):
        nfp_context = event.data

        network_function = nfp_context['network_function']
        config_status = self.config_driver.check_config_complete(nfp_context)

        if config_status == nfp_constants.ERROR:

            LOG.info(_LI("NSO: applying user config failed for "
                         "network function %(network_function_id)s data "
                         "%(data)s"), {'data': nfp_context,
                                       'network_function_id':
                                       network_function['id']})
            updated_network_function = {'status': nfp_constants.ERROR}
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                updated_network_function)

            # Complete the original event APPLY_USER_CONFIG here
            event_desc = nfp_context.pop('event_desc')
            apply_config_event = self._controller.new_event(
                id='APPLY_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            self._controller.event_complete(
                apply_config_event, result="FAILED")
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            # Complete the original event DEVICE_ACTIVE here
            event_desc = nfp_context.pop('event_desc')
            apply_config_event = self._controller.new_event(
                id='APPLY_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            self._controller.event_complete(
                apply_config_event, result="SUCCESS")

            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    def check_for_user_config_deleted(self, event):
        request_data = event.data
        event_data = {
            'network_function_id': request_data['network_function_id']
        }
        try:
            network_function = self.db_handler.get_network_function(
                self.db_session,
                request_data['network_function_id'])
            config_status = self.config_driver.is_config_delete_complete(
                request_data['heat_stack_id'], request_data['tenant_id'],
                network_function)
        except Exception as err:
            # FIXME: May be we need a count before removing the poll event
            LOG.error(_LE("Error: %(err)s while verifying configuration delete"
                          " completion."), {'err': err})
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=event_data, is_internal_event=True)
            self._controller.event_complete(event)
            return STOP_POLLING
        if config_status == nfp_constants.ERROR:
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=event_data, is_internal_event=True)
            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            updated_network_function = {'heat_stack_id': None}
            self.db_handler.update_network_function(
                self.db_session,
                request_data['network_function_id'],
                updated_network_function)
            if request_data['action'] == 'update':
                self._create_event("UPDATE_USER_CONFIG_IN_PROGRESS",
                                   event_data=request_data,
                                   original_event=event)
            else:
                event_data = {
                    'network_function_id': request_data['network_function_id']
                }
                self._create_event('USER_CONFIG_DELETED',
                                   event_data=event_data,
                                   is_internal_event=True)
                self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    def handle_user_config_applied(self, event):
        request_data = event.data
        network_function = {
            'status': nfp_constants.ACTIVE,
            'heat_stack_id': request_data['heat_stack_id']
        }
        self.db_handler.update_network_function(
            self.db_session,
            request_data['network_function_id'],
            network_function)
        # Trigger RPC to notify the Create_Service caller with status

    def handle_config_applied(self, event):
        nfp_context = event.data['nfp_context']
        base_mode = nfp_context['base_mode']
        network_function_id = event.data['network_function_id']
        if base_mode:
            network_function = {
                'status': nfp_constants.ACTIVE,
            }
            self.db_handler.update_network_function(
                self.db_session,
                network_function_id,
                network_function)
            LOG.info(_LI("NSO: applying user config is successfull moving "
                         "network function %(network_function_id)s to ACTIVE"),
                     {'network_function_id':
                      network_function_id})
        else:
            network_function_instance_id = (
                event.data['network_function_instance_id'])
            if network_function_instance_id:
                nfi = {
                    'status': nfp_constants.ACTIVE,
                }
                nfi = self.db_handler.update_network_function_instance(
                    self.db_session, network_function_instance_id, nfi)

            event_desc = nfp_context['event_desc']
            key = nfp_context['key']
            id = nfp_context['id']

            # Complete the original event here
            event = self._controller.new_event(id=id, key=key,
                                               desc_dict=event_desc)
            self._controller.event_complete(event, result='HANDLED')

    def handle_update_user_config_failed(self, event):
        event_data = event.data
        network_function_id = event_data['network_function_id']
        LOG.error(_LE("NSO: updating user config failed, moving "
                      "network function %(network_function_id)s to ERROR"),
                  {'network_function_id': network_function_id})
        self.handle_user_config_failed(event)

    def handle_user_config_failed(self, event):
        request_data = event.data
        updated_network_function = {
            'status': nfp_constants.ERROR,
            'heat_stack_id': request_data.get('heat_stack_id')
        }
        self.db_handler.update_network_function(
            self.db_session,
            request_data['network_function_id'],
            updated_network_function)
        # Trigger RPC to notify the Create_Service caller with status

    def handle_user_config_deleted(self, event):
        request_data = event.data
        network_function = self.db_handler.get_network_function(
            self.db_session,
            request_data['network_function_id'])
        service_profile_id = network_function['service_profile_id']
        base_mode_support = self._get_base_mode_support(service_profile_id)
        if base_mode_support:
            self.db_handler.delete_network_function(
                self.db_session, network_function['id'])
            return
        for nfi_id in network_function['network_function_instances']:
            self._create_event('DELETE_NETWORK_FUNCTION_INSTANCE',
                               event_data=nfi_id,
                               is_internal_event=True)

    # Change to Delete_failed or continue with instance and device
    # delete if config delete fails? or status CONFIG_DELETE_FAILED ??
    def handle_user_config_delete_failed(self, event):
        request_data = event.data
        updated_network_function = {
            'status': nfp_constants.ERROR,
        }
        self.db_handler.update_network_function(
            self.db_session,
            request_data['network_function_id'],
            updated_network_function)
        # Trigger RPC to notify the Create_Service caller with status

    # When NDO deletes Device DB, the Foreign key NSI will be nulled
    # So we have to pass the NSI ID in delete event to NDO and process
    # the result based on that
    def handle_device_deleted(self, event):
        request_data = event.data
        nfi_id = request_data['network_function_instance_id']
        nfi = self.db_handler.get_network_function_instance(
            self.db_session, nfi_id)
        self.db_handler.delete_network_function_instance(
            self.db_session, nfi_id)
        network_function = self.db_handler.get_network_function(
            self.db_session, nfi['network_function_id'])
        nf_id = network_function['id']
        if not network_function['network_function_instances']:
            self.db_handler.delete_network_function(
                self.db_session, nfi['network_function_id'])
        LOG.info(_LI("NSO: Deleted network function: %(nf_id)s"),
                 {'nf_id': nf_id})
        # Inform delete service caller with delete completed RPC

    def get_network_function(self, context, network_function_id):
        try:
            nfp_logging.store_logging_context(
                meta_id=network_function_id,
                auth_token=context.auth_token)
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)
            return network_function
        except Exception:
            LOG.exception(_LE("Failed to retrieve Network Function details for"
                              " %(network_function)s"),
                          {'network_function': network_function_id})
            return None

    def get_network_functions(self, context, filters):
        return self.db_handler.get_network_functions(
            self.db_session, filters)

    def _update_network_function_status(self, network_function_id, operation):
        self.db_handler.update_network_function(
            self.db_session,
            network_function_id,
            {'status': self.status_map[operation]['status'],
             'status_description': self.status_map[operation][
                'status_description']})

    def handle_policy_target_added(self, context, network_function_id,
                                   policy_target):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        network_function = self.db_handler.get_network_function(
            self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR,
                 'status_description': ("Config Update for Policy Target "
                                        "addition event failed")})
            return
        self._update_network_function_status(network_function['id'],
                                             operation='pt_add')
        service_config = network_function['service_config']
        service_type = self._get_service_type(
            network_function['service_profile_id'])
        network_function_data = {
            'network_function_details': network_function_details,
            'policy_target': policy_target,
            'service_type': service_type
        }
        self.pt_add_user_config(network_function_data,
                                service_config)

    def policy_target_add_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        policy_target = request_data['policy_target']
        config_id = self.config_driver.handle_policy_target_operations(
            network_function_details, policy_target, "add")
        network_function = network_function_details['network_function']
        request_data = {
            'heat_stack_id': config_id,
            'tenant_id': network_function['tenant_id'],
            'network_function_id': network_function['id'],
            'network_function_details': network_function_details
        }
        if not config_id:
            self._controller.event_complete(event)
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        self.db_handler.update_network_function(
            self.db_session,
            network_function['id'],
            {'heat_stack_id': config_id})
        self._controller.event_complete(event)
        self._create_event('APPLY_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_poll_event=True, original_event=event)

    def handle_policy_target_removed(self, context, network_function_id,
                                     policy_target):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        network_function = self.db_handler.get_network_function(
            self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR,
                 'status_description': ("Config Update for Policy Target "
                                        "removed event failed")})
            return
        self._update_network_function_status(network_function['id'],
                                             operation='pt_remove')
        service_config = network_function['service_config']
        service_type = self._get_service_type(
            network_function['service_profile_id'])
        network_function_data = {
            'network_function_details': network_function_details,
            'policy_target': policy_target,
            'service_type': service_type
        }
        self.pt_remove_user_config(network_function_data,
                                   service_config)

    def policy_target_remove_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        policy_target = request_data['policy_target']
        config_id = self.config_driver.handle_policy_target_operations(
            network_function_details, policy_target, "remove")
        network_function = network_function_details['network_function']
        request_data = {
            'heat_stack_id': config_id,
            'tenant_id': network_function['tenant_id'],
            'network_function_id': network_function['id'],
            'network_function_details': network_function_details
        }
        if not config_id:
            self._controller.event_complete(event)
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        self.db_handler.update_network_function(
            self.db_session,
            network_function['id'],
            {'heat_stack_id': config_id})

        self._controller.event_complete(event)
        self._create_event('APPLY_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_poll_event=True, original_event=event)

    def handle_consumer_ptg_added(self, context, network_function_id,
                                  consumer_ptg):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        network_function = self.db_handler.get_network_function(
            self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR,
                 'status_description': ("Config Update for Consumer Policy"
                                        " Target Group Addition failed")})
            return
        self._update_network_function_status(network_function['id'],
                                             operation='ptg_add')
        service_config = network_function['service_config']
        service_type = self._get_service_type(
            network_function['service_profile_id'])
        network_function_data = {
            'network_function_details': network_function_details,
            'consumer_ptg': consumer_ptg,
            'service_type': service_type
        }
        self.consumer_add_user_config(network_function_data,
                                      service_config)

    def consumer_ptg_add_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        consumer_ptg = request_data['consumer_ptg']
        stack_id = network_function_details['network_function'
                                            ]['heat_stack_id']
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        if not self.config_driver.is_update_config_supported(service_type):
            stack_id = self.config_driver.delete_config(
                stack_id,
                consumer_ptg['tenant_id'])
            request_data = {
                'heat_stack_id': stack_id,
                'network_function_id': network_function['id'],
                'tenant_id': consumer_ptg['tenant_id'],
                'action': 'update',
                'operation': request_data['operation'],
                'consumer_ptg': request_data['consumer_ptg']
            }
            self._controller.event_complete(event)
            self._create_event('UPDATE_USER_CONFIG_PREPARING_TO_START',
                               event_data=request_data,
                               is_poll_event=True, original_event=event)
        else:
            self._controller.event_complete(event)
            self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                               event_data=event.data,
                               is_internal_event=True)

    def handle_consumer_ptg_removed(self, context, network_function_id,
                                    consumer_ptg):
        nfp_logging.store_logging_context(
            meta_id=network_function_id,
            auth_token=context.auth_token)
        network_function = self.db_handler.get_network_function(
            self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            self.db_handler.update_network_function(
                self.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR,
                 'status_description': ("Config Update for Consumer Policy"
                                        " Target Group Removal failed")})
            return
        self._update_network_function_status(network_function['id'],
                                             operation='ptg_remove')
        service_config = network_function['service_config']
        service_type = self._get_service_type(
            network_function['service_profile_id'])
        network_function_data = {
            'network_function_details': network_function_details,
            'consumer_ptg': consumer_ptg,
            'service_type': service_type
        }
        self.consumer_remove_user_config(network_function_data,
                                         service_config)

    def consumer_ptg_remove_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        consumer_ptg = request_data['consumer_ptg']
        stack_id = network_function_details['network_function'
                                            ]['heat_stack_id']
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        if not self.config_driver.is_update_config_supported(service_type):
            stack_id = self.config_driver.delete_config(
                stack_id,
                consumer_ptg['tenant_id'])
            request_data = {
                'heat_stack_id': stack_id,
                'network_function_id': network_function['id'],
                'tenant_id': consumer_ptg['tenant_id'],
                'action': 'update',
                'operation': request_data['operation'],
                'consumer_ptg': request_data['consumer_ptg']
            }

            self._controller.event_complete(event)
            self._create_event('UPDATE_USER_CONFIG_PREPARING_TO_START',
                               event_data=request_data,
                               is_poll_event=True, original_event=event)
        else:
            self._controller.event_complete(event)
            self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                               event_data=event.data,
                               is_internal_event=True)

    def get_port_info(self, port_id):
        try:
            port_info = self.db_handler.get_port_info(
                self.db_session, port_id)
            return port_info
        except Exception:
            LOG.exception(_LE("Failed to retrieve Port Info for"
                              " %(port_id)s"),
                          {'port_id': port_id})
            return None

    def get_network_function_details(self, network_function_id):
        network_function = None
        network_function_instance = None
        network_function_device = None
        service_type = None

        nfp_context = nfp_core_context.get_nfp_context()
        if nfp_context:
            network_function = nfp_context.get('network_function', None)
            network_function_instance = nfp_context.get(
                'network_function_instance', None)
            network_function_device = nfp_context.get(
                'network_function_device', None)
            service_details = nfp_context.get('service_details', None)
            if service_details:
                service_type = service_details.get('service_type', None)
        if not network_function:
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)

        network_function_details = {
            'network_function': network_function,
            'service_type': service_type
        }

        if not network_function_instance:
            network_function_instances = network_function[
                'network_function_instances']
            if not network_function_instances:
                return network_function_details
            network_function_instance = (
                self.db_handler.get_network_function_instance(
                    self.db_session, network_function_instances[0]))

        network_function_details[
            'network_function_instance'] = network_function_instance

        if not network_function_device:
            if network_function_instance['network_function_device_id']:
                network_function_device = (
                    self.db_handler.get_network_function_device(
                        self.db_session,
                        network_function_instance[
                            'network_function_device_id']))
        network_function_details['network_function_device'] = (
            network_function_device)
        return network_function_details

    def get_network_function_context(self, network_function_id):
        network_function_details = self.get_network_function_details(
            network_function_id)

        ports_info = []
        for id in network_function_details[
                'network_function_instance']['port_info']:
            port_info = self.get_port_info(id)
            ports_info.append(port_info)

        mngmt_port_info = None
        mgmt_port_id = network_function_details[
            'network_function_device']['mgmt_port_id']
        if mgmt_port_id is not None:
            mngmt_port_info = self.get_port_info(mgmt_port_id)

        monitor_port_id = network_function_details[
            'network_function_device']['monitoring_port_id']
        monitor_port_info = None
        if monitor_port_id is not None:
            monitor_port_info = self.get_port_info(monitor_port_id)

        nf_context = {'network_function_details': network_function_details,
                      'ports_info': ports_info,
                      'mngmt_port_info': mngmt_port_info,
                      'monitor_port_info': monitor_port_info}
        return nf_context


class NSOConfiguratorRpcApi(object):

    """Service Manager side of the Service Manager to Service agent RPC API"""
    API_VERSION = '1.0'
    target = oslo_messaging.Target(version=API_VERSION)

    def __init__(self, context, conf):
        super(NSOConfiguratorRpcApi, self).__init__()
        self.conf = conf
        self.context = context
        self.client = n_rpc.get_client(self.target)
        self.rpc_api = self.client.prepare(
            version=self.API_VERSION,
            topic=nfp_rpc_topics.NFP_NSO_CONFIGURATOR_TOPIC)

    def _get_request_info(self, user_config_data, operation):
        network_function_details = user_config_data[
            'network_function_details']
        network_function_instance = network_function_details.get(
            'network_function_instance')
        nfp_context = nfp_core_context.get_nfp_context()
        rpc_nfp_context = None
        if nfp_context:
            rpc_nfp_context = {
                'event_desc': nfp_context.get('event_desc', None),
                'key': nfp_context.pop('key', None),
                'id': nfp_context.pop('id', None),
                'base_mode': nfp_context.pop('base_mode', None)}
        request_info = {
            'nf_id': network_function_details['network_function']['id'],
            'nfi_id': (network_function_instance['id']
                       if network_function_instance else ''),
            'nfd_id': None,
            'requester': nfp_constants.SERVICE_ORCHESTRATOR,
            'operation': operation,
            'logging_context': nfp_logging.get_logging_context(),
            'nfp_context': rpc_nfp_context
        }
        if operation in ['consumer_add', 'consumer_remove']:
            request_info.update({'consumer_ptg': user_config_data[
                'consumer_ptg']})
        elif operation in ['pt_add', 'pt_remove']:
            request_info.update({'policy_target': user_config_data[
                'policy_target']})

        nfd = network_function_details.get('network_function_device')
        if nfd:
            request_info['nfd_id'] = network_function_details[
                'network_function_device']['id']
            nfd_ip = nfd['mgmt_ip_address']
            request_info.update({'device_ip': nfd_ip})
        return request_info

    def _update_params(self, user_config_data, config_params, operation):
        request_info = self._get_request_info(user_config_data, operation)
        config_params['info']['context'] = request_info

    def create_request_structure(self, user_config_data,
                                 service_config, config_tag):
        config_params = {
            'info': {
                'context': None,
                'service_type': user_config_data['service_type'].lower(),
                'service_vendor': None
            },
            'config': [{
                'resource': nfp_constants.CONFIG_TAG_RESOURCE_MAP[config_tag],
                'resource_data': {
                    'config_string': service_config,
                }
            }]
        }
        return config_params

    def create_network_function_user_config(self, user_config_data,
                                            service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='create')
        LOG.info(_LI("Sending create heat config request to configurator "
                     "with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')
        nfp_logging.clear_logging_context()

    def delete_network_function_user_config(self, user_config_data,
                                            service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='delete')
        LOG.info(_LI("Sending delete heat config request to configurator "
                     " with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')
        nfp_logging.clear_logging_context()

    def update_network_function_user_config(self, user_config_data,
                                            service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='update')
        LOG.info(_LI("Sending update heat config request to configurator "
                     " with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'UPDATE')
        nfp_logging.clear_logging_context()

    def policy_target_add_user_config(self, user_config_data,
                                      service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='pt_add')
        LOG.info(_LI("Sending Policy Target add heat config request to "
                     "configurator with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')
        nfp_logging.clear_logging_context()

    def policy_target_remove_user_config(self, user_config_data,
                                         service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='pt_remove')
        LOG.info(_LI("Sending Policy Target remove heat config request to "
                     "configurator with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')
        nfp_logging.clear_logging_context()

    def consumer_add_user_config(self, user_config_data,
                                 service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='consumer_add')
        LOG.info(_LI("Sending consumer add heat config request to "
                     "configurator with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')
        nfp_logging.clear_logging_context()

    def consumer_remove_user_config(self, user_config_data,
                                    service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='consumer_remove')
        LOG.info(_LI("Sending consumer remove heat config request to "
                     "configurator with config_params = %(config_params)s") %
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')
        nfp_logging.clear_logging_context()
