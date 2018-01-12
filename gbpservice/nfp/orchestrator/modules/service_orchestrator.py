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

from neutron.common import rpc as n_rpc
from neutron.db import api as db_api
from neutron_lib import context as n_context
from oslo_log import helpers as log_helpers
import oslo_messaging

from gbpservice._i18n import _
from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions as nfp_exc
from gbpservice.nfp.common import topics as nfp_rpc_topics
from gbpservice.nfp.core import context as module_context
from gbpservice.nfp.core.event import Event
from gbpservice.nfp.core import module as nfp_api
from gbpservice.nfp.core import path as nfp_path
from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.lib import nfp_context_manager as nfp_ctx_mgr
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
GATEWAY_SERVICES = [nfp_constants.FIREWALL, nfp_constants.VPN]


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
              'DEVICE_CREATED',
              'DEVICE_ACTIVE', 'DEVICE_DELETED',
              'DEVICE_CREATE_FAILED', 'SEND_USER_CONFIG',
              'CHECK_HEAT_CONFIG_RESULT', 'APPLY_USER_CONFIG',
              'APPLY_USER_CONFIG_BASEMODE',
              'DELETE_USER_CONFIG', 'UPDATE_USER_CONFIG',
              'POLICY_TARGET_ADD', 'POLICY_TARGET_REMOVE',
              'CONSUMER_ADD', 'CONSUMER_REMOVE',
              'APPLY_USER_CONFIG_IN_PROGRESS',
              'INITIATE_USER_CONFIG',
              'UPDATE_NETWORK_FUNCTION_DESCRIPTION',
              'UPDATE_USER_CONFIG_PREPARING_TO_START',
              'UPDATE_USER_CONFIG_IN_PROGRESS',
              'UPDATE_USER_CONFIG_STILL_IN_PROGRESS',
              'DELETE_USER_CONFIG_IN_PROGRESS',
              'CONFIG_APPLIED', 'USER_CONFIG_APPLIED', 'USER_CONFIG_DELETED',
              'USER_CONFIG_DELETE_FAILED', 'USER_CONFIG_UPDATE_FAILED',
              'USER_CONFIG_FAILED', 'CHECK_USER_CONFIG_COMPLETE',
              'SERVICE_CONFIGURED', 'CREATE_NETWORK_FUNCTION_INSTANCE_DB',
              'DELETE_NETWORK_FUNCTION_DB']
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
        module_context.init(network_function)
        LOG.info("Received RPC call for CREATE NETWORK FUNCTION for "
                 "tenant:%(tenant_id)s",
                 {'tenant_id': network_function[
                     'resource_owner_context']['tenant_id']})

        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.create_network_function(
            context, network_function)

    @log_helpers.log_method_call
    def get_network_function(self, context, network_function_id):
        '''Invoked in an RPC Call. Return the Network function DB object'''
        module_context.init()
        LOG.debug("Received RPC call for GET NETWORK FUNCTION for NFI %s",
                  network_function_id)

        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function(
            context, network_function_id)

    @log_helpers.log_method_call
    def get_network_functions(self, context, filters=None):
        '''Invoked in an RPC Call.

        Returns the Network functions from DB
        '''
        module_context.init()
        LOG.info("Received RPC call for GET NETWORK FUNCTIONS ")
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
        module_context.init()
        LOG.info("Received RPC call for UPDATE NETWORK FUNCTION for NF:"
                 "%(network_function_id)s",
                 {'network_function_id': network_function_id})
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.update_network_function(
            context, network_function_id, config)

    @log_helpers.log_method_call
    def delete_network_function(self, context, network_function_id,
            network_function_data):
        '''Delete the network Function.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        module_context.init()
        LOG.info("Received RPC call for DELETE NETWORK FUNCTION for NF:"
                 "%(network_function_id)s",
                 {'network_function_id': network_function_id})

        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.delete_network_function(
            context, network_function_id, network_function_data)

    @log_helpers.log_method_call
    def policy_target_added_notification(self, context, network_function_id,
                                         policy_target):
        '''Update Configuration to react to member addition.

        Invoked in an RPC call. Return the updated Network function DB object.
        Results in an Event for async processing of Network Function Instance.
        '''
        module_context.init()
        LOG.info("Received RPC call for POLICY TARGET ADDED NOTIFICATION "
                 "for NF:"
                 " %(network_function_id)s",
                 {'network_function_id': network_function_id})
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
        module_context.init()
        LOG.info("Received RPC call for POLICY TARGET REMOVED "
                 "NOTIFICATION for NF:%(network_function_id)s",
                 {'network_function_id': network_function_id})
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
        module_context.init()
        LOG.info("Received RPC call CONSUMER PTG ADDED NOTIFICATION "
                 "for NF:%(network_function_id)s",
                 {'network_function_id': network_function_id})
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
        module_context.init()
        LOG.info("Received RPC call for CONSUMER PTG REMOVED NOTIFICATION "
                 "for NF:%(network_function_id)s",
                 {'network_function_id': network_function_id})
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        service_orchestrator.handle_consumer_ptg_removed(
            context, network_function_id, policy_target_group)

    @log_helpers.log_method_call
    def get_network_function_details(self, context, network_function_id):
        '''Invoked in an RPC Call.

        Return the Network function Details object
        '''
        module_context.init()
        LOG.debug("Received RPC call for GET NETWORK FUNCTION DETAILS in "
                  "for NF:%s",
                  network_function_id)
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function_details(
            network_function_id)

    @log_helpers.log_method_call
    def get_port_info(self, context, port_id):
        '''Invoked in an RPC Call. Return the Port Info Details object'''
        module_context.init()
        LOG.debug("Received RPC call for GET PORT INFO in "
                  "for PORT ID:%s",
                  port_id)
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_port_info(port_id)

    @log_helpers.log_method_call
    def get_network_function_context(self, context, network_function_id):
        '''Invoked in an RPC Call.
        Return the Network function context
        '''
        module_context.init()
        LOG.debug("Received RPC call for GET NETWORK FUNCTION CONTEXT in "
                  "for NF:%s",
                  network_function_id)
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_network_function_context(
            network_function_id)

    @log_helpers.log_method_call
    def get_plumbing_info(self, context, request_info):
        module_context.init()
        LOG.debug("Received RPC call for GET PLUMBING INFO "
                  "for request info:%s",
                  request_info)
        service_orchestrator = ServiceOrchestrator(self._controller, self.conf)
        return service_orchestrator.get_pt_info_for_plumbing(request_info)


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
        network_function_instance = event_data.get('network_function_instance')
        if network_function_instance:
            NF = network_function_instance.get('network_function_id')
            NFI = network_function_instance.get('id')
        else:
            NF = None
            NFI = None
        if NF and NFI:
            LOG.info("Created event %(event_name)s with NF:%(nf)s "
                     "and NFI:%(nfi)s ",
                     {'event_name': event_id,
                      'nf': NF,
                      'nfi': NFI})
        else:
            LOG.info("Created event %(event_name)s ",
                     {'event_name': event_id})

    def _create_event(self, event_id, event_data=None,
                      is_poll_event=False, original_event=None,
                      serialize=False, max_times=10):
        if is_poll_event:
            ev = self._controller.new_event(
                id=event_id, data=event_data,
                serialize=original_event.sequence,
                binding_key=original_event.binding_key,
                key=original_event.key)
            LOG.debug("poll event started for %s", (ev.id))
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
        nfp_context = module_context.init()
        info = notification_data.get('info')
        responses = notification_data.get('notification')
        request_info = info.get('context')
        operation = request_info.get('operation')
        logging_context = request_info.get('logging_context', {})
        nfp_context['log_context'] = logging_context
        if 'nfp_context' in request_info:
            nfp_context.update(request_info['nfp_context'])

        serialize = False

        for response in responses:
            resource = response.get('resource')
            data = response.get('data')
            result = data.get('status_code')

            if result.lower() != 'success':
                if operation == 'create':
                    event_id = self.rpc_event_mapping[resource][0]
                elif operation == 'delete':
                    # No need to handle this
                    # event_id = self.rpc_event_mapping[resource][1]
                    return
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


class NFPDbPatch(nfp_db.NFPDbBase):

    """Patch for Db class.

    This class is used by service orchestrator to complete the path.
    In the CREATE/UPDATE operations, at last service orchestrator
    invokes update_network_function to update status to be ACTIVE/ERROR,
    and there are many error paths. Instead of doing 'path_complete'
    at multiple places, patched the Db class to override update &
    delete network_function methods. Here, the path is completed and
    then the base class methods are invoked to do the actual db operation.
    """

    def __init__(self, controller):
        self._controller = controller
        super(NFPDbPatch, self).__init__()

    def update_network_function(self, session, network_function_id,
                                updated_network_function):
        status = updated_network_function.get('status')
        if status == 'ACTIVE' or status == 'ERROR':
            self._controller.path_complete_event()
        return super(NFPDbPatch, self).update_network_function(
            session, network_function_id, updated_network_function)

    def delete_network_function(self, session, network_function_id):
        self._controller.path_complete_event()
        return super(NFPDbPatch, self).delete_network_function(
            session, network_function_id)


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
        self.conf = config
        self.db_handler = NFPDbPatch(controller)
        self.gbpclient = openstack_driver.GBPClient(config)
        self.keystoneclient = openstack_driver.KeystoneClient(config)
        self.config_driver = heat_driver.HeatDriver(config)
        neutron_context = n_context.get_admin_context()
        self.configurator_rpc = NSOConfiguratorRpcApi(neutron_context, config)
        self.UPDATE_USER_CONFIG_MAXRETRY = (
            nfp_constants.UPDATE_USER_CONFIG_PREPARING_TO_START_MAXRETRY)
        self.UPDATE_USER_CONFIG_STILL_IN_PROGRESS_MAXRETRY = (
            nfp_constants.UPDATE_USER_CONFIG_STILL_IN_PROGRESS_MAXRETRY)
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
        return db_api.get_writer_session()

    def event_method_mapping(self, event_id):
        event_handler_mapping = {
            "DELETE_NETWORK_FUNCTION": self.delete_network_function,
            "CREATE_NETWORK_FUNCTION_INSTANCE": (
                self.create_network_function_instance),
            "DELETE_NETWORK_FUNCTION_INSTANCE": (
                self.delete_network_function_instance),
            "DEVICE_CREATED": self.handle_device_created,
            "DEVICE_ACTIVE": self.handle_device_active,
            "SEND_USER_CONFIG": self.send_user_config,
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
            "INITIATE_USER_CONFIG": self.initiate_user_config,
            "UPDATE_NETWORK_FUNCTION_DESCRIPTION": (
                self.update_network_function_description),
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
                self.check_for_user_config_deleted_fast),
            "CONFIG_APPLIED": self.handle_config_applied,
            "USER_CONFIG_APPLIED": self.handle_user_config_applied,
            "USER_CONFIG_DELETED": self.handle_user_config_deleted,
            "USER_CONFIG_DELETE_FAILED": self.handle_user_config_delete_failed,
            "USER_CONFIG_UPDATE_FAILED": self.handle_update_user_config_failed,
            "USER_CONFIG_FAILED": self.handle_user_config_failed,
            "SERVICE_CONFIGURED": self.handle_service_configured,
            "CREATE_NETWORK_FUNCTION_INSTANCE_DB": (
                self.create_network_function_instance_db),
            "DELETE_NETWORK_FUNCTION_DB": self.delete_network_function_db
        }
        if event_id not in event_handler_mapping:
            raise Exception(_("Invalid Event ID"))
        else:
            return event_handler_mapping[event_id]

    def handle_event(self, event):
        event_data = event.context
        network_function_instance = event_data.get(
            'network_function_instance')
        if network_function_instance:
            NF = network_function_instance.get('network_function_id')
            NFI = network_function_instance.get('id')
        else:
            NF = None
            NFI = None
        if NF and NFI:
            LOG.info("Received event %(event_name)s with NF:%(nf)s and "
                     "NFI:%(nfi)s ",
                     {'event_name': event.id,
                      'nf': NF,
                      'nfi': NFI})
        else:
            LOG.info("Received event %(event_name)s ",
                     {'event_name': event.id})
        try:
            event_handler = self.event_method_mapping(event.id)
            event_handler(event)
        except Exception as e:
            LOG.exception("Error in processing event: %(event_id)s for "
                          "event data %(event_data)s. Error: %(error)s",
                          {'event_id': event.id, 'event_data': event.data,
                           'error': e})
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)
            raise e

    def handle_poll_event(self, event):
        LOG.info("Received poll event %(id)s",
                 {'id': event.id})
        try:
            event_handler = self.event_method_mapping(event.id)
            return event_handler(event)
        except Exception:
            LOG.exception("Error in processing poll event: "
                          "%(event_id)s", {'event_id': event.id})

    def event_cancelled(self, event, reason):
        nfp_context = event.context
        if event.id == 'CHECK_USER_CONFIG_COMPLETE':
            network_function = nfp_context['network_function']
            LOG.info("Applying user config failed for "
                     "NF:%(network_function_id)s "
                     "with reason %(reason)s"
                     " ", {'network_function_id': network_function[
                           'id'], 'reason': str(reason)})
            operation = nfp_context['log_context'].get('path')
            LOG.error("[Event:Service%(operation)sFailed]",
                      {'operation': operation.capitalize()})
            LOG.event('%s network function failed.' % operation.capitalize(),
                      stats_type=nfp_constants.error_event)

            binding_key = nfp_context['service_details'][
                'service_vendor'].lower() + network_function['id']
            # Complete the original event INITIATE_USER_CONFIG here
            event_desc = nfp_context.pop('event_desc', None)
            apply_config_event = self._controller.new_event(
                id='INITIATE_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            apply_config_event.binding_key = binding_key
            self._controller.event_complete(
                apply_config_event, result="FAILED")

        elif event.id == 'APPLY_USER_CONFIG_IN_PROGRESS' or (
                event.id == 'UPDATE_USER_CONFIG_STILL_IN_PROGRESS'):
            request_data = event.data
            LOG.info("Applying user config failed for "
                     "NF: %(network_function_id)s data:"
                     "%(data)s with reason %(reason)s"
                     "", {'data': request_data,
                         'network_function_id': request_data[
                             'network_function_id'],
                         'reason': str(reason)})

            updated_network_function = {'status': nfp_constants.ERROR}
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    request_data['network_function_id'],
                    updated_network_function)

            operation = nfp_context['log_context'].get('path')
            LOG.error("[Event:Service%(operation)sFailed]",
                      {'operation': operation.capitalize()})
            LOG.event('%s network function failed.' % operation.capitalize(),
                      stats_type=nfp_constants.error_event)

        elif event.id == 'DELETE_USER_CONFIG_IN_PROGRESS' or (
                event.id == 'UPDATE_USER_CONFIG_PREPARING_TO_START'):
            request_data = event.data
            event_data = {
                'network_function_id': request_data['network_function_id']
            }

            if event.id == 'DELETE_USER_CONFIG_IN_PROGRESS':
                ducf_event = self._controller.new_event(
                    id='DELETE_USER_CONFIG',
                    key=request_data['network_function_id'],
                    binding_key=request_data['network_function_id'],
                    desc_dict=request_data['event_desc'])
                self._controller.event_complete(ducf_event, result="FAILED")

            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=event_data, is_internal_event=True)

    def handle_exception(self, event, exception):
        return ExceptionHandler.handle(self, event, exception)

    def _log_event_created(self, event_id, event_data):
        network_function_instance = event_data.get(
            'network_function_instance')
        if network_function_instance:
            NF = network_function_instance.get('network_function_id')
            NFI = network_function_instance.get('id')
        else:
            NF = None
            NFI = None
        if NF and NFI:
            LOG.info("Created event %(event_name)s with NF:%(nf)s and "
                     "NFI:%(nfi)s ",
                     {'event_name': event_id,
                      'nf': NF,
                      'nfi': NFI})
        else:
            LOG.info("Created event %(event_name)s ",
                     {'event_name': event_id})
    # REVISIT(ashu): Merge this _create_event, and above one to have
    # single function.

    def _create_event(self, event_id, event_data=None,
                      key=None, binding_key=None, serialize=False,
                      is_poll_event=False, original_event=None,
                      is_internal_event=False, max_times=20):
        if not is_internal_event:
            if is_poll_event:
                ev = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid)
                LOG.debug("poll event started for %s", (ev.id))
                self._controller.poll_event(ev, max_times=max_times)
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
            nfp_context = module_context.get()
            self._log_event_created(event_id, nfp_context)
        else:
            nfp_context = module_context.get()
            if original_event:
                event = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid,
                    context=nfp_context)
            else:
                # Same module API, so calling corresponding function
                # directly.
                event = self._controller.new_event(
                    id=event_id,
                    data=event_data,
                    context=nfp_context)
            self.handle_event(event)

    def _get_base_mode_support(self, service_profile_id):
        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_token = kcm.retry(self.keystoneclient.get_admin_token)
        with nfp_ctx_mgr.GBPContextManager as gcm:
            service_profile = gcm.retry(self.gbpclient.get_service_profile,
                                        admin_token, service_profile_id)
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        resource_data = {'admin_token': admin_token,
                         'service_profile': service_profile,
                         'service_details': service_details}
        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)
        return base_mode_support, resource_data

    def _get_service_type(self, service_profile_id):
        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_token = kcm.retry(self.keystoneclient.get_admin_token)
        with nfp_ctx_mgr.GBPContextManager as gcm:
            service_profile = gcm.retry(self.gbpclient.get_service_profile,
                                        admin_token, service_profile_id)
        service_type = service_profile['service_type']
        return service_type

    def update_network_function_user_config(self, network_function_id,
                                            service_config_str,
                                            operation):
        tag_str, config_str = self.config_driver.parse_template_config_string(
            service_config_str)
        if not config_str:
            LOG.error('Exception while parsing config string, config '
                      'string: %(config_str)s is improper for '
                      'network_function id: %(network_function_id)s',
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
            LOG.error('Exception while parsing config string, config '
                      'string: %(config_str)s is improper for '
                      'network_function id: %(network_function_id)s',
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
        LOG.info("[TenantID:%(tenant_id)s, "
                 "ServiceChainID:%(service_chain_id)s, "
                 "ServiceInstanceID:%(service_instance_id)s, "
                 "ServiceType:%(service_type)s, "
                 "ServiceProvider:%(service_provider)s]",
                 {'tenant_id': nf['tenant_id'],
                  'service_chain_id': nf['service_chain_id'],
                  'service_instance_id': nfi['id'],
                  'service_type': service_type,
                  'service_provider': service_vendor})

    def _validate_service_vendor(self, service_vendor):
        if (service_vendor not in self.conf.orchestrator.supported_vendors):
            raise Exception(
                _("The NFP Node driver does not support this service "
                "profile with the service vendor %s.") % service_vendor)

    def create_network_function(self, context, network_function_info):
        self._validate_create_service_input(context, network_function_info)
        nfp_context = module_context.get()
        service_profile = network_function_info['service_profile']
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])

        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_token = kcm.retry(self.keystoneclient.get_admin_token)
            admin_tenant_id = kcm.retry(
                self.keystoneclient.get_admin_tenant_id, admin_token)

        network_function_info['resource_owner_context'][
            'admin_token'] = admin_token
        network_function_info['resource_owner_context'][
            'admin_tenant_id'] = admin_tenant_id

        tenant_id = network_function_info['tenant_id']

        # GBP or Neutron
        # mode = network_function_info['network_function_mode']
        service_profile_id = service_profile['id']
        service_id = network_function_info['service_chain_node']['id']
        service_chain_id = network_function_info[
            'service_chain_instance']['id']

        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)
        # REVISIT(ashu): take the first few characters just like neutron does
        # with ovs interfaces inside the name spaces..
        name = "%s_%s" % (network_function_info[
            'service_chain_node']['name'][:6],
            network_function_info[
            'service_chain_instance']['name'][:6])
        service_config_str = network_function_info.pop('service_config')
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
        with nfp_ctx_mgr.DbContextManager:
            network_function = self.db_handler.create_network_function(
                self.db_session, network_function)
        network_function.pop('service_config')

        # Update ncp_node_instance_nf_mapping with nf_id
        network_function_map = {
            'network_function_id': network_function['id'],
            'status': nfp_constants.PENDING_CREATE,
            'status_details': 'Processing create in orchestrator'
        }
        with nfp_ctx_mgr.DbContextManager:
            self.db_handler.update_node_instance_network_function_map(
                self.db_session, service_id, service_chain_id,
                network_function_map)
        nfp_path.create_path(network_function['id'])
        nfp_context['event_desc']['path_type'] = 'create'
        nfp_context['event_desc']['path_key'] = network_function['id']
        nfp_context['log_context']['path'] = 'create'
        nfp_context['log_context']['meta_id'] = network_function['id']
        nfp_context['log_context']['auth_token'] = context.auth_token

        LOG.info("[Event:ServiceCreateInitiated]")
        LOG.event("Started create network function.",
                  stats_type=nfp_constants.request_event)

        nfp_context.update(network_function_info)

        service_details['service_type'] = service_profile['service_type']
        service_details['network_mode'] = nfp_context['network_function_mode']
        nfp_context['network_function'] = network_function
        nfp_context['service_details'] = service_details
        nfp_context['share_existing_device'] = False
        nfp_context['base_mode'] = base_mode_support
        LOG.info("Handling RPC call CREATE NETWORK FUNCTION for "
                 "%(service_type)s with tenant:%(tenant_id)s",
                 {'tenant_id': tenant_id,
                  'service_type': service_profile['service_type']})
        if base_mode_support:
            # Store the context in current thread
            # In base mode support, create user config directly, no need to
            # create network function instance, network function device first.
            self.create_network_function_user_config(network_function['id'],
                                                     service_config_str)
        else:
            # Create and event to perform Network service instance
            ev = self._controller.new_event(
                id='CREATE_NETWORK_FUNCTION_INSTANCE_DB',
                key=network_function['id'])
            self._controller.post_event(ev)
            # self.create_network_function_instance_db(nfp_context)

        return network_function

    def update_network_function(self, context, network_function_id,
                                user_config):
        nfp_context = module_context.get()
        nfp_path.update_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'update'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'update'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        # Handle config update
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function_id,
                     {'service_config': user_config,
                      'status': nfp_constants.PENDING_UPDATE})
        LOG.info("[Event:ServiceUpdateInitiated]")
        LOG.event("Started update network function.",
                  stats_type=nfp_constants.request_event)

        self.update_network_function_user_config(network_function_id,
                                                 user_config,
                                                 operation='update')

    def delete_network_function(self, context, network_function_id,
                                network_function_data):
        nfp_context = module_context.get()
        nfp_path.delete_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'delete'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'delete'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        network_function_details = self.get_network_function_details(
            network_function_id)
        service_config = (
            network_function_details['network_function'].pop(
                'service_config'))
        service_profile_id = network_function_details[
            'network_function']['service_profile_id']
        base_mode_support, resource_data = (
            self._get_base_mode_support(service_profile_id))
        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_tenant_id = kcm.retry(
                self.keystoneclient.get_admin_tenant_id,
                resource_data['admin_token'])
        network_function_details['admin_tenant_id'] = admin_tenant_id
        nfi = network_function_details.get('network_function_instance', None)
        nfd = network_function_details.get('network_function_device', None)
        nfi_id = nfi.get('id', '-') if nfi else '-'
        nfd_id = nfd.get('id', '-') if nfd else '-'
        nfp_context['log_context']['nfi_id'] = nfi_id
        nfp_context['log_context']['nfd_id'] = nfd_id

        if (not base_mode_support and
                not network_function_details[
                    'network_function']['network_function_instances']):
            with nfp_ctx_mgr.DbContextManager:
                self.db_handler.delete_network_function(
                    self.db_session, network_function_id)
            LOG.info("[Event:ServiceDeleteCompleted]")
            LOG.event("Completed delete network function.",
                      stats_type=nfp_constants.response_event)

            # network_function_details['service_type is None because
            # nfp core context is not set
            # so getting service_type from resource_data
            service_type = resource_data['service_profile']['service_type']
            LOG.event("Sending service deleted event to controller.",
                      type='SERVICE_DELETED',
                      nf_id=network_function_id,
                      service_type=service_type)
            return
        network_function_details.update(resource_data)
        network_function_details.update(
            {'base_mode_support': base_mode_support})
        network_function = {
            'status': nfp_constants.PENDING_DELETE
        }
        service_chain_instance_details = {
                'service_chain_instance': network_function_data[
                    'service_chain_instance'],
                'provider': network_function_data['provider'],
                'consumer': network_function_data['consumer']
        }
        network_function_details.update(service_chain_instance_details)
        with nfp_ctx_mgr.DbContextManager as dcm:
            network_function = dcm.lock(
                self.db_session,
                self.db_handler.update_network_function,
                network_function_id, network_function)
        nfp_context.update(network_function_details)

        LOG.info("[Event:ServiceDeleteInitiated]")
        LOG.event("Started delete network function.",
                  stats_type=nfp_constants.request_event)
        if not base_mode_support:
            self._create_event('DELETE_NETWORK_FUNCTION_INSTANCE',
                               event_data=network_function_details,
                               is_internal_event=True)

        dnf_event = self._controller.new_event(
            id='DELETE_NETWORK_FUNCTION_DB',
            key=network_function_id)

        GRAPH = {dnf_event: []}

        if network_function['config_policy_id']:
            ducf_event = (
                self._controller.new_event(id='DELETE_USER_CONFIG',
                                           key=network_function_id,
                                           serialize=True,
                                           binding_key=network_function_id))
            GRAPH[dnf_event].append(ducf_event)
        else:
            self.delete_network_function_user_config(network_function_id,
                                                     service_config)
        if not base_mode_support:
            dnfd_event = self._controller.new_event(
                id='DELETE_NETWORK_FUNCTION_DEVICE',
                key=network_function_id,
                serialize=True,
                binding_key=network_function_id)
            GRAPH[dnf_event].append(dnfd_event)
        self._controller.post_graph(
            GRAPH, dnf_event, graph_str='DELETE_NETWORK_FUNCTION_GRAPH')

    def delete_user_config(self, event):
        network_function_details = event.context

        network_function_info = network_function_details['network_function']
        if not network_function_info['config_policy_id']:
            self._controller.event_complete(event, result="SUCCESS")
            return

        config_policy_id = self.config_driver.delete_config(
            network_function_info['config_policy_id'],
            network_function_info['tenant_id'],
            network_function_info)
        request_data = {
            'config_policy_id': network_function_info['config_policy_id'],
            'tenant_id': network_function_info['tenant_id'],
            'network_function_id': network_function_info['id'],
            'action': 'delete'
        }
        if not config_policy_id:
            # self._create_event('USER_CONFIG_DELETE_FAILED',
            # event_data=request_data, is_internal_event=True)
            self._controller.event_complete(event, result="FAILED")
            return
        request_data['event_desc'] = event.desc.to_dict()
        self._create_event(
            'DELETE_USER_CONFIG_IN_PROGRESS',
            event_data=request_data,
            is_poll_event=True, original_event=event,
            max_times=nfp_constants.DELETE_USER_CONFIG_IN_PROGRESS_MAXRETRY)

    def _update_nfp_context(self, nfp_context):
        provider = nfp_context['provider']
        consumer = nfp_context['consumer']
        provider['pt'] = provider['pt'][0]
        provider['ptg'] = provider['ptg'][0]
        provider['port'] = provider['port'][0]
        if consumer['pt']:
            consumer['pt'] = consumer['pt'][0]
        if consumer['ptg']:
            consumer['ptg'] = consumer['ptg'][0]
        if consumer['port']:
            consumer['port'] = consumer['port'][0]

    def create_network_function_instance_db(self, event):
        nfp_context = event.context

        network_function = nfp_context['network_function']
        service_details = nfp_context['service_details']

        port_info = []
        # REVISIT(ashu): Only pick few chars from id
        name = '%s_%s' % (network_function['id'][:3],
                          network_function['name'])
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
        with nfp_ctx_mgr.DbContextManager:
            nfi_db = self.db_handler.create_network_function_instance(
                self.db_session, create_nfi_request)
        # Sending LogMeta Details to visibility
        self._report_logging_info(network_function,
                                  nfi_db,
                                  service_details['service_type'],
                                  service_details['service_vendor'])

        nfp_context['network_function_instance'] = nfi_db

        self._update_nfp_context(nfp_context)

        ev = self._controller.new_event(
            id='CREATE_NETWORK_FUNCTION_INSTANCE',
            key=network_function['id'])
        self._controller.post_event(ev)

        self._controller.event_complete(event)

    def create_network_function_instance(self, event):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        consumer = nfp_context['consumer']
        provider = nfp_context['provider']
        network_function_instance = nfp_context[
            'network_function_instance']
        port_info = []
        for ele in [consumer, provider]:
            if ele['pt']:
                # REVISIT(ashu): Only pick few chars from id
                port_info.append(
                    {'id': ele['pt']['id'],
                     'port_model': ele['port_model'],
                     'port_classification': ele['port_classification']
                     })

        nfi = {
            'port_info': port_info
        }
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.update_network_function_instance(
                self.db_session, network_function_instance['id'], nfi)
        nfp_context['network_function_instance'] = nfi

        nfp_context['log_context']['nfi_id'] = nfi['id']

        LOG.info("Creating event CREATE NETWORK FUNCTION DEVICE "
                 "for NF: %(network_function_id)s",
                 {'network_function_id': network_function['id']})

        ev = self._controller.new_event(
            id='CREATE_NETWORK_FUNCTION_DEVICE',
            key=network_function['id'] + nfi['id'])

        if nfp_context.get('binding_key'):
            ev.sequence = True
            ev.binding_key = nfp_context.get('binding_key')

            LOG.debug("Acquiring tenant based lock for "
                      "CREATE_NETWORK_FUNCTION_DEVICE event with binding "
                      "key: %s, sequence: %s", (
                          ev.binding_key, ev.sequence))
        self._controller.post_event(ev)
        if event.binding_key and not nfp_context.get('is_nfi_in_graph'):
            LOG.debug("Releasing lock for CREATE_NETWORK_FUNCTION_INSTANCE"
                      " event for gateway services sharing with binding key:"
                      " %s", event.binding_key)
            self._controller.event_complete(event)

    def handle_device_created(self, event):
        # Not needed for NFP
        """
        request_data = event.data
        nfi = {
            'network_function_device_id': request_data[
                'network_function_device_id']
        }
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.update_network_function_instance(
                self.db_session,
                request_data['network_function_instance_id'], nfi)
        self._controller.event_complete(event)
        """
        return

    def send_user_config(self, event):
        nfp_context = event.context

        network_function_instance = nfp_context['network_function_instance']
        network_function_device = nfp_context['network_function_device']
        network_function = nfp_context['network_function']
        network_function_instance['status'] = nfp_constants.ACTIVE
        network_function_instance[
            'network_function_device_id'] = network_function_device['id']
        # get service_config from nf
        service_config = nfp_context['service_chain_node'].get('config')
        nfp_context['event_desc'] = event.desc.to_dict()
        nfp_context['key'] = event.key
        nfp_context['id'] = event.id
        self.create_network_function_user_config(network_function['id'],
                                                 service_config)

    def handle_device_active(self, event):
        request_data = event.data
        nfi = {
            'status': nfp_constants.ACTIVE,
            'network_function_device_id': request_data[
                'network_function_device_id']
        }
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.update_network_function_instance(
                self.db_session,
                request_data['network_function_instance_id'], nfi)
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

            # Complete this event first
            self._controller.event_complete(event)
            # Complete the original event here
            event = self._controller.new_event(id=id, key=key,
                                               desc_dict=event_desc)
            self._controller.event_complete(event, result='SUCCESS')

    def apply_user_config_basemode(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        request_data['config_policy_id'] = self.config_driver.apply_config(
            network_function_details)  # Heat driver to launch stack
        network_function = network_function_details['network_function']
        request_data['network_function_id'] = network_function['id']
        if not request_data['config_policy_id']:
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        request_data['tenant_id'] = network_function['tenant_id']
        request_data['network_function_details'] = network_function_details
        LOG.debug("handle_device_active config_policy_id: %s",
                  request_data['config_policy_id'])
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'config_policy_id': request_data['config_policy_id'],
                      'description': network_function['description']})
        self._create_event(
            'APPLY_USER_CONFIG_IN_PROGRESS',
            event_data=request_data,
            is_poll_event=True,
            original_event=event,
            max_times=nfp_constants.APPLY_USER_CONFIG_IN_PROGRESS_MAXRETRY)

    def initiate_user_config(self, event):
        # Split the user config creation in 2 steps,
        # get, update the description in network function and
        # apply user config
        event_results = event.result
        for c_event in event_results:
            if c_event.id == "SEND_USER_CONFIG" and (
                    c_event.result.upper() == "FAILED"):
                self._controller.event_complete(event, result="FAILED")
                return
            elif c_event.id == "SEND_USER_CONFIG" and (
                    c_event.result.upper() == "HANDLED"):
                self._controller.event_complete(
                    event, result="SUCCESS")
                return
        nfp_context = event.context
        nfp_context['event_desc'] = event.desc.to_dict()
        network_function = nfp_context['network_function']
        ev = self._controller.new_event(
            id='UPDATE_NETWORK_FUNCTION_DESCRIPTION',
            key=network_function['id'])
        self._controller.post_event(ev)

    def update_network_function_description(self, event):
        nfp_context = event.context

        network_function = nfp_context['network_function']
        network_function['description'] = str(network_function['description'])
        neutron_resource_desc = (
            self.config_driver.get_neutron_resource_description(nfp_context))
        if not neutron_resource_desc:
            LOG.error(
                "Preparing neutron resource description failed in "
                "config driver, marking user config as Failed for "
                "network function: %(nf)s", {'nf': network_function})
            nfp_context['network_function_id'] = network_function['id']
            binding_key = nfp_context['service_details'][
                'service_vendor'].lower() + network_function['id']
            # Complete the original event INITIATE_USER_CONFIG here
            event_desc = nfp_context.pop('event_desc', None)
            apply_config_event = self._controller.new_event(
                id='INITIATE_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            apply_config_event.binding_key = binding_key
            self._controller.event_complete(
                apply_config_event, result="FAILED")
            # self._create_event('USER_CONFIG_FAILED',
            # event_data=nfp_context, is_internal_event=True)
            return
        nf_desc = network_function['description'] + \
            '\n' + neutron_resource_desc
        nfp_context['network_function'].update({'description': nf_desc})
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'description': nf_desc})
        ev = self._controller.new_event(
            id='APPLY_USER_CONFIG',
            key=network_function['id'])
        self._controller.post_event(ev)
        self._controller.event_complete(event)

    def apply_user_config(self, event):
        nfp_context = event.context

        network_function = nfp_context['network_function']
        nfp_context['config_policy_id'] = self.config_driver.apply_heat_config(
            nfp_context)  # Heat driver to launch stack
        nfp_context['network_function_id'] = network_function['id']
        if not nfp_context['config_policy_id']:
            # self._create_event('USER_CONFIG_FAILED',
            # event_data=nfp_context, is_internal_event=True)
            binding_key = nfp_context['service_details'][
                'service_vendor'].lower() + network_function['id']
            # Complete the original event INITIATE_USER_CONFIG here
            event_desc = nfp_context.pop('event_desc', None)
            apply_config_event = self._controller.new_event(
                id='INITIATE_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            apply_config_event.binding_key = binding_key
            self._controller.event_complete(
                apply_config_event, result="FAILED")
            self._controller.event_complete(event, result='FAILED')
            return

        LOG.debug("handle_device_active config_policy_id: %s",
                  nfp_context['config_policy_id'])
        nfp_context['network_function'].update(
            {'config_policy_id': nfp_context['config_policy_id']})
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'config_policy_id': nfp_context['config_policy_id']})
        nfp_context['event_desc'] = event.desc.to_dict()
        self._create_event(
            'CHECK_USER_CONFIG_COMPLETE',
            is_poll_event=True,
            original_event=event,
            max_times=nfp_constants.CHECK_USER_CONFIG_COMPLETE_MAXRETRY)
        self._controller.event_complete(event)

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
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        request_data.update({'service_type': service_type})
        self._controller.event_complete(event)
        self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_internal_event=True,
                           original_event=event)

    def handle_continue_update_user_config(self, event):
        request_data = event.data
        network_function_details = self.get_network_function_details(
            request_data['network_function_id'])
        network_function = network_function_details['network_function']

        LOG.info("[Event:ServiceUpdateInitiated]")
        LOG.event("Started update network function.",
                  stats_type=nfp_constants.request_event)
        nfi = network_function_details.get('network_function_instance', None)
        nfd = network_function_details.get('network_function_device', None)
        nfi_id = nfi.get('id', '-') if nfi else '-'
        nfd_id = nfd.get('id', '-') if nfd else '-'

        nfp_context = event.context
        nfp_context['log_context']['nfi_id'] = nfi_id
        nfp_context['log_context']['nfd_id'] = nfd_id

        original_stack_id = network_function_details[
            'network_function']['config_policy_id']
        service_type = request_data['service_type']
        if not self.config_driver.is_update_config_supported(service_type):
            network_function_details['network_function'][
                'config_policy_id'] = None

        if request_data['operation'] == 'update':
            config_id = self.config_driver.update_config(
                network_function_details,
                network_function_details[
                    'network_function']['config_policy_id'])
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

        if config_id:
            request_data = {
                'config_policy_id': config_id,
                'tenant_id': network_function['tenant_id'],
                'network_function_id': network_function['id'],
                'network_function_details': network_function_details,
                'operation': request_data['operation'],
                'stack_id_to_delete': original_stack_id,
                'service_type': service_type
            }
        else:
            event_id = ('USER_CONFIG_UPDATE_FAILED'
                        if request_data['operation'] == 'update'
                        else 'USER_CONFIG_FAILED')
            self._create_event(event_id,
                               event_data=request_data,
                               is_internal_event=True)
            if event.binding_key:
                self._controller.event_complete(event)
            return
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'config_policy_id': config_id})
        self._create_event(
            'UPDATE_USER_CONFIG_STILL_IN_PROGRESS',
            event_data=request_data,
            is_poll_event=True, original_event=event,
            max_times=self.UPDATE_USER_CONFIG_STILL_IN_PROGRESS_MAXRETRY)

    def handle_device_create_failed(self, event):
        request_data = event.data
        nfi = {
            'status': nfp_constants.ERROR,
        }
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.update_network_function_instance(
                self.db_session,
                request_data['network_function_instance_id'], nfi)
            network_function = {'status': nfp_constants.ERROR}
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     nfi['network_function_id'],
                     network_function)
        nfp_context = event.context
        operation = nfp_context['log_context'].get('path')

        LOG.error("[Event:Service%(operation)sFailed]",
                  {'operation': operation.capitalize()})
        LOG.event('%s network function failed.' % operation.capitalize(),
                  stats_type=nfp_constants.error_event)

        # Trigger RPC to notify the Create_Service caller with status

    def handle_driver_error(self, network_function_id):
        LOG.error("Error occurred while processing network function "
                  "CRUD operations, marking network function: %(nf_id)s "
                  "as ERROR to initiate cleanup.",
                  {'nf_id': network_function_id})
        network_function_details = self.get_network_function_details(
            network_function_id)
        network_function_id = network_function_details.get(
            'network_function')['id']
        network_function = {'status': nfp_constants.ERROR}
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function_id, network_function)
        nfp_context = module_context.get()
        operation = nfp_context['log_context'].get('path')
        LOG.error("[Event:Service%(operation)sFailed]",
                  {'operation': operation.capitalize()})
        LOG.event('%s network function failed.' % operation.capitalize(),
                  stats_type=nfp_constants.error_event)

        if network_function_details.get('network_function_instance'):
            network_function_instance_id = network_function_details[
                'network_function_instance']['id']
            nfi = {
                'status': nfp_constants.ERROR,
            }
            with nfp_ctx_mgr.DbContextManager:
                nfi = self.db_handler.update_network_function_instance(
                    self.db_session, network_function_instance_id, nfi)

    def _update_network_function_instance(self):
        pass

    def delete_network_function_instance(self, event):
        network_function_details = event.context
        nfi_id = network_function_details['network_function_instance']['id']
        nfi = {'status': nfp_constants.PENDING_DELETE}
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.update_network_function_instance(
                self.db_session, nfi_id, nfi)
        network_function_details['network_function_instance'] = nfi

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

        service_profile = create_service_request['service_profile']
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        service_vendor = service_details.get('service_vendor')
        if (not service_vendor or
                not service_details.get('device_type')):
            raise Exception(_("service_vendor or device_type not provided in "
                            "service profile's service flavor field."
                            "Provided service profile: %s") % service_profile)
        self._validate_service_vendor(service_vendor.lower())

    @nfp_api.poll_event_desc(
        event='APPLY_USER_CONFIG_IN_PROGRESS',
        spacing=nfp_constants.APPLY_USER_CONFIG_IN_PROGRESS_SPACING)
    def apply_user_config_in_progress(self, event):
        request_data = event.data
        config_status = self.config_driver.is_config_complete(
            request_data['config_policy_id'], request_data['tenant_id'],
            request_data['network_function_details'])
        if config_status == nfp_constants.ERROR:
            LOG.info("Applying user config failed for "
                     "NF:%(network_function_id)s ", {
                         'network_function_id':
                         request_data['network_function_id']})
            updated_network_function = {'status': nfp_constants.ERROR}
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    request_data['network_function_id'],
                    updated_network_function)
            operation = event.context['log_context'].get('path')
            LOG.error("[Event:Service%(operation)sFailed]",
                      {'operation': operation.capitalize()})
            LOG.event('%s network function failed.' % operation.capitalize(),
                      stats_type=nfp_constants.error_event)

            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            if (request_data.get('operation') in [
                    'consumer_add',
                    'consumer_remove', 'update'] and not
                    self.config_driver.is_update_config_supported(
                        request_data['service_type'])):

                self.config_driver.delete_config(
                    request_data['stack_id_to_delete'],
                    request_data['tenant_id'])
                request_data = {
                    'config_policy_id': request_data['stack_id_to_delete'],
                    'network_function_id': request_data['network_function_id'],
                    'tenant_id': request_data['tenant_id'],
                    'action': 'update',
                    'operation': request_data['operation'],
                    'service_type': request_data['service_type']
                }
                self._controller.event_complete(event)
                self._create_event(
                    'UPDATE_USER_CONFIG_PREPARING_TO_START',
                    event_data=request_data,
                    is_poll_event=True, original_event=event,
                    max_times=self.UPDATE_USER_CONFIG_MAXRETRY)
                return STOP_POLLING
            updated_network_function = {'status': nfp_constants.ACTIVE}
            LOG.info("Applying user config is successfull moving "
                     "NF:%(network_function_id)s to ACTIVE",
                     {'network_function_id':
                      request_data['network_function_id']})
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    request_data['network_function_id'],
                    updated_network_function)

            operation = event.context['log_context'].get('path')
            LOG.info("[Event:Service%(operation)sCompleted]",
                     {'operation': operation.capitalize()})
            LOG.event('Completed %s network function.' % operation,
                      stats_type=nfp_constants.response_event)

            nf_id = request_data['network_function_id']
            with nfp_ctx_mgr.DbContextManager:
                network_function = self.db_handler.get_network_function(
                    self.db_session, nf_id)
            service_profile_id = network_function['service_profile_id']
            # Revisit(shabbir): service_type should be passed from previous
            # event
            service_type = self._get_service_type(service_profile_id)
            LOG.event('Completed %s network function.' % operation,
                      type='SERVICE_UPDATED',
                      nf_id=nf_id,
                      service_type=service_type)

            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    def handle_service_configured(self, event):
        nfp_context = event.context

        network_function = nfp_context['network_function']
        updated_network_function = {'status': nfp_constants.ACTIVE}
        LOG.info("Applying user config is successfull moving "
                 "NF: %(network_function_id)s to ACTIVE",
                 {'network_function_id': network_function['id']})
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     updated_network_function)
        operation = nfp_context['log_context'].get('path')

        LOG.info("[Event:Service%(operation)sCompleted]",
                 {'operation': operation.capitalize()})
        LOG.event('Completed %s network function.' % operation,
                  stats_type=nfp_constants.response_event)

        service_type = nfp_context['service_details']['service_type']
        nf_id = network_function['id']
        LOG.event("Sending service created event to controller.",
                  type='SERVICE_CREATED',
                  nf_id=nf_id,
                  service_type=service_type)

        self._controller.event_complete(event)

    @nfp_api.poll_event_desc(
        event='CHECK_USER_CONFIG_COMPLETE',
        spacing=nfp_constants.CHECK_USER_CONFIG_COMPLETE_SPACING)
    def check_for_user_config_complete(self, event):
        nfp_context = event.context

        network_function = nfp_context['network_function']
        binding_key = nfp_context[
            'service_details'][
            'service_vendor'].lower() + network_function['id']
        config_status = self.config_driver.check_config_complete(nfp_context)
        if config_status == nfp_constants.ERROR:

            LOG.info("Applying user config failed for "
                     "NF: %(network_function_id)s", {
                         'network_function_id':
                         network_function['id']})
            # Complete the original event APPLY_USER_CONFIG here
            event_desc = nfp_context.pop('event_desc', None)
            apply_config_event = self._controller.new_event(
                id='INITIATE_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            apply_config_event.binding_key = binding_key
            self._controller.event_complete(
                apply_config_event, result="FAILED")
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            # Complete the original event DEVICE_ACTIVE here
            event_desc = nfp_context.pop('event_desc', None)
            apply_config_event = self._controller.new_event(
                id='INITIATE_USER_CONFIG',
                key=network_function['id'],
                desc_dict=event_desc)
            apply_config_event.binding_key = binding_key
            self._controller.event_complete(
                apply_config_event, result="SUCCESS")

            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    @nfp_api.poll_event_desc(
        event='UPDATE_USER_CONFIG_PREPARING_TO_START',
        spacing=nfp_constants.UPDATE_USER_CONFIG_PREPARING_TO_START_SPACING)
    def check_for_user_config_deleted(self, event):
        request_data = event.data
        try:
            with nfp_ctx_mgr.DbContextManager:
                network_function = self.db_handler.get_network_function(
                    self.db_session,
                    request_data['network_function_id'])
            config_status = self.config_driver.is_config_delete_complete(
                request_data['config_policy_id'], request_data['tenant_id'],
                network_function)
        except Exception as err:
            # REVISIT: May be we need a count before removing the poll event
            LOG.error("Error: %(err)s while verifying configuration "
                      "delete completion.", {'err': err})
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=request_data, is_internal_event=True)
            self._controller.event_complete(event)
            return STOP_POLLING
        service_profile_id = network_function['service_profile_id']
        # Revisit(shabbir): service_type should be passed from previous event
        service_type = self._get_service_type(service_profile_id)
        if config_status == nfp_constants.ERROR:
            self._create_event('USER_CONFIG_DELETE_FAILED',
                               event_data=request_data, is_internal_event=True)
            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            updated_network_function = {'status': nfp_constants.ACTIVE}
            LOG.info("Applying user config is successfull moving "
                     "NF:%(network_function_id)s to ACTIVE",
                     {'network_function_id':
                      request_data['network_function_id']})
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    request_data['network_function_id'],
                    updated_network_function)
            operation = event.context['log_context'].get('path')

            LOG.info("[Event:Service%(operation)sCompleted]",
                     {'operation': operation.capitalize()})
            LOG.event('Completed %s network function.' % operation,
                      stats_type=nfp_constants.response_event)

            nf_id = request_data['network_function_id']
            LOG.event("Sending service updated event to controller.",
                      type='SERVICE_UPDATED',
                      nf_id=nf_id,
                      service_type=service_type)

            self._controller.event_complete(event)
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    @nfp_api.poll_event_desc(
        event='DELETE_USER_CONFIG_IN_PROGRESS',
        spacing=nfp_constants.DELETE_USER_CONFIG_IN_PROGRESS_SPACING)
    def check_for_user_config_deleted_fast(self, event):
        request_data = event.data
        nf_id = request_data['network_function_id']
        try:
            config_status = self.config_driver.is_config_delete_complete(
                request_data['config_policy_id'], request_data['tenant_id'])
        except Exception as err:
            # REVISIT: May be we need a count before removing the poll event
            LOG.error("Error: %(err)s while verifying configuration "
                      "delete completion.", {'err': err})
            # self._create_event('USER_CONFIG_DELETE_FAILED',
            #                    event_data=event_data, is_internal_event=True)
            self._controller.event_complete(event)
            ducf_event = self._controller.new_event(
                id='DELETE_USER_CONFIG',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=request_data['event_desc'])
            self._controller.event_complete(ducf_event, result="FAILED")

            return STOP_POLLING
        if config_status == nfp_constants.ERROR:
            # self._create_event('USER_CONFIG_DELETE_FAILED',
            #                    event_data=event_data, is_internal_event=True)
            self._controller.event_complete(event)
            ducf_event = self._controller.new_event(
                id='DELETE_USER_CONFIG',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=request_data['event_desc'])
            self._controller.event_complete(ducf_event, result="FAILED")
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.COMPLETED:
            self._controller.event_complete(event)
            ducf_event = self._controller.new_event(
                id='DELETE_USER_CONFIG',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=request_data['event_desc'])
            self._controller.event_complete(ducf_event, result="SUCCESS")
            return STOP_POLLING
            # Trigger RPC to notify the Create_Service caller with status
        elif config_status == nfp_constants.IN_PROGRESS:
            return CONTINUE_POLLING

    def handle_user_config_applied(self, event):
        request_data = event.data
        network_function = {
            'status': nfp_constants.ACTIVE,
            'config_policy_id': request_data['config_policy_id']
        }
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
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
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    network_function_id,
                    network_function)
            LOG.info("Applying user config is successfull moving "
                     "NF: %(network_function_id)s to ACTIVE",
                     {'network_function_id':
                      network_function_id})
        else:
            '''
            network_function_instance_id = (
                event.data['network_function_instance_id'])
            if network_function_instance_id:
                nfi = {
                    'status': nfp_constants.ACTIVE,
                }
                nfi = self.db_handler.update_network_function_instance(
                    self.db_session, network_function_instance_id, nfi)
            '''
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
        LOG.error("NSO: updating user config failed, moving "
                  "network function %(network_function_id)s to ERROR",
                  {'network_function_id': network_function_id})
        self.handle_user_config_failed(event)

    def handle_user_config_failed(self, event):
        request_data = event.data
        updated_network_function = {
            'status': nfp_constants.ERROR,
            'config_policy_id': request_data.get('config_policy_id')
        }
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     request_data['network_function_id'],
                     updated_network_function)
        # Trigger RPC to notify the Create_Service caller with status
        operation = event.context['log_context'].get('path')
        LOG.error("[Event:Service%(operation)sFailed]",
                  {'operation': operation.capitalize()})
        LOG.event('%s network function failed.' % operation.capitalize(),
                  stats_type=nfp_constants.error_event)

    def handle_user_config_deleted(self, event):
        # DELETE DEVICE_CONFIGURATION is not serialized with DELETE
        # SERVICE_CONFIGURATION so,no logic need to be added here.
        pass

    # Change to Delete_failed or continue with instance and device
    # delete if config delete fails? or status CONFIG_DELETE_FAILED ??
    def handle_user_config_delete_failed(self, event):
        request_data = event.data
        updated_network_function = {
            'status': nfp_constants.ERROR,
        }
        # If stack delete fails after successfull  heat stack create
        # in fw update case
        # still we make network function status active to allow subsequent
        # sharing
        if (request_data.get('operation') in [
                'consumer_add', 'consumer_remove', 'update'] and not
            self.config_driver.is_update_config_supported(
                request_data['service_type'])):
            updated_network_function.update({'status': nfp_constants.ACTIVE})
            LOG.warning(
                "Failed to delete old stack id: %(stack_id)s in"
                "firewall update case, Need to manually delete it",
                {"stack_id": request_data['config_policy_id']})

        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     request_data['network_function_id'],
                     updated_network_function)
        # Trigger RPC to notify the Create_Service caller with status

    # When NDO deletes Device DB, the Foreign key NSI will be nulled
    # So we have to pass the NSI ID in delete event to NDO and process
    # the result based on that
    def delete_network_function_db(self, event):
        results = event.result
        for result in results:
            if result.result.lower() != 'success':
                LOG.error("Event: %(result_id)s failed",
                          {'result_id': result.id})

        network_function_details = event.context
        if not network_function_details['base_mode_support']:
            nfi_id = (
                network_function_details['network_function_instance']['id'])
            with nfp_ctx_mgr.DbContextManager.new(
                    suppress=(
                        nfp_exc.NetworkFunctionInstanceNotFound,)):

                self.db_handler.delete_network_function_instance(
                    self.db_session, nfi_id)

        nf_id = network_function_details['network_function']['id']
        with nfp_ctx_mgr.DbContextManager:
            nf = self.db_handler.get_network_function(
                self.db_session, nf_id)

        if not nf['network_function_instances']:
            with nfp_ctx_mgr.DbContextManager:
                self.db_handler.delete_network_function(
                    self.db_session, nf['id'])
            LOG.info("[Event:ServiceDeleteCompleted]")
            LOG.event("Completed delete network function.",
                      stats_type=nfp_constants.response_event)

            service_type = network_function_details['service_profile'][
                'service_type']
            LOG.event("Sending service deleted event to controller.",
                      type='SERVICE_DELETED',
                      nf_id=nf_id,
                      service_type=service_type)

        LOG.info("Deleted NF:%(nf_id)s ",
                 {'nf_id': nf['id']})
        self._controller.event_complete(event)

    def handle_device_deleted(self, event):
        request_data = event.data
        nfi_id = request_data['network_function_instance_id']
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.db_handler.get_network_function_instance(
                self.db_session, nfi_id)
            self.db_handler.delete_network_function_instance(
                self.db_session, nfi_id)
            network_function = self.db_handler.get_network_function(
                self.db_session, nfi['network_function_id'])
        nf_id = network_function['id']
        if not network_function['network_function_instances']:
            with nfp_ctx_mgr.DbContextManager:
                self.db_handler.delete_network_function(
                    self.db_session, nfi['network_function_id'])
            LOG.info("[Event:ServiceDeleteCompleted]")
            LOG.event("Completed delete network function.",
                      stats_type=nfp_constants.response_event)

            service_type = request_data['service_type']
            LOG.event("Sending service deleted event to controller.",
                      type='SERVICE_DELETED',
                      nf_id=nf_id,
                      service_type=service_type)

        LOG.info("Deleted NF:%(nf_id)s ",
                 {'nf_id': nf_id})
        # Inform delete service caller with delete completed RPC

    def get_network_function(self, context, network_function_id):
        try:
            nfp_context = module_context.get()
            nfp_context['log_context']['meta_id'] = network_function_id
            nfp_context['log_context']['auth_token'] = context.auth_token

            with nfp_ctx_mgr.DbContextManager:
                network_function = self.db_handler.get_network_function(
                    self.db_session, network_function_id)
            return network_function
        except nfp_exc.NetworkFunctionNotFound:
            LOG.warning("Failed to retrieve Network Function details for"
                        " %(network_function)s",
                        {'network_function': network_function_id})
            return None
        except Exception:
            LOG.exception("Failed to retrieve Network Function details for"
                          " %(network_function)s",
                          {'network_function': network_function_id})
            return None

    def get_network_functions(self, context, filters):
        with nfp_ctx_mgr.DbContextManager:
            return self.db_handler.get_network_functions(
                self.db_session, filters)

    def _update_network_function_status(self, network_function_id, operation):
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function_id,
                     {'status': self.status_map[operation]['status'],
                      'status_description': self.status_map[operation][
                         'status_description']})

    def handle_policy_target_added(self, context, network_function_id,
                                   policy_target):
        nfp_context = module_context.get()
        nfp_path.update_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'update'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'update'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        with nfp_ctx_mgr.DbContextManager:
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support, _ = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    network_function['id'],
                    {'status': nfp_constants.ERROR,
                     'status_description': (
                         "Config Update for Policy Target "
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
            'config_policy_id': config_id,
            'tenant_id': network_function['tenant_id'],
            'network_function_id': network_function['id'],
            'network_function_details': network_function_details
        }
        if not config_id:
            self._controller.event_complete(event)
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'config_policy_id': config_id})
        self._controller.event_complete(event)
        self._create_event(
            'APPLY_USER_CONFIG_IN_PROGRESS',
            event_data=request_data,
            is_poll_event=True, original_event=event,
            max_times=nfp_constants.APPLY_USER_CONFIG_IN_PROGRESS_MAXRETRY)

    def handle_policy_target_removed(self, context, network_function_id,
                                     policy_target):
        nfp_context = module_context.get()
        nfp_path.update_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'update'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'update'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        with nfp_ctx_mgr.DbContextManager:
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support, _ = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    network_function['id'],
                    {'status': nfp_constants.ERROR,
                     'status_description': (
                         "Config Update for Policy Target "
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
            'config_policy_id': config_id,
            'tenant_id': network_function['tenant_id'],
            'network_function_id': network_function['id'],
            'network_function_details': network_function_details
        }
        if not config_id:
            self._controller.event_complete(event)
            self._create_event('USER_CONFIG_FAILED',
                               event_data=request_data, is_internal_event=True)
            return
        with nfp_ctx_mgr.DbContextManager as dcm:
            dcm.lock(self.db_session, self.db_handler.update_network_function,
                     network_function['id'],
                     {'config_policy_id': config_id})

        self._controller.event_complete(event)
        self._create_event(
            'APPLY_USER_CONFIG_IN_PROGRESS',
            event_data=request_data,
            is_poll_event=True, original_event=event,
            max_times=nfp_constants.APPLY_USER_CONFIG_IN_PROGRESS_MAXRETRY)

    def handle_consumer_ptg_added(self, context, network_function_id,
                                  consumer_ptg):
        nfp_context = module_context.get()
        nfp_path.update_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'update'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'update'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        with nfp_ctx_mgr.DbContextManager:
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)
        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support, _ = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(self.db_session,
                         self.db_handler.update_network_function,
                         network_function['id'],
                         {'status': nfp_constants.ERROR,
                          'status_description': (
                              "Config Update for Consumer Policy"
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
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        request_data.update({'service_type': service_type})
        self._controller.event_complete(event)
        self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_internal_event=True,
                           original_event=event)

    def handle_consumer_ptg_removed(self, context, network_function_id,
                                    consumer_ptg):
        nfp_context = module_context.get()
        nfp_path.update_path(network_function_id)
        nfp_context['event_desc']['path_type'] = 'update'
        nfp_context['event_desc']['path_key'] = network_function_id
        nfp_context['log_context']['path'] = 'update'
        nfp_context['log_context']['meta_id'] = network_function_id
        nfp_context['log_context']['auth_token'] = context.auth_token

        with nfp_ctx_mgr.DbContextManager:
            network_function = self.db_handler.get_network_function(
                self.db_session, network_function_id)

        network_function_details = self.get_network_function_details(
            network_function_id)
        base_mode_support, _ = self._get_base_mode_support(
            network_function['service_profile_id'])
        if not base_mode_support:
            required_attributes = ["network_function",
                                   "network_function_instance",
                                   "network_function_device"]
        else:
            required_attributes = ["network_function"]
        if (set(required_attributes) & set(network_function_details.keys()) !=
                set(required_attributes)):
            with nfp_ctx_mgr.DbContextManager as dcm:
                dcm.lock(
                    self.db_session,
                    self.db_handler.update_network_function,
                    network_function['id'],
                    {'status': nfp_constants.ERROR,
                     'status_description': (
                         "Config Update for Consumer Policy"
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
        network_function = network_function_details['network_function']
        service_profile_id = network_function['service_profile_id']
        service_type = self._get_service_type(service_profile_id)
        request_data.update({'service_type': service_type})
        self._controller.event_complete(event)
        self._create_event('UPDATE_USER_CONFIG_IN_PROGRESS',
                           event_data=request_data,
                           is_internal_event=True,
                           original_event=event)

    def get_port_info(self, port_id):
        try:
            with nfp_ctx_mgr.DbContextManager:
                port_info = self.db_handler.get_port_info(
                    self.db_session, port_id)
            return port_info
        except Exception:
            LOG.exception("Failed to retrieve Port Info for"
                          " %(port_id)s",
                          {'port_id': port_id})
            return None

    def get_network_function_details(self, network_function_id):
        network_function = None
        network_function_instance = None
        network_function_device = None
        service_type = None

        nfp_context = module_context.get()
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
            with nfp_ctx_mgr.DbContextManager:
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
            # Assuming single network_function_instance
            with nfp_ctx_mgr.DbContextManager:
                network_function_instance = (
                    self.db_handler.get_network_function_instance(
                        self.db_session, network_function_instances[0]))

        network_function_details[
            'network_function_instance'] = network_function_instance

        if not network_function_device:
            if network_function_instance['network_function_device_id']:
                with nfp_ctx_mgr.DbContextManager:
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
        network_function_device = (
            network_function_details['network_function_device'])
        ports_info = []
        for id in network_function_details[
                'network_function_instance']['port_info']:
            port_info = self.get_port_info(id)
            ports_info.append(port_info)

        mngmt_port_info = None
        monitor_port_info = None
        if network_function_device:
            mgmt_port_id = network_function_device['mgmt_port_id']
            if mgmt_port_id is not None:
                mngmt_port_info = self.get_port_info(mgmt_port_id)

            monitor_port_id = network_function_device['monitoring_port_id']
            if monitor_port_id is not None:
                monitor_port_info = self.get_port_info(monitor_port_id)

        nf_context = {'network_function_details': network_function_details,
                      'ports_info': ports_info,
                      'mngmt_port_info': mngmt_port_info,
                      'monitor_port_info': monitor_port_info}
        return nf_context

    def get_pt_info_for_plumbing(self, chain_info):
        plumbing_request = {'management': [], 'provider': [{}],
                            'consumer': [{}]}
        service_type = chain_info['profile']['service_type']
        if service_type.lower() in GATEWAY_SERVICES:
            plumbing_request['plumbing_type'] = nfp_constants.GATEWAY_TYPE
        else:
            plumbing_request['plumbing_type'] = nfp_constants.ENDPOINT_TYPE
        return plumbing_request


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
        nfp_context = module_context.get()
        rpc_nfp_context = None
        if nfp_context:
            rpc_nfp_context = {
                'event_desc': nfp_context.get('event_desc', None),
                'key': nfp_context.pop('key', None),
                'id': nfp_context.pop('id', None),
                'base_mode': nfp_context.pop('base_mode', None)}
            nf_data = {
                'service_chain_instance': nfp_context.get(
                    'service_chain_instance'),
                'provider': nfp_context.get('provider'),
                'consumer': nfp_context.get('consumer')
            }
            rpc_nfp_context.update(nf_data)
        request_info = {
            'nf_id': network_function_details['network_function']['id'],
            'nfi_id': (network_function_instance['id']
                       if network_function_instance else ''),
            'nfd_id': None,
            'requester': nfp_constants.SERVICE_ORCHESTRATOR,
            'operation': operation,
            'logging_context': nfp_context['log_context'],
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
        LOG.info("Sending create heat config request to configurator ")
        LOG.debug("Sending create heat config request to configurator "
                  "with config_params = %s",
                  config_params)

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')

    def delete_network_function_user_config(self, user_config_data,
                                            service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='delete')
        LOG.info("Sending delete heat config request to configurator ")
        LOG.debug("Sending delete heat config request to configurator "
                  " with config_params = %s",
                  config_params)
        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')

    def update_network_function_user_config(self, user_config_data,
                                            service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='update')
        LOG.info("Sending update heat config request to configurator. ")

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'UPDATE')

    def policy_target_add_user_config(self, user_config_data,
                                      service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='pt_add')
        LOG.info("Sending Policy Target and heat config request to "
                 "configurator .")

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')

    def policy_target_remove_user_config(self, user_config_data,
                                         service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='pt_remove')
        LOG.info("Sending Policy Target remove heat config request to "
                 "configurator. ")

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')

    def consumer_add_user_config(self, user_config_data,
                                 service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='consumer_add')
        LOG.info("Sending consumer and heat config request to "
                 "configurator .")

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE')

    def consumer_remove_user_config(self, user_config_data,
                                    service_config, config_tag):
        config_params = self.create_request_structure(user_config_data,
                                                      service_config,
                                                      config_tag)
        self._update_params(user_config_data,
                            config_params, operation='consumer_remove')
        LOG.info("Sending consumer remove heat config request to "
                 "configurator .")

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE')


class ExceptionHandler(object):

    @staticmethod
    def event_method_mapping(event_id):
        event_handler_mapping = {
            "CREATE_NETWORK_FUNCTION_INSTANCE_DB": (
                ExceptionHandler.handle_create_nfi_db_exception),
            "CREATE_NETWORK_FUNCTION_INSTANCE": (
                ExceptionHandler.handle_create_nfi_exception),
            "DEVICE_CREATED": ExceptionHandler.handle_device_created_exception,
            "SEND_USER_CONFIG":
                ExceptionHandler.handle_send_heat_config_exception,
            "APPLY_USER_CONFIG":
                ExceptionHandler.handle_apply_user_config_exception,
            "APPLY_USER_CONFIG_BASEMODE":
                ExceptionHandler.handle_apply_user_config_basemode_exception,
            "CHECK_HEAT_CONFIG_RESULT":
                ExceptionHandler.handle_check_heat_config_result_exception,
            "INITIATE_USER_CONFIG":
                ExceptionHandler.handle_initiate_user_config_exception,
            "UPDATE_NETWORK_FUNCTION_DESCRIPTION": (
                ExceptionHandler.handle_update_nf_description_exception),
            "CHECK_USER_CONFIG_COMPLETE": (
                ExceptionHandler.handle_check_user_config_complete_exception),
            "SERVICE_CONFIGURED": (
                ExceptionHandler.handle_service_configured_exception),
            "CONFIG_APPLIED": ExceptionHandler.handle_config_applied_exception,
            "DEVICE_CREATE_FAILED": (
                ExceptionHandler.handle_device_create_failed_exception),
            "DELETE_NETWORK_FUNCTION_INSTANCE": (
                ExceptionHandler.handle_delete_nfi_exception),
            "DELETE_USER_CONFIG": (
                ExceptionHandler.handle_delete_user_config_exception),
            "DELETE_USER_CONFIG_IN_PROGRESS": (
                ExceptionHandler.handle_check_user_config_deleted_exception),
            "DELETE_NETWORK_FUNCTION_DB": (
                ExceptionHandler.handle_delete_network_function_db_exception),
        }
        if event_id not in event_handler_mapping:
            raise Exception(_("Invalid Event ID"))
        else:
            return event_handler_mapping[event_id]

    @staticmethod
    def handle(orchestrator, event, exception):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        message = "Traceback: %s" % traceback.format_exception(
            exc_type, exc_value, exc_traceback)
        LOG.error(message)

        exception_handler = ExceptionHandler.event_method_mapping(event.id)
        return exception_handler(orchestrator, event, exception)

    @staticmethod
    def handle_create_nfi_db_exception(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_create_nfi_exception(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_device_created_exception(orchestrator, event, exception):
        device = event.data
        network_function_id = device['network_function_id']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function_id,
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_send_heat_config_exception(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_check_heat_config_result_exception(
            orchestrator, event, exception):

        nfp_context = event.data['nfp_context']
        base_mode = nfp_context['base_mode']
        if base_mode:
            network_function = nfp_context['network_function']
            orchestrator.db_handler.update_network_function(
                orchestrator.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR})
            orchestrator._controller.event_complete(event, result='FAILED')
            return
        event_desc = nfp_context['event_desc']
        key = nfp_context['key']
        id = nfp_context['id']
        # Complete the original event here
        ev = orchestrator._controller.new_event(id=id, key=key,
                                                desc_dict=event_desc)
        orchestrator._controller.event_complete(ev, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_apply_user_config_exception(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        event_desc = nfp_context.pop('event_desc', None)
        apply_config_event = orchestrator._controller.new_event(
            id='INITIATE_USER_CONFIG',
            key=network_function['id'],
            desc_dict=event_desc)
        orchestrator._controller.event_complete(
            apply_config_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_apply_user_config_basemode_exception(
            orchestrator, event, exception):

        nfp_context = event.data
        network_function = nfp_context['network_function']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_initiate_user_config_exception(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_update_nf_description_exception(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        event_desc = nfp_context.pop('event_desc', None)
        apply_config_event = orchestrator._controller.new_event(
            id='INITIATE_USER_CONFIG',
            key=network_function['id'],
            desc_dict=event_desc)
        orchestrator._controller.event_complete(
            apply_config_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_check_user_config_complete_exception(
            orchestrator, event, exception):

        nfp_context = event.context
        network_function = nfp_context['network_function']
        event_desc = nfp_context.pop('event_desc', None)
        apply_config_event = orchestrator._controller.new_event(
            id='INITIATE_USER_CONFIG',
            key=network_function['id'],
            desc_dict=event_desc)
        orchestrator._controller.event_complete(
            apply_config_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')
        return {'poll': False}

    @staticmethod
    def handle_service_configured_exception(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_config_applied_exception(orchestrator, event, exception):
        nfp_context = event.data['nfp_context']
        network_function = nfp_context['network_function']
        base_mode = nfp_context['base_mode']
        if base_mode:
            orchestrator.db_handler.update_network_function(
                orchestrator.db_session,
                network_function['id'],
                {'status': nfp_constants.ERROR})
            orchestrator._controller.event_complete(event, result='FAILED')
            return

        event_desc = nfp_context['event_desc']
        key = nfp_context['key']
        id = nfp_context['id']
        ev = orchestrator._controller.new_event(id=id, key=key,
                                                desc_dict=event_desc)
        orchestrator._controller.event_complete(ev, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_device_create_failed_exception(orchestrator, event, exception):
        request_data = event.data
        network_function_id = request_data['network_function_id']
        orchestrator.db_handler.update_network_function(
            orchestrator.db_session,
            network_function_id,
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_delete_nfi_exception(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_delete_user_config_exception(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def handle_check_user_config_deleted_exception(
            orchestrator, event, exception):

        request_data = event.data
        nf_id = request_data['network_function_id']
        orchestrator._controller.event_complete(event, result='FAILED')
        ducf_event = orchestrator._controller.new_event(
            id='DELETE_USER_CONFIG',
            key=nf_id,
            binding_key=nf_id,
            desc_dict=request_data['event_desc'])
        orchestrator._controller.event_complete(ducf_event, result="FAILED")
        return {"poll": False}

    @staticmethod
    def handle_delete_network_function_db_exception(
            orchestrator, event, exception):

        orchestrator._controller.event_complete(event, result='FAILED')
