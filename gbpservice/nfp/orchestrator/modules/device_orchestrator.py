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


import oslo_messaging as messaging

from gbpservice._i18n import _
from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import topics as nsf_topics
from gbpservice.nfp.common import utils as nfp_utils
from gbpservice.nfp.core import context as module_context
from gbpservice.nfp.core.event import Event
from gbpservice.nfp.core import module as nfp_api
from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.lib import nfp_context_manager as nfp_ctx_mgr
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.db import nfp_db as nfp_db
from gbpservice.nfp.orchestrator.drivers import orchestration_driver
from gbpservice.nfp.orchestrator.openstack import openstack_driver
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.db import api as db_api

import copy
import sys
import traceback

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)

STOP_POLLING = {'poll': False}
CONTINUE_POLLING = {'poll': True}


def rpc_init(controller, config):
    rpcmgr = RpcHandler(config, controller)
    agent = RpcAgent(
        controller,
        host=config.host,
        topic=nsf_topics.NFP_CONFIGURATOR_NDO_TOPIC,
        manager=rpcmgr)
    controller.register_rpc_agents([agent])


def events_init(controller, config, device_orchestrator):
    events = ['CREATE_NETWORK_FUNCTION_DEVICE', 'DEVICE_SPAWNING',
              'DEVICE_HEALTHY', 'HEALTH_MONITOR_COMPLETE',
              'DEVICE_UP',
              'CONFIGURE_DEVICE', 'CREATE_DEVICE_CONFIGURATION',
              'CONFIGURATION_COMPLETE',
              'DEVICE_CONFIGURED', "DELETE_CONFIGURATION",
              'DELETE_NETWORK_FUNCTION_DEVICE',
              'DELETE_CONFIGURATION_COMPLETED',
              'DEVICE_BEING_DELETED',
              'DEVICE_NOT_REACHABLE',
              'DEVICE_CONFIGURATION_FAILED',
              'PLUG_INTERFACES', 'UNPLUG_INTERFACES',
              'UPDATE_DEVICE_CONFIG_PARAMETERS',
              'DEVICE_CONFIG_PARAMETERS_UPDATED',
              'PERIODIC_HM_DEVICE_REACHABLE',
              'PERIODIC_HM_DEVICE_NOT_REACHABLE',
              'PERFORM_INITIAL_HEALTH_CHECK',
              'PERFORM_PERIODIC_HEALTH_CHECK',
              'PERFORM_CLEAR_HM']
    events_to_register = []
    for event in events:
        events_to_register.append(
            Event(id=event, handler=device_orchestrator))
    controller.register_events(events_to_register)


def nfp_module_init(controller, config):
    events_init(controller, config, DeviceOrchestrator(controller, config))
    rpc_init(controller, config)
    LOG.debug("Device Orchestrator: module_init")


class RpcHandler(object):
    RPC_API_VERSION = '1.0'

    def __init__(self, conf, controller):
        super(RpcHandler, self).__init__()
        self.conf = conf
        self._controller = controller
        self.rpc_event_mapping = {
            nfp_constants.HEALTHMONITOR_RESOURCE: [
                'HEALTH_MONITOR_COMPLETE',
                'DEVICE_NOT_REACHABLE',
                'DEVICE_NOT_REACHABLE',
                'PERIODIC_HM_DEVICE_REACHABLE',
                'PERIODIC_HM_DEVICE_NOT_REACHABLE', ],
            nfp_constants.GENERIC_CONFIG: [
                'DEVICE_CONFIGURED',
                'DELETE_CONFIGURATION_COMPLETED',
                'DEVICE_CONFIGURATION_FAILED'],
        }

    def _log_event_created(self, event_id, event_data):
        NFD = event_data.get('network_function_device_id')
        NF = event_data.get('network_function_id')
        NFI = event_data.get('network_function_instance_id')

        if NFD and NF and NFI:
            LOG.info(_LI("Created event %(event_name)s with"
                         " NF:%(nf)s ,NFI:%(nfi)s and NFD:%(nfd)s"),
                     {'event_name': event_id,
                      'nf': NF,
                      'nfi': NFI,
                      'nfd': NFD})
        else:
            LOG.info(_LI("Created event %(event_name)s "),
                     {'event_name': event_id})

    def _create_event(self, event_id, event_data=None, key=None,
                      is_poll_event=False, original_event=False, max_times=10):
        if is_poll_event:
            ev = self._controller.new_event(
                id=event_id, data=event_data,
                serialize=original_event.sequence,
                binding_key=original_event.binding_key,
                key=original_event.desc.uuid)
            LOG.debug("poll event started for %s", ev.id)
            self._controller.poll_event(ev, max_times=10)
        else:
            ev = self._controller.new_event(
                id=event_id,
                key=key,
                data=event_data)
            self._controller.post_event(ev)
        self._log_event_created(event_id, event_data)

    def handle_periodic_hm_resource(self, result):
        if result == nfp_constants.SUCCESS:
            event_id = self.rpc_event_mapping[
                nfp_constants.HEALTHMONITOR_RESOURCE][3]
        else:
            event_id = self.rpc_event_mapping[
                nfp_constants.HEALTHMONITOR_RESOURCE][4]
        return event_id

    # RPC APIs status notification from Configurator
    def network_function_notification(self, context, notification_data):
        nfp_context = module_context.init()
        info = notification_data.get('info')
        responses = notification_data.get('notification')
        request_info = info.get('context')
        operation = request_info.get('operation')
        logging_context = request_info.get('logging_context', {})
        # nfp_context = request_info.get('nfp_context')
        nfp_context['log_context'] = logging_context
        if 'nfp_context' in request_info:
            nfp_context['event_desc'] = request_info[
                'nfp_context'].get('event_desc', {})

        for response in responses:
            resource = response.get('resource')
            data = response.get('data')
            result = data.get('status_code')
            if resource not in [nfp_constants.HEALTHMONITOR_RESOURCE,
                                nfp_constants.PERIODIC_HM]:
                resource = nfp_constants.GENERIC_CONFIG

            is_delete_request = True if operation == 'delete' else False

            if resource == nfp_constants.PERIODIC_HM:
                event_id = self.handle_periodic_hm_resource(result)
                break

            if is_delete_request:
                event_id = self.rpc_event_mapping[resource][1]
            else:
                event_id = self.rpc_event_mapping[resource][0]

            if result.lower() != 'success':
                LOG.info(_LI("RPC Handler response data:%(data)s"),
                         {'data': data})
                if is_delete_request:
                    # Ignore any deletion errors, generate SUCCESS event
                    event_id = self.rpc_event_mapping[resource][1]
                else:
                    event_id = self.rpc_event_mapping[resource][2]
                break

        nf_id = request_info.pop('nf_id')
        nfi_id = request_info.pop('nfi_id')
        nfd_id = request_info.pop('nfd_id')
        request_info['network_function_id'] = nf_id
        request_info['network_function_instance_id'] = nfi_id
        request_info['network_function_device_id'] = nfd_id
        event_data = request_info
        event_data['id'] = request_info['network_function_device_id']

        key = nf_id
        self._create_event(event_id=event_id,
                           event_data=event_data,
                           key=key)


class DeviceOrchestrator(nfp_api.NfpEventHandler):
    """device Orchestrator For Network Services

    This class handles the orchestration of Network Function Device lifecycle.
    It deals with physical service resources - Network Devices. This module
    interacts with Service Orchestrator and Configurator. Service Orchestrator
    sends device create/delete request, Device orchestrator sends/receieves
    RPC to/from configurator to create generic config. Device Orchestrator
    loads drivers specified in config file, and selects corresponding drivers
    based on service vendor.

    Workflow for create:
    1) Service Orchestarator calls Device Orcehstrator(NDO) for creating new
    device, create_network_function_device gets called in the context of
    event handler. This method checks with drivers for device sharing, if
    device sharing supported then request the driver to plug the
    interfaces(step-3) else request driver to create a new device and poll
    for its status(Here a DB entry is created with status as PENDING_CREATE).
    2) If the driver returns status as ACTIVE or ERROR, the poll event is
    stopped, if it returns any other status, the poll event is continued.
    2) In case of new device creation, once device become ACTIVE, NDO plug
    the interfaces.
    3) After plugging the interfaces NDO sends RPC call to configurator for
    creating generic config.
    4) Rpc Handler receives notification API from configurator, In case of
    success update DB with status as ACTIVE and create event DEVICE_CREATED
    for Service Orchestrator. In case of any error, create event
    DEVICE_CREATE_FAILED and update DB as ERROR.

    """

    def __init__(self, controller, config):
        self._controller = controller
        self.config = config
        self.nsf_db = nfp_db.NFPDbBase()
        self.gbpclient = openstack_driver.GBPClient(config)
        self.keystoneclient = openstack_driver.KeystoneClient(config)

        neutron_context = n_context.get_admin_context()
        self.configurator_rpc = NDOConfiguratorRpcApi(neutron_context,
                                                      self.config)

        self.status_map = {
            'INIT': 'Created Network Service Device with status INIT.',
            'PENDING_CREATE': '',
            'DEVICE_SPAWNING': ('Creating NFD, launched the new device, ' +
                                'polling on its status'),
            'DEVICE_UP': 'Device is UP/ACTIVE',
            'PERFORM_HEALTH_CHECK': 'perform health check of service vm',
            'HEALTH_CHECK_PENDING': ('Device health check is going on ' +
                                     ' through configurator'),
            'HEALTH_CHECK_COMPLETED': 'Health check succesfull for device',
            'INTERFACES_PLUGGED': 'Interfaces Plugging successfull',
            'PENDING_CONFIGURATION_CREATE': ('Started configuring device ' +
                                             'for routes, license, etc'),
            'DEVICE_READY': 'Device is ready to use',
            'ACTIVE': 'Device is Active.',
            'DEVICE_NOT_UP': 'Device not became UP/ACTIVE',
        }
        self.orchestration_driver = orchestration_driver.OrchestrationDriver(
            self.config)

    @property
    def db_session(self):
        return db_api.get_session()

    def event_method_mapping(self, event_id):
        event_handler_mapping = {
            "CREATE_NETWORK_FUNCTION_DEVICE": (
                self.create_network_function_device),
            "PERFORM_INITIAL_HEALTH_CHECK": self.perform_initial_health_check,
            "PERFORM_PERIODIC_HEALTH_CHECK":
                self.perform_periodic_health_check,
            "PERFORM_CLEAR_HM": self.perform_clear_hm,
            "DEVICE_UP": self.device_up,
            "PLUG_INTERFACES": self.plug_interfaces_fast,
            "DEVICE_HEALTHY": self.plug_interfaces,
            "HEALTH_MONITOR_COMPLETE": self.health_monitor_complete,
            "CONFIGURE_DEVICE": self.configure_device,
            "CREATE_DEVICE_CONFIGURATION": self.create_device_configuration,
            "CONFIGURATION_COMPLETE": self.configuration_complete,
            "DEVICE_CONFIGURED": self.device_configuration_complete,

            "DELETE_NETWORK_FUNCTION_DEVICE": (
                self.delete_network_function_device),
            "DELETE_CONFIGURATION_COMPLETED": (
                self.delete_configuration_complete),
            "UNPLUG_INTERFACES": self.unplug_interfaces,
            "DELETE_DEVICE": self.delete_device,
            "DELETE_CONFIGURATION": self.delete_device_configuration,
            "DEVICE_NOT_REACHABLE": self.handle_device_not_reachable,
            "PERIODIC_HM_DEVICE_REACHABLE": (
                self.periodic_hm_handle_device_reachable),
            "PERIODIC_HM_DEVICE_NOT_REACHABLE": (
                self.periodic_hm_handle_device_not_reachable),
            "PLUG_INTERFACE_FAILED": self.handle_plug_interface_failed,
            "DEVICE_CONFIGURATION_FAILED": self.handle_device_config_failed,
            "DEVICE_ERROR": self.handle_device_create_error,
            "DEVICE_NOT_UP": self.handle_device_not_up,
            "DRIVER_ERROR": self.handle_driver_error,
            'UPDATE_DEVICE_CONFIG_PARAMETERS': self.update_config_params,
            'DEVICE_CONFIG_PARAMETERS_UPDATED': (
                self.device_configuration_updated)
        }
        if event_id not in event_handler_mapping:
            raise Exception(_("Invalid event ID"))
        else:
            return event_handler_mapping[event_id]

    def handle_event(self, event):
        try:
            event_data = event.context
            NFD = event_data.get('network_function_device_id')
            NF = event_data.get('network_function_id')
            NFI = event_data.get('network_function_instance_id')

            if NFD and NF and NFI:
                LOG.info(_LI("Received event %(event_name)s with "
                             "NF:%(nf)s ,NFI:%(nfi)s and NFD:%(nfd)s"),
                         {'event_name': event.id,
                          'nf': NF,
                          'nfi': NFI,
                          'nfd': NFD})
            else:
                LOG.info(_LI("Received event %(event_name)s "),
                         {'event_name': event.id})
            event_handler = self.event_method_mapping(event.id)
            event_handler(event)
        except Exception as e:
            LOG.error(_LE("error in processing event: %(event_id)s for "
                          "event data %(event_data)s. error: %(error)s"),
                      {'event_id': event.id, 'event_data': event.data,
                       'error': e})
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)
            raise e

    def handle_exception(self, event, exception):
        return ExceptionHandler.handle(self, event, exception)

    # Helper functions
    def _log_event_created(self, event_id, event_data):
        network_function_instance = event_data.get('network_function_instance')
        if network_function_instance:
            nf = network_function_instance.get('network_function_id')
            nfi = network_function_instance.get('id')
        else:
            nf = None
            nfi = None
        if nf and nfi:
            LOG.info(_LI("Created event %(event_name)s with NF:%(nf)s and "
                         "NFI:%(nfi)s "),
                     {'event_name': event_id,
                      'nf': nf,
                      'nfi': nfi})
        else:
            LOG.info(_LI("Created event %(event_name)s "),
                     {'event_name': event_id})

    def _create_event(self, event_id, event_data=None,
                      is_poll_event=False, original_event=False,
                      is_internal_event=False, max_times=10):
        if not is_internal_event:
            if is_poll_event:
                ev = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid)
                LOG.debug("poll event started for %s", ev.id)
                self._controller.poll_event(ev, max_times=max_times)
            else:
                ev = self._controller.new_event(
                    id=event_id,
                    data=event_data)
                self._controller.post_event(ev)
            nfp_context = module_context.get()
            self._log_event_created(event_id, nfp_context)
        else:
            # Same module API, so calling corresponding function directly.
            nfp_context = module_context.get()
            event = self._controller.new_event(
                id=event_id,
                data=event_data,
                context=nfp_context)
            self.handle_event(event)

    def _release_cnfd_lock(self, device):
        nf_id = device['network_function_id']
        nfi_id = device['network_function_instance_id']
        ev = self._controller.new_event(
            id='CREATE_NETWORK_FUNCTION_DEVICE',
            data=device, key=nf_id + nfi_id)
        if device.get('binding_key'):
            ev.binding_key = device.get('binding_key')
            LOG.debug("Releasing tenant based lock for "
                      "CREATE_NETWORK_FUNCTION_DEVICE event with binding "
                      "key: %s", ev.binding_key)
        self._controller.event_complete(ev)

    def event_cancelled(self, ev, reason):
        LOG.info(_LI("Poll event %(event_id)s cancelled."),
                 {'event_id': ev.id})

        if ev.id == 'DEVICE_SPAWNING':
            LOG.info(_LI("Device is not up still after 10secs of launch"))
            # create event DEVICE_NOT_UP
            device = self._prepare_failure_case_device_data(ev.data)
            self._create_event(event_id='DEVICE_NOT_UP',
                               event_data=device,
                               is_internal_event=True)
            self._update_network_function_device_db(device,
                                                    'DEVICE_NOT_UP')
        if ev.id == 'DEVICE_BEING_DELETED':
            LOG.info(_LI("Device is not deleted completely."
                         " Continuing further cleanup of resources."
                         " Possibly there could be stale port resources"
                         " on Compute"))
            device = ev.data
            orchestration_driver = self._get_orchestration_driver(
                device['service_details']['service_vendor'])
            device_id = device['id']
            del device['id']
            nf_id = device['network_function_id']
            orchestration_driver.delete_network_function_device(device)
            self._delete_network_function_device_db(device_id, device)
            dnfd_event = (
                self._controller.new_event(id='DELETE_NETWORK_FUNCTION_DEVICE',
                                           key=nf_id,
                                           binding_key=nf_id,
                                           desc_dict=device.get(
                                               'event_desc')))
            self._controller.event_complete(dnfd_event, result='FAILED')

    def _update_device_status(self, device, state, status_desc=None):
        device['status'] = state
        if status_desc:
            device['status_description'] = status_desc
        else:
            device['status_description'] = self.status_map.get(state)

    def _get_port(self, port_id):
        with nfp_ctx_mgr.DbContextManager:
            return self.nsf_db.get_port_info(self.db_session, port_id)

    def _get_ports(self, port_ids):
        data_ports = []
        for port_id in port_ids:
            with nfp_ctx_mgr.DbContextManager:
                port_info = self.nsf_db.get_port_info(self.db_session,
                                                      port_id)
            data_ports.append(port_info)
            return data_ports

    def _create_network_function_device_db(self, device_info, state):

        self._update_device_status(device_info, state)
        # (ashu) driver should return device_id as vm_id
        device_id = device_info.pop('id')
        device_info['id'] = device_id
        device_info['reference_count'] = 0
        device_info['interfaces_in_use'] = 0
        with nfp_ctx_mgr.DbContextManager:
            device = self.nsf_db.create_network_function_device(
                self.db_session,
                device_info)
        return device

    def _update_network_function_device_db(self, device, state,
                                           status_desc=''):
        self._update_device_status(device, state, status_desc)
        updated_device = copy.deepcopy(device)
        updated_device.pop('reference_count', None)
        updated_device.pop('interfaces_in_use', None)
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.update_network_function_device(self.db_session,
                                                       updated_device['id'],
                                                       updated_device)
        device.update(updated_device)

    def _delete_network_function_device_db(self, device_id, device):
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.delete_network_function_device(self.db_session,
                                                       device_id)

    def _get_network_function_info(self, device_id):
        nfi_filters = {'network_function_device_id': [device_id]}
        with nfp_ctx_mgr.DbContextManager:
            network_function_instances = (
                self.nsf_db.get_network_function_instances(self.db_session,
                                                           nfi_filters))
            network_function_ids = [nf['network_function_id']
                                    for nf in network_function_instances]
            network_functions = (
                self.nsf_db.get_network_functions(
                    self.db_session,
                    {'id': network_function_ids}))
            return network_functions

    def _get_network_function_devices(self, filters=None):
        with nfp_ctx_mgr.DbContextManager:
            network_function_devices = (
                self.nsf_db.get_network_function_devices(self.db_session,
                                                         filters))
        for device in network_function_devices:
            mgmt_port_id = device.pop('mgmt_port_id')
            mgmt_port_id = self._get_port(mgmt_port_id)
            device['mgmt_port_id'] = mgmt_port_id

            network_functions = (
                self._get_network_function_info(device['id']))
            device['network_functions'] = network_functions
        return network_function_devices

    def _increment_device_ref_count(self, device):
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.increment_network_function_device_count(
                self.db_session,
                device['id'],
                'reference_count')
        device['reference_count'] += 1

    def _decrement_device_ref_count(self, device):
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.decrement_network_function_device_count(
                self.db_session,
                device['id'],
                'reference_count')
        device['reference_count'] -= 1

    def _increment_device_interface_count(self, device):
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.increment_network_function_device_count(
                self.db_session,
                device['id'],
                'interfaces_in_use',
                len(device['ports']))

        device['interfaces_in_use'] += len(device['ports'])

    def _decrement_device_interface_count(self, device):
        with nfp_ctx_mgr.DbContextManager:
            self.nsf_db.decrement_network_function_device_count(
                self.db_session,
                device['id'],
                'interfaces_in_use',
                len(device['ports']))

        device['interfaces_in_use'] -= len(device['ports'])

    def _get_orchestration_driver(self, service_vendor):
        return self.orchestration_driver

    def _get_device_data(self, nfd_request):

        device_data = {}
        network_function = nfd_request.get('network_function')
        network_function_instance = nfd_request['network_function_instance']
        service_details = nfd_request['service_details']
        device_data['name'] = network_function_instance['name']
        device_data['share_existing_device'] = (
            nfd_request.get('share_existing_device'))
        device_data['management_network_info'] = (
            nfd_request.get('management_network_info'))

        if network_function:
            device_data['network_function_id'] = network_function['id']
            device_data['service_chain_id'] = (
                network_function['service_chain_id'])

        device_data['network_function_instance_id'] = (
            network_function_instance['id'])
        device_data['tenant_id'] = network_function_instance['tenant_id']

        nsi_port_info = []
        for port_id in network_function_instance.pop('port_info'):
            with nfp_ctx_mgr.DbContextManager:
                port_info = self.nsf_db.get_port_info(self.db_session,
                                                      port_id)
            nsi_port_info.append(port_info)

        device_data['ports'] = nsi_port_info

        device_data['service_details'] = service_details
        if nsi_port_info[0]['port_model'] == nfp_constants.GBP_PORT:
            device_data['service_details']['network_mode'] = (
                nfp_constants.GBP_MODE)
        else:
            device_data['service_details']['network_mode'] = (
                nfp_constants.NEUTRON_MODE)
        device_data['service_vendor'] = service_details['service_vendor']

        return device_data

    def _get_nsf_db_resource(self, resource_name, resource_id):
        db_method = getattr(self.nsf_db, 'get_' + resource_name)
        return db_method(self.db_session, resource_id)

    def _update_device_data(self, device, device_data):
        device.update(device_data)
        return device

    def _make_ports_dict(self, consumer, provider, port_type):

        t_ports = []
        for ptg in [consumer, provider]:
            if (port_type in ptg.keys()) and ptg[port_type]:
                t_ports.append({
                    'id': ptg[port_type].get('id'),
                    'port_classification': ptg.get(
                        'port_classification'),
                    'port_model': ptg.get('port_model')
                })
        return t_ports

    def _prepare_device_data_from_nfp_context(self, nfp_context):
        device_data = {}

        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        service_details = nfp_context['service_details']

        device_data['token'] = nfp_context[
            'resource_owner_context']['admin_token']
        device_data['admin_tenant_id'] = nfp_context[
            'resource_owner_context']['admin_tenant_id']
        device_data['name'] = network_function_instance['name']
        device_data['share_existing_device'] = nfp_context[
            'share_existing_device']

        management_network_info = {
            'id': nfp_context['management_ptg_id'],
            'port_model': nfp_constants.GBP_NETWORK
        }

        consumer = nfp_context['consumer']
        provider = nfp_context['provider']

        ports = self._make_ports_dict(nfp_context.get(
            'explicit_consumer', consumer), provider, 'pt')

        device_data['provider_name'] = provider['ptg']['name']
        device_data['management_network_info'] = management_network_info

        device_data['network_function_id'] = network_function['id']
        device_data['service_chain_id'] = network_function['service_chain_id']
        device_data[
            'network_function_instance_id'] = network_function_instance['id']
        device_data['tenant_id'] = network_function_instance['tenant_id']
        device_data['ports'] = ports
        device_data['service_details'] = service_details
        device_data['service_details']['network_mode'] = nfp_constants.GBP_MODE
        device_data['service_vendor'] = service_details['service_vendor']
        device_data['server_grp_id'] = nfp_context.get('server_grp_id')
        device_data['interfaces_to_attach'] = (
            nfp_context.get('interfaces_to_attach'))

        if nfp_context.get('files'):
            device_data['files'] = nfp_context['files']
        if nfp_context.get('user_data'):
            device_data['user_data'] = nfp_context['user_data']
        return device_data

    def _create_nfd_entry(self, nfp_context, driver_device_info,
                          device_data, service_details):
        nfp_context['provider_metadata'] = driver_device_info.get(
            'provider_metadata')
        # Update nfp_context management with newly created mgmt port
        management = nfp_context['management']
        management['port'] = driver_device_info[
            'mgmt_neutron_port_info']['neutron_port']
        management['port']['ip_address'] = management[
            'port']['fixed_ips'][0]['ip_address']
        management['subnet'] = driver_device_info[
            'mgmt_neutron_port_info']['neutron_subnet']

        # Update newly created device with required params
        device = self._update_device_data(driver_device_info, device_data)
        device['network_function_device_id'] = device['id']

        # check for any explicit interface and its type.
        for interface in nfp_context.get('explicit_interfaces', []):
            if interface['type'] == 'gateway':
                device['gateway_port'] = interface['port']

        name = '%s_%s_%s_%s' % (
            device['provider_name'],
            service_details['service_type'],
            nfp_context['resource_owner_context']['tenant_name'][:6],
            device['network_function_device_id'][:3])
        device['name'] = name
        # Create DB entry with status as DEVICE_SPAWNING
        network_function_device = (
            self._create_network_function_device_db(device,
                                                    'DEVICE_SPAWNING'))

        nfp_context['network_function_device'] = network_function_device
        return device

    def _update_nfp_context_with_ports(self, nfp_context, device):
        # REVISIT(mak) Wrong but nfp_db method needs in this format
        network_function_device = nfp_context['network_function_device']
        network_function_device['mgmt_port_id'] = device['mgmt_port_id']

    def _post_create_nfd_events(self, event, nfp_context, device):

        nfp_context['event_desc'] = event.desc.to_dict()
        # Updating nfi with nfd_id before device spawning
        # to stop orchestration to move further.
        nfi = {
            'network_function_device_id': device['id'],
        }
        with nfp_ctx_mgr.DbContextManager:
            nfi = self.nsf_db.update_network_function_instance(
                self.db_session,
                device['network_function_instance_id'], nfi)
        # This event is act as a dummy event for nfp,
        # for non-hotplug sharing it will be used
        self._create_event(event_id='DEVICE_CREATED',
                           event_data=device)

        self._create_event(event_id='DEVICE_SPAWNING',
                           event_data=nfp_context,
                           is_poll_event=True,
                           original_event=event,
                           max_times=nfp_constants.DEVICE_SPAWNING_MAXRETRY)

    # Create path
    def create_network_function_device(self, event):
        """ Returns device instance for a new service

        This method either returns existing device which could be reused for a
        new service or it creates new device instance
        """

        nfp_context = event.context
        nfd_request = self._prepare_failure_case_device_data(nfp_context)
        service_details = nfp_context['service_details']

        LOG.info(_LI("Received event CREATE NETWORK FUNCTION "
                     "DEVICE request."))

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])

        device_data = self._prepare_device_data_from_nfp_context(nfp_context)

        LOG.info(_LI("Creating new device:%(device)s"),
                 {'device': nfd_request})
        device_data['volume_support'] = (
            self.config.device_orchestrator.volume_support)
        device_data['volume_size'] = (
            self.config.device_orchestrator.volume_size)
        device_data['explicit_interfaces'] = nfp_context.get(
            'explicit_interfaces', [])
        driver_device_info = (
            orchestration_driver.create_network_function_device(
                device_data))
        if not driver_device_info:
            LOG.info(_LI("Device creation failed"))
            self._create_event(event_id='DEVICE_ERROR',
                               event_data=nfd_request,
                               is_internal_event=True)
            self._controller.event_complete(event)
            return None

        device = self._create_nfd_entry(nfp_context, driver_device_info,
                                        device_data, service_details)
        self._increment_device_ref_count(device)
        self._increment_device_interface_count(device)
        nfd_id = device.get('network_function_device_id',
                            '-') if device else '-'
        nfp_context['log_context']['nfd_id'] = nfd_id
        self._update_nfp_context_with_ports(nfp_context, driver_device_info)

        self._post_create_nfd_events(event, nfp_context, device)

    def _post_device_up_event_graph(self, nfp_context):
        nf_id = nfp_context['network_function']['id']
        nfi_id = nfp_context['network_function_instance']['id']
        du_event = self._controller.new_event(id="DEVICE_UP",
                                              key=nf_id + nfi_id)

        hc_event = self._controller.new_event(
            id="PERFORM_INITIAL_HEALTH_CHECK",
            key=nf_id + nfi_id)

        plug_int_event = self._controller.new_event(id="PLUG_INTERFACES",
                                                    key=nf_id + nfi_id)
        GRAPH = ({
            du_event: [hc_event, plug_int_event]})

        self._controller.post_graph(
            GRAPH, du_event, graph_str='HEALTH_MONITOR_GRAPH')

    @nfp_api.poll_event_desc(event='DEVICE_SPAWNING',
                             spacing=nfp_constants.DEVICE_SPAWNING_SPACING)
    def check_device_is_up(self, event):
        nfp_context = event.context

        service_details = nfp_context['service_details']
        network_function_device = nfp_context['network_function_device']
        token = nfp_context['resource_owner_context']['admin_token']
        tenant_id = nfp_context['resource_owner_context']['admin_tenant_id']

        device = {
            'token': token,
            'tenant_id': tenant_id,
            'id': network_function_device['id'],
            'service_details': service_details}

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])

        is_device_up = (
            orchestration_driver.get_network_function_device_status(device))

        if is_device_up == nfp_constants.ACTIVE:
            LOG.info(_LI("Device with NFD:%(id)s came up for "
                         "tenant:%(tenant)s "),
                     {'id': network_function_device['id'],
                      'tenant': tenant_id})
            self._post_device_up_event_graph(nfp_context)

            return STOP_POLLING
        elif is_device_up == nfp_constants.ERROR:
            # create event DEVICE_NOT_UP
            device = self._prepare_failure_case_device_data(nfp_context)
            self._create_event(event_id='DEVICE_NOT_UP',
                               event_data=device,
                               is_internal_event=True)
            self._update_network_function_device_db(device,
                                                    'DEVICE_NOT_UP')
            return STOP_POLLING
        else:
            # Continue polling until device status became ACTIVE/ERROR.
            return CONTINUE_POLLING

    def _post_configure_device_graph(self, nfp_context, serialize=False):
        nf_id = nfp_context['network_function']['id']
        nfi_id = nfp_context['network_function_instance']['id']
        sc_instance_id = nfp_context['service_chain_instance']['id']
        binding_key = nfp_context['service_details'][
            'service_vendor'].lower() + nf_id
        device_configure_event = self._controller.new_event(
            id='CREATE_DEVICE_CONFIGURATION',
            key=nf_id,
            serialize=serialize,
            binding_key=binding_key)
        check_heat_config = self._controller.new_event(
            id='SEND_USER_CONFIG',
            key=nf_id)
        user_config_event = self._controller.new_event(
            id='INITIATE_USER_CONFIG',
            key=nf_id,
            serialize=serialize,
            binding_key=binding_key)
        device_configured_event = self._controller.new_event(
            id='CONFIGURATION_COMPLETE',
            key=nf_id,
            serialize=serialize,
            binding_key=sc_instance_id)
        device_periodic_hm_event = self._controller.new_event(
            id='PERFORM_PERIODIC_HEALTH_CHECK',
            key=nf_id + nfi_id)

        # Start periodic health monitor after device configuration

        GRAPH = ({
            device_periodic_hm_event: [device_configured_event],
            device_configured_event: [device_configure_event,
                                      user_config_event],
            user_config_event: [check_heat_config]})

        self._controller.post_graph(GRAPH, device_periodic_hm_event,
                                    graph_str='DEVICE_CONFIGURATION_GRAPH')

    def device_up(self, event, serialize_config=False):
        nfp_context = event.context

        # Get the results of PLUG_INTERFACES & PERFORM_INITIAL_HEALTH_CHECK
        # events results.
        nf_id = nfp_context['network_function']['id']
        nfi_id = nfp_context['network_function_instance']['id']
        device = self._prepare_failure_case_device_data(nfp_context)
        # Get the results of PLUG_INTERFACES & PERFORM_INITIAL_HEALTH_CHECK
        # events results.
        results = event.result
        for result in results:
            if result.result.lower() != 'success':
                # Release CNFD Event lock
                self._release_cnfd_lock(device)
                self._create_event(event_id='DEVICE_CREATE_FAILED',
                                   event_data=device)
                return self._controller.event_complete(event, result='FAILED')

        network_function_device = nfp_context['network_function_device']

        nfd_id = '-'
        if network_function_device:
            nfd_id = network_function_device.get('id', '-')
        nfp_context['log_context']['nfd_id'] = nfd_id
        # Update NFI to ACTIVE State
        nfi = {
            'status': nfp_constants.ACTIVE}
        nfi = self.nsf_db.update_network_function_instance(
            self.db_session, nfi_id, nfi)
        self._update_network_function_device_db(
            network_function_device, nfp_constants.ACTIVE)

        LOG.info(_LI(
            "Configuration completed for device with NFD:%(device_id)s. "
            "Updated DB status to ACTIVE."),
            {'device_id': network_function_device['id']})
        LOG.debug("Device detail:%s",
                  network_function_device)
        # Release CNFD Event lock
        self._release_cnfd_lock(device)
        self._post_configure_device_graph(nfp_context,
                                          serialize=serialize_config)
        event.key = nf_id + nfi_id
        self._controller.event_complete(event)

    def prepare_health_check_device_info(self, event, periodicity):

        nfp_context = event.context

        service_details = nfp_context['service_details']
        network_function_device = nfp_context['network_function_device']
        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        mgmt_ip_address = nfp_context['management']['port']['ip_address']
        tenant_id = nfp_context['resource_owner_context']['admin_tenant_id']

        # The driver tells which protocol / port to monitor ??
        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        nfp_context['event_desc'] = event.desc.to_dict()
        device = {
            'id': network_function_device['id'],
            'tenant_id': tenant_id,
            'mgmt_ip_address': mgmt_ip_address,
            'service_details': service_details,
            'network_function_id': network_function['id'],
            'periodicity': periodicity,
            'network_function_instance_id': network_function_instance['id'],
            'nfp_context': {'event_desc': nfp_context['event_desc'],
                            'id': event.id, 'key': event.key},
        }
        return device, orchestration_driver

    def perform_clear_hm(self, event):
        nfp_context = event.data
        network_function = nfp_context['network_function']
        service_details = nfp_context['service_details']
        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        nfp_context['event_desc'] = event.desc.to_dict()
        device = {
            'id': nfp_context['network_function_device_id'],
            'tenant_id': nfp_context['tenant_id'],
            'mgmt_ip_address': nfp_context['mgmt_ip_address'],
            'service_details': service_details,
            'network_function_id': network_function['id'],
            'network_function_instance_id': nfp_context[
                'network_function_instance_id'],
            'nfp_context': {'event_desc': nfp_context['event_desc'],
                            'id': event.id, 'key': event.key},
        }
        clear_hm_req = (
            orchestration_driver.get_network_function_device_config(
                device, nfp_constants.HEALTHMONITOR_RESOURCE))
        if not clear_hm_req:
            self._controller.event_complete(event, result="FAILED")
            return None

        self.configurator_rpc.delete_network_function_device_config(
            device,
            clear_hm_req)
        LOG.debug("Clear HM RPC sent to configurator for device: "
                  "%s with parameters: %s", (
                      device['id'], clear_hm_req))
        self._controller.event_complete(event, result="SUCCESS")

    def perform_periodic_health_check(self, event):
        event_results = event.result
        for result in event_results:
            if result.result.lower() != "success":
                return self._controller.event_complete(event, result="FAILED")

        device, orchestration_driver = (
            self.prepare_health_check_device_info(event,
                                                  nfp_constants.FOREVER))
        hm_req = (
            orchestration_driver.get_network_function_device_config(
                device, nfp_constants.HEALTHMONITOR_RESOURCE))
        if not hm_req:
            self._controller.event_complete(event, result="FAILED")
            return None

        self.configurator_rpc.create_network_function_device_config(device,
                                                                    hm_req)
        LOG.debug("Health Check RPC sent to configurator for device: "
                  "%s with health check parameters: %s", (
                      device['id'], hm_req))
        self._controller.event_complete(event, result="SUCCESS")

    def perform_initial_health_check(self, event):
        device, orchestration_driver = (
            self.prepare_health_check_device_info(event,
                                                  nfp_constants.INITIAL))
        hm_req = (
            orchestration_driver.get_network_function_device_config(
                device, nfp_constants.HEALTHMONITOR_RESOURCE))
        if not hm_req:
            self._controller.event_complete(event, result="FAILED")
            return None
        self.configurator_rpc.create_network_function_device_config(device,
                                                                    hm_req)
        LOG.debug("Health Check RPC sent to configurator for device: "
                  "%s with health check parameters: %s", (
                      device['id'], hm_req))

    def _get_service_type(self, service_profile_id):
        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_token = kcm.retry(
                self.keystoneclient.get_admin_token, tries=3)
        with nfp_ctx_mgr.GBPContextManager as gcm:
            service_profile = gcm.retry(self.gbpclient.get_service_profile,
                                        admin_token, service_profile_id)
        return service_profile['service_type'].lower()

    def _prepare_device_data(self, device_info):
        network_function_id = device_info['network_function_id']
        network_function_device_id = device_info['network_function_device_id']
        network_function_instance_id = (
            device_info['network_function_instance_id'])

        network_function = self._get_nsf_db_resource(
            'network_function',
            network_function_id)
        network_function_device = self._get_nsf_db_resource(
            'network_function_device',
            network_function_device_id)
        network_function_instance = self._get_nsf_db_resource(
            'network_function_instance',
            network_function_instance_id)

        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            admin_token = kcm.retry(
                self.keystoneclient.get_admin_token, tries=3)
        with nfp_ctx_mgr.GBPContextManager as gcm:
            service_profile = gcm.retry(
                self.gbpclient.get_service_profile,
                admin_token,
                network_function['service_profile_id'])
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])

        device_info.update({
            'network_function_instance': network_function_instance})
        device_info.update({'id': network_function_device_id})
        service_details.update({'service_type': self._get_service_type(
            network_function['service_profile_id'])})
        device_info.update({'service_details': service_details})

        device = self._get_device_data(device_info)
        device = self._update_device_data(device, network_function_device)

        mgmt_port_id = network_function_device.pop('mgmt_port_id')
        mgmt_port_id = self._get_port(mgmt_port_id)
        device['mgmt_port_id'] = mgmt_port_id
        device['network_function_id'] = network_function_id

        return device

    def _prepare_device_data_fast(self, network_function_details):
        network_function = network_function_details['network_function']
        network_function_device = network_function_details[
            'network_function_device']
        admin_token = network_function_details['admin_token']
        service_profile = network_function_details['service_profile']
        service_details = network_function_details['service_details']
        service_details.update(
            {'service_type': service_profile['service_type']})
        device = self._get_device_data(network_function_details)
        device = self._update_device_data(device, network_function_device)
        mgmt_port_id = network_function_device.pop('mgmt_port_id')
        mgmt_port_id = self._get_port(mgmt_port_id)
        device['mgmt_port_id'] = mgmt_port_id
        device['network_function_id'] = network_function['id']
        device['network_function_device_id'] = (
            network_function_device['id'])
        device['token'] = admin_token
        device['tenant_id'] = (
            network_function_details['admin_tenant_id'])
        device['service_profile'] = service_profile
        return device

    def health_monitor_complete(self, event, result='SUCCESS'):
        nfp_context = event.data['nfp_context']
        # device = nfp_context['network_function_device']
        # network_function = nfp_context['network_function']

        # Invoke event_complete for original event which is
        # PERFORM_INITIAL_HEALTH_CHECK
        event_desc = nfp_context.pop('event_desc', None)
        nfp_context.pop('id', None)
        key = nfp_context.pop('key', None)
        self._controller.event_complete(event)
        new_event = self._controller.new_event(
            id="PERFORM_INITIAL_HEALTH_CHECK",
            key=key, desc_dict=event_desc)
        self._controller.event_complete(new_event, result=result)

    def plug_interfaces(self, event, is_event_call=True):
        if is_event_call:
            device_info = event.data
        else:
            device_info = event
        # Get event data, as configurator sends back only request_info, which
        # contains nf_id, nfi_id, nfd_id.
        device = self._prepare_device_data(device_info)
        self._update_network_function_device_db(device,
                                                'HEALTH_CHECK_COMPLETED')
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])

        _ifaces_plugged_in = (
            orchestration_driver.plug_network_function_device_interfaces(
                device))
        if _ifaces_plugged_in:
            self._increment_device_interface_count(device)
            self._create_event(event_id='CONFIGURE_DEVICE',
                               event_data=device,
                               is_internal_event=True)
        else:
            self._create_event(event_id='DEVICE_CONFIGURATION_FAILED',
                               event_data=device,
                               is_internal_event=True)

    def plug_interfaces_fast(self, event):

        # In this case, the event will be
        # happening in parallel with HEALTHMONITORING,
        # so, we should not generate CONFIGURE_DEVICE & should not update
        # DB with HEALTH_CHECK_COMPLETED.

        nfp_context = event.context

        service_details = nfp_context['service_details']
        network_function_device = nfp_context['network_function_device']
        nf_id = network_function_device['id']
        nfi_id = nfp_context['network_function_instance']['id']
        token = nfp_context['resource_owner_context']['admin_token']
        tenant_id = nfp_context['resource_owner_context']['admin_tenant_id']

        consumer = nfp_context['consumer']
        provider = nfp_context['provider']

        event.key = nf_id + nfi_id

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        ports = self._make_ports_dict(
            nfp_context.get('explicit_consumer', consumer),
            provider, 'port')

        device = {
            'id': network_function_device['id'],
            'ports': ports,
            'service_details': service_details,
            'token': token,
            'tenant_id': tenant_id,
            'interfaces_in_use': network_function_device['interfaces_in_use'],
            'status': network_function_device['status'],
            'provider_metadata': nfp_context['provider_metadata'],
            'enable_port_security': nfp_context.get('enable_port_security')
        }

        _ifaces_plugged_in = (
            orchestration_driver.plug_network_function_device_interfaces(
                device))
        if _ifaces_plugged_in:
            # self._increment_device_interface_count(device)
            # [REVISIT(mak)] - Check how incremented ref count can be
            # updated in DB
            self._controller.event_complete(event, result="SUCCESS")
        else:
            self._create_event(event_id="PLUG_INTERFACE_FAILED",
                               is_internal_event=True)
            self._controller.event_complete(event, result="FAILED")

    def configure_device(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        config_params = (
            orchestration_driver.get_network_function_device_config(
                device, nfp_constants.GENERIC_CONFIG))
        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            return None
        # Sends RPC to configurator to create generic config
        self.configurator_rpc.create_network_function_device_config(
            device, config_params)

    def create_device_configuration(self, event):
        nfp_context = event.context

        service_details = nfp_context['service_details']
        consumer = nfp_context['consumer']
        provider = nfp_context['provider']
        management = nfp_context['management']
        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        network_function_device = nfp_context['network_function_device']
        tenant_id = nfp_context['resource_owner_context']['admin_tenant_id']

        binding_key = service_details[
            'service_vendor'].lower() + network_function['id']

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        device = {
            'tenant_id': tenant_id,
            'mgmt_ip_address': management['port']['ip_address'],
            'mgmt_ip': network_function_device['mgmt_ip_address'],
            'provider_ip': provider['port']['ip_address'],
            'provider_cidr': provider['subnet']['cidr'],
            'provider_mac': provider['port']['mac_address'],
            'provider_gateway_ip': provider['subnet']['gateway_ip']}

        if consumer['port'] and consumer['subnet']:
            device.update({'consumer_ip': consumer['port']['ip_address'],
                           'consumer_cidr': consumer['subnet']['cidr'],
                           'consumer_mac': consumer['port']['mac_address'],
                           'consumer_gateway_ip': consumer[
                               'subnet']['gateway_ip']})

        nfp_context['event_desc'] = event.desc.to_dict()
        device.update({
            'id': network_function_device['id'],
            'mgmt_ip_address': network_function_device['mgmt_ip_address'],
            'service_details': service_details,
            'network_function_id': network_function['id'],
            'network_function_instance_id': network_function_instance['id'],
            'nfp_context': {
                'event_desc': nfp_context['event_desc'],
                'id': event.id, 'key': event.key,
                'network_function_device': network_function_device,
                'binding_key': binding_key}})

        config_params = (
            orchestration_driver.
            get_network_function_device_config(
                device, nfp_constants.GENERIC_CONFIG))

        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            self._controller.event_complete(event, result="FAILED")
            return None

        event_data = {'device': device, 'nfp_context': nfp_context,
                      'config_params': config_params}
        self._create_event(event_id='UPDATE_DEVICE_CONFIG_PARAMETERS',
                           event_data=event_data)

    def device_configuration_updated(self, event):
        nfp_context, config_params, device = (
            event.data['nfp_context'], event.data['config_params'],
            event.data['device'])
        # Set forward_route as False in resource_data for configurator to
        # handle routes differently, when vpn is in service chain
        if nfp_utils.is_vpn_in_service_chain(
                nfp_context['service_chain_specs']):
            for cfg in config_params['config']:
                cfg['resource_data']['forward_route'] = False
        else:
            for cfg in config_params['config']:
                cfg['resource_data']['forward_route'] = True
        # Sends RPC to configurator to create generic config
        self.configurator_rpc.create_network_function_device_config(
            device, config_params)
        self._controller.event_complete(event=event, result='SUCCESS')

    def configuration_complete(self, event):
        nfp_context = event.context
        nf_id = nfp_context['network_function']['id']
        event_results = event.result
        for result in event_results:
            if result.result.lower() != "success":
                device = self._prepare_failure_case_device_data(nfp_context)
                self._create_event(event_id='DEVICE_CREATE_FAILED',
                                   event_data=device)
                return self._controller.event_complete(event, result="FAILED")
        sc_event = self._controller.new_event(id="SERVICE_CONFIGURED",
                                              key=nf_id)
        self._controller.post_event(sc_event)
        self._controller.event_complete(event, result="SUCCESS")

    def device_configuration_complete(self, event, result='SUCCESS'):
        nfp_context = event.data['nfp_context']

        # Invoke event_complete for original event which is
        # CREATE_DEVICE_CONFIGURATION
        event_desc = nfp_context.pop('event_desc', None)
        key = nfp_context.pop('key', None)
        self._controller.event_complete(event)
        event = self._controller.new_event(id="CREATE_DEVICE_CONFIGURATION",
                                           key=key, desc_dict=event_desc)
        event.binding_key = nfp_context.pop('binding_key', None)
        self._controller.event_complete(event, result=result)

    def delete_network_function_device(self, event):
        network_function_details = event.context
        nfd = network_function_details['network_function_device']
        if not nfd:
            self._controller.event_complete(event, result="SUCCESS")
            return
        device = self._prepare_device_data_fast(network_function_details)
        LOG.info(_LI("Recieved DELETE NETWORK FUNCTION "
                     "DEVICE request "))
        device['event_desc'] = event.desc.to_dict()
        self._create_event(event_id='DELETE_CONFIGURATION',
                           event_data=device,
                           is_internal_event=True)

    def delete_device_configuration(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        config_params = (
            orchestration_driver.get_network_function_device_config(
                device, nfp_constants.GENERIC_CONFIG, is_delete=True))
        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            nf_id = device['network_function_id']
            dnfd_event = (
                self._controller.new_event(
                    id='DELETE_NETWORK_FUNCTION_DEVICE',
                    key=nf_id,
                    binding_key=nf_id,
                    desc_dict=device.get('event_desc')))
            self._controller.event_complete(dnfd_event, result='FAILED')
            # TODO(mak): If driver returns ERROR,
            # then we are not proceeding further
            # Stale vms will exist in this case.
            # Need to handle this case where
            # driver returned None So dont initiate configurator API but call
            # unplug_interfaces and device delete to delete vms.
            return None

        # Sends RPC call to configurator to delete generic config API
        self.configurator_rpc.delete_network_function_device_config(
            device, config_params)

    def unplug_interfaces(self, event):
        result = "SUCCESS"
        device = event.data
        self._decrement_device_ref_count(device)
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])

        is_interface_unplugged = (
            orchestration_driver.unplug_network_function_device_interfaces(
                device))
        if is_interface_unplugged:
            mgmt_port_id = device['mgmt_port_id']
            self._decrement_device_interface_count(device)
            device['mgmt_port_id'] = mgmt_port_id
        else:
            result = "FAILED"
        self._create_event(event_id='DELETE_DEVICE',
                           event_data=device,
                           is_internal_event=True)
        self._controller.event_complete(event, result=result)

    def delete_configuration_complete(self, event):
        device = event.data['nfp_context']
        nfd_id = event.data['network_function_device_id']
        nf_id = event.data['network_function_id']
        unplug_interfaces = (
            self._controller.new_event(id='UNPLUG_INTERFACES',
                                       data=device,
                                       key=nf_id,
                                       binding_key=nfd_id,
                                       serialize=True))
        self._controller.post_event(unplug_interfaces)
        self._controller.event_complete(event)

    def delete_device(self, event):
        # Update status in DB, send DEVICE_DELETED event to NSO.
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])

        network_function = (
            self.nsf_db.get_network_function(
                self.db_session,
                device['network_function_id']))
        device['network_function'] = network_function
        chm_event = self._controller.new_event(
            id='PERFORM_CLEAR_HM',
            key=device['network_function_id'],
            data=device)
        self._controller.post_event(chm_event)

        orchestration_driver.delete_network_function_device(device)
        self._create_event(
            event_id='DEVICE_BEING_DELETED',
            event_data=device,
            is_poll_event=True,
            original_event=event,
            max_times=nfp_constants.DEVICE_BEING_DELETED_MAXRETRY)

    @nfp_api.poll_event_desc(
        event='DEVICE_BEING_DELETED',
        spacing=nfp_constants.DEVICE_BEING_DELETED_SPACING)
    def check_device_deleted(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        status = orchestration_driver.get_network_function_device_status(
            device, ignore_failure=True)
        if not status:
            try:
                device_id = device['id']
                del device['id']
                orchestration_driver.delete_network_function_device(device)
                self._delete_network_function_device_db(device_id, device)
                if device.get('event_desc'):
                    nf_id = device['network_function_id']
                    dnfd_event = (
                        self._controller.new_event(
                            id='DELETE_NETWORK_FUNCTION_DEVICE',
                            key=nf_id,
                            binding_key=nf_id,
                            desc_dict=device['event_desc']))
                    self._controller.event_complete(
                        dnfd_event, result='SUCCESS')
                return STOP_POLLING
            except Exception as exc:
                device['id'] = device_id
                err = ("Exception - %s - in DEVICE_BEING_DELETED" % (exc))
                LOG.error(err)
                return CONTINUE_POLLING
        else:
            return CONTINUE_POLLING

    # Error Handling
    def handle_device_create_error(self, event):
        device = event.data
        LOG.error(_LE("Device creation failed, for device %(device)s"),
                  {'device': device})
        device['network_function_device_id'] = device.get('id')
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)

    def handle_device_not_up(self, event):
        device = event.data
        self._release_cnfd_lock(device)
        status = nfp_constants.ERROR
        desc = 'Device not became ACTIVE'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)

    def _prepare_failure_case_device_data(self, nfp_context):
        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        device = {'network_function_id': network_function['id'],
                  'network_function_instance_id': network_function_instance[
            'id'], 'binding_key': nfp_context.get('binding_key')}
        network_function_device = nfp_context.get('network_function_device')
        if network_function_device:
            device.update(
                {'network_function_device_id': network_function_device['id']})
            device.update(network_function_device)
        return device

    def handle_plug_interface_failed(self, event):
        nfp_context = event.context
        device = self._prepare_failure_case_device_data(nfp_context)
        # self._release_cnfd_lock(device)
        status = nfp_context['network_function_device']['status']
        desc = "Failed to plug interfaces"
        self._update_network_function_device_db(device, status, desc)
        # self._create_event(event_id='DEVICE_CREATE_FAILED',
        #                    event_data=device)

    def handle_device_not_reachable(self, event):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Device not reachable, Health Check Failed'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        # self._create_event(event_id='DEVICE_CREATE_FAILED',
        #                    event_data=device)
        self.health_monitor_complete(event, result='FAILED')

    def periodic_hm_handle_device_reachable(self, event):
        device = event.data
        status = nfp_constants.ACTIVE
        desc = 'Device is ACTIVE'
        self._update_network_function_device_db(device, status, desc)

    def periodic_hm_handle_device_not_reachable(self, event):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Device not reachable, Health Check Failed'
        self._update_network_function_device_db(device, status, desc)

    def handle_device_config_failed(self, event):
        # device = event.data
        nfp_context = event.data['nfp_context']

        device = nfp_context['network_function_device']
        status = device['status']
        desc = 'Configuring Device Failed.'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        # self._create_event(event_id='DEVICE_CREATE_FAILED',
        #                    event_data=event.data)
        LOG.debug("Device create failed for device: %s, with "
                  "data: %s", (device['id'], device))
        self.device_configuration_complete(event, result='FAILED')

    def handle_interfaces_setup_failed(self, event):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Interfaces Plugging failed'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)
        LOG.debug("Interface Plugging failed for device: %s,"
                  "with config: %s", (device['id'], device))

    def handle_driver_error(self, event):
        device = event.data
        LOG.error(_LE("Exception occured in driver, driver returned None "
                      " for device %(device)s"), {'device': device})
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        self._update_network_function_device_db(device, status, desc)
        # device['network_function_device_id'] = device['id']
        # self._create_event(event_id='DEVICE_CREATE_FAILED',
        #                    event_data=device)

    def update_config_params(self, event):
        self._create_event(event_id='DEVICE_CONFIG_PARAMETERS_UPDATED',
                           event_data=event.data, is_internal_event=True)
        self._controller.event_complete(event=event, result='SUCCESS')


class NDOConfiguratorRpcApi(object):
    """Service Manager side of the Service Manager to Service agent RPC API"""
    API_VERSION = '1.0'
    target = messaging.Target(version=API_VERSION)

    def __init__(self, context, conf):
        super(NDOConfiguratorRpcApi, self).__init__()
        self.conf = conf
        self.context = context
        self.client = n_rpc.get_client(self.target)
        self.rpc_api = self.client.prepare(
            version=self.API_VERSION,
            topic=nsf_topics.NFP_NDO_CONFIGURATOR_TOPIC)

    def _get_request_info(self, device, operation):
        nfp_context = module_context.get()
        request_info = {
            'nf_id': device['network_function_id'],
            'nfi_id': (
                device['network_function_instance_id']),
            'nfd_id': device['id'],
            'requester': nfp_constants.DEVICE_ORCHESTRATOR,
            'operation': operation,
            'logging_context': nfp_context['log_context'],
            # So that notification callbacks can work on cached data
            # 'orig_nfp_context': device.get('orig_nfp_context'),
            'nfp_context': device.get('nfp_context', None),
            'service_profile': device.get('service_profile'),
            'service_vm_context': nfp_utils.get_service_vm_context(
                device['service_details']['service_vendor']),
        }
        nfd_ip = device.get('mgmt_ip_address')
        request_info.update({'device_ip': nfd_ip})
        return request_info

    def _update_params(self, device_data, config_params, operation):
        request_info = self._get_request_info(device_data, operation)
        if not config_params:
            return None
        config_params['info'] = {
            'service_type': device_data['service_details']['service_type'],
            'service_vendor': device_data['service_details']['service_vendor'],
            'context': request_info,
        }
        if device_data.get('service_feature'):
            config_params['info'].update(
                {'service_feature': device_data.get('service_feature')})
        if config_params.get('service_info'):
            config_params['info'].update(config_params.pop('service_info'))

    def create_network_function_device_config(self, device_data,
                                              config_params):
        self._update_params(device_data, config_params, operation='create')
        LOG.info(_LI("Sending create NFD config request to configurator "
                     "for NF:%(nf_id)s "),
                 {'nf_id': config_params['info']['context']['nf_id']})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE',
                                               True)

    def delete_network_function_device_config(self, device_data,
                                              config_params):
        self._update_params(device_data, config_params, operation='delete')
        config_params['info']['context']['nfp_context'] = device_data
        LOG.info(_LI("Sending delete NFD config request to configurator "))

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE',
                                               True)


class ExceptionHandler(object):

    @staticmethod
    def event_method_mapping(event_id):
        event_handler_mapping = {
            "CREATE_NETWORK_FUNCTION_DEVICE": (
                ExceptionHandler.create_network_function_device),
            "DEVICE_SPAWNING": ExceptionHandler.device_spawning,
            "PERFORM_INITIAL_HEALTH_CHECK":
                ExceptionHandler.perform_initial_health_check,
            "DEVICE_UP": ExceptionHandler.device_up,
            "PLUG_INTERFACES": ExceptionHandler.plug_interfaces,
            "HEALTH_MONITOR_COMPLETE":
                ExceptionHandler.health_monitor_complete,
            "CREATE_DEVICE_CONFIGURATION":
                ExceptionHandler.create_device_configuration,
            "DEVICE_CONFIGURED":
                ExceptionHandler.device_configuration_complete,
            "CONFIGURATION_COMPLETE": ExceptionHandler.configuration_complete,
            "DELETE_NETWORK_FUNCTION_DEVICE": (
                ExceptionHandler.delete_network_function_device),
            "DELETE_CONFIGURATION":
                ExceptionHandler.delete_device_configuration,
            "DELETE_CONFIGURATION_COMPLETED": (
                ExceptionHandler.delete_configuration_complete),
            "UNPLUG_INTERFACES": ExceptionHandler.unplug_interfaces,
            "DELETE_DEVICE": ExceptionHandler.delete_device,
            "DEVICE_BEING_DELETED": ExceptionHandler.device_being_deleted,
            "PERIODIC_HM_DEVICE_NOT_REACHABLE": (
                ExceptionHandler.periodic_hm_handle_device_not_reachable),
            "DEVICE_NOT_REACHABLE": (
                ExceptionHandler.health_monitor_complete),
            "DEVICE_CONFIGURATION_FAILED": (
                ExceptionHandler.device_configuration_complete),
            "PERFORM_PERIODIC_HEALTH_CHECK": (
                ExceptionHandler.perform_periodic_health_check),
        }
        if event_id not in event_handler_mapping:
            raise Exception(_("Invalid event ID"))
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
    def create_network_function_device(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        # [REVISIT: AKASH] Updating NF from device_orchestrator is wrong way
        # of doing, but still doing it, will correct it later
        orchestrator.nsf_db.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def perform_initial_health_check(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def device_up(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        device = orchestrator._prepare_failure_case_device_data(nfp_context)
        orchestrator._release_cnfd_lock(device)
        orchestrator.nsf_db.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def plug_interfaces(orchestrator, event, exception):
        nfp_context = event.context
        device = orchestrator._prepare_failure_case_device_data(nfp_context)
        status = nfp_context['network_function_device']['status']
        desc = "Failed to plug interfaces"
        orchestrator._update_network_function_device_db(device, status, desc)
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def health_monitor_complete(orchestrator, event, exception):
        nfp_context = event.data['nfp_context']
        event_desc = nfp_context.pop('event_desc', None)
        nfp_context.pop('id', None)
        key = nfp_context.pop('key', None)
        ev = orchestrator._controller.new_event(
            id="PERFORM_INITIAL_HEALTH_CHECK",
            key=key, desc_dict=event_desc)
        orchestrator._controller.event_complete(ev, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def create_device_configuration(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def device_configuration_complete(orchestrator, event, exception):
        nfp_context = event.data['nfp_context']
        event_desc = nfp_context.pop('event_desc')
        key = nfp_context.pop('key')
        ev = orchestrator._controller.new_event(
            id="CREATE_DEVICE_CONFIGURATION",
            key=key, desc_dict=event_desc)
        ev.binding_key = nfp_context.pop('binding_key')
        orchestrator._controller.event_complete(ev, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def configuration_complete(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        orchestrator.nsf_db.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def delete_network_function_device(orchestrator, event, exception):
        network_function_details = event.context
        device = network_function_details['network_function_device']
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        orchestrator._update_network_function_device_db(device, status, desc)
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def delete_device_configuration(orchestrator, event, exception):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        orchestrator._update_network_function_device_db(device, status, desc)
        nf_id = device['network_function_id']
        dnfd_event = (
            orchestrator._controller.new_event(
                id='DELETE_NETWORK_FUNCTION_DEVICE',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=device.get('event_desc')))
        orchestrator._controller.event_complete(dnfd_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def delete_configuration_complete(orchestrator, event, exception):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        orchestrator._update_network_function_device_db(device, status, desc)
        nf_id = device['network_function_id']
        dnfd_event = (
            orchestrator._controller.new_event(
                id='DELETE_NETWORK_FUNCTION_DEVICE',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=device.get('event_desc')))
        orchestrator._controller.event_complete(dnfd_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def unplug_interfaces(orchestrator, event, exception):
        device = event.data
        nf_id = device['network_function_id']
        dnfd_event = (
            orchestrator._controller.new_event(
                id='DELETE_NETWORK_FUNCTION_DEVICE',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=device.get('event_desc')))
        orchestrator._controller.event_complete(dnfd_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def delete_device(orchestrator, event, exception):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        orchestrator._update_network_function_device_db(device, status, desc)
        nf_id = device['network_function_id']
        dnfd_event = (
            orchestrator._controller.new_event(
                id='DELETE_NETWORK_FUNCTION_DEVICE',
                key=nf_id,
                binding_key=nf_id,
                desc_dict=device.get('event_desc')))
        orchestrator._controller.event_complete(dnfd_event, result='FAILED')
        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def device_being_deleted(orchestrator, event, exception):
        return {'poll': True}

    @staticmethod
    def device_spawning(orchestrator, event, exception):
        nfp_context = event.context
        network_function = nfp_context['network_function']
        device = orchestrator._prepare_failure_case_device_data(nfp_context)
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        orchestrator._update_network_function_device_db(device, status, desc)
        orchestrator._release_cnfd_lock(device)
        orchestrator.nsf_db.update_network_function(
            orchestrator.db_session,
            network_function['id'],
            {'status': nfp_constants.ERROR})
        orchestrator._controller.event_complete(event, result='FAILED')
        return {'poll': False}

    @staticmethod
    def periodic_hm_handle_device_not_reachable(orchestrator,
                                                event, exception):

        orchestrator._controller.event_complete(event, result='FAILED')

    @staticmethod
    def perform_periodic_health_check(orchestrator, event, exception):
        orchestrator._controller.event_complete(event, result='FAILED')
