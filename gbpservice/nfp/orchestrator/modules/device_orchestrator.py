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

from neutron import i18n
import oslo_messaging as messaging

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import topics as nsf_topics
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import module as nfp_api
from gbpservice.nfp.core import rpc as nfp_rpc
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.db import nfp_db as nfp_db
from gbpservice.nfp.orchestrator.drivers import orchestration_driver
from gbpservice.nfp.orchestrator.openstack import openstack_driver
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.db import api as db_api

import sys
import traceback

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)

STOP_POLLING = {'poll': False}
CONTINUE_POLLING = {'poll': True}

Event = nfp_event.Event
RpcAgent = nfp_rpc.RpcAgent
_LE = i18n._LE
_LI = i18n._LI


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
              'DELETE_CONFIGURATION_COMPLETED', 'DEVICE_BEING_DELETED',
              'DEVICE_NOT_REACHABLE',
              'DEVICE_CONFIGURATION_FAILED', 'PERFORM_HEALTH_CHECK',
              'PLUG_INTERFACES']
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
            'healthmonitor': ['HEALTH_MONITOR_COMPLETE',
                              'DEVICE_NOT_REACHABLE',
                              'DEVICE_NOT_REACHABLE'],
            'interfaces': ['DEVICE_CONFIGURED',
                           'DELETE_CONFIGURATION_COMPLETED',
                           'DEVICE_CONFIGURATION_FAILED'],
            'routes': ['DEVICE_CONFIGURED',
                       'DELETE_CONFIGURATION_COMPLETED',
                       'DEVICE_CONFIGURATION_FAILED'],
        }

    def _log_event_created(self, event_id, event_data):
        LOG.info(_LI("Device Orchestrator, RPC Handler, Created event "
                     "%s(event_name)s with event data: %(event_data)s"),
                 {'event_name': event_id, 'event_data': event_data})

    def _create_event(self, event_id, event_data=None,
                      is_poll_event=False, original_event=False):
        if is_poll_event:
            ev = self._controller.new_event(
                id=event_id, data=event_data,
                serialize=original_event.sequence,
                binding_key=original_event.binding_key,
                key=original_event.desc.uuid)
            LOG.debug("poll event started for %s" % (ev.id))
            self._controller.poll_event(ev, max_times=10)
        else:
            ev = self._controller.new_event(
                id=event_id,
                data=event_data)
            self._controller.post_event(ev)
        self._log_event_created(event_id, event_data)

    # RPC APIs status notification from Configurator
    def network_function_notification(self, context, notification_data):
        info = notification_data.get('info')
        responses = notification_data.get('notification')
        request_info = info.get('context')
        operation = request_info.get('operation')
        logging_context = request_info.get('logging_context')
        # nfp_context = request_info.get('nfp_context')
        nfp_logging.store_logging_context(**logging_context)

        for response in responses:
            resource = response.get('resource')
            data = response.get('data')
            result = data.get('status_code')

            is_delete_request = True if operation == 'delete' else False

            if is_delete_request:
                event_id = self.rpc_event_mapping[resource][1]
            else:
                event_id = self.rpc_event_mapping[resource][0]

            if result.lower() != 'success':
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

        self._create_event(event_id=event_id,
                           event_data=event_data)
        nfp_logging.clear_logging_context()


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
            'DEVICE_SPAWNING': ('Creating NSD, launched the new device, ' +
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
            "PERFORM_HEALTH_CHECK": self.perform_health_check,
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
            "DELETE_CONFIGURATION_COMPLETED": self.unplug_interfaces,
            "DELETE_DEVICE": self.delete_device,
            "DELETE_CONFIGURATION": self.delete_device_configuration,
            "DEVICE_NOT_REACHABLE": self.handle_device_not_reachable,
            "PLUG_INTERFACE_FAILED": self.handle_plug_interface_failed,
            "DEVICE_CONFIGURATION_FAILED": self.handle_device_config_failed,
            "DEVICE_ERROR": self.handle_device_create_error,
            "DEVICE_NOT_UP": self.handle_device_not_up,
            "DRIVER_ERROR": self.handle_driver_error
        }
        if event_id not in event_handler_mapping:
            raise Exception("Invalid event ID")
        else:
            return event_handler_mapping[event_id]

    def handle_event(self, event):
        try:
            nf_id = (event.data['network_function_id']
                     if 'network_function_id' in event.data else None)
            LOG.info(_LI("NDO: received event %(id)s for network function : "
                         "%(nf_id)s"),
                     {'id': event.id, 'nf_id': nf_id})
            event_handler = self.event_method_mapping(event.id)
            event_handler(event)
        except Exception as e:
            LOG.exception(_LE("Error in processing event: %(event_id)s for "
                              "event data %(event_data)s. Error: %(error)s"),
                          {'event_id': event.id, 'event_data': event.data,
                           'error': e})
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)

    # Helper functions
    def _log_event_created(self, event_id, event_data):
        LOG.info(_LI("Device Orchestrator created event %s(event_name)s "
                     "with event data: %(event_data)s"), {
                         'event_name': event_id, 'event_data': event_data})

    def _create_event(self, event_id, event_data=None,
                      is_poll_event=False, original_event=False,
                      is_internal_event=False):
        if not is_internal_event:
            if is_poll_event:
                ev = self._controller.new_event(
                    id=event_id, data=event_data,
                    serialize=original_event.sequence,
                    binding_key=original_event.binding_key,
                    key=original_event.desc.uuid)
                LOG.debug("poll event started for %s" % (ev.id))
                self._controller.poll_event(ev, max_times=20)
            else:
                ev = self._controller.new_event(
                    id=event_id,
                    data=event_data)
                self._controller.post_event(ev)
            self._log_event_created(event_id, event_data)
        else:
            # Same module API, so calling corresponding function directly.
            event = self._controller.new_event(
                id=event_id,
                data=event_data)
            self.handle_event(event)

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
            orchestration_driver.delete_network_function_device(device)
            self._delete_network_function_device_db(device_id, device)
            # DEVICE_DELETED event for NSO
            self._create_event(event_id='DEVICE_DELETED',
                               event_data=device)

    def _update_device_status(self, device, state, status_desc=None):
        device['status'] = state
        if status_desc:
            device['status_description'] = status_desc
        else:
            device['status_description'] = self.status_map.get(state)

    def _get_port(self, port_id):
        return self.nsf_db.get_port_info(self.db_session, port_id)

    def _get_ports(self, port_ids):
        data_ports = []
        for port_id in port_ids:
            port_info = self.nsf_db.get_port_info(self.db_session, port_id)
            data_ports.append(port_info)
        return data_ports

    def _create_network_function_device_db(self, device_info, state):

        self._update_device_status(device_info, state)
        # (ashu) driver should return device_id as vm_id
        device_id = device_info.pop('id')
        device_info['id'] = device_id
        device_info['reference_count'] = 0
        device_info['interfaces_in_use'] = 0
        device = self.nsf_db.create_network_function_device(self.db_session,
                                                            device_info)
        return device

    def _update_network_function_device_db(self, device, state,
                                           status_desc=''):
        self._update_device_status(device, state, status_desc)
        self.nsf_db.update_network_function_device(self.db_session,
                                                   device['id'], device)

    def _delete_network_function_device_db(self, device_id, device):
        self.nsf_db.delete_network_function_device(self.db_session, device_id)

    def _get_network_function_info(self, device_id):
        nfi_filters = {'network_function_device_id': [device_id]}
        network_function_instances = (
            self.nsf_db.get_network_function_instances(self.db_session,
                                                       nfi_filters))
        network_function_ids = [nf['network_function_id']
                                for nf in network_function_instances]
        network_functions = (
            self.nsf_db.get_network_functions(self.db_session,
                                              {'id': network_function_ids}))
        return network_functions

    def _get_network_function_devices(self, filters=None):
        network_function_devices = self.nsf_db.get_network_function_devices(
            self.db_session, filters)
        for device in network_function_devices:
            mgmt_port_id = device.pop('mgmt_port_id')
            mgmt_port_id = self._get_port(mgmt_port_id)
            device['mgmt_port_id'] = mgmt_port_id

            network_functions = (
                self._get_network_function_info(device['id']))
            device['network_functions'] = network_functions
        return network_function_devices

    def _increment_device_ref_count(self, device):
        device['reference_count'] += 1

    def _decrement_device_ref_count(self, device):
        device['reference_count'] -= 1

    def _increment_device_interface_count(self, device):
        device['interfaces_in_use'] += len(device['ports'])
        self._update_network_function_device_db(device, device['status'])

    def _decrement_device_interface_count(self, device):
        device['interfaces_in_use'] -= len(device['ports'])
        self._update_network_function_device_db(device, device['status'])

    def _get_orchestration_driver(self, service_vendor):
        return self.orchestration_driver

    def _get_device_to_reuse(self, device_data, dev_sharing_info):
        device_filters = dev_sharing_info['filters']
        orchestration_driver = self._get_orchestration_driver(
            device_data['service_details']['service_vendor'])

        devices = self._get_network_function_devices(device_filters)

        device = orchestration_driver.select_network_function_device(
            devices,
            device_data)
        return device

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
            port_info = self.nsf_db.get_port_info(self.db_session, port_id)
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

        ports = self._make_ports_dict(consumer, provider, 'pt')

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

        return device_data

    # Create path
    def create_network_function_device(self, event):
        """ Returns device instance for a new service

        This method either returns existing device which could be reused for a
        new service or it creates new device instance
        """

        device = None

        nfp_context = event.data
        nfd_request = self._prepare_failure_case_device_data(nfp_context)
        service_details = nfp_context['service_details']

        LOG.info(_LI("Device Orchestrator received create network service "
                     "device request with data %(data)s"),
                 {'data': nfd_request})

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])

        device_data = self._prepare_device_data_from_nfp_context(nfp_context)

        LOG.info(_LI("Creating new device,"
                     "device request: %(device)s"), {'device': nfd_request})

        driver_device_info = (
            orchestration_driver.create_network_function_device(
                device_data))
        if not driver_device_info:
            LOG.info(_LI("Device creation failed"))
            self._create_event(event_id='DEVICE_ERROR',
                               event_data=nfd_request,
                               is_internal_event=True)
            return None

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

        # Create DB entry with status as DEVICE_SPAWNING
        network_function_device = (
            self._create_network_function_device_db(device,
                                                    'DEVICE_SPAWNING'))

        # REVISIT(mak) Wrong but nfp_db method needs in this format
        network_function_device['mgmt_port_id'] = device['mgmt_port_id']
        nfp_context['network_function_device'] = network_function_device

        # Create an event to NSO, to give device_id
        device_created_data = {
            'network_function_instance_id': (
                nfp_context['network_function_instance']['id']),
            'network_function_device_id': device['id']
        }

        self._create_event(event_id='DEVICE_SPAWNING',
                           event_data=nfp_context,
                           is_poll_event=True,
                           original_event=event)
        self._create_event(event_id='DEVICE_CREATED',
                           event_data=device_created_data)

    def _post_device_up_event_graph(self, nfp_context):
        nf_id = nfp_context['network_function']['id']
        du_event = self._controller.new_event(id="DEVICE_UP",
                                              key=nf_id,
                                              data=nfp_context,
                                              graph=True)

        hc_event = self._controller.new_event(id="PERFORM_HEALTH_CHECK",
                                              key=nf_id,
                                              data=nfp_context,
                                              graph=True)

        plug_int_event = self._controller.new_event(id="PLUG_INTERFACES",
                                                    key=nf_id,
                                                    data=nfp_context,
                                                    graph=True)

        graph = nfp_event.EventGraph(du_event)
        graph.add_node(hc_event, du_event)
        graph.add_node(plug_int_event, du_event)

        graph_event = self._controller.new_event(id="HEALTH_MONITOR_GRAPH",
                                                 graph=graph)
        graph_nodes = [du_event, hc_event, plug_int_event]
        self._controller.post_event_graph(graph_event, graph_nodes)

    @nfp_api.poll_event_desc(event='DEVICE_SPAWNING', spacing=2)
    def check_device_is_up(self, event):
        nfp_context = event.data

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
            # [REVISIT(mak)] - Update interfaces count here before
            # sending health monitor rpc in PERFORM_HEALTH_CHECK event.
            # [REVISIT(mak)] to handle a very corner case where
            # PLUG_INTERFACES completes later than HEALTHMONITOR.
            # till proper fix is identified.
            provider = nfp_context['provider']['ptg']
            consumer = nfp_context['consumer']['ptg']
            network_function_device = nfp_context['network_function_device']

            if provider:
                network_function_device['interfaces_in_use'] += 1
            if consumer:
                network_function_device['interfaces_in_use'] += 1

            # nf_id = nfp_context['network_function']['id']
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

    def _post_configure_device_graph(self, nfp_context):
        nf_id = nfp_context['network_function']['id']
        device_configured_event = self._controller.new_event(
            id='CONFIGURATION_COMPLETE',
            key=nf_id,
            data=nfp_context,
            graph=True)
        device_configure_event = self._controller.new_event(
            id='CREATE_DEVICE_CONFIGURATION',
            key=nf_id,
            data=nfp_context,
            graph=True)
        user_config_event = self._controller.new_event(
            id='APPLY_USER_CONFIG',
            key=nf_id,
            data=nfp_context,
            graph=True)

        check_heat_config = self._controller.new_event(
            id='SEND_HEAT_CONFIG',
            key=nf_id,
            data=nfp_context,
            graph=True)
        graph = nfp_event.EventGraph(device_configured_event)
        graph.add_node(device_configure_event, device_configured_event)
        graph.add_node(user_config_event, device_configured_event)
        graph.add_node(check_heat_config, user_config_event)

        event_graph = self._controller.new_event(
            id='DEVICE_CONFIGURATION_GRAPH',
            graph=graph)
        graph_nodes = [device_configured_event, device_configure_event,
                       user_config_event, check_heat_config]
        self._controller.post_event_graph(event_graph, graph_nodes)

    def device_up(self, event):
        nfp_context = event.data

        # Get the results of PLUG_INTERFACES & PERFORM_HEALTH_CHECK events
        # results.
        results = event.graph.get_leaf_node_results(event)

        for result in results:
            if result.result.lower() != 'success':
                return self._controller.event_complete(event, result='FAILED')

        self._post_configure_device_graph(nfp_context)
        self._controller.event_complete(event)

    def perform_health_check(self, event):
        nfp_context = event.data

        service_details = nfp_context['service_details']
        network_function_device = nfp_context['network_function_device']
        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        mgmt_ip_address = nfp_context['management']['port']['ip_address']

        # The driver tells which protocol / port to monitor ??
        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        nfp_context['event_desc'] = event.desc.to_dict()
        device = {
            'id': network_function_device['id'],
            'mgmt_ip_address': mgmt_ip_address,
            'service_details': service_details,
            'network_function_id': network_function['id'],
            'network_function_instance_id': network_function_instance['id'],
            'nfp_context': {'event_desc': nfp_context['event_desc'],
                            'id': event.id, 'key': event.key}
        }

        hm_req = (
            orchestration_driver.get_network_function_device_healthcheck_info(
                device))
        if not hm_req:
            self._controller.event_complete(event, result="FAILED")
            return None

        self.configurator_rpc.create_network_function_device_config(device,
                                                                    hm_req)
        LOG.debug("Health Check RPC sent to configurator for device: "
                  "%s with health check parameters: %s" % (
                      device['id'], hm_req))

        device['status'] = 'HEALTH_CHECK_PENDING'
        self._update_network_function_device_db(device,
                                                'HEALTH_CHECK_PENDING')

    def _get_service_type(self, service_profile_id):
        admin_token = self.keystoneclient.get_admin_token()
        service_profile = self.gbpclient.get_service_profile(
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

        admin_token = self.keystoneclient.get_admin_token()
        service_profile = self.gbpclient.get_service_profile(
            admin_token, network_function['service_profile_id'])
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

    def health_monitor_complete(self, event, result='SUCCESS'):
        nfp_context = event.data['nfp_context']
        # device = nfp_context['network_function_device']
        # network_function = nfp_context['network_function']

        # Invoke event_complete for original event which is
        # PERFORM_HEALTH_CHECK
        event_desc = nfp_context.pop('event_desc')
        nfp_context.pop('id')
        key = nfp_context.pop('key')
        event = self._controller.new_event(id="PERFORM_HEALTH_CHECK",
                                           key=key, desc_dict=event_desc)
        self._controller.event_complete(event, result=result)

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
        # happening in paralell with HEALTHMONITORIN,
        # so, we should not generate CONFIGURE_DEVICE & should not update
        # DB with HEALTH_CHECK_COMPLETED.

        nfp_context = event.data

        service_details = nfp_context['service_details']
        network_function_device = nfp_context['network_function_device']
        token = nfp_context['resource_owner_context']['admin_token']
        tenant_id = nfp_context['resource_owner_context']['admin_tenant_id']

        consumer = nfp_context['consumer']
        provider = nfp_context['provider']

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])

        ports = self._make_ports_dict(consumer, provider, 'port')

        device = {
            'id': network_function_device['id'],
            'ports': ports,
            'service_details': service_details,
            'token': token,
            'tenant_id': tenant_id,
            'interfaces_in_use': network_function_device['interfaces_in_use'],
            'status': network_function_device['status']}

        _ifaces_plugged_in = (
            orchestration_driver.plug_network_function_device_interfaces(
                device))
        if _ifaces_plugged_in:
            self._increment_device_interface_count(device)
            # [REVISIT(mak)] - Check how incremented ref count can be
            # updated in DB
            self._controller.event_complete(event, result="SUCCESS")
        else:
            self._create_event(event_id="PLUG_INTERFACE_FAILED",
                               event_data=nfp_context,
                               is_internal_event=True)
            self._controller.event_complete(event, result="FAILED")

    def configure_device(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        config_params = (
            orchestration_driver.get_network_function_device_config_info(
                device))
        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            return None
        # Sends RPC to configurator to create generic config
        self.configurator_rpc.create_network_function_device_config(
            device, config_params)

    def create_device_configuration(self, event):
        nfp_context = event.data

        service_details = nfp_context['service_details']
        # token = nfp_context['resource_owner_context']['admin_token']
        # tenant_id = nfp_context['resource_owner_context']['tenant_id']
        consumer = nfp_context['consumer']
        provider = nfp_context['provider']
        management = nfp_context['management']
        network_function = nfp_context['network_function']
        network_function_instance = nfp_context['network_function_instance']
        network_function_device = nfp_context['network_function_device']

        orchestration_driver = self._get_orchestration_driver(
            service_details['service_vendor'])
        device = {
            'mgmt_ip': management['port']['ip_address'],
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

        config_params = (
            orchestration_driver.
            get_create_network_function_device_config_info(
                device))
        nfp_context['event_desc'] = event.desc.to_dict()
        device.update({
            'id': network_function_device['id'],
            'mgmt_ip_address': management['port']['ip_address'],
            'service_details': service_details,
            'network_function_id': network_function['id'],
            'network_function_instance_id': network_function_instance['id'],
            'nfp_context': {
                'event_desc': nfp_context['event_desc'],
                'id': event.id, 'key': event.key,
                'network_function_device': network_function_device}})

        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            self._controller.event_complete(event, result="FAILED")
            return None
        # Sends RPC to configurator to create generic config
        self.configurator_rpc.create_network_function_device_config(
            device, config_params)

    def configuration_complete(self, event):
        nfp_context = event.data
        nf_id = nfp_context['network_function']['id']
        event_results = event.graph.get_leaf_node_results(event)
        for result in event_results:
            if result.result != "SUCCESS":
                self._controller.event_complete(event)
                return
        sc_event = self._controller.new_event(id="SERVICE_CONFIGURED",
                                              key=nf_id,
                                              data=nfp_context)
        self._controller.post_event(sc_event)
        self._controller.event_complete(event)

    def device_configuration_complete(self, event, result='SUCCESS'):
        nfp_context = event.data['nfp_context']

        device = nfp_context['network_function_device']

        if result.lower() == 'success':
            self._increment_device_ref_count(device)
            self._update_network_function_device_db(
                device, nfp_constants.ACTIVE)
            LOG.info(_LI(
                "Device Configuration completed for device: %(device_id)s"
                "Updated DB status to ACTIVE, Incremented device "
                "reference count for %(device)s"),
                {'device_id': device['id'], 'device': device})

        # Invoke event_complete for original event which is
        # CREATE_DEVICE_CONFIGURATION
        event_desc = nfp_context.pop('event_desc')
        key = nfp_context.pop('key')
        event = self._controller.new_event(id="CREATE_DEVICE_CONFIGURATION",
                                           key=key, desc_dict=event_desc)
        self._controller.event_complete(event, result=result)

    # Delete path
    def delete_network_function_device(self, event):
        delete_nfd_request = event.data
        network_function_instance = (
            delete_nfd_request.pop('network_function_instance'))
        delete_nfd_request['network_function_instance_id'] = (
            network_function_instance['id'])
        device = self._prepare_device_data(delete_nfd_request)
        LOG.info(_LI("Device Orchestrator received delete network service "
                     "device request for device %(device)s"),
                 {'device': delete_nfd_request})

        self._create_event(event_id='DELETE_CONFIGURATION',
                           event_data=device,
                           is_internal_event=True)

    def delete_device_configuration(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        config_params = (
            orchestration_driver.get_network_function_device_config_info(
                device))
        if not config_params:
            self._create_event(event_id='DRIVER_ERROR',
                               event_data=device,
                               is_internal_event=True)
            return None
        # Sends RPC call to configurator to delete generic config API
        self.configurator_rpc.delete_network_function_device_config(
            device, config_params)

    def unplug_interfaces(self, event):
        device_info = event.data
        device = self._prepare_device_data(device_info)
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
            # Ignore unplug error
            pass
        self._create_event(event_id='DELETE_DEVICE',
                           event_data=device,
                           is_internal_event=True)

    def delete_device(self, event):
        # Update status in DB, send DEVICE_DELETED event to NSO.
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])

        self._decrement_device_ref_count(device)
        orchestration_driver.delete_network_function_device(device)
        self._create_event(event_id='DEVICE_BEING_DELETED',
                           event_data=device,
                           is_poll_event=True,
                           original_event=event)

    @nfp_api.poll_event_desc(event='DEVICE_BEING_DELETED', spacing=2)
    def check_device_deleted(self, event):
        device = event.data
        orchestration_driver = self._get_orchestration_driver(
            device['service_details']['service_vendor'])
        status = orchestration_driver.get_network_function_device_status(
            device, ignore_failure=True)
        if not status:
            device_id = device['id']
            del device['id']
            orchestration_driver.delete_network_function_device(device)
            self._delete_network_function_device_db(device_id, device)
            # DEVICE_DELETED event for NSO
            self._create_event(event_id='DEVICE_DELETED',
                               event_data=device)
            return STOP_POLLING
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
            'id']}
        network_function_device = nfp_context.get('network_function_device')
        if network_function_device:
            device.update(
                {'network_function_device_id': network_function_device['id']})
            device.update(network_function_device)
        return device

    def handle_plug_interface_failed(self, event):
        nfp_context = event.data
        device = self._prepare_failure_case_device_data(nfp_context)
        status = nfp_constants.ERROR
        desc = "Failed to plug interfaces"
        self._update_network_function_device_db(device, status, desc)
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)

    def handle_device_not_reachable(self, event):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Device not reachable, Health Check Failed'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)
        self.health_monitor_complete(event, result='FAILED')

    def handle_device_config_failed(self, event):
        device = event.data
        status = nfp_constants.ERROR
        desc = 'Configuring Device Failed.'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)
        LOG.debug("Device create failed for device: %s, with "
                  "data: %s" % (device['id'], device))
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
                  "with config: %s" % (device['id'], device))

    def handle_driver_error(self, event):
        device = event.data
        LOG.error(_LE("Exception occured in driver, driver returned None "
                      " for device %(device)s"), {'device': device})
        status = nfp_constants.ERROR
        desc = 'Exception in driver, driver return None'
        self._update_network_function_device_db(device, status, desc)
        device['network_function_device_id'] = device['id']
        self._create_event(event_id='DEVICE_CREATE_FAILED',
                           event_data=device)


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
        request_info = {
            'nf_id': device['network_function_id'],
            'nfi_id': (
                device['network_function_instance_id']),
            'nfd_id': device['id'],
            'requester': nfp_constants.DEVICE_ORCHESTRATOR,
            'operation': operation,
            'logging_context': nfp_logging.get_logging_context(),
            # So that notification callbacks can work on cached data
            'nfp_context': device.get('nfp_context', None)
        }
        nfd_ip = device['mgmt_ip_address']
        request_info.update({'device_ip': nfd_ip})
        return request_info

    def _update_params(self, device_data, config_params, operation):
        request_info = self._get_request_info(device_data, operation)
        if not config_params:
            return None
        config_params['info'] = {
            'service_type': device_data['service_details']['service_type'],
            'service_vendor': device_data['service_details']['service_vendor'],
            'context': request_info
        }

    def create_network_function_device_config(self, device_data,
                                              config_params):
        self._update_params(device_data, config_params, operation='create')
        LOG.info(_LI("Sending create NFD config request to configurator "
                     "with config_params = %(config_params)s"),
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'CREATE',
                                               True)
        nfp_logging.clear_logging_context()

    def delete_network_function_device_config(self, device_data,
                                              config_params):
        self._update_params(device_data, config_params, operation='delete')
        LOG.info(_LI("Sending delete NFD config request to configurator "
                     "with config_params = %(config_params)s"),
                 {'config_params': config_params})

        transport.send_request_to_configurator(self.conf,
                                               self.context,
                                               config_params,
                                               'DELETE',
                                               True)
        nfp_logging.clear_logging_context()
