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

import copy
import os

from neutron._i18n import _LI

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.lib import (
    generic_config_constants as gen_cfg_const)
from gbpservice.contrib.nfp.configurator.lib import constants as common_const
from gbpservice.contrib.nfp.configurator.lib import data_parser
from gbpservice.contrib.nfp.configurator.lib import utils
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

LOG = nfp_logging.getLogger(__name__)


class GenericConfigRpcManager(agent_base.AgentBaseRPCManager):
    """Implements APIs invoked by configurator for processing RPC messages.

    RPC client of configurator module receives RPC messages from REST server
    and invokes the API of this class. The instance of this class is registered
    with configurator module using register_service_agent API. Configurator
    module identifies the service agent object based on service type and
    invokes ones of the methods of this class to configure the device.

    """

    def __init__(self, sc, conf):
        """Instantiates child and parent class objects.

        Passes the instances of core service controller and oslo configuration
        to parent instance inorder to provide event enqueue facility for batch
        processing event.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        """

        self.parse = data_parser.DataParser()
        super(GenericConfigRpcManager, self).__init__(sc, conf)

    def _send_event(self, context, resource_data, event_id, event_key=None):
        """Posts an event to framework.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: Keyword arguments which are passed as data to event
        :param event_id: Unique identifier for the event
        :param event_key: Event key for serialization

        """

        arg_dict = {'context': context,
                    'resource_data': resource_data}
        ev = self.sc.new_event(id=event_id, data=arg_dict, key=event_key)
        self.sc.post_event(ev)

    def configure_interfaces(self, context, resource_data):
        """Enqueues event for worker to process configure interfaces request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """

        self._send_event(context,
                         resource_data,
                         gen_cfg_const.EVENT_CONFIGURE_INTERFACES)

    def clear_interfaces(self, context, resource_data):
        """Enqueues event for worker to process clear interfaces request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """

        self._send_event(context,
                         resource_data,
                         gen_cfg_const.EVENT_CLEAR_INTERFACES)

    def configure_routes(self, context, resource_data):
        """Enqueues event for worker to process configure routes request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """

        self._send_event(context,
                         resource_data,
                         gen_cfg_const.EVENT_CONFIGURE_ROUTES)

    def clear_routes(self, context, resource_data):
        """Enqueues event for worker to process clear routes request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """

        self._send_event(context,
                         resource_data,
                         gen_cfg_const.EVENT_CLEAR_ROUTES)

    def configure_healthmonitor(self, context, resource_data):
        """Enqueues event for worker to process configure healthmonitor request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """
        LOG.info(_LI("Received configure health monitor api for nfds:"
                     "%(nfds)s"),
                 {'nfds': resource_data['nfds']})
        resource_data['fail_count'] = 0
        self._send_event(context,
                         resource_data,
                         gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR,
                         resource_data['nfds'][0]['vmid'])

    def clear_healthmonitor(self, context, resource_data):
        """Enqueues event for worker to process clear healthmonitor request.

        :param context: The agent info dictionary prepared in demuxer library
         which contains the API context alongside other information.
        :param kwargs: RPC Request data

        Returns: None

        """
        LOG.info(_LI("Received clear health monitor api for nfds:"
                     "%(nfds)s"),
                 {'nfds': resource_data['nfds']})
        event_key = resource_data['nfds'][0]['vmid']
        poll_event_id = gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR
        self.sc.stop_poll_event(event_key, poll_event_id)


class GenericConfigEventHandler(agent_base.AgentBaseEventHandler,
                                nfp_api.NfpEventHandler):
    """Implements event handlers and their helper methods.

    Object of this class is registered with the event class of core service
    controller. Based on the event key, handle_event method of this class is
    invoked by core service controller.
    """

    def __init__(self, sc, drivers, rpcmgr):
        super(GenericConfigEventHandler, self).__init__(
            sc, drivers, rpcmgr)
        self.sc = sc

    def _get_driver(self, service_type, service_vendor, service_feature):
        """Retrieves service driver object based on service type input.

        Currently, service drivers are identified with service type. Support
        for single driver per service type is provided. When multi-vendor
        support is going to be provided, the driver should be selected based
        on both service type and vendor name.

        :param service_type: Service type - firewall/vpn/loadbalancer

        Returns: Service driver instance

        """

        return self.drivers[service_type + service_vendor + service_feature]

    def handle_event(self, ev):
        """Processes the generated events in worker context.

        Processes the following events.
        - Configure Interfaces
        - Clear Interfaces
        - Configure routes
        - Clear routes
        - Configure health monitor
        - Clear health monitor
        Enqueues responses into notification queue.

        Returns: None

        """
        try:
            event_data = ev.data
            if ev.id == 'PROCESS_BATCH':
                NFI = event_data['sa_req_list'][0][
                    'agent_info']['context']['nfi_id']
                NF = event_data['sa_req_list'][0][
                    'agent_info']['context']['nf_id']
            else:
                NFI = event_data['context']['context']['nfi_id']
                NF = event_data['context']['context']['nf_id']
        except Exception:
            NFI = None
            NF = None

        msg = ("Handling event '%s', with NF:%s and NFI:%s"
               % (ev.id, NF, NFI))
        LOG.info(msg)

        # Process batch of request data blobs
        try:
            # Process batch of request data blobs
            if ev.id == common_const.EVENT_PROCESS_BATCH:
                self.process_batch(ev)
                return
            # Process HM poll events
            elif ev.id == gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR:
                resource_data = ev.data.get('resource_data')
                periodicity = resource_data['nfds'][0]['periodicity']
                EV_CONF_HM_MAXRETRY = (
                    gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR_MAXRETRY)
                if periodicity == gen_cfg_const.INITIAL:
                    self.sc.poll_event(
                        ev,
                        max_times=EV_CONF_HM_MAXRETRY)

                elif periodicity == gen_cfg_const.FOREVER:
                    self.sc.poll_event(ev)
            else:
                self._process_event(ev)
        except Exception as err:
            msg = ("Failed to process event %s, reason %s "
                   % (ev.data, err))
            LOG.error(msg)
            return

    def send_periodic_hm_notification(self, ev, nfd, result, notification_id):
        ev_copy = copy.deepcopy(ev)
        ev_copy.data["context"]["notification_data"] = {}
        ev_copy.data["context"]["context"]["nfp_context"]["id"] = (
            notification_id)
        ev_copy.data['context']['context']['nfd_id'] = nfd.get('vmid')
        notification_data = self._prepare_notification_data(ev_copy, result)
        self.notify._notification(notification_data)

    def handle_periodic_hm(self, ev, result):
        resource_data = ev.data['resource_data']
        nfd = ev.data["resource_data"]['nfds'][0]
        periodic_polling_reason = nfd["periodic_polling_reason"]
        if result == common_const.FAILED:
            """If health monitoring fails continuously for MAX_FAIL_COUNT times
                send fail notification to orchestrator
            """
            resource_data['fail_count'] = resource_data.get('fail_count') + 1
            if (resource_data.get('fail_count') >=
                    gen_cfg_const.MAX_FAIL_COUNT):
                # REVISIT(Shishir): Remove statefull logic from here,
                # need to come up with statleless logic.
                if periodic_polling_reason == (
                        gen_cfg_const.DEVICE_TO_BECOME_DOWN):
                    notification_id = gen_cfg_const.DEVICE_NOT_REACHABLE
                    self.send_periodic_hm_notification(ev, nfd, result,
                                                       notification_id)
                    nfd["periodic_polling_reason"] = (
                        gen_cfg_const.DEVICE_TO_BECOME_UP)
        elif result == common_const.SUCCESS:
            """set fail_count to 0 if it had failed earlier even once
            """
            resource_data['fail_count'] = 0
            if periodic_polling_reason == gen_cfg_const.DEVICE_TO_BECOME_UP:
                notification_id = gen_cfg_const.DEVICE_REACHABLE
                self.send_periodic_hm_notification(ev, nfd, result,
                                                   notification_id)
                nfd["periodic_polling_reason"] = (
                    gen_cfg_const.DEVICE_TO_BECOME_DOWN)

    def _process_event(self, ev):
        LOG.debug(" Handling event %s " % (ev.data))
        # Process single request data blob
        resource_data = ev.data['resource_data']
        # The context inside ev.data is the agent info dictionary prepared
        # in demuxer library which contains the API context alongside
        # other information like service vendor, type etc..
        agent_info = ev.data['context']
        context = agent_info['context']
        service_type = agent_info['resource_type']
        service_vendor = agent_info['service_vendor']
        service_feature = agent_info.get('service_feature', '')

        try:
            msg = ("Worker process with ID: %s starting "
                   "to handle task: %s for service type: %s. "
                   % (os.getpid(), ev.id, str(service_type)))
            LOG.debug(msg)

            driver = self._get_driver(service_type, service_vendor,
                                      service_feature)

            # Invoke service driver methods based on event type received
            result = getattr(driver, "%s" % ev.id.lower())(context,
                                                           resource_data)
        except Exception as err:
            msg = ("Failed to process ev.id=%s, ev=%s reason=%s" %
                   (ev.id, ev.data, err))
            LOG.error(msg)
            result = common_const.FAILED

        if ev.id == gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR:
            if (resource_data['nfds'][0][
                'periodicity'] == gen_cfg_const.INITIAL and
                    result == common_const.SUCCESS):
                notification_data = self._prepare_notification_data(ev,
                                                                    result)
                self.notify._notification(notification_data)
                msg = ("VM Health check successful")
                LOG.info(msg)
                return {'poll': False}
            elif resource_data['nfds'][0]['periodicity'] == (
                    gen_cfg_const.FOREVER):
                ev.data["context"]["resource"] = gen_cfg_const.PERIODIC_HM
                self.handle_periodic_hm(ev, result)
        else:
            """For other events, irrespective of result send notification"""
            notification_data = self._prepare_notification_data(ev, result)
            self.notify._notification(notification_data)

    def prepare_notification_result(self, result):
        if result in common_const.SUCCESS:
            data = {'status_code': common_const.SUCCESS}
        else:
            data = {'status_code': common_const.FAILURE,
                    'error_msg': result}
        return data

    def _prepare_notification_data(self, ev, result):
        """Prepare notification data as expected by config agent

        :param ev: event object
        :param result: result of the handled event

        Returns: notification_data

        """
        agent_info = ev.data['context']
        context = agent_info['context']

        # Retrieve notification and remove it from context. Context is used
        # as transport from batch processing function to this last event
        # processing function. To keep the context unchanged, delete the
        # notification_data before invoking driver API.
        notification_data = agent_info['notification_data']
        service_type = agent_info['resource_type']
        resource = agent_info['resource']

        data = self.prepare_notification_result(result)
        msg = {'info': {'service_type': service_type,
                        'context': context},
               'notification': [{'resource': resource,
                                 'data': data}]
               }
        if not notification_data:
            notification_data.update(msg)
        else:
            data = {'resource': resource,
                    'data': data}
            notification_data['notification'].append(data)
        return notification_data

    def event_cancelled(self, ev, reason):
        """Invoked by process framework when poll ev object reaches
           polling threshold ev.max_times.
           Finally it Enqueues response into notification queue.

        :param ev: Event object

        Returns: None

        """
        msg = ('Cancelled poll event. Event Data: %s ' % (ev.data))
        LOG.error(msg)
        result = common_const.FAILED
        notification_data = self._prepare_notification_data(ev, result)
        self.notify._notification(notification_data)

    @nfp_api.poll_event_desc(
        event=gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR,
        spacing=gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR_SPACING)
    def handle_configure_healthmonitor(self, ev):
        """Decorator method called for poll event CONFIGURE_HEALTHMONITOR
           Finally it Enqueues response into notification queue.

        :param ev: Event object

        Returns: None

        """
        return self._process_event(ev)


def events_init(sc, drivers, rpcmgr):
    """Registers events with core service controller.

    All the events will come to handle_event method of class instance
    registered in 'handler' field.

    :param drivers: Driver instances registered with the service agent
    :param rpcmgr: Instance to receive all the RPC messages from configurator
    module.

    Returns: None

    """

    event_id_list = [
        gen_cfg_const.EVENT_CONFIGURE_INTERFACES,
        gen_cfg_const.EVENT_CLEAR_INTERFACES,
        gen_cfg_const.EVENT_CONFIGURE_ROUTES,
        gen_cfg_const.EVENT_CLEAR_ROUTES,
        gen_cfg_const.EVENT_CONFIGURE_HEALTHMONITOR,
        gen_cfg_const.EVENT_CLEAR_HEALTHMONITOR,
        common_const.EVENT_PROCESS_BATCH
    ]
    events = []

    for event in event_id_list:
        events.append(
            nfp_event.Event(
                id=event,
                handler=GenericConfigEventHandler(sc, drivers, rpcmgr)))

    sc.register_events(events)


def load_drivers(conf):
    """Imports all the driver files.

    Returns: Dictionary of driver objects with a specified service type and
    vendor name

    """

    cutils = utils.ConfiguratorUtils(conf)
    drivers = cutils.load_drivers()

    for service_type, driver_name in drivers.iteritems():
        driver_obj = driver_name(conf=conf)
        drivers[service_type] = driver_obj
    LOG.info(_LI("Generic config agent loaded drivers drivers:"
                 "%(drivers)s"),
             {'drivers': drivers})
    return drivers


def register_service_agent(cm, sc, conf, rpcmgr):
    """Registers generic configuration service agent with configurator module.

    :param cm: Instance of configurator module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration
    :param rpcmgr: Instance containing RPC methods which are invoked by
    configurator module on corresponding RPC message arrival

    """

    service_type = gen_cfg_const.SERVICE_TYPE
    cm.register_service_agent(service_type, rpcmgr)


def init_agent(cm, sc, conf):
    """Initializes generic configuration agent.

    :param cm: Instance of configuration module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration

    """

    try:
        drivers = load_drivers(conf)
    except Exception as err:
        msg = ("Generic configuration agent failed to load service drivers."
               "Error:%s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Generic configuration agent loaded service"
               " drivers successfully.")
        LOG.debug(msg)

    rpcmgr = GenericConfigRpcManager(sc, conf)

    try:
        events_init(sc, drivers, rpcmgr)
    except Exception as err:
        msg = ("Generic configuration agent failed to initialize events. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Generic configuration agent initialized"
               " events successfully.")
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf, rpcmgr)
    except Exception as err:
        msg = ("Failed to register generic configuration agent with"
               " configurator module. %s" % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Generic configuration agent registered with configuration"
               " module successfully.")
        LOG.debug(msg)


def init_agent_complete(cm, sc, conf):
    msg = ("Initialization of generic configuration agent completed.")
    LOG.info(msg)
