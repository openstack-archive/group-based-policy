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


import os

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.drivers.base import base_driver
from gbpservice.contrib.nfp.configurator.lib import data_filter
from gbpservice.contrib.nfp.configurator.lib import utils
from gbpservice.contrib.nfp.configurator.lib import vpn_constants as const
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

from neutron._i18n import _LI
import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)


class VpnaasRpcSender(data_filter.Filter):
    """
    Implements VPNaas response path to Neutron plugin.

    Methods of this class are invoked by the VPNaasEventHandler class
    for sending response from driver to the VPNaas Neutron plugin.

    """
    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, sc):
        self._sc = sc
        self._notify = agent_base.AgentBaseNotification(sc)
        super(VpnaasRpcSender, self).__init__(None, None)

    def get_vpn_services(self, context, ids=None, filters=None):
        """Gets list of vpnservices for tenant.
        :param context: dictionary which holds details of vpn service type like
            For IPSEC connections :
                List of vpnservices
                lIst of ipsec connections
                ike policy & ipsec policy.
        :param ids: based on which the filter library extracts the data.
        :param filter: based on which the filter library extracts the data.

        Returns: Dictionary of vpn service type which matches with the filters.
        """
        LOG.info(_LI("Sending RPC for GET VPN SERVICES with %(filters)s "),
                 {'filters': filters})
        return self.call(
            context,
            self.make_msg('get_vpn_services', ids=ids, filters=filters))

    def get_vpn_servicecontext(self, context, filters=None):
        """Get list of vpnservice context on this host.
        :param context: dictionary which holds details of vpn service type like
            For IPSEC connections :
                List of vpnservices
                lIst of ipsec connections
                ike policy & ipsec policy.
        :param filter: based on which the filter library extracts the data
        from context dictionary.

        Returns: dictionary of vpnservice
        """
        LOG.info(_LI("Sending RPC for GET VPN SERVICECONTEXT with "
                     "Filters:%(filters)s "),
                 {'filters': filters})
        return self.call(
            context,
            self.make_msg(
                'get_vpn_servicecontext', filters=filters))

    def get_ipsec_conns(self, context, filters):
        """
        Get list of ipsec conns with filters
        specified.
        """
        LOG.info(_LI("Sending RPC for GET IPSEC CONNS with Filters:"
                     "%(filters)s "),
                 {'filters': filters})
        return self.call(
            context,
            self.make_msg(
                'get_ipsec_conns',
                filters=filters))

    def update_status(self, context, status):
        """Update local status.

        This method call updates status attribute of
        VPNServices.
        """
        msg = {'info': {'service_type': const.SERVICE_TYPE,
                        'context': context['agent_info']['context']},
               'notification': [{
                   'resource': context['agent_info']['resource'],
                   'data': {'status': status,
                            'notification_type': (
                                'update_status')}}]
               }
        LOG.info(_LI("Sending Notification 'Update Status' with "
                     "status:%(status)s "),
                 {'status': status})
        self._notify._notification(msg)

    def ipsec_site_conn_deleted(self, context, resource_id):
        """ Notify VPNaaS plugin about delete of ipsec-site-conn """

        msg = {'info': {'service_type': const.SERVICE_TYPE,
                        'context': context['agent_info']['context']},
               'notification': [{
                   'resource': context['agent_info']['resource'],
                   'data': {'resource_id': resource_id,
                            'notification_type': (
                                'ipsec_site_conn_deleted')}}]
               }
        LOG.info(_LI("Sending Notification 'Ipsec Site Conn Deleted' "
                     "for resource:%(resource_id)s "),
                 {'resource_id': resource_id})
        self._notify._notification(msg)


class VPNaasRpcManager(agent_base.AgentBaseRPCManager):
    """
    Implements VPNaasRpcManager class which receives requests
        from Configurator to Agent.

    Methods of this class are invoked by the configurator. Events are
    created according to the requests received and enqueued to worker queues.

    """

    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        """Instantiates child and parent class objects.

        Passes the instances of core service controller and oslo configuration
        to parent instance in order to provide event enqueue facility for batch
        processing event.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        """

        super(VPNaasRpcManager, self).__init__(sc, conf)

    def vpnservice_updated(self, context, **resource_data):
        """Registers the VPNaas plugin events to update the vpn configurations.

        :param context: dictionary, confined to the specific service type.
        :param resource_data: dictionary, confined to the specific
               operation type.

        Returns: None
        """

        LOG.info(_LI("Received request 'VPN Service Updated'."
                     "for API '%(api)s'"),
                 {'api': resource_data.get('reason', '')})
        arg_dict = {'context': context,
                    'resource_data': resource_data}
        # Serializing the event because simultaneous configure
        # requests overrides the same crypto-map in the service VM
        # which results in corrupting the crypto-map

        resource_type = resource_data.get('rsrc_type')
        if resource_type and resource_type.lower() == 'ipsec_site_connection':
            ev = self.sc.new_event(id='VPNSERVICE_UPDATED',
                                   key=resource_data['resource']['id'],
                                   data=arg_dict,
                                   serialize=True,
                                   binding_key=resource_data[
                                       'resource']['vpnservice_id'])
            msg = "serializing event: %s" % ('VPNSERVICE_UPDATED')
            LOG.debug(msg)
        else:
            ev = self.sc.new_event(id='VPNSERVICE_UPDATED', data=arg_dict)

        self.sc.post_event(ev)


class VPNaasEventHandler(nfp_api.NfpEventHandler):
    """
    Handler class to invoke the vpn driver methods.
    For every event that gets invoked from worker process lands over here
    to make a call to the driver methods.
    """

    def __init__(self, sc, drivers):
        """ Instantiates class object.

        :param sc: Service Controller object that is used to communicate
        with process model core file.
        :param drivers: dictionary of driver name to object mapping

        """
        self._sc = sc
        self._drivers = drivers
        self._plugin_rpc = VpnaasRpcSender(self._sc)

    def _get_driver(self, service_vendor, service_feature):

        driver_id = const.SERVICE_TYPE + service_vendor + service_feature
        return self._drivers[driver_id]

    def handle_event(self, ev):
        """
        Demultiplexes the vpn request to appropriate  driver methods.

        :param ev: event object sent from the process model.

        Returns: None
        """
        if ev.id == 'VPN_SYNC':
            self._sc.poll_event(ev)

        if ev.id == 'VPNSERVICE_UPDATED':
            try:
                msg = ("Worker process with ID: %s starting "
                       "to handle task: %s of topic: %s. "
                       % (os.getpid(),
                          ev.id, const.VPN_GENERIC_CONFIG_RPC_TOPIC))
                LOG.debug(msg)
                agent_info = ev.data['context']['agent_info']
                service_vendor = agent_info['service_vendor']
                service_feature = agent_info['service_feature']
                driver = self._get_driver(service_vendor, service_feature)
                LOG.info(_LI("Invoking driver with service vendor:"
                             "%(service_vendor)s "),
                         {'service_vendor': service_vendor})
                setattr(VPNaasEventHandler, "service_driver", driver)
                self._vpnservice_updated(ev, driver)
            except Exception as err:
                msg = ("Failed to perform the operation: %s. %s"
                       % (ev.id, str(err).capitalize()))
                LOG.error(msg)
            finally:
                self._sc.event_complete(ev)

    def _vpnservice_updated(self, ev, driver):
        """
        Makes call to the respective operation method of vpn driver.

        :param ev: event object sent from the process model.
        :param driver: vpn driver class object.

        Returns: None.
        """
        context = ev.data.get('context')
        resource_data = ev.data.get('resource_data')
        msg = "Vpn service updated from server side"
        LOG.info(msg)

        try:
            driver.vpnservice_updated(context, resource_data)

            if 'ipsec_site_conns' in context['service_info']:
                for item in context['service_info']['ipsec_site_conns']:
                    if item['id'] == resource_data['resource']['id'] and (
                            resource_data['reason'] == 'create'):
                        item['status'] = 'INIT'
                        arg_dict = {'context': context,
                                    'resource_data': resource_data}
                        ev1 = self._sc.new_event(id='VPN_SYNC',
                                                 key='VPN_SYNC', data=arg_dict)
                        self._sc.post_event(ev1)
                    break
        except Exception as err:
            msg = ("Failed to update VPN service. %s"
                   % str(err).capitalize())
            LOG.error(msg)
        reason = resource_data.get('reason')
        rsrc = resource_data.get('rsrc_type')

        if (reason == 'delete' and rsrc == 'ipsec_site_connection'):
            conn = resource_data['resource']
            resource_id = conn['id']
            self._plugin_rpc.ipsec_site_conn_deleted(context,
                                                     resource_id=resource_id)

    def _get_service_vendor(self, vpn_svc):
        """
        Extracts the vendor from the description.
        :param vpn_svc: vpn service operation type dictionary,
        which it gets from filter library

        Returns: None
        """
        svc_desc = vpn_svc['description']
        tokens = svc_desc.split(';')
        vendor = tokens[5].split('=')[1]
        return vendor

    def _sync_ipsec_conns(self, context, svc_context):
        """
        Gets the status of the vpn service.
        :param context: Dictionary of the vpn service type.
        :param vendor: vendor name
        :param svc_context: vpn service operation type dictionary,
        which it gets filter library

        Returns: None
        """
        try:
            return self.service_driver.check_status(context, svc_context)
        except Exception as err:
            msg = ("Failed to sync ipsec connection information. %s."
                   % str(err).capitalize())
            LOG.error(msg)

    @nfp_api.poll_event_desc(event='VPN_SYNC', spacing=10)
    def sync(self, ev):
        """Periodically updates the status of vpn service, whether the
        tunnel is UP or DOWN.

        :param context: Dictionary of the vpn service type.

        Returns: None
        """

        context = ev.data.get('context')
        s2s_contexts = self._plugin_rpc.get_vpn_servicecontext(context)
        state = self._sync_ipsec_conns(context, s2s_contexts[0])
        if state in {const.STATE_ACTIVE,
                     const.STATE_ERROR}:
            return {'poll': False}


def events_init(sc, drivers):
    """Registers events with core service controller.

    All the events will come to handle_event method of class instance
    registered in 'handler' field.

    :param sc: Object of Service Controller from the process model to regiters
    the different events
    :param drivers: Driver instance registered with the service agent

    Returns: None
    """
    evs = [
        nfp_event.Event(id='VPNSERVICE_UPDATED',
                        handler=VPNaasEventHandler(sc, drivers)),
        nfp_event.Event(id='VPN_SYNC',
                        handler=VPNaasEventHandler(sc, drivers))]

    sc.register_events(evs)


def load_drivers(sc, conf):
    """Loads the drivers dynamically.

    Loads the drivers that register with the agents.
    :param sc: Object of the Service Controller class from core
    service controller.

    Returns: dictionary of instances of the respective driver classes.
    """

    ld = utils.ConfiguratorUtils(conf)
    drivers = ld.load_drivers(const.SERVICE_TYPE)

    for service_type, driver_name in drivers.iteritems():
        driver_obj = driver_name(conf=conf)
        drivers[service_type] = driver_obj

    return drivers


def register_service_agent(cm, sc, conf):
    """Registers the agents with Cofigurator module.
    Puts all the agents into the dictionary with their service types.
    :prarm cm: Configurator module's object to communicate back and forth
    :param sc: Object of the Service Controller class from core
    service controller.
    :param conf: Object of oslo configurator passed from the core service
    controller

    Returns: None
    """

    rpcmgr = VPNaasRpcManager(conf, sc)
    cm.register_service_agent(const.SERVICE_TYPE, rpcmgr)


def init_agent(cm, sc, conf):
    """Loads the drivers and registers the agents.
    Loads the dynamicaaly both the drivers and agents, registers the agents
    with their service types.

    :prarm cm: Configurator module's object to communicate back and forth
    :param sc: Object of the Service Controller class from core
    service controller.
    :param conf: Object of oslo configurator passed from the core service
    controller

    Returns: None

    """
    try:
        drivers = load_drivers(sc, conf)
    except Exception as err:
        msg = ("VPNaas failed to load drivers. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = "VPNaas loaded drivers successfully."
        LOG.debug(msg)

    try:
        events_init(sc, drivers)
    except Exception as err:
        msg = ("VPNaas Events initialization unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = "VPNaas Events initialization successful."
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf)
        bdobj = base_driver.BaseDriver(conf)
        bdobj.register_agent_object_with_driver('agent', VpnaasRpcSender(sc))
    except Exception as err:
        msg = ("VPNaas service agent registration unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = "VPNaas service agent registration successful."
        LOG.debug(msg)

    msg = "VPN as a Service Module Initialized."
    LOG.info(msg)


def init_agent_complete(cm, sc, conf):
    """
    Initializes periodic tasks.
    """
    msg = " vpn agent init complete"
    LOG.info(msg)
