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

from oslo_log import helpers as log_helpers

from gbpservice._i18n import _LI
from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.contrib.nfp.configurator.lib import demuxer
from gbpservice.contrib.nfp.configurator.lib import utils
from gbpservice.nfp.core import context as module_context
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import rpc


LOG = nfp_logging.getLogger(__name__)


class ConfiguratorRpcManager(object):
    """Implements procedure calls invoked by an REST server.

    Implements following RPC methods.
      - create_network_function_device_config
      - delete_network_function_device_config
      - update_network_function_device_config
      - create_network_function_config
      - delete_network_function_config
      - update_network_function_config
      - get_notifications
    Also implements local methods for supporting RPC methods

    """

    def __init__(self, sc, cm, conf, demuxer):
        self.sc = sc
        self.cm = cm
        self.conf = conf
        self.demuxer = demuxer

    def _get_service_agent_instance(self, service_type):
        """Provides service agent instance based on service type.

        :param service_type: firewall/vpn/loadbalancer/generic_config

        Returns: Instance of service agent for a given service type

        """

        return self.cm.sa_instances[service_type]

    def _invoke_service_agent(self, operation,
                              request_data, is_generic_config=False):
        """Maps and invokes an RPC call to a service agent method.

        Takes help of de-multiplexer to get service type and corresponding
        data and invokes the method of service agent. Service agent instance
        is identified based on the service type passed in the request data

        :param operation: Operation type - create/delete/update
        :param request_data: RPC data

        Returns: None

        """

        # Retrieves service type from RPC data
        service_type = self.demuxer.get_service_type(request_data)
        if (const.invalid_service_type == service_type):
            msg = ("Configurator received invalid service type %s." %
                   service_type)
            raise Exception(msg)

        # Retrieves service agent information from RPC data
        # Format of sa_req_list:
        # [{'method': <m1>, 'kwargs': <rpc_data1>}, {}, ... ]
        sa_req_list, service_type = self.demuxer.get_service_agent_info(
            operation, service_type,
            request_data, is_generic_config)
        if not sa_req_list:
            msg = ("Configurator received invalid data format for service"
                   " type %s. Data format: %r" % (service_type, request_data))
            raise Exception(msg)

        # Retrieves service agent instance using service type
        sa_instance = self._get_service_agent_instance(service_type)
        if not sa_instance:
            msg = ("Failed to find agent with service type %s." % service_type)
            raise Exception(msg)

        # Notification data list that needs to be returned after processing
        # RPC request. Format of notification data:
        # notification_data[
        #    {
        #        'receiver': <neutron/orchestrator>,
        #        'resource': <firewall/vpn/loadbalancer/healthmonitor/
        #                    routes/interfaces>,
        #        'method': <network_function_device_notification/
        #                  *aaS response RPC method name>,
        #        'kwargs': [{<data1>}, {data2}]
        #    },
        #    {
        #    }, ...
        # ]
        #
        # Initially, notification data will be empty and is populated
        # after processing each request data in the request data list
        notification_data = {}

        # Handover the request data list and notification data to the
        # identified service agent
        sa_instance.process_request(sa_req_list, notification_data)

    @log_helpers.log_method_call
    def create_network_function_device_config(self, context, request_data):
        """RPC method to configure a network service device.

        Configures a network service VM to facilitate network service
        operation. This RPC method is invoked by the configurator REST
        server. It configures a network service based on the configuration
        request specified in the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC CREATE NETWORK FUNCTION DEVICE CONFIG "
                         "for %(service_type)s, NFI: %(nfi)s, "
                         "NF_ID: %(nf_id)s"),
                     {'service_type': request_data['info']['service_type'],
                      'nfi': request_data['info']['context']['nfi_id'],
                      'nf_id': request_data['info']['context']['nf_id']})

            self._invoke_service_agent('create', request_data, True)
        except Exception as err:
            msg = ("Failed to create network device configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def delete_network_function_device_config(self, context, request_data):
        """RPC method to clear configuration of a network service device.

        Clears configuration of a network service VM. This RPC method is
        invoked by the configurator REST server. It clears configuration
        of a network service based on the configuration request specified
        in the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC DELETE NETWORK FUNCTION DEVICE CONFIG "
                         "for %(service_type)s, NFI: %(nfi)s, "
                         "NF_ID: %(nf_id)s"),
                     {'service_type': request_data['info']['service_type'],
                      'nfi': request_data['info']['context']['nfi_id'],
                      'nf_id': request_data['info']['context']['nf_id']})

            self._invoke_service_agent('delete', request_data, True)
        except Exception as err:
            msg = ("Failed to delete network device configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def update_network_function_device_config(self, context, request_data):
        """RPC method to update of configuration in a network service device.

        Updates configuration of a network service VM. This RPC method is
        invoked by the configurator REST server. It updates configuration
        of a network service based on the configuration request specified
        in the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC UPDATE NETWORK FUNCTION DEVICE CONFIG "
                         "for %(service_type)s, NFI: %(nfi)s, "
                         "NF_ID: %(nf_id)s"),
                     {'service_type': request_data['info']['service_type'],
                      'nfi': request_data['info']['context']['nfi_id'],
                      'nf_id': request_data['info']['context']['nf_id']})

            self._invoke_service_agent('update', request_data, True)
        except Exception as err:
            msg = ("Failed to update network device configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def create_network_function_config(self, context, request_data):
        """RPC method to configure a network service.

        Configures a network service specified in the request data. This
        RPC method is invoked by the configurator REST server. It configures
        a network service based on the configuration request specified in
        the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC CREATE NETWORK FUNCTION CONFIG "
                         "for %(service_type)s "),
                     {'service_type': request_data['info']['service_type']})

            self._invoke_service_agent('create', request_data)
        except Exception as err:
            msg = ("Failed to create network service configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def delete_network_function_config(self, context, request_data):
        """RPC method to clear configuration of a network service.

        Clears configuration of a network service. This RPC method is
        invoked by the configurator REST server. It clears configuration
        of a network service based on the configuration request specified
        in the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC DELETE NETWORK FUNCTION CONFIG "
                         "for %(service_type)s "),
                     {'service_type': request_data['info']['service_type']})

            self._invoke_service_agent('delete', request_data)
        except Exception as err:
            msg = ("Failed to delete network service configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def update_network_function_config(self, context, request_data):
        """RPC method to update of configuration in a network service.

        Updates configuration of a network service. This RPC method is
        invoked by the configurator REST server. It updates configuration
        of a network service based on the configuration request specified
        in the request_data argument.

        :param context: RPC context instance
        :param request_data: RPC data

        Returns: None

        """

        try:
            nfp_context = module_context.init()
            log_info = request_data.get('info')
            logging_context = log_info['context'].get('logging_context', {})
            nfp_context['log_context'] = logging_context
            LOG.info(_LI("Received RPC UPDATE NETWORK FUNCTION CONFIG "
                         "for %(service_type)s "),
                     {'service_type': request_data['info']['service_type']})

            self._invoke_service_agent('update', request_data)
        except Exception as err:
            msg = ("Failed to update network service configuration. %s" %
                   str(err).capitalize())
            LOG.error(msg)

    @log_helpers.log_method_call
    def get_notifications(self, context):
        """RPC method to get all notifications published by configurator.

        Gets all the notifications from the notifications from notification
        queue and sends to configurator agent

        :param context: RPC context instance

        Returns: notification_data

        """
        module_context.init()
        LOG.info(_LI("Received RPC GET NOTIFICATIONS "))
        events = self.sc.get_stashed_events()
        notifications = []
        for event in events:
            notification = event.data
            msg = ("Notification Data: %r" % notification)
            notifications.append(notification)
            LOG.info(msg)
        return notifications


class ConfiguratorModule(object):
    """Implements configurator module APIs.

    Implements methods which are either invoked by registered service
    agents or by the configurator global methods. The methods invoked
    by configurator global methods interface with service agents.

    """

    def __init__(self, sc):
        self.sa_instances = {}
        self.imported_sas = []

    def register_service_agent(self, service_type, service_agent):
        """Stores service agent object.

        :param service_type: Type of service - firewall/vpn/loadbalancer/
        generic_config.
        :param service_agent: Instance of service agent class.

        Returns: Nothing

        """

        if service_type not in self.sa_instances:

            msg = ("Configurator registered service agent of type %s." %
                   service_type)
            LOG.info(msg)
        else:
            msg = ("Identified duplicate registration with service type %s." %
                   service_type)
            LOG.warn(msg)

        # Register the service agent irrespective of previous registration
        self.sa_instances.update({service_type: service_agent})

    def init_service_agents(self, sc, conf):
        """Invokes service agent initialization method.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        Returns: None

        """

        for agent in self.imported_sas:
            try:
                agent.init_agent(self, sc, conf)
            except AttributeError as attr_err:
                LOG.error(agent.__dict__)
                raise AttributeError(agent.__file__ + ': ' + str(attr_err))

    def init_service_agents_complete(self, sc, conf):
        """Invokes service agent initialization complete method.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        Returns: None

        """

        for agent in self.imported_sas:
            try:
                agent.init_agent_complete(self, sc, conf)
            except AttributeError as attr_err:
                LOG.error(agent.__dict__)
                raise AttributeError(agent.__file__ + ': ' + str(attr_err))


def init_rpc(sc, cm, conf, demuxer):
    """Initializes oslo RPC client.

    Creates RPC manager object and registers the configurator's RPC
    agent object with core service controller.

    :param sc: Service Controller object that is used for interfacing
    with core service controller.
    :param cm: Configurator module object that is used for accessing
    ConfiguratorModule class methods.
    :param conf: Configuration object that is used for configuration
    parameter access.
    :param demuxer: De-multiplexer object that is used for accessing
    ServiceAgentDemuxer class methods.

    Returns: None

    """

    # Initializes RPC client
    rpc_mgr = ConfiguratorRpcManager(sc, cm, conf, demuxer)
    configurator_agent = rpc.RpcAgent(sc,
                                      topic=const.CONFIGURATOR_RPC_TOPIC,
                                      manager=rpc_mgr)

    # Registers RPC client object with core service controller
    sc.register_rpc_agents([configurator_agent])


def get_configurator_module_instance(sc, conf):
    """ Provides ConfiguratorModule class object and loads service agents.

    Returns: Instance of ConfiguratorModule class

    """

    cm = ConfiguratorModule(sc)
    conf_utils = utils.ConfiguratorUtils(conf)

    # Loads all the service agents under AGENT_PKG module path
    cm.imported_sas = conf_utils.load_agents(const.AGENTS_PKG)
    msg = ("Configurator loaded service agents from %s location."
           % (cm.imported_sas))
    LOG.info(msg)
    return cm


def nfp_module_init(sc, conf):
    """Initializes configurator module.

    Creates de-multiplexer object and invokes all the agent entry point
    functions. Initializes oslo RPC client for receiving messages from
    REST server. Exceptions are raised to parent function for all types
    of failures.

    :param sc: Service Controller object that is used for interfacing
    with core service controller.
    :param conf: Configuration object that is used for configuration
    parameter access.

    Returns: None
    Raises: Generic exception including error message

    """

    # Create configurator module and de-multiplexer objects
    try:
        cm = get_configurator_module_instance(sc, conf)
        demuxer_instance = demuxer.ServiceAgentDemuxer()
    except Exception as err:
        msg = ("Failed to initialize configurator de-multiplexer. %s."
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Initialized configurator de-multiplexer.")
        LOG.info(msg)

    # Initialize all the pre-loaded service agents
    try:
        cm.init_service_agents(sc, conf)
    except Exception as err:
        msg = ("Failed to initialize configurator agent modules. %s."
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Initialized configurator agents.")
        LOG.info(msg)

    # Initialize RPC client for receiving messages from REST server
    try:
        init_rpc(sc, cm, conf, demuxer_instance)
    except Exception as err:
        msg = ("Failed to initialize configurator RPC with topic %s. %s."
               % (const.CONFIGURATOR_RPC_TOPIC, str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Initialized configurator RPC with topic %s."
               % const.CONFIGURATOR_RPC_TOPIC)
        LOG.debug(msg)


def nfp_module_post_init(sc, conf):
    """Invokes service agent's initialization complete methods.

    :param sc: Service Controller object that is used for interfacing
    with core service controller.
    :param conf: Configuration object that is used for configuration
    parameter access.

    Returns: None
    Raises: Generic exception including error message

    """

    try:
        cm = get_configurator_module_instance(sc, conf)
        cm.init_service_agents_complete(sc, conf)
    except Exception as err:
        msg = ("Failed to trigger initialization complete for configurator"
               " agent modules. %s." % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Initialization of configurator agent modules completed.")
        LOG.info(msg)
