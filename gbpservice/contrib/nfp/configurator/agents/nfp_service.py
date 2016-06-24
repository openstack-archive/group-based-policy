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
import oslo_messaging as messaging

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.lib import (
                                nfp_service_constants as const)
from gbpservice.contrib.nfp.configurator.lib import utils as load_driver
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


class ConfigScriptRpcManager(agent_base.AgentBaseRPCManager):
    """ Implements ConfigScriptRpcManager class which receives requests
        from Configurator module.

    Methods of this class are invoked by the configurator. Events are
    created according to the requests received and enqueued to worker queues.

    """

    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, sc, conf):
        """Instantiates child and parent class objects.

        :param sc: Service Controller object that is used to communicate
        with process model core file.
        :param conf: Configuration object that is used for configuration
        parameter access.

        """

        super(ConfigScriptRpcManager, self).__init__(sc, conf)

    def run_nfp_service(self, context, resource_data):
        """ Receives request to execute config script.

        :param context: RPC context
        :param kwargs: Contains configuration script and request information

        """

        msg = ("ConfigScriptRpcManager received Create Heat request.")
        LOG.debug(msg)

        arg_dict = {'context': context,
                    'resource_data': resource_data}
        ev = self.sc.new_event(id=const.CREATE_NFP_SERVICE_EVENT,
                               data=arg_dict, key=None)
        self.sc.post_event(ev)


class ConfigScriptEventHandler(agent_base.AgentBaseEventHandler):
    """ Handler class which invokes nfp_service driver methods

    Worker processes dequeue the worker queues and invokes the
    appropriate handler class methods for ConfigScript methods.

    """

    def __init__(self, sc, drivers, rpcmgr):
        """ Initializes parent and child class objects.

        :param sc: Service Controller object that is used to communicate
        with process model.
        :param drivers: Dictionary of driver name to object mapping
        :param rpcmgr: ConfigScriptRpcManager class object

        """

        super(ConfigScriptEventHandler, self).__init__(sc, drivers, rpcmgr)
        self.sc = sc
        self.drivers = drivers
        self.rpcmgr = rpcmgr

    def _get_driver(self):
        """ Retrieves driver object given the service type.

        """

        driver_id = const.SERVICE_TYPE
        return self.drivers[driver_id]

    def handle_event(self, ev):
        """ Demultiplexes the nfp_service request to appropriate
        driver methods.

        :param ev: Event object sent from process model event handler

        """

        try:
            agent_info = ev.data['context']
            notification_context = agent_info['context']
            resource = agent_info['resource']
            resource_data = ev.data['resource_data']

            msg = ("Worker process with ID: %s starting to "
                   "handle task: %s of type ConfigScript. "
                   % (os.getpid(), ev.id))
            LOG.debug(msg)

            driver = self._get_driver()
            self.method = getattr(driver, "run_%s" % resource)

            result = self.method(notification_context, resource_data)
        except Exception as err:
            result = const.ERROR_RESULT
            msg = ("Failed to handle event: %s. %s"
                   % (ev.id, str(err).capitalize()))
            LOG.error(msg)
        finally:
            del agent_info['notification_data']
            del agent_info['service_vendor']
            service_type = agent_info.pop('resource_type')

            if result in const.UNHANDLED_RESULT:
                data = {'status_code': const.UNHANDLED_RESULT}
            else:
                data = {'status_code': const.FAILURE,
                        'error_msg': result}

            msg = {'info': {'service_type': service_type,
                            'context': notification_context},
                   'notification': [{'resource': resource,
                                     'data': data}]
                   }

            self.notify._notification(msg)


def events_init(sc, drivers, rpcmgr):
    """Registers events with core service controller.

    All the events will come to handle_event method of class instance
    registered in 'handler' field.

    :param drivers: Driver instances registered with the service agent
    :param rpcmgr: Instance to receive all the RPC messages from configurator
    module.

    Returns: None

    """

    event = nfp_event.Event(
        id=const.CREATE_NFP_SERVICE_EVENT,
        handler=ConfigScriptEventHandler(sc, drivers, rpcmgr))
    sc.register_events([event])


def load_drivers(conf):
    """Imports all the driver files corresponding to this agent.

    Returns: Dictionary of driver objects with a specified service type and
    vendor name

    """

    ld = load_driver.ConfiguratorUtils()
    drivers = ld.load_drivers(const.DRIVERS_DIR)

    for service_type, driver_name in drivers.iteritems():
        driver_obj = driver_name(conf=conf)
        drivers[service_type] = driver_obj

    return drivers


def register_service_agent(cm, sc, conf, rpcmgr):
    """Registers ConfigScript service agent with configurator module.

    :param cm: Instance of configurator module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration
    :param rpcmgr: Instance containing RPC methods which are invoked by
    configurator module on corresponding RPC message arrival

    """

    service_type = const.SERVICE_TYPE
    cm.register_service_agent(service_type, rpcmgr)


def init_agent(cm, sc, conf):
    """Initializes Config Script agent.

    :param cm: Instance of configuration module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration

    """

    try:
        drivers = load_drivers(conf)
    except Exception as err:
        msg = ("Config Script failed to load drivers. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Config Script loaded drivers successfully.")
        LOG.debug(msg)

    rpcmgr = ConfigScriptRpcManager(sc, conf)
    try:
        events_init(sc, drivers, rpcmgr)
    except Exception as err:
        msg = ("Config Script Events initialization unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Config Script Events initialization successful.")
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf, rpcmgr)
    except Exception as err:
        msg = ("Config Script service agent registration unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Config Script service agent registration successful.")
        LOG.debug(msg)

    msg = ("ConfigScript as a Service Module Initialized.")
    LOG.info(msg)


def init_agent_complete(cm, sc, conf):
    """ Initializes periodic tasks

    """

    msg = (" Config Script agent init complete")
    LOG.info(msg)
