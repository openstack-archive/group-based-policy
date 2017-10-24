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

import operator
import os
import oslo_messaging as messaging
import requests
import six

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.lib import constants as common_const
from gbpservice.contrib.nfp.configurator.lib import fw_constants as const
from gbpservice.contrib.nfp.configurator.lib import utils as load_driver
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

from oslo_serialization import jsonutils

LOG = nfp_logging.getLogger(__name__)


class FwaasRpcSender(agent_base.AgentBaseEventHandler):
    """ Implements Fwaas response path to Neutron plugin.

    Methods of this class are invoked by the FwaasEventHandler class
    for sending response from driver to the Fwaas Neutron plugin.

    """

    def __init__(self, sc, host, drivers, rpcmgr):
        super(FwaasRpcSender, self).__init__(sc, drivers, rpcmgr)
        self.host = host

    def set_firewall_status(self, agent_info,
                            firewall_id, status, firewall=None):
        """ Enqueues the response from FwaaS operation to neutron plugin.

        :param context: Neutron context
        :param firewall_id: id of firewall resource
        :param status: ACTIVE/ ERROR

        """

        msg = {'info': {'service_type': const.SERVICE_TYPE,
                        'context': agent_info['context']},
               'notification': [{
                   'resource': agent_info['resource'],
                   'data': {'firewall_id': firewall_id,
                            'host': self.host,
                            'status': status,
                            'notification_type': (
                                'set_firewall_status')}}]
               }
        LOG.info("Sending Notification 'Set Firewall Status' to "
                 "Orchestrator for firewall: %(fw_id)s with status:"
                 "%(status)s",
                 {'fw_id': firewall_id,
                  'status': status})
        self.notify._notification(msg)

    def firewall_deleted(self, agent_info, firewall_id, firewall=None):
        """ Enqueues the response from FwaaS operation to neutron plugin.

        :param context: Neutron context
        :param firewall_id: id of firewall resource

        """

        msg = {'info': {'service_type': const.SERVICE_TYPE,
                        'context': agent_info['context']},
               'notification': [{
                   'resource': agent_info['resource'],
                   'data': {'firewall_id': firewall_id,
                            'host': self.host,
                            'notification_type': (
                                'firewall_deleted')}}]
               }
        LOG.info("Sending Notification 'Firewall Deleted' to "
                 "Orchestrator for firewall: %(fw_id)s ",
                 {'fw_id': firewall_id})
        self.notify._notification(msg)


class FWaasRpcManager(agent_base.AgentBaseRPCManager):
    """ Implements FWaasRpcManager class which receives requests
        from Configurator to Agent.

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

        super(FWaasRpcManager, self).__init__(sc, conf)

    def _create_event(self, context, firewall, host, method):
        """ Creates and enqueues the events to the worker queues.

        :param context: Neutron context
        :param firewall: Firewall resource object from neutron fwaas plugin
        :param host: Name of the host machine
        :param method: CREATE_FIREWALL/UPDATE_FIREWALL/DELETE_FIREWALL

        """

        # To solve the huge data issue with firewalls,
        # especially with 250 firewall rule test which
        # gets multipled with each consumer in the chain.
        # Even the zipped data is huge and cannot be sent
        # over pipe. Writing it to file here and event handler
        # will read it from file and process further.

        filename = "/tmp/" + firewall['id']
        with open(filename, 'w') as f:
            f.write(jsonutils.dumps(firewall))

        arg_dict = {'context': context,
                    'firewall': {'file_path': filename},
                    'host': host}
        # REVISIT(mak): How to send large data ?
        # New API required to send over unix sockert ?
        context['service_info'] = {}

        # ev = self.sc.new_event(id=method, data={}, key=None)
        ev = self.sc.new_event(id=method, data=arg_dict, key=None)
        self.sc.post_event(ev)

    def create_firewall(self, context, firewall, host):
        """ Receives request to create firewall from configurator

        """

        LOG.info("Received request 'Create Firewall'.")
        self._create_event(context, firewall,
                           host, const.FIREWALL_CREATE_EVENT)

    def update_firewall(self, context, firewall, host):
        """ Receives request to update firewall from configurator

        """
        LOG.info("Received request 'Update Firewall'.")
        self._create_event(context, firewall,
                           host, const.FIREWALL_UPDATE_EVENT)

    def delete_firewall(self, context, firewall, host):
        """ Receives request to delete firewall from configurator

        """
        LOG.info("Received request 'Delete Firewall'.")
        self._create_event(context, firewall,
                           host, const.FIREWALL_DELETE_EVENT)


class FWaasEventHandler(nfp_api.NfpEventHandler):
    """ Handler class which invokes firewall driver methods

    Worker processes dequeue the worker queues and invokes the
    appropriate handler class methods for Fwaas methods.

    """

    def __init__(self, sc, drivers, rpcmgr, conf):
        """ Instantiates class object.

        :param sc: Service Controller object that is used to communicate
        with process model core file.
        :param drivers: dictionary of driver name to object mapping
        :param rpcmgr: FwaasRpcManager class object

        """

        self.sc = sc
        self.conf = conf
        self.drivers = drivers
        self.host = self.conf.host
        self.rpcmgr = rpcmgr
        self.plugin_rpc = FwaasRpcSender(sc, self.host,
                                         self.drivers, self.rpcmgr)

    def _get_driver(self, service_vendor, service_feature):
        """ Retrieves driver object given the service type

        """

        driver_id = const.SERVICE_TYPE + service_vendor + service_feature
        return self.drivers[driver_id]

    def _is_firewall_rule_exists(self, fw):
        """ Checks if firewall rules are present in the request data

        :param fw: Firewall resource object

        """

        if not fw['firewall_rule_list']:
            return False
        else:
            return True

    def handle_event(self, ev):
        """ Demultiplexes the firewall request to appropriate
        driver methods.

        :param ev: event object sent from process model event handler

        """

        try:
            msg = ("Handling event %s" % (ev.id))
            LOG.info(msg)

            # The context here in ev.data is the neutron context that was
            # renamed to context in the agent_base. This erstwhile
            # neutron context contains the agent info which in turn contains
            # the API context alongside other relevant information like
            # service vendor and type. Agent info is constructed inside
            # the demuxer library.

            if ev.data['firewall'].get('file_path', None):
                filename = ev.data['firewall']['file_path']
                string = str()
                with open(filename, 'r') as f:
                    string = f.read()
                ev.data['firewall'] = jsonutils.loads(string)
                try:
                    os.remove(filename)
                except Exception as e:
                    msg = ("Exception while removing the file %r, "
                           "with error: %r" % (filename, e))
                    LOG.error(msg)

            agent_info = ev.data['context']['agent_info']
            service_vendor = agent_info['service_vendor']
            service_feature = agent_info.get('service_feature', '')
            driver = self._get_driver(service_vendor, service_feature)
            LOG.info("Invoking driver with service vendor:"
                     "%(service_vendor)s ",
                     {'service_vendor': service_vendor})
            self.method = getattr(driver, "%s" % (ev.id.lower()))
            self.invoke_driver_for_plugin_api(ev)
            msg = ("Handled event %s successfully" % (ev.id))
            LOG.info(msg)
        except Exception as err:
            msg = ("Failed handling event: %s. Reason %s"
                   % (ev.id, str(err).capitalize()))
            LOG.error(msg)

    def _remove_duplicate_fw_rules(self, rules):
        """ Removes duplicate rules from the rules list. """
        # 'description' filter field needs to be added if required
        filter_keys = ['action', 'destination_ip_address', 'destination_port',
                       'enabled', 'ip_version', 'protocol',
                       'source_ip_address', 'source_port', 'shared']
        filter_rules = []
        for rule in rules:
            filter_rules.append({k: rule[k] for k in filter_keys})

        unique_rules = [dict(tupleized) for tupleized in set(
            tuple(rule.items()) for rule in filter_rules)]
        result = []
        for d1 in unique_rules:
            for d2 in rules:
                if d1.viewitems() <= d2.viewitems():
                    result.append(d2)
                    break
        result.sort(key=operator.itemgetter('position'))
        for index, x in enumerate(result):
            x['position'] = index + 1
        return result

    def invoke_driver_for_plugin_api(self, ev):
        """ Invokes the appropriate driver methods

        :param ev: event object sent from process model event handler

        """

        context = ev.data['context']
        agent_info = context.get('agent_info')
        firewall = ev.data.get('firewall')
        host = ev.data.get('host')
        firewall['firewall_rule_list'] = self._remove_duplicate_fw_rules(
            firewall['firewall_rule_list'])

        if ev.id == const.FIREWALL_CREATE_EVENT:
            if not self._is_firewall_rule_exists(firewall):
                msg = ("Firewall rule list is empty, setting Firewall "
                       "status to ACTIVE %s" % (firewall))
                LOG.info(msg)
                return self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'],
                    common_const.STATUS_ACTIVE, firewall)
            # Added to handle in service vm agents. VM agent will add
            # default DROP rule.
            # if not self._is_firewall_rule_exists(firewall):
            #     self.plugin_rpc.set_firewall_status(
            #         context, firewall['id'], const.STATUS_ACTIVE)
            try:
                status = self.method(context, firewall, host)
            except Exception as err:
                self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'], common_const.STATUS_ERROR)
                msg = ("Failed to configure Firewall and status is "
                       "changed to ERROR. %s." % str(err).capitalize())
                LOG.error(msg)
            else:
                self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'], status, firewall)
                msg = ("Configured Firewall and status set to %s" % status)
                LOG.info(msg)

        elif ev.id == const.FIREWALL_DELETE_EVENT:
            if not self._is_firewall_rule_exists(firewall):
                msg = ("Firewall rule list is empty, sending firewall deleted "
                       "status to plugin %s" % (firewall))
                LOG.info(msg)
                return self.plugin_rpc.firewall_deleted(
                    agent_info, firewall['id'], firewall)
            try:
                status = self.method(context, firewall, host)
            except requests.ConnectionError:
                # REVISIT(VIKASH): It can't be correct everytime
                msg = ("There is a connection error for firewall %r of "
                       "tenant %r. Assuming either there is serious "
                       "issue with VM or data path is completely "
                       "broken. For now marking that as delete."
                       % (firewall['id'], firewall['tenant_id']))
                LOG.warning(msg)
                self.plugin_rpc.firewall_deleted(
                    agent_info, firewall['id'], firewall)

            except Exception as err:
                # REVISIT(VIKASH): Is it correct to raise ? As the subsequent
                # attempt to clean will only re-raise the last one.And it
                # can go on and on and may not be ever recovered.
                self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'], common_const.STATUS_ERROR)
                msg = ("Failed to delete Firewall and status is "
                       "changed to ERROR. %s." % str(err).capitalize())
                LOG.error(msg)
                # raise(err)
            else:
                if status == common_const.STATUS_ERROR:
                    self.plugin_rpc.set_firewall_status(
                        agent_info, firewall['id'], status)
                else:
                    msg = ("Firewall %r deleted of tenant: %r" % (
                           firewall['id'], firewall['tenant_id']))
                    LOG.info(msg)
                    self.plugin_rpc.firewall_deleted(
                        agent_info, firewall['id'], firewall)

        elif ev.id == const.FIREWALL_UPDATE_EVENT:
            if not self._is_firewall_rule_exists(firewall):
                return self.plugin_rpc.set_firewall_status(
                    agent_info,
                    common_const.STATUS_ACTIVE, firewall)
            try:
                status = self.method(context, firewall, host)
            except Exception as err:
                self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'], common_const.STATUS_ERROR)
                msg = ("Failed to update Firewall and status is "
                       "changed to ERROR. %s." % str(err).capitalize())
                LOG.error(msg)
            else:
                self.plugin_rpc.set_firewall_status(
                    agent_info, firewall['id'], status, firewall)
                msg = ("Updated Firewall and status set to %s" % status)
                LOG.info(msg)
        else:
            msg = ("Wrong call to Fwaas event handler.")
            raise Exception(msg)


def events_init(sc, drivers, rpcmgr, conf):
    """Registers events with core service controller.

    All the events will come to handle_event method of class instance
    registered in 'handler' field.

    :param drivers: Driver instances registered with the service agent
    :param rpcmgr: Instance to receive all the RPC messages from configurator
    module.

    Returns: None

    """

    event_id_list = [const.FIREWALL_CREATE_EVENT,
                     const.FIREWALL_UPDATE_EVENT,
                     const.FIREWALL_DELETE_EVENT]
    evs = []
    for event in event_id_list:
        evs.append(nfp_event.Event(id=event, handler=FWaasEventHandler(
            sc, drivers, rpcmgr, conf)))
    sc.register_events(evs)


def load_drivers(conf):
    """Imports all the driver files corresponding to this agent.

    Returns: Dictionary of driver objects with a specified service type and
    vendor name

    """

    ld = load_driver.ConfiguratorUtils(conf)
    drivers = ld.load_drivers(const.SERVICE_TYPE)

    for service_type, driver_name in six.iteritems(drivers):
        driver_obj = driver_name(conf=conf)
        drivers[service_type] = driver_obj

    LOG.info("Firewall loaded drivers:%(drivers)s",
             {'drivers': drivers})
    return drivers


def register_service_agent(cm, sc, conf, rpcmgr):
    """Registers Fwaas service agent with configurator module.

    :param cm: Instance of configurator module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration
    :param rpcmgr: Instance containing RPC methods which are invoked by
    configurator module on corresponding RPC message arrival

    """

    service_type = const.SERVICE_TYPE
    cm.register_service_agent(service_type, rpcmgr)


def init_agent(cm, sc, conf):
    """Initializes Fwaas agent.

    :param cm: Instance of configuration module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration

    """

    try:
        drivers = load_drivers(conf)
    except Exception as err:
        msg = ("Fwaas failed to load drivers. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Fwaas loaded drivers successfully.")
        LOG.debug(msg)

    rpcmgr = FWaasRpcManager(sc, conf)
    try:
        events_init(sc, drivers, rpcmgr, conf)
    except Exception as err:
        msg = ("Fwaas Events initialization unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Fwaas Events initialization successful.")
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf, rpcmgr)
    except Exception as err:
        msg = ("Fwaas service agent registration unsuccessful. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise Exception(err)
    else:
        msg = ("Fwaas service agent registration successful.")
        LOG.debug(msg)

    msg = ("FIREWALL as a Service Module Initialized.")
    LOG.info(msg)


def init_agent_complete(cm, sc, conf):
    """ Initializes periodic tasks

    """

    msg = (" Firewall agent init complete")
    LOG.info(msg)
