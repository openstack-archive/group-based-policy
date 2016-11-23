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
import oslo_messaging

from oslo_config import cfg as oslo_config

from oslo_messaging.rpc import dispatcher as om_rpc_dispatcher
from oslo_messaging import server as msg_server
from oslo_service import loopingcall as oslo_looping_call
from oslo_service import periodic_task as oslo_periodic_task

from neutron.agent import rpc as n_agent_rpc
from neutron.common import rpc as n_rpc

from neutron import context as n_context

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)

n_rpc.init(oslo_config.CONF)


def get_rpc_server(transport, target, endpoints,
                   executor='blocking', serializer=None):
    dispatcher = RPCDispatcher(target, endpoints, serializer)
    return msg_server.MessageHandlingServer(transport, dispatcher, executor)

# monkey patching
# get_rpc_server() function of oslo_messaging creates rpc server
# with its own dispatcher but we want to create rpc server with our
# modified dispatcher,hence there is need to override
# get_rpc_server() function
oslo_messaging.get_rpc_server = get_rpc_server


"""Wrapper class for Neutron RpcAgent definition.

    NFP modules will use this class for the agent definition.
    Associates the state reporting of agent to ease
    the usage for modules.
"""


class RpcAgent(n_rpc.Service):

    def __init__(
            self, sc, host=None,
            topic=None, manager=None, report_state=None, priority=0):
        # report_state =
        #   {<agent_state_keys>, 'plugin_topic': '', 'report_interval': ''}
        super(RpcAgent, self).__init__(
            host=host, topic=topic, manager=manager)
        self.sc = sc
        self.host = host
        self.topic = topic
        self.manager = manager
        self.priority = priority
        # Check if the agent needs to report state
        if report_state:
            self._report_state = ReportState(report_state)

    def start(self):
        LOG.debug("RPCAgent listening on %s" % (self.identify))
        super(RpcAgent, self).start()

    def report_state(self):
        if hasattr(self, '_report_state'):
            LOG.debug("Agent (%s) reporting state" %
                      (self.identify()))
            self._report_state.report()

    def identify(self):
        return "(host=%s,topic=%s)" % (self.host, self.topic)

"""This class implements the state reporting for neutron *aaS agents

    One common place of handling of reporting logic.
    Each nfp module just need to register the reporting data and
    plugin topic.
"""


class ReportState(object):

    def __init__(self, data):
        self._n_context = n_context.get_admin_context_without_session()
        self._data = data
        self._topic = data.pop('plugin_topic', None)
        self._interval = data.pop('report_interval', 0)
        self._state_rpc = n_agent_rpc.PluginReportStateAPI(
            self._topic)

    def report(self):
        try:
            LOG.debug("Reporting state with data (%s)" %
                      (self._data))
            self._state_rpc.report_state(self._n_context, self._data)
            self._data.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            message = "Neutron server does not support state report."
            "Agent State reporting will be disabled"
            LOG.info(message)
            return
        except Exception:
            message = "Stopped reporting agent state!"
            LOG.exception(message)

"""Periodic task to report neutron *aaS agent state.

    Derived from oslo periodic task, to report the agents state
    if any, to neutron *aaS plugin.
"""


class ReportStateTask(oslo_periodic_task.PeriodicTasks):

    def __init__(self, conf, controller):
        super(ReportStateTask, self).__init__(conf)
        self._controller = controller
        # Start a looping at the defined pulse
        pulse = oslo_looping_call.FixedIntervalLoopingCall(
            self.run_periodic_tasks, None, None)
        pulse.start(
            interval=5, initial_delay=None)

    @oslo_periodic_task.periodic_task(spacing=10)
    def report_state(self, context):
        # trigger the state reporting
        self._controller.report_state()


"""RPC method dispatcher

   This class handles the dispatch of a method when rpc server
   receives message.
"""


class RPCDispatcher(om_rpc_dispatcher.RPCDispatcher):

    def __init__(self, target, endpoints, serializer):
        super(RPCDispatcher, self).__init__(target, endpoints, serializer)

    def _do_dispatch(self, endpoint, method, ctxt, args):
        rpc_callback = getattr(endpoint, '_rpc_callback')
        endpoint = rpc_callback(method)
        if not endpoint:
            raise om_rpc_dispatcher.NoSuchMethod(method)
        return super(RPCDispatcher, self)._do_dispatch(
            endpoint, method, ctxt, args)

    def _dispatch(self, ctxt, message):
        """Dispatch an RPC message to the appropriate endpoint method.

        :param ctxt: the request context
        :type ctxt: dict
        :param message: the message payload
        :type message: dict
        """
        rpc_manager = self.endpoints[0]
        rpc_manager.target.version = message.get('version', '1.0')
        method = message.get('method')
        setattr(rpc_manager, method, '')
        result = super(RPCDispatcher, self)._dispatch(ctxt, message)
        return result

"""Core's RPC Manager

"""


class RpcManager(object):
    # value of version of the target instance will be updated with
    # rpc client's version in dispatcher when client make rpc call/cast
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, sc, conf, agents):
        self.sc = sc
        self.conf = conf
        self.agents = agents

    def _rpc_callback(self, method):
        """Determine the rpc manager of which, method to be dispatched

        :param method: rpc method name to be dispatched
        :return manager: rpc manager having the highest priority, method
         and the same version
        """
        agents = sorted(
            self.agents, key=operator.attrgetter('priority'), reverse=True)
        # client rpc version
        version = self.target.version
        for agent in agents:
            if hasattr(agent.manager, 'target'):
                target = agent.manager.target
            else:
                target = oslo_messaging.Target()
            if (hasattr(agent.manager, method) and
                om_rpc_dispatcher.RPCDispatcher._is_compatible(
                    target, version)):
                return agent.manager
