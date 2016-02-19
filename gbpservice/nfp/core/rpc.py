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

from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging

from oslo_service import loopingcall as oslo_looping_call
from oslo_service import periodic_task as oslo_periodic_task

from neutron.agent import rpc as n_agent_rpc
from neutron.common import rpc as n_rpc

from neutron import context as n_context

from gbpservice.nfp.core import common as nfp_common

LOGGER = oslo_logging.getLogger(__name__)
LOG = nfp_common.log
identify = nfp_common.identify

"""Wrapper class for Neutron RpcAgent definition.

    NFP modules will use this class for the agent definition.
    Associates the state reporting of agent to ease
    the usage for modules.
"""


class RpcAgent(n_rpc.Service):

    def __init__(
            self, sc, host=None,
            topic=None, manager=None, report_state=None):
        # report_state =
        #   {<agent_state_keys>, 'plugin_topic': '', 'report_interval': ''}
        super(RpcAgent, self).__init__(host=host, topic=topic, manager=manager)

        # Check if the agent needs to report state
        if report_state:
            self._report_state = ReportState(report_state)

    def start(self):
        LOG(LOGGER, 'DEBUG', "RPCAgent listening on %s" % (self.identify))
        super(RpcAgent, self).start()

    def report_state(self):
        if hasattr(self, '_report_state'):
            LOG(LOGGER, 'DEBUG', "Agent (%s) reporting state" %
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
            LOG(LOGGER, 'DEBUG', "Reporting state with data (%s)" %
                (self._data))
            self._state_rpc.report_state(self._n_context, self._data)
            self._data.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            LOG(LOGGER, 'WARN',
                "Neutron server does not support state report."
                "Agent State reporting will be "
                "disabled.")
            return
        except Exception:
            LOG(LOGGER, 'EXCEPTION', "Stopped reporting agent state!")

"""Periodic task to report neutron *aaS agent state.

    Derived from oslo periodic task, to report the agents state
    if any, to neutron *aaS plugin.
"""


class ReportStateTask(oslo_periodic_task.PeriodicTasks):

    def __init__(self, sc):
        super(ReportStateTask, self).__init__(oslo_config.CONF)
        self._sc = sc
        # Start a looping at the defined pulse
        pulse = oslo_looping_call.FixedIntervalLoopingCall(
            self.run_periodic_tasks, None, None)
        pulse.start(
            interval=oslo_config.CONF.reportstate_interval, initial_delay=None)

    @oslo_periodic_task.periodic_task(spacing=5)
    def report_state(self, context):
        # trigger the state reporting
        self._sc.report_state()


def load_nfp_symbols(namespace):
    nfp_common.load_nfp_symbols(namespace)

load_nfp_symbols(globals())
