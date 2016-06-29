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

from gbpservice.contrib.nfp.config_orchestrator.common import topics
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v1.haproxy\
    import haproxy_lb_driver
from neutron.common import constants as n_const
from neutron.common import topics as n_topics
from neutron_lbaas.services.loadbalancer.drivers.common import (
    agent_driver_base as adb)


class HaproxyOnVMPluginDriver(adb.AgentDriverBase):
    device_driver = haproxy_lb_driver.DRIVER_NAME

    def __init__(self, plugin):
        # Monkey patch LB agent topic and LB agent type
        #adb.l_const.LOADBALANCER_AGENT = topics.LB_NFP_CONFIGAGENT_TOPIC
        #adb.q_const.AGENT_TYPE_LOADBALANCER = 'NFP Loadbalancer agent'
        n_topics.LOADBALANCER_AGENT = topics.LB_NFP_CONFIGAGENT_TOPIC
        n_const.AGENT_TYPE_LOADBALANCER = 'NFP Loadbalancer agent'

        super(HaproxyOnVMPluginDriver, self).__init__(plugin)
