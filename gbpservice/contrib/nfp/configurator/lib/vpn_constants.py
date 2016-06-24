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

DRIVERS_DIR = 'gbpservice.contrib.nfp.configurator.drivers.vpn'

SERVICE_TYPE = 'vpn'


STATE_PENDING = 'PENDING_CREATE'
STATE_INIT = 'INIT'
STATE_ACTIVE = 'ACTIVE'
STATE_ERROR = 'ERROR'


VPN_GENERIC_CONFIG_RPC_TOPIC = "vyos_vpn_topic"

VPN_PLUGIN_TOPIC = 'vpn_plugin'
VPN_AGENT_TOPIC = 'vpn_agent'
