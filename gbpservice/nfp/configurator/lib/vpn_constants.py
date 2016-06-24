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

DRIVERS_DIR = 'gbpservice.nfp.configurator.drivers.vpn'

SERVICE_TYPE = 'vpn'
SERVICE_VENDOR = 'vyos'

STATE_PENDING = 'PENDING_CREATE'
STATE_INIT = 'INIT'
STATE_ACTIVE = 'ACTIVE'
STATE_ERROR = 'ERROR'
NEUTRON = 'NEUTRON'

STATUS_ACTIVE = "ACTIVE"
STATUS_DELETED = "DELETED"
STATUS_UPDATED = "UPDATED"
STATUS_ERROR = "ERROR"
STATUS_SUCCESS = "SUCCESS"

CONFIGURATION_SERVER_PORT = 8888
REST_TIMEOUT = 90
request_url = "http://%s:%s/%s"
SUCCESS_CODES = [200, 201, 202, 203, 204]
ERROR_CODES = [400, 404, 500]

VYOS = 'vyos'
SM_RPC_TOPIC = 'VPN-sm-topic'
VPN_RPC_TOPIC = "vpn_topic"
VPN_GENERIC_CONFIG_RPC_TOPIC = "vyos_vpn_topic"

VPN_PLUGIN_TOPIC = 'vpn_plugin'
VPN_AGENT_TOPIC = 'vpn_agent'

CONFIGURATION_SERVER_PORT = '8888'
