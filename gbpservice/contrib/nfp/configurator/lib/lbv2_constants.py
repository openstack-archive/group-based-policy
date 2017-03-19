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

SERVICE_TYPE = 'loadbalancerv2'
NEUTRON = 'neutron'

LBAAS_AGENT_RPC_TOPIC = 'lbaasv2_agent'
LBAAS_GENERIC_CONFIG_RPC_TOPIC = 'lbaas_generic_config'
LBAAS_PLUGIN_RPC_TOPIC = 'n-lbaas-plugin'
AGENT_TYPE_LOADBALANCER = 'OC Loadbalancer V2 agent'

# Resources names
LOADBALANCER = 'loadbalancer'
LISTENER = 'listener'
POOL = 'pool'
MEMBER = 'member'
HEALTHMONITOR = 'healthmonitor'
SNI = 'sni'
L7POLICY = 'l7policy'
L7RULE = 'l7rule'
# Resources names for update apis
OLD_LOADBALANCER = 'old_loadbalancer'
OLD_LISTENER = 'old_listener'
OLD_POOL = 'old_pool'
OLD_MEMBER = 'old_member'
OLD_HEALTHMONITOR = 'old_healthmonitor'

# Operations
CREATE = 'create'
UPDATE = 'update'
DELETE = 'delete'

# Service operation status constants
ACTIVE = "ACTIVE"
DOWN = "DOWN"
CREATED = "CREATED"
PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"
INACTIVE = "INACTIVE"
ERROR = "ERROR"
STATUS_SUCCESS = "SUCCESS"

ACTIVE_PENDING_STATUSES = (
    ACTIVE,
    PENDING_CREATE,
    PENDING_UPDATE
)

REQUEST_URL = "http://%s:%s/%s"

# Constants to extend status strings in neutron.plugins.common.constants
ONLINE = 'ONLINE'
OFFLINE = 'OFFLINE'
DEGRADED = 'DEGRADED'
DISABLED = 'DISABLED'
NO_MONITOR = 'NO_MONITOR'

""" HTTP request/response """
HTTP_REQ_METHOD_POST = 'POST'
HTTP_REQ_METHOD_GET = 'GET'
HTTP_REQ_METHOD_PUT = 'PUT'
HTTP_REQ_METHOD_DELETE = 'DELETE'
CONTENT_TYPE_HEADER = 'Content-type'
JSON_CONTENT_TYPE = 'application/json'

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

PROTOCOL_TCP = 'TCP'
PROTOCOL_HTTP = 'HTTP'
PROTOCOL_HTTPS = 'HTTPS'

HEALTH_MONITOR_PING = 'PING'
HEALTH_MONITOR_TCP = 'TCP'
HEALTH_MONITOR_HTTP = 'HTTP'
HEALTH_MONITOR_HTTPS = 'HTTPS'

LBAAS = 'lbaas'

""" Event ids """
EVENT_CREATE_LOADBALANCER_V2 = 'CREATE_LOADBALANCER_V2'
EVENT_UPDATE_LOADBALANCER_V2 = 'UPDATE_LOADBALANCER_V2'
EVENT_DELETE_LOADBALANCER_V2 = 'DELETE_LOADBALANCER_V2'

EVENT_CREATE_LISTENER_V2 = 'CREATE_LISTENER_V2'
EVENT_UPDATE_LISTENER_V2 = 'UPDATE_LISTENER_V2'
EVENT_DELETE_LISTENER_V2 = 'DELETE_LISTENER_V2'

EVENT_CREATE_POOL_V2 = 'CREATE_POOL_V2'
EVENT_UPDATE_POOL_V2 = 'UPDATE_POOL_V2'
EVENT_DELETE_POOL_V2 = 'DELETE_POOL_V2'

EVENT_CREATE_MEMBER_V2 = 'CREATE_MEMBER_V2'
EVENT_UPDATE_MEMBER_V2 = 'UPDATE_MEMBER_V2'
EVENT_DELETE_MEMBER_V2 = 'DELETE_MEMBER_V2'

EVENT_CREATE_HEALTH_MONITOR_V2 = 'CREATE_HEALTH_MONITOR_V2'
EVENT_UPDATE_HEALTH_MONITOR_V2 = 'UPDATE_HEALTH_MONITOR_V2'
EVENT_DELETE_HEALTH_MONITOR_V2 = 'DELETE_HEALTH_MONITOR_V2'

EVENT_AGENT_UPDATED_V2 = 'AGENT_UPDATED_V2'
EVENT_COLLECT_STATS_V2 = 'COLLECT_STATS_V2'
