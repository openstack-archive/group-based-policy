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

supported_service_types = ['firewall', 'vpn', 'loadbalancer', 'loadbalancerv2']
NFP_SERVICE_LIST = ['heat', 'ansible']
invalid_service_type = 'invalid'
NFP_SERVICE = 'nfp_service'
SUCCESS = 'SUCCESS'
FAILED = 'FAILED'
FAILURE = 'FAILURE'
GENERIC_CONFIG = 'generic_config'
ORCHESTRATOR = 'orchestrator'
EVENT_STASH = 'STASH_EVENT'
EVENT_PROCESS_BATCH = 'PROCESS_BATCH'
NFD_NOTIFICATION = 'network_function_device_notification'
RABBITMQ_HOST = '127.0.0.1'  # send notifications to 'RABBITMQ_HOST'
NOTIFICATION_QUEUE = 'configurator-notifications'
FIREWALL = 'firewall'
VPN = 'vpn'
LOADBALANCER = 'loadbalancer'
VYOS = 'vyos'
LOADBALANCERV2 = 'loadbalancerv2'
HAPROXY = 'haproxy'
HAPROXY_LBAASV2 = 'haproxy_lbaasv2'
CREATE = 'create'
UPDATE = 'update'
DELETE = 'delete'
POST = 'post'
PUT = 'put'
UNHANDLED = "UNHANDLED"

HEALTHMONITOR = 'healthmonitor'
INTERFACES = 'interfaces'
ROUTES = 'routes'

SUCCESS_CODES = [200, 201, 202, 203, 204]
ERROR_CODES = [400, 404, 500]

STATUS_ACTIVE = "ACTIVE"
STATUS_DELETED = "DELETED"
STATUS_UPDATED = "UPDATED"
STATUS_ERROR = "ERROR"
STATUS_SUCCESS = "SUCCESS"
UNHANDLED = "UNHANDLED"
DOWN = "Down"

AGENTS_PKG = ['gbpservice.contrib.nfp.configurator.agents']
CONFIGURATOR_RPC_TOPIC = 'configurator'
