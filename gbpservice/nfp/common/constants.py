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

FIREWALL = 'firewall'
LOADBALANCER = 'loadbalancer'
VPN = 'vpn'

GBP_MODE = "gbp"
NEUTRON_MODE = "neutron"
NOVA_MODE = "nova"

NEUTRON_PORT = "neutron_port"
GBP_PORT = "gbp_policy_target"

NEUTRON_NETWORK = "neutron_network"
GBP_NETWORK = "gbp_group"

PROVIDER = "provider"
CONSUMER = "consumer"
MANAGEMENT = "management"
MONITOR = "monitoring"
GATEWAY_TYPE = "gateway"
ENDPOINT_TYPE = "endpoint"

CREATE = "create"
UPDATE = "update"
DELETE = "delete"

ACTIVE_PORT = "ACTIVE"
STANDBY_PORT = "STANDBY"
MASTER_PORT = "MASTER"
STANDALONE_PORT = "STANDALONE"

ACTIVE = "ACTIVE"
# REVISIT(ashu) - Merge to have single BUILD state
PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"
ERROR = "ERROR"

DEVICE_ORCHESTRATOR = "device_orch"
SERVICE_ORCHESTRATOR = "service_orch"

HEAT_CONFIG_TAG = 'heat_config'
CONFIG_INIT_TAG = 'config_init'
ANSIBLE_TAG = 'ansible'
CUSTOM_JSON = 'custom_json'

COMPLETED = "COMPLETED"
IN_PROGRESS = "IN_PROGRESS"

CONFIG_INIT_TAG = "config_init"
CONFIG_SCRIPT = 'config_script'

CONFIG_TAG_RESOURCE_MAP = {
    HEAT_CONFIG_TAG: 'heat',
    CONFIG_INIT_TAG: 'config_init',
    ANSIBLE_TAG: 'ansible',
    CUSTOM_JSON: 'custom_json'}

LOADBALANCER_RPC_API_VERSION = "2.0"
LOADBALANCERV2_RPC_API_VERSION = "1.0"

HEALTHMONITOR_RESOURCE = 'healthmonitor'
INTERFACE_RESOURCE = 'interfaces'
ROUTES_RESOURCE = 'routes'
MANAGEMENT_INTERFACE_NAME = 'mgmt_interface'

VYOS_VENDOR = 'vyos'
HAPROXY_VENDOR = 'haproxy'
HAPROXY_LBAASV2 = 'haproxy_lbaasv2'
NFP_VENDOR = 'nfp'
L3_INSERTION_MODE = "l3"
