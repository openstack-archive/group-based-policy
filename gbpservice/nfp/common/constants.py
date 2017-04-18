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
LOADBALANCERV2 = 'loadbalancerv2'
VPN = 'vpn'
GENERIC_CONFIG = 'generic_config'

GBP_MODE = "gbp"
NEUTRON_MODE = "neutron"
NOVA_MODE = "nova"

NEUTRON_PORT = "neutron_port"
GBP_PORT = "gbp_policy_target"

NEUTRON_NETWORK = "neutron_network"
GBP_NETWORK = "gbp_group"

PROVIDER = "provider"
CONSUMER = "consumer"
STITCHING = "stitching"
MANAGEMENT = "management"
MONITOR = "monitoring"
GATEWAY_TYPE = "gateway"
ENDPOINT_TYPE = "endpoint"

CREATE = "create"
UPDATE = "update"
DELETE = "delete"

SUCCESS = 'SUCCESS'

FOREVER = 'forever'
INITIAL = 'initial'

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

MAXIMUM_INTERFACES = 'maximum_interfaces'
SUPPORTS_SHARING = 'supports_device_sharing'
SUPPORTS_HOTPLUG = 'supports_hotplug'

PERIODIC_HM = 'periodic_healthmonitor'
DEVICE_TO_BECOME_DOWN = 'DEVICE_TO_BECOME_DOWN'

METADATA_SUPPORTED_ATTRIBUTES = [MAXIMUM_INTERFACES,
                                 SUPPORTS_SHARING,
                                 SUPPORTS_HOTPLUG]

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

request_event = "REQUEST"
response_event = "RESPONSE"
error_event = "ERROR"

#POLLING EVENTS SPACING AND MAXRETRIES
DEVICE_SPAWNING_SPACING = 10
DEVICE_SPAWNING_MAXRETRY = 25

DEVICE_BEING_DELETED_SPACING = 5
DEVICE_BEING_DELETED_MAXRETRY = 20

APPLY_USER_CONFIG_IN_PROGRESS_SPACING = 10
APPLY_USER_CONFIG_IN_PROGRESS_MAXRETRY = 20

UPDATE_USER_CONFIG_PREPARING_TO_START_SPACING = 10
UPDATE_USER_CONFIG_PREPARING_TO_START_MAXRETRY = 40

UPDATE_USER_CONFIG_STILL_IN_PROGRESS_MAXRETRY = 300

DELETE_USER_CONFIG_IN_PROGRESS_SPACING = 10
DELETE_USER_CONFIG_IN_PROGRESS_MAXRETRY = 20

CHECK_USER_CONFIG_COMPLETE_SPACING = 10
CHECK_USER_CONFIG_COMPLETE_MAXRETRY = 40

PULL_NOTIFICATIONS_SPACING = 10

#nfp_node_deriver_config
# all units in sec.
SERVICE_CREATE_TIMEOUT = 1500
SERVICE_DELETE_TIMEOUT = 600

# heat stack creation timeout
STACK_ACTION_WAIT_TIME = 600


# default directory for config files
CONFIG_DIR = '/etc/nfp/'
