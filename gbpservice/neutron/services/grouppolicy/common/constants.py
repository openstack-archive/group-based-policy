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

from neutron.plugins.common import constants


constants.GROUP_POLICY = "GROUP_POLICY"
constants.SERVICECHAIN = "SERVICECHAIN"

GBP_PREFIXES = {
    constants.GROUP_POLICY: "/grouppolicy",
    constants.SERVICECHAIN: "/servicechain",
}

GP_ACTION_ALLOW = 'allow'
GP_ACTION_REDIRECT = 'redirect'

GP_DIRECTION_IN = 'in'
GP_DIRECTION_OUT = 'out'
GP_DIRECTION_BI = 'bi'

GP_NETWORK_SVC_PARAM_TYPE = 'type'
GP_NETWORK_SVC_PARAM_NAME = 'name'
GP_NETWORK_SVC_PARAM_VALUE = 'value'

GP_NETWORK_SVC_PARAM_TYPE_IP_SINGLE = 'ip_single'
GP_NETWORK_SVC_PARAM_TYPE_IP_POOL = 'ip_pool'
GP_NETWORK_SVC_PARAM_TYPE_STRING = 'string'

GP_NETWORK_SVC_PARAM_VALUE_SELF_SUBNET = 'self_subnet'
GP_NETWORK_SVC_PARAM_VALUE_NAT_POOL = 'nat_pool'

STATUS_ACTIVE = 'ACTIVE'
STATUS_BUILD = 'BUILD'
STATUS_ERROR = 'ERROR'

PRE_COMMIT = 'pre_commit'
POST_COMMIT = 'post_commit'

STATUS_STATES = [STATUS_ACTIVE, STATUS_BUILD, STATUS_ERROR]

PRECOMMIT_POLICY_DRIVERS = ['aim_mapping']
