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

# NOTE(ivar): right now, the flowclassifier plugin doesn't support
# notifications right now. Adding our own using the proper resource name
# could be dangerous for compatibility once they suddenly start supporting
# them. We create our own resource type and make sure to modify it once
# support is added to the SFC project.

from networking_sfc.extensions import flowclassifier

LOGICAL_SRC_NET = 'logical_source_network'
LOGICAL_DST_NET = 'logical_destination_network'
HEALTHCHECK_POLICY = 'healthcheck_policy'
AIM_FLC_L7_PARAMS = {
    LOGICAL_SRC_NET: {
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': None,
        'validate': {'type:uuid_or_none': None}},
    LOGICAL_DST_NET: {
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': None,
        'validate': {'type:uuid_or_none': None}}
}
AIM_PPG_PARAMS = {
    'healthcheck_type': {
        'type:values': ['', 'icmp', 'tcp']
    },
    'healthcheck_frequency': {
        'type:non_negative': None
    },
    'healthcheck_tcp_port': {
        'convert_to': flowclassifier.normalize_port_value
    },
}
AIM_FLC_PARAMS = ['source_ip_prefix', 'destination_ip_prefix']
