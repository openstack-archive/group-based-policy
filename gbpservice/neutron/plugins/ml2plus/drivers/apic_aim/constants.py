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

from neutron_lib import constants as n_constants

GBP_FLOW_CLASSIFIER = 'gbp_flowclassifier'
GBP_PORT = 'gbp_port'
GBP_NETWORK_VRF = 'gbp_network_vrf'
GBP_NETWORK_EPG = 'gbp_network_epg'
GBP_NETWORK_LINK = 'gbp_network_link'

DEVICE_OWNER_SNAT_PORT = 'apic:snat-pool'
DEVICE_OWNER_SVI_PORT = 'apic:svi'

IPV4_ANY_CIDR = '0.0.0.0/0'
IPV4_METADATA_CIDR = '169.254.169.254/16'

PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
PROMISCUOUS_SUFFIX = 'promiscuous'
