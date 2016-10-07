# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
#
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.extensions import address_scope

ALIAS = 'cisco-apic'

DIST_NAMES = 'apic:distinguished_names'
SYNC_STATE = 'apic:synchronization_state'

BD = 'BridgeDomain'
EPG = 'EndpointGroup'
SUBNET = 'Subnet'
VRF = 'VRF'

SYNC_SYNCED = 'synced'
SYNC_BUILD = 'build'
SYNC_ERROR = 'error'

APIC_ATTRIBUTES = {
    DIST_NAMES: {'allow_post': False, 'allow_put': False, 'is_visible': True},
    SYNC_STATE: {'allow_post': False, 'allow_put': False, 'is_visible': True}
}

EXTENDED_ATTRIBUTES_2_0 = {
    attributes.NETWORKS: APIC_ATTRIBUTES,
    attributes.SUBNETS: APIC_ATTRIBUTES,
    address_scope.ADDRESS_SCOPES: APIC_ATTRIBUTES
}


class Cisco_apic(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco APIC"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Extension exposing mapping of Neutron resources to Cisco "
                "APIC constructs")

    @classmethod
    def get_updated(cls):
        return "2016-03-31T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
