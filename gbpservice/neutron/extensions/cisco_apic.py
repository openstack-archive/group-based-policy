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
NAT_TYPE = 'apic:nat_type'
SNAT_HOST_POOL = 'apic:snat_host_pool'
EXTERNAL_CIDRS = 'apic:external_cidrs'

BD = 'BridgeDomain'
EPG = 'EndpointGroup'
SUBNET = 'Subnet'
VRF = 'VRF'
EXTERNAL_NETWORK = 'ExternalNetwork'
AP = 'ApplicationProfile'

SYNC_SYNCED = 'synced'
SYNC_BUILD = 'build'
SYNC_ERROR = 'error'
SYNC_NOT_APPLICABLE = 'N/A'

APIC_ATTRIBUTES = {
    DIST_NAMES: {'allow_post': False, 'allow_put': False, 'is_visible': True},
    SYNC_STATE: {'allow_post': False, 'allow_put': False, 'is_visible': True}
}

EXT_NET_ATTRIBUTES = {
    DIST_NAMES: {
        # DN of corresponding APIC L3Out external network; can be
        # specified only on create.
        # Change 'allow_put' if updates on other DNs is allowed later,
        # and validate that ExternalNetwork DN may not be updated.
        'allow_post': True, 'allow_put': False,
        'is_visible': True,
        'default': None,
        'validate': {
            'type:dict_or_none': {
                EXTERNAL_NETWORK: {'type:string': None,
                                   'required': True}
            }
        }
    },
    NAT_TYPE: {
        # whether NAT is enabled, and if so its type
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': 'distributed',
        'validate': {'type:values': ['distributed', 'edge', '']},
    },
    EXTERNAL_CIDRS: {
        # Restrict external traffic to specified addresses
        'allow_put': True, 'allow_post': True,
        'is_visible': True, 'default': ['0.0.0.0/0'],
        'convert_to': attributes.convert_none_to_empty_list,
        'validate': {'type:subnet_list': None},
    },
}

EXT_SUBNET_ATTRIBUTES = {
    SNAT_HOST_POOL: {
        # whether an external subnet should be used as a pool
        # for allocating host-based SNAT addresses
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': False,
        'convert_to': attributes.convert_to_boolean,
    }
}

ADDRESS_SCOPE_ATTRIBUTES = {
    DIST_NAMES: {
        # DN of corresponding APIC VRF; can be specified only on create.
        # Change 'allow_put' if updates on other DNs is allowed later,
        # and validate that VRF DN may not be updated.
        'allow_post': True, 'allow_put': False,
        'is_visible': True,
        'default': None,
        'validate': {
            'type:dict_or_none': {
                VRF: {'type:string': None,
                      'required': True}
            }
        }
    }
}


EXTENDED_ATTRIBUTES_2_0 = {
    attributes.NETWORKS: dict(
        APIC_ATTRIBUTES.items() + EXT_NET_ATTRIBUTES.items()),
    attributes.SUBNETS: dict(
        APIC_ATTRIBUTES.items() + EXT_SUBNET_ATTRIBUTES.items()),
    address_scope.ADDRESS_SCOPES: dict(
        APIC_ATTRIBUTES.items() + ADDRESS_SCOPE_ATTRIBUTES.items())
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
