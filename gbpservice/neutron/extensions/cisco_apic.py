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

import ast
import functools
import six

from neutron.api.v2 import attributes
from neutron.extensions import address_scope
from neutron_lib.api import converters as conv
from neutron_lib.api import extensions
from neutron_lib.api import validators as valid
from oslo_log import log as logging

ALIAS = 'cisco-apic'

DIST_NAMES = 'apic:distinguished_names'
SYNC_STATE = 'apic:synchronization_state'
NAT_TYPE = 'apic:nat_type'
SNAT_HOST_POOL = 'apic:snat_host_pool'
EXTERNAL_CIDRS = 'apic:external_cidrs'
SVI = 'apic:svi'
BGP = 'apic:bgp_enable'
BGP_ASN = 'apic:bgp_asn'
BGP_TYPE = 'apic:bgp_type'
NESTED_DOMAIN_NAME = 'apic:nested_domain_name'
NESTED_DOMAIN_TYPE = 'apic:nested_domain_type'
NESTED_DOMAIN_INFRA_VLAN = 'apic:nested_domain_infra_vlan'
NESTED_DOMAIN_ALLOWED_VLANS = 'apic:nested_domain_allowed_vlans'
NESTED_DOMAIN_SERVICE_VLAN = 'apic:nested_domain_service_vlan'
NESTED_DOMAIN_NODE_NETWORK_VLAN = 'apic:nested_domain_node_network_vlan'

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

VLANS_LIST = 'vlans_list'
VLAN_RANGES = 'vlan_ranges'
APIC_MAX_VLAN = 4093
APIC_MIN_VLAN = 1
VLAN_RANGE_START = 'start'
VLAN_RANGE_END = 'end'

LOG = logging.getLogger(__name__)


def _validate_apic_vlan(data, key_specs=None):
    if data is None:
        return
    try:
        val = int(data)
        if val >= APIC_MIN_VLAN and val <= APIC_MAX_VLAN:
            return
        msg = _("Invalid value for VLAN: '%s'") % data
        LOG.debug(msg)
        return msg
    except (ValueError, TypeError):
        msg = _("Invalid data format for VLAN: '%s'") % data
        LOG.debug(msg)
        return msg


def _validate_apic_vlan_range(data, key_specs=None):
    if data is None:
        return

    expected_keys = [VLAN_RANGE_START, VLAN_RANGE_END]
    msg = valid._verify_dict_keys(expected_keys, data)
    if msg:
        return msg
    for k in expected_keys:
        msg = _validate_apic_vlan(data[k])
        if msg:
            return msg
    if int(data[VLAN_RANGE_START]) > int(data[VLAN_RANGE_END]):
        msg = _("Invalid start, end for VLAN range %s") % data
        return msg


def _validate_dict_or_string(data, key_specs=None):
    if data is None:
        return

    if isinstance(data, str) or isinstance(data, six.string_types):
        try:
            data = ast.literal_eval(data)
        except Exception:
            msg = _("Allowed VLANs %s cannot be converted to dict") % data
            return msg

    return valid.validate_dict_or_none(data, key_specs)


def convert_apic_vlan(value):
    if value is None:
        return
    else:
        return int(value)


def convert_nested_domain_allowed_vlans(value):
    if value is None:
        return

    if isinstance(value, str) or isinstance(value, six.string_types):
        value = ast.literal_eval(value)

    vlans_list = []
    if VLANS_LIST in value:
        for vlan in value[VLANS_LIST]:
            vlans_list.append(convert_apic_vlan(vlan))
    if VLAN_RANGES in value:
        for vlan_range in value[VLAN_RANGES]:
            for vrng in [VLAN_RANGE_START, VLAN_RANGE_END]:
                vlan_range[vrng] = convert_apic_vlan(vlan_range[vrng])
            vlans_list.extend(range(vlan_range[VLAN_RANGE_START],
                vlan_range[VLAN_RANGE_END] + 1))
    # eliminate duplicates
    vlans_list = list(set(vlans_list))
    # sort
    vlans_list.sort()
    value[VLANS_LIST] = vlans_list
    return value


valid.validators['type:apic_vlan'] = _validate_apic_vlan
valid.validators['type:apic_vlan_list'] = functools.partial(
        valid._validate_list_of_items, _validate_apic_vlan)
valid.validators['type:apic_vlan_range_list'] = functools.partial(
        valid._validate_list_of_items, _validate_apic_vlan_range)
valid.validators['type:dict_or_string'] = _validate_dict_or_string


APIC_ATTRIBUTES = {
    DIST_NAMES: {'allow_post': False, 'allow_put': False, 'is_visible': True},
    SYNC_STATE: {'allow_post': False, 'allow_put': False, 'is_visible': True}
}

NET_ATTRIBUTES = {
    SVI: {
        'allow_post': True, 'allow_put': False,
        'is_visible': True, 'default': False,
        'convert_to': conv.convert_to_boolean,
    },
    BGP: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': False,
        'convert_to': conv.convert_to_boolean,
    },
    BGP_TYPE: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': 'default_export',
        'validate': {'type:values': ['default_export', '']},
    },
    BGP_ASN: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': "0",
        'validate': {'type:non_negative': None},
    },
    NESTED_DOMAIN_NAME: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': '',
        'validate': {'type:string': None},
    },
    NESTED_DOMAIN_TYPE: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': '',
        'validate': {'type:string': None},
    },
    NESTED_DOMAIN_INFRA_VLAN: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': None,
        'validate': {'type:apic_vlan': None},
        'convert_to': convert_apic_vlan,
    },
    NESTED_DOMAIN_SERVICE_VLAN: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': None,
        'validate': {'type:apic_vlan': None},
        'convert_to': convert_apic_vlan,
    },
    NESTED_DOMAIN_NODE_NETWORK_VLAN: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': None,
        'validate': {'type:apic_vlan': None},
        'convert_to': convert_apic_vlan,
    },
    NESTED_DOMAIN_ALLOWED_VLANS: {
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': None,
        'validate': {
            'type:dict_or_string': {
                VLANS_LIST: {'type:apic_vlan_list': None},
                VLAN_RANGES: {'type:apic_vlan_range_list': None},
            }
        },
        'convert_to': convert_nested_domain_allowed_vlans,
    },
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
        'convert_to': conv.convert_none_to_empty_list,
        'validate': {'type:subnet_list': None},
    },
}

EXT_SUBNET_ATTRIBUTES = {
    SNAT_HOST_POOL: {
        # whether an external subnet should be used as a pool
        # for allocating host-based SNAT addresses
        'allow_post': True, 'allow_put': True,
        'is_visible': True, 'default': False,
        'convert_to': conv.convert_to_boolean,
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
        APIC_ATTRIBUTES.items() + EXT_NET_ATTRIBUTES.items() +
        NET_ATTRIBUTES.items()),
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
