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
from neutron.extensions import l3

from gbpservice.neutron.extensions import cisco_apic

ALIAS = 'cisco-apic-l3'

EXTERNAL_PROVIDED_CONTRACTS = 'apic:external_provided_contracts'
EXTERNAL_CONSUMED_CONTRACTS = 'apic:external_consumed_contracts'

CONTRACT = 'Contract'
CONTRACT_SUBJECT = 'ContractSubject'
UNSCOPED_VRF = 'no_scope-VRF'
SCOPED_VRF = 'as_%s-VRF'

EXT_GW_ATTRIBUTES = {
    EXTERNAL_PROVIDED_CONTRACTS: {
        # Additional contracts provided by external network
        'allow_put': True, 'allow_post': True,
        'is_visible': True, 'default': None,
        'convert_to': attributes.convert_none_to_empty_list,
        'validate': {'type:list_of_unique_strings': None},
    },
    EXTERNAL_CONSUMED_CONTRACTS: {
        # Additional contracts consumed by external network
        'allow_put': True, 'allow_post': True,
        'is_visible': True, 'default': None,
        'convert_to': attributes.convert_none_to_empty_list,
        'validate': {'type:list_of_unique_strings': None},
    }
}

EXTENDED_ATTRIBUTES_2_0 = {
    l3.ROUTERS: dict(cisco_apic.APIC_ATTRIBUTES.items() +
                     EXT_GW_ATTRIBUTES.items())
}

# Pass this key with the value True in the interface_info parameter to
# add_router_interface to override validation that normally disallows
# topologies where the same network has multiple subnets connected to
# multiple routers, which would result in unintended routing. This is
# intended only for use in the aim_mapping GBP policy driver to get
# from one valid topology to another within a transaction, and is not
# supported for any other use. It may be removed in a future release
# without any deprecation notice.
OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION = (
    'apic_aim_override_network_routing_topology_validation')


class Cisco_apic_l3(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco APIC L3"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Extension exposing mapping of Neutron L3 resources to Cisco "
                "APIC constructs")

    @classmethod
    def get_updated(cls):
        return "2016-09-06T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
