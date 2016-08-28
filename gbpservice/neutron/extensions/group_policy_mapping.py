#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron.api import extensions
from neutron.api.v2 import attributes as attr

from gbpservice.neutron.extensions import group_policy as gp


# Extended attributes for Group Policy resource to map to Neutron constructs
EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGETS: {
        'port_id': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True, 'default': None},
        'fixed_ips': {'allow_post': True, 'allow_put': True,
                      'default': attr.ATTR_NOT_SPECIFIED,
                      'convert_list_to': attr.convert_kvp_list_to_dict,
                      'validate': {'type:fixed_ips': None},
                      'enforce_policy': True,
                      'is_visible': True},
    },
    gp.POLICY_TARGET_GROUPS: {
        'subnets': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'is_visible': True, 'default': None},
    },
    gp.L2_POLICIES: {
        'network_id': {'allow_post': True, 'allow_put': False,
                       'validate': {'type:uuid_or_none': None},
                       'is_visible': True, 'default': None},
    },
    gp.L3_POLICIES: {
        'address_scope_v4_id': {'allow_post': True, 'allow_put': False,
                                'validate': {'type:uuid_or_none': None},
                                'is_visible': True, 'default': None},
        'address_scope_v6_id': {'allow_post': True, 'allow_put': False,
                                'validate': {'type:uuid_or_none': None},
                                'is_visible': True, 'default': None},
        'subnetpools_v4': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'is_visible': True, 'default': None},
        'subnetpools_v6': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'is_visible': True, 'default': None},
        'routers': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'is_visible': True, 'default': None},
    },
    gp.EXTERNAL_SEGMENTS: {
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid_or_none': None},
                      'is_visible': True, 'default': None},
    },
    gp.NAT_POOLS: {
        'subnet_id': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid_or_none': None},
                      'is_visible': True, 'default': None},
    }
}


class Group_policy_mapping(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Group Policy Abstraction Mapping to Neutron Resources"

    @classmethod
    def get_alias(cls):
        return "group-policy-mapping"

    @classmethod
    def get_description(cls):
        return "Extension for Group Policy Abstraction Mapping"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/gp/v2.0/"

    @classmethod
    def get_updated(cls):
        return "2014-03-03T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    @classmethod
    def get_plugin_interface(cls):
        return gp.GroupPolicyPluginBase
