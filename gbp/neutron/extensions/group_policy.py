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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as nexc
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services import service_base

import gbp.neutron.extensions
from gbp.neutron.services.grouppolicy.common import constants as gp_constants

# The code below is a monkey patch of key Neutron's modules. This is needed for
# the GBP service to be loaded correctly. GBP extensions' path is added
# to Neutron's so that it's found at extension scanning time.

extensions.append_api_extensions_path(gbp.neutron.extensions.__path__)
constants.GROUP_POLICY = "GROUP_POLICY"
constants.COMMON_PREFIXES["GROUP_POLICY"] = "/grouppolicy"
constants.EXT_TO_SERVICE_MAPPING['gp'] = constants.GROUP_POLICY
constants.ALLOWED_SERVICES.append(constants.GROUP_POLICY)


LOG = logging.getLogger(__name__)


# Group Policy Exceptions
class EndpointNotFound(nexc.NotFound):
    message = _("Endpoint %(endpoint_id)s could not be found")


class EndpointGroupNotFound(nexc.NotFound):
    message = _("EndpointGroup %(endpoint_group_id)s could not be found")


class L2PolicyNotFound(nexc.NotFound):
    message = _("L2Policy %(l2_policy_id)s could not be found")


class L3PolicyNotFound(nexc.NotFound):
    message = _("L3Policy %(l3_policy_id)s could not be found")


class InvalidDefaultSubnetPrefixLength(nexc.InvalidInput):
    message = _("Default subnet prefix length %(length)s is invalid for"
                "ipv%(protocol)s")


class GroupPolicyInvalidProtocol(nexc.InvalidInput):
    message = _("Protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


# Group Policy Values
gp_supported_actions = [None, gp_constants.GP_ALLOW, gp_constants.GP_REDIRECT]
gp_supported_directions = [None, gp_constants.GP_DIRECTION_IN,
                           gp_constants.GP_DIRECTION_OUT,
                           gp_constants.GP_DIRECTION_BI]
gp_supported_protocols = [None, constants.TCP, constants.UDP, constants.ICMP]


# Group Policy input value conversion and validation functions
def convert_protocol(value):
    if value is None:
        return
    if value.lower() in gp_supported_protocols:
        return value.lower()
    else:
        raise GroupPolicyInvalidProtocol(protocol=value,
                                         values=
                                         gp_supported_protocols)


def convert_action_to_case_insensitive(value):
    if value is None:
        return
    else:
        return value.lower()


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def _validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


attr.validators['type:port_range'] = _validate_port_range


ENDPOINTS = 'endpoints'
ENDPOINT_GROUPS = 'endpoint_groups'
L2_POLICIES = 'l2_policies'
L3_POLICIES = 'l3_policies'
POLICY_CLASSIFIERS = 'policy_classifiers'
POLICY_ACTIONS = 'policy_actions'
POLICY_RULES = 'policy_rules'


RESOURCE_ATTRIBUTE_MAP = {
    ENDPOINTS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoint_group_id': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_or_none': None},
                              'required': True, 'is_visible': True},
    },
    ENDPOINT_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoints': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid_list': None},
                      'convert_to': attr.convert_none_to_empty_list,
                      'default': None, 'is_visible': True},
        'l2_policy_id': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True},
        'provided_contracts': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:dict_or_none': None},
                               'convert_to': attr.convert_none_to_empty_dict,
                               'default': None, 'is_visible': True},
        'consumed_contracts': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:dict_or_none': None},
                               'convert_to': attr.convert_none_to_empty_dict,
                               'default': None, 'is_visible': True},
    },
    L2_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'endpoint_groups': {'allow_post': False, 'allow_put': False,
                            'validate': {'type:uuid_list': None},
                            'convert_to': attr.convert_none_to_empty_list,
                            'default': None, 'is_visible': True},
        'l3_policy_id': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True,
                         'required': True},
        # TODO(Sumit): uncomment when supported in data path
        # 'allow_broadcast': {'allow_post': True, 'allow_put': True,
        #                    'default': True, 'is_visible': True,
        #                    'convert_to': attr.convert_to_boolean,
        #                    'required': False},
    },
    L3_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': attr.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'default': 4, 'is_visible': True},
        'ip_pool': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:subnet': None},
                    'default': '10.0.0.0/8', 'is_visible': True},
        'subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                 'convert_to': attr.convert_to_int,
                                 # for ipv4 legal values are 2 to 30
                                 # for ipv6 legal values are 2 to 127
                                 'default': 24, 'is_visible': True},
        'l2_policies': {'allow_post': False, 'allow_put': False,
                        'validate': {'type:uuid_list': None},
                        'convert_to': attr.convert_none_to_empty_list,
                        'default': None, 'is_visible': True},
    },
    POLICY_CLASSIFIERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol,
                     'validate': {'type:values': gp_supported_protocols}},
        'port_range': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:port_range': None},
                       'convert_to': convert_port_to_string,
                       'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:values': gp_supported_directions},
                      'default': None, 'is_visible': True},
    },
    POLICY_ACTIONS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'action_type': {'allow_post': True, 'allow_put': True,
                        'convert_to': convert_action_to_case_insensitive,
                        'validate': {'type:values': gp_supported_actions},
                        'is_visible': True, 'default': 'allow'},
        'action_value': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True},
    },
    POLICY_RULES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
        'policy_classifier_id': {'allow_post': True, 'allow_put': True,
                                 'validate': {'type:uuid': None},
                                 'is_visible': True, 'required': True},
        'policy_actions': {'allow_post': True, 'allow_put': True,
                           'default': None, 'is_visible': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list},
    },
}


class Group_policy(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Group Policy Abstraction"

    @classmethod
    def get_alias(cls):
        return "group-policy"

    @classmethod
    def get_description(cls):
        return "Extension for Group Policy Abstraction"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/gp/v2.0/"

    @classmethod
    def get_updated(cls):
        return "2014-03-03T12:00:00-00:00"

    @classmethod
    def get_resources(cls):
        special_mappings = {'l2_policies': 'l2_policy',
                            'l3_policies': 'l3_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.GROUP_POLICY)

    @classmethod
    def get_plugin_interface(cls):
        return GroupPolicyPluginBase

    def update_attributes_map(self, attributes):
        super(Group_policy, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class GroupPolicyPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.GROUP_POLICY

    def get_plugin_type(self):
        return constants.GROUP_POLICY

    def get_plugin_description(self):
        return 'Group Policy plugin'

    @abc.abstractmethod
    def get_endpoints(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_endpoint(self, context, endpoint_id, fields=None):
        pass

    @abc.abstractmethod
    def create_endpoint(self, context, endpoint):
        pass

    @abc.abstractmethod
    def update_endpoint(self, context, endpoint_id, endpoint):
        pass

    @abc.abstractmethod
    def delete_endpoint(self, context, endpoint_id):
        pass

    @abc.abstractmethod
    def get_endpoint_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_endpoint_group(self, context, endpoint_group_id, fields=None):
        pass

    @abc.abstractmethod
    def create_endpoint_group(self, context, endpoint_group):
        pass

    @abc.abstractmethod
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        pass

    @abc.abstractmethod
    def delete_endpoint_group(self, context, endpoint_group_id):
        pass

    @abc.abstractmethod
    def get_l2_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_l2_policy(self, context, l2_policy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_l2_policy(self, context, l2_policy):
        pass

    @abc.abstractmethod
    def update_l2_policy(self, context, l2_policy_id, l2_policy):
        pass

    @abc.abstractmethod
    def delete_l2_policy(self, context, l2_policy_id):
        pass

    @abc.abstractmethod
    def get_l3_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_l3_policy(self, context, l3_policy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_l3_policy(self, context, l3_policy):
        pass

    @abc.abstractmethod
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        pass

    @abc.abstractmethod
    def delete_l3_policy(self, context, l3_policy_id):
        pass

    @abc.abstractmethod
    def get_policy_classifiers(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_classifier(self, context, policy_classifier_id,
                              fields=None):
        pass

    @abc.abstractmethod
    def create_policy_classifier(self, context, policy_classifier):
        pass

    @abc.abstractmethod
    def update_policy_classifier(self, context, policy_classifier_id,
                                 policy_classifier):
        pass

    @abc.abstractmethod
    def delete_policy_classifier(self, context, policy_classifier_id):
        pass

    @abc.abstractmethod
    def get_policy_actions(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_action(self, context, policy_action_id, fields=None):
        pass

    @abc.abstractmethod
    def create_policy_action(self, context, policy_action):
        pass

    @abc.abstractmethod
    def update_policy_action(self, context, policy_action_id, policy_action):
        pass

    @abc.abstractmethod
    def delete_policy_action(self, context, policy_action_id):
        pass

    @abc.abstractmethod
    def get_policy_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_rule(self, context, policy_rule_id, fields=None):
        pass

    @abc.abstractmethod
    def create_policy_rule(self, context, policy_rule):
        pass

    @abc.abstractmethod
    def update_policy_rule(self, context, policy_rule_id, policy_rule):
        pass

    @abc.abstractmethod
    def delete_policy_rule(self, context, policy_rule_id):
        pass
