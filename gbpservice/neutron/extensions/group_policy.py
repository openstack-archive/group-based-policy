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
import re

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants
from neutron.services import service_base
from neutron_lib.api import converters as conv
from neutron_lib.api import validators as valid
from neutron_lib import constants as nlib_const
from neutron_lib import exceptions as nexc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import six

from gbpservice.neutron import extensions as gbp_extensions
from gbpservice.neutron.extensions import patch  # noqa
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_constants)


# The code below is a monkey patch of key Neutron's modules. This is needed for
# the GBP service to be loaded correctly. GBP extensions' path is added
# to Neutron's so that it's found at extension scanning time.
extensions.append_api_extensions_path(gbp_extensions.__path__)

LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('default_ip_pool',
               default='10.0.0.0/8',
               help=_("IP pool for implicitly created default L3 policies, "
                      "from which subnets are allocated for policy target "
                      "groups.")),
]

cfg.CONF.register_opts(opts, "group_policy_group")
GBP_CONF = cfg.CONF.group_policy_group


# Group Policy Exceptions
class GbpResourceNotFound(nexc.NotFound):
    message = _("Group Policy resource %(identity)s with id %(id)s could not "
                "be found")


class PolicyTargetNotFound(nexc.NotFound):
    message = _("Policy Target %(policy_target_id)s could not be found")


class PolicyTargetGroupNotFound(nexc.NotFound):
    message = _("Policy Target Group %(policy_target_group_id)s could not "
                "be found")


class ApplicationPolicyGroupNotFound(nexc.NotFound):
    message = _("Application Policy Group %(application_policy_group_id)s "
                "could not be found")


class ManagementPolicyTargetGroupExists(nexc.BadRequest):
    message = _("Service Management Policy Target Group already exists for "
                "this tenant.")


class L2PolicyNotFound(nexc.NotFound):
    message = _("L2Policy %(l2_policy_id)s could not be found")


class L2PolicyInUse(nexc.InUse):
    message = _("Unable to complete operation, L2Policy %(l2_policy_id)s is "
                "in use")


class L3PolicyNotFound(nexc.NotFound):
    message = _("L3Policy %(l3_policy_id)s could not be found")


class L3PolicyInUse(nexc.InUse):
    message = _("Unable to complete operation, L3Policy %(l3_policy_id)s is "
                "in use")


class NetworkServicePolicyInUse(nexc.InUse):
    message = _("Unable to complete operation, NetworkServicePolicy "
                "%(network_service_policy_id)s is in use")


class NetworkServicePolicyNotFound(nexc.NotFound):
    message = _("NetworkServicePolicy %(network_service_policy_id)s "
                "could not be found")


class InvalidDefaultSubnetPrefixLength(nexc.InvalidInput):
    message = _("Default subnet prefix length %(length)s is invalid for "
                "ipv%(protocol)s")


class SubnetPrefixLengthExceedsIpPool(nexc.InvalidInput):
    message = _("IP pool %(ip_pool)s prefix greater "
                "than subnet mask %(subnet_size)s")


class InvalidIpPoolSize(nexc.InvalidInput):
    message = _("IP pool %(ip_pool)s is invalid:%(err_msg)s"
                "Pool size=%(size)s")


class InvalidIpPoolPrefixLength(nexc.InvalidInput):
    message = _("IP pool %(ip_pool)s is invalid:%(err_msg)s"
                "Prefix Length=%(prefixlen)s")


class InvalidIpPoolVersion(nexc.InvalidInput):
    message = _("%(ip_pool)s is not a ipv%(version)s address.")


class PolicyClassifierNotFound(nexc.NotFound):
    message = _("PolicyClassifier %(policy_classifier_id)s could not be found")


class PolicyClassifierInUse(nexc.InUse):
    message = _("Unable to complete operation, PolicyClassifier "
                "%(policy_classifier_id)s is in use")


class PolicyActionNotFound(nexc.NotFound):
    message = _("PolicyAction %(policy_action_id)s could not be found")


class PolicyActionInUse(nexc.InUse):
    message = _("Unable to complete operation, PolicyAction "
                "%(policy_action_id)s is in use")


class PolicyRuleNotFound(nexc.NotFound):
    message = _("PolicyRule %(policy_rule_id)s could not be found")


class PolicyRuleInUse(nexc.InUse):
    message = _("Unable to complete operation, PolicyRule %(policy_rule_id)s "
                "is in use")


class PolicyRuleSetNotFound(nexc.NotFound):
    message = _("Policy Rule Set %(policy_rule_set_id)s could not be found")


class PolicyRuleSetInUse(nexc.InUse):
    message = _("Unable to complete operation, PolicyRuleSet "
                "%(policy_rule_set_id)s is in use")


class ExternalPolicyNotFound(nexc.NotFound):
    message = _("External Policy %(id)s could not be found")


class ExternalSegmentNotFound(nexc.NotFound):
    message = _("External Segment %(id)s could not be found")


class ExternalSegmentInUse(nexc.InUse):
    message = _("Unable to complete operation, External Segment "
                "%(es_id)s is in use")


class NATPoolNotFound(nexc.NotFound):
    message = _("NAT Pool %(id)s could not be found")


class BadPolicyRuleSetRelationship(nexc.BadRequest):
    message = _("Policy Rule Set %(parent_id)s is an invalid parent for "
                "%(child_id)s, make sure that child policy_rule_set has no "
                "children, or that you are not creating a relationship loop")


class ThreeLevelPolicyRuleSetHierarchyNotSupported(nexc.BadRequest):
    message = _("Can't add children to policy_rule_set %(policy_rule_set_id)s "
                "which already has a parent. Only one level "
                "of policy_rule_set hierarchy supported.")


class GroupPolicyInvalidPortValue(nexc.InvalidInput):
    message = _("Invalid value for port %(port)s")


class GroupPolicyInvalidProtocol(nexc.InvalidInput):
    message = _("Protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class IpAddressOverlappingInExternalSegment(nexc.BadRequest):
    message = _("One or more requested IP addresses are already allocated for "
                "External Segment %(es_id)s.")


# Group Policy Values
gp_supported_actions = [None, gp_constants.GP_ACTION_ALLOW,
                        gp_constants.GP_ACTION_REDIRECT]
gp_supported_directions = [None, gp_constants.GP_DIRECTION_IN,
                           gp_constants.GP_DIRECTION_OUT,
                           gp_constants.GP_DIRECTION_BI]
gp_supported_protocols = [None, nlib_const.PROTO_NAME_TCP,
                          nlib_const.PROTO_NAME_UDP,
                          nlib_const.PROTO_NAME_ICMP]
gp_network_service_param_types = [
    gp_constants.GP_NETWORK_SVC_PARAM_TYPE_IP_SINGLE,
    gp_constants.GP_NETWORK_SVC_PARAM_TYPE_IP_POOL,
    gp_constants.GP_NETWORK_SVC_PARAM_TYPE_STRING]
gp_network_service_param_keys = [
    gp_constants.GP_NETWORK_SVC_PARAM_TYPE,
    gp_constants.GP_NETWORK_SVC_PARAM_NAME,
    gp_constants.GP_NETWORK_SVC_PARAM_VALUE]
gp_network_service_param_values = [
    gp_constants.GP_NETWORK_SVC_PARAM_VALUE_SELF_SUBNET,
    gp_constants.GP_NETWORK_SVC_PARAM_VALUE_NAT_POOL]


# Group Policy input value conversion and validation functions
def convert_protocol(value):
    if value is None:
        return
    try:
        val = int(value)
        if val >= 0 and val <= 255:
            return value
        raise GroupPolicyInvalidProtocol(
            protocol=value, values=gp_supported_protocols)
    except (ValueError, TypeError):
        protocol = value.lower()
        if protocol in gp_supported_protocols:
            return protocol
        raise GroupPolicyInvalidProtocol(
            protocol=value, values=gp_supported_protocols)
    except AttributeError:
        raise GroupPolicyInvalidProtocol(
            protocol=value, values=gp_supported_protocols)


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


def convert_to_int_if_needed(value):
    if not value or value is nlib_const.ATTR_NOT_SPECIFIED:
        return value
    else:
        return conv.convert_to_int(value)


def _validate_gbp_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':', 1)
    lower_range = 0

    for p in ports:
        try:
            val = int(p)
            if val <= 0 or val > 65535:
                msg = _("Invalid port '%s', valid range 0 < port < 65536") % p
                LOG.debug(msg)
                return msg
            if val <= lower_range:
                msg_dict = dict(p1=lower_range, p2=val)
                msg = _("Invalid port range: %(p1)s:%(p2)s, "
                        "valid range 0 < port1 < port2") % msg_dict
                LOG.debug(msg)
                return msg
            lower_range = val
        except (ValueError, TypeError):
            msg = _("Port value '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg


def _validate_network_svc_params(data, key_specs=None):
    if data is None:
        return
    # A valid network_svc_params dict is:
    # [{'type': <type>, 'name': <param_name>, 'value': <param_value>}]
    # e.g. [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]
    # The type and value are validated, the name is treated as a literal.
    # The name of the param is chosen by the service chain implementation,
    # and as such is validated by the service chain provider.
    # The supported types are defined in gp_network_service_param_types.
    # The supported values are defined in gp_network_service_param_values,
    # but the values are not validated when the tpye is 'string'.
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        LOG.debug(msg)
        return msg
    for d in data:
        if not isinstance(d, dict):
            msg = _("'%s' is not a dictionary") % d
            LOG.debug(msg)
            return msg
        if set(d) != set(gp_network_service_param_keys):
            s = ", ".join(set(d) - set(gp_network_service_param_keys))
            msg = _("Unknown key(s) '%s' in network service params") % s
            LOG.debug(msg)
            return msg
        if d['type'] not in gp_network_service_param_types:
            msg = _("Network service param type(s) '%s' not supported") % (
                d['type'])
            LOG.debug(msg)
            return msg
        if d['type'] != gp_constants.GP_NETWORK_SVC_PARAM_TYPE_STRING:
            if d['value'] not in gp_network_service_param_values:
                msg = _("Network service param value '%s' is not "
                        "supported") % d['value']
                LOG.debug(msg)
                return msg


def _validate_external_dict(data, key_specs=None):
    if data is None:
        return
    if not isinstance(data, dict):
        msg = _("'%s' is not a dictionary") % data
        LOG.debug(msg)
        return msg
    for d in data:
        if not uuidutils.is_uuid_like(d):
            msg = _("'%s' is not a valid UUID") % d
            LOG.debug(msg)
            return msg
        if not isinstance(data[d], list):
            msg = _("'%s' is not a list") % data[d]
            LOG.debug(msg)
            return msg


def _validate_gbproutes(data, valid_values=None):
    # Shamelessly copied from Neutron, will pass even if nexthop is valid
    if not isinstance(data, list):
        msg = _("Invalid data format for hostroute: '%s'") % data
        LOG.debug(msg)
        return msg

    expected_keys = ['destination', 'nexthop']
    hostroutes = []
    for hostroute in data:
        msg = valid._verify_dict_keys(expected_keys, hostroute)
        if msg:
            LOG.debug(msg)
            return msg
        msg = valid.validate_subnet(hostroute['destination'])
        if msg:
            LOG.debug(msg)
            return msg
        if hostroute['nexthop']:
            msg = valid.validate_ip_address(hostroute['nexthop'])
        if msg:
            LOG.debug(msg)
            return msg
        if hostroute in hostroutes:
            msg = _("Duplicate hostroute '%s'") % hostroute
            LOG.debug(msg)
            return msg
        hostroutes.append(hostroute)


def _validate_gbp_resource_name(data, valid_values=None):
    # Any REST API defined GBP resource name is restricted to 128 characters
    return valid.validate_string(data, max_len=128)


AUTO_PTG_REGEX = re.compile('auto[0-9a-f]{32}\Z', re.I)


def _validate_gbp_uuid_or_none(data, valid_values=None):
    if data is not None:
        if not bool(AUTO_PTG_REGEX.match(data)):
            return valid.validate_uuid_or_none(data)


valid.validators['type:gbp_port_range'] = _validate_gbp_port_range
valid.validators['type:network_service_params'] = _validate_network_svc_params
valid.validators['type:external_dict'] = _validate_external_dict
valid.validators['type:gbproutes'] = _validate_gbproutes
valid.validators['type:gbp_resource_name'] = _validate_gbp_resource_name
valid.validators['type:gbp_uuid_or_none'] = _validate_gbp_uuid_or_none


POLICY_TARGETS = 'policy_targets'
POLICY_TARGET_GROUPS = 'policy_target_groups'
L2_POLICIES = 'l2_policies'
L3_POLICIES = 'l3_policies'
POLICY_CLASSIFIERS = 'policy_classifiers'
POLICY_ACTIONS = 'policy_actions'
POLICY_RULES = 'policy_rules'
POLICY_RULE_SETS = 'policy_rule_sets'
NETWORK_SERVICE_POLICIES = 'network_service_policies'
EXTERNAL_POLICIES = 'external_policies'
EXTERNAL_SEGMENTS = 'external_segments'
NAT_POOLS = 'nat_pools'
APPLICATION_POLICY_GROUPS = 'application_policy_groups'


RESOURCE_ATTRIBUTE_MAP = {
    POLICY_TARGETS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'policy_target_group_id': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:gbp_uuid_or_none': None},
                                   'required': True, 'is_visible': True},
        'cluster_id': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': None},
                       'default': '', 'is_visible': True}
    },
    POLICY_TARGET_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'policy_targets': {'allow_post': False, 'allow_put': False,
                           'validate': {'type:uuid_list': None},
                           'convert_to': conv.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
        'l2_policy_id': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True},
        'application_policy_group_id': {'allow_post': True, 'allow_put': True,
                                        'validate':
                                        {'type:uuid_or_none': None},
                                        'default': None, 'is_visible': True},
        'provided_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      conv.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        'consumed_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      conv.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        'network_service_policy_id': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:uuid_or_none': None},
                                      'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        'service_management': {'allow_post': True, 'allow_put': True,
                               'default': False,
                               'convert_to': conv.convert_to_boolean,
                               'is_visible': True, 'required_by_policy': True,
                               'enforce_policy': True},
    },
    APPLICATION_POLICY_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'policy_target_groups': {'allow_post': False, 'allow_put': False,
                                 'validate': {'type:uuid_list': None},
                                 'convert_to': conv.convert_none_to_empty_list,
                                 'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    L2_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'policy_target_groups': {'allow_post': False, 'allow_put': False,
                                 'validate': {'type:uuid_list': None},
                                 'convert_to': conv.convert_none_to_empty_list,
                                 'default': None, 'is_visible': True},
        'l3_policy_id': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True,
                         'required': True},
        'inject_default_route': {'allow_post': True, 'allow_put': True,
                                 'default': True, 'is_visible': True,
                                 'convert_to': conv.convert_to_boolean,
                                 'required': False},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        # TODO(Sumit): uncomment when supported in data path
        # 'allow_broadcast': {'allow_post': True, 'allow_put': True,
        #                    'default': True, 'is_visible': True,
        #                    'convert_to': conv.convert_to_boolean,
        #                    'required': False},
    },
    L3_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': conv.convert_to_int,
                       # The value 46 is used to indicate dual-stack
                       # (IPv4 and IPv6)
                       'validate': {'type:values': [4, 6, 46]},
                       'default': 4, 'is_visible': True},
        'ip_pool': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:string_or_none': None},
                    'default': GBP_CONF.default_ip_pool, 'is_visible': True},
        'subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                 'convert_to': conv.convert_to_int,
                                 # This parameter only applies to ipv4
                                 # prefixes. For IPv4 legal values are
                                 # 2 to 30. For ipv6, this parameter
                                 # is ignored
                                 'default': 24, 'is_visible': True},
        'l2_policies': {'allow_post': False, 'allow_put': False,
                        'validate': {'type:uuid_list': None},
                        'convert_to': conv.convert_none_to_empty_list,
                        'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        'external_segments': {
            'allow_post': True, 'allow_put': True, 'default': None,
            'validate': {'type:external_dict': None},
            'convert_to': conv.convert_none_to_empty_dict, 'is_visible': True},
    },
    POLICY_CLASSIFIERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol},
        'port_range': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:gbp_port_range': None},
                       'convert_to': convert_port_to_string,
                       'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:values': gp_supported_directions},
                      'default': gp_constants.GP_DIRECTION_BI,
                      'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_ACTIONS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'action_type': {'allow_post': True, 'allow_put': False,
                        'convert_to': convert_action_to_case_insensitive,
                        'validate': {'type:values': gp_supported_actions},
                        'is_visible': True, 'default': 'allow'},
        'action_value': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_RULES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': conv.convert_to_boolean,
                    'is_visible': True},
        'policy_classifier_id': {'allow_post': True, 'allow_put': True,
                                 'validate': {'type:uuid': None},
                                 'is_visible': True, 'required': True},
        'policy_actions': {'allow_post': True, 'allow_put': True,
                           'default': None, 'is_visible': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': conv.convert_none_to_empty_list},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_RULE_SETS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'parent_id': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'child_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                   'default': None, 'is_visible': True,
                                   'validate': {'type:uuid_list': None},
                                   'convert_to':
                                   conv.convert_none_to_empty_list},
        'policy_rules': {'allow_post': True, 'allow_put': True,
                         'default': None, 'validate': {'type:uuid_list': None},
                         'convert_to': conv.convert_none_to_empty_list,
                         'is_visible': True},
        'consuming_policy_target_groups': {
            'allow_post': False, 'allow_put': False, 'default': None,
            'is_visible': True},
        'consuming_external_policies': {
            'allow_post': False, 'allow_put': False, 'default': None,
            'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    NETWORK_SERVICE_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'policy_target_groups': {'allow_post': False, 'allow_put': False,
                                 'validate': {'type:uuid_list': None},
                                 'convert_to': conv.convert_none_to_empty_list,
                                 'default': None, 'is_visible': True},
        'network_service_params': {'allow_post': True, 'allow_put': False,
                                   'validate':
                                   {'type:network_service_params': None},
                                   'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    EXTERNAL_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'external_segments': {
            'allow_post': True, 'allow_put': True, 'default': None,
            'validate': {'type:uuid_list': None},
            'convert_to': conv.convert_none_to_empty_list, 'is_visible': True},
        'provided_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      conv.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        'consumed_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      conv.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    EXTERNAL_SEGMENTS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': conv.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'default': 4, 'is_visible': True},
        'cidr': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:subnet': None},
                 'default': '172.16.0.0/12', 'is_visible': True},
        'external_policies': {
            'allow_post': False, 'allow_put': False, 'default': None,
            'validate': {'type:uuid_list': None},
            'convert_to': conv.convert_none_to_empty_list, 'is_visible': True},
        'external_routes': {
            'allow_post': True, 'allow_put': True,
            'default': nlib_const.ATTR_NOT_SPECIFIED,
            'validate': {'type:gbproutes': None},
            'is_visible': True},
        'l3_policies': {'allow_post': False, 'allow_put': False,
                        'validate': {'type:uuid_list': None},
                        'convert_to': conv.convert_none_to_empty_list,
                        'default': None, 'is_visible': True},
        'port_address_translation': {
            'allow_post': True, 'allow_put': True,
            'default': False, 'convert_to': conv.convert_to_boolean,
            'is_visible': True, 'required_by_policy': True,
            'enforce_policy': True},
        'nat_pools': {
            'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid_list': None},
            'default': [],
            'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    NAT_POOLS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},
        'ip_version': {'allow_post': True, 'allow_put': False,
                       'convert_to': conv.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'default': 4, 'is_visible': True},
        'ip_pool': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:subnet': None},
                    'is_visible': True},
        'external_segment_id': {'allow_post': True, 'allow_put': True,
                                'validate': {'type:uuid_or_none': None},
                                'is_visible': True, 'required': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': conv.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    }
}


group_based_policy_quota_opts = [
    cfg.IntOpt('quota_l3_policy',
               default=-1,
               help=_('Number of L3 Policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_l2_policy',
               default=-1,
               help=_('Number of L2 Policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_application_policy_group',
               default=-1,
               help=_('Number of Application Policy Groups allowed per tenant.'
                      ' A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_target_group',
               default=-1,
               help=_('Number of Policy Target Groups allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_target',
               default=-1,
               help=_('Number of Policy Targets allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_classifier',
               default=-1,
               help=_('Number of Policy Classifiers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_action',
               default=-1,
               help=_('Number of Policy Actions allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_rule',
               default=-1,
               help=_('Number of Policy Rules allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_policy_rule_set',
               default=-1,
               help=_('Number of Policy Rule Sets allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_external_policy',
               default=-1,
               help=_('Number of External Policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_external_segment',
               default=-1,
               help=_('Number of External Segments allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_nat_pool',
               default=-1,
               help=_('Number of NAT Pools allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_network_service_policy',
               default=-1,
               help=_('Number of Network Service Policies allowed per '
                      'tenant. A negative value means unlimited.')),
]
cfg.CONF.register_opts(group_based_policy_quota_opts, 'QUOTAS')


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
        special_mappings = {
            'l2_policies': 'l2_policy', 'l3_policies': 'l3_policy',
            'network_service_policies': 'network_service_policy',
            'external_policies': 'external_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        gbp_extensions.register_plurals(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.GROUP_POLICY,
                                                   register_quota=True)

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
    def get_policy_targets(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_target(self, context, policy_target_id, fields=None):
        pass

    @abc.abstractmethod
    def create_policy_target(self, context, policy_target):
        pass

    @abc.abstractmethod
    def update_policy_target(self, context, policy_target_id, policy_target):
        pass

    @abc.abstractmethod
    def delete_policy_target(self, context, policy_target_id):
        pass

    @abc.abstractmethod
    def get_policy_target_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_target_group(self, context, policy_target_group_id,
                                fields=None):
        pass

    @abc.abstractmethod
    def create_policy_target_group(self, context, policy_target_group):
        pass

    @abc.abstractmethod
    def update_policy_target_group(self, context, policy_target_group_id,
                                   policy_target_group):
        pass

    @abc.abstractmethod
    def delete_policy_target_group(self, context, policy_target_group_id):
        pass

    @abc.abstractmethod
    def get_application_policy_groups(self, context, filters=None,
                                      fields=None):
        pass

    @abc.abstractmethod
    def get_application_policy_group(self, context,
                                     application_policy_group_id,
                                     fields=None):
        pass

    @abc.abstractmethod
    def create_application_policy_group(self, context,
                                        application_policy_group):
        pass

    @abc.abstractmethod
    def update_application_policy_group(self, context,
                                        application_policy_group_id,
                                        application_policy_group):
        pass

    @abc.abstractmethod
    def delete_application_policy_group(self, context,
                                        application_policy_group_id):
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
    def get_network_service_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_network_service_policy(
        self, context, network_service_policy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_network_service_policy(self, context, network_service_policy):
        pass

    @abc.abstractmethod
    def update_network_service_policy(
        self, context, network_service_policy_id, network_service_policy):
        pass

    @abc.abstractmethod
    def delete_network_service_policy(
        self, context, network_service_policy_id):
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

    @abc.abstractmethod
    def create_policy_rule_set(self, context, policy_rule_set):
        pass

    @abc.abstractmethod
    def update_policy_rule_set(self, context, policy_rule_set_id,
                               policy_rule_set):
        pass

    @abc.abstractmethod
    def get_policy_rule_sets(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_policy_rule_set(self, context, policy_rule_set_id, fields=None):
        pass

    @abc.abstractmethod
    def delete_policy_rule_set(self, context, policy_rule_set_id):
        pass

    @abc.abstractmethod
    def create_external_policy(self, context, external_policy):
        pass

    @abc.abstractmethod
    def update_external_policy(self, context, external_policy_id,
                               external_policy):
        pass

    @abc.abstractmethod
    def get_external_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_external_policy(self, context, external_policy_id,
                            fields=None):
        pass

    @abc.abstractmethod
    def delete_external_policy(self, context, external_policy_id):
        pass

    @abc.abstractmethod
    def create_external_segment(self, context, external_segment):
        pass

    @abc.abstractmethod
    def update_external_segment(self, context, external_segment_id,
                                external_segment):
        pass

    @abc.abstractmethod
    def get_external_segments(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_external_segment(self, context, external_segment_id, fields=None):
        pass

    @abc.abstractmethod
    def delete_external_segment(self, context, external_segment_id):
        pass

    @abc.abstractmethod
    def create_nat_pool(self, context, nat_pool):
        pass

    @abc.abstractmethod
    def update_nat_pool(self, context, nat_pool_id, nat_pool):
        pass

    @abc.abstractmethod
    def get_nat_pools(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_nat_pool(self, context, nat_pool_id, fields=None):
        pass

    @abc.abstractmethod
    def delete_nat_pool(self, context, nat_pool_id):
        pass
