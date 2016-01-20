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
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexc
from oslo_config import cfg

from gbpservice.neutron.extensions import group_policy as gp
from gbpservice.neutron.services.grouppolicy.common import exceptions as gp_exc

PROXY_TYPE_L2 = 'l2'
PROXY_TYPE_L3 = 'l3'
DEFAULT_PROXY_TYPE = PROXY_TYPE_L3
PROXY_GROUP = 'proxy_group'

opts = [
    cfg.StrOpt('default_proxy_ip_pool',
               default='192.168.0.0/16',
               help=_("Proxy IP pool for implicitly created default "
                      "L3 policies, from which subnets are allocated for "
                      "policy target groups with proxy_group_id set to a "
                      "valid value.")),
    cfg.IntOpt('default_proxy_subnet_prefix_length',
               default=28,
               help=_("Proxy Subnet prefix length for implicitly created "
                      "default L3 polices, controlling size of subnets "
                      "allocated for policy target groups with proxy_group_id "
                      "set to a valid value.")),
]

cfg.CONF.register_opts(opts, "group_policy_proxy_group")
PROXY_CONF = cfg.CONF.group_policy_proxy_group


class ProxyGroupBadRequest(gp_exc.GroupPolicyBadRequest):
    message = _("Invalid input for Proxy Group extension, reason: %(msg)s")


class InvalidProxiedGroup(nexc.InvalidInput, ProxyGroupBadRequest):
    message = _("Proxied group %(group_id)s already has a proxy.")


class ProxyTypeSetWithoutProxiedPTG(nexc.InvalidInput, ProxyGroupBadRequest):
    message = _("Proxy type can't be set without a proxied PTG.")


class InvalidProxyGatewayGroup(nexc.InvalidInput, ProxyGroupBadRequest):
    message = _("Proxy gateway can't be set for non proxy PTG %(group_id)s.")


EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGET_GROUPS: {
        'proxied_group_id': {
            'allow_post': True, 'allow_put': False,
            'validate': {'type:uuid_or_none': None}, 'is_visible': True,
            'default': attr.ATTR_NOT_SPECIFIED,
            'enforce_policy': True},
        'proxy_type': {
            'allow_post': True, 'allow_put': False,
            'validate': {'type:values': ['l2', 'l3', None]},
            'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED,
            'enforce_policy': True},
        'proxy_group_id': {
            'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid_or_none': None}, 'is_visible': True,
            'enforce_policy': True},
        # TODO(ivar): The APIs should allow the creation of a group with a
        # custom subnet prefix length. It may be useful for both the proxy
        # groups and traditional ones.
    },
    gp.L3_POLICIES: {
        'proxy_ip_pool': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:subnet': None},
                          'default': PROXY_CONF.default_proxy_ip_pool,
                          'is_visible': True},
        'proxy_subnet_prefix_length': {
            'allow_post': True, 'allow_put': True,
            'convert_to': attr.convert_to_int,
            'default': attr.convert_to_int(
                PROXY_CONF.default_proxy_subnet_prefix_length),
            'is_visible': True},
        # Proxy IP version is the same as the standard L3 pool ip version
    },
    gp.POLICY_TARGETS: {
        # This policy target will be used to reach the -proxied- PTG
        'proxy_gateway': {
            'allow_post': True, 'allow_put': False, 'default': False,
            'convert_to': attr.convert_to_boolean,
            'is_visible': True, 'required_by_policy': True,
            'enforce_policy': True},
        # This policy target is the default gateway for the -current- PTG
        # Only for internal use.
        'group_default_gateway': {
            'allow_post': True, 'allow_put': False, 'default': False,
            'convert_to': attr.convert_to_boolean,
            'is_visible': True, 'required_by_policy': True,
            'enforce_policy': True},
    },
}


class Driver_proxy_group(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "group policy poxy group extension"

    @classmethod
    def get_alias(cls):
        return PROXY_GROUP

    @classmethod
    def get_description(cls):
        return _("Add proxy_group_id attribute to policy target groups.")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/grouppolicy/"
                "proxy_group/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2015-08-03T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
