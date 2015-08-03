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

from gbpservice.neutron.extensions import group_policy as gp


class InvalidProxiedGroup(nexc.InvalidInput):
    message = _("Proxied group %(group_id)s already has a proxy.")


EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGET_GROUPS: {
        'proxied_group_id': {
            'allow_post': True, 'allow_put': False,
            'validate': {'type:uuid_or_none': None}, 'is_visible': True,
            'default': attr.ATTR_NOT_SPECIFIED,
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
                          'default': '192.168.0.0/16', 'is_visible': True},
        'proxy_subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                       'convert_to': attr.convert_to_int,
                                       # for ipv4 legal values are 2 to 30
                                       # for ipv6 legal values are 2 to 127
                                       'default': 29, 'is_visible': True},
        # Proxy IP version is the same as the standard L3 pool ip version
    },
}


class Driver_proxy_group(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "group policy poxy group extension"

    @classmethod
    def get_alias(cls):
        return "proxy_group"

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
