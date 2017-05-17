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

from neutron_lib.api import extensions
from neutron_lib import constants

from gbpservice.neutron.extensions import group_policy as gp


EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGETS: {
        'pt_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.POLICY_TARGET_GROUPS: {
        'ptg_extension': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True,
                          'enforce_policy': True},
    },
    gp.L2_POLICIES: {
        'l2p_extension': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True,
                          'enforce_policy': True},
    },
    gp.L3_POLICIES: {
        'l3p_extension': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True,
                          'enforce_policy': True},
    },
    gp.POLICY_CLASSIFIERS: {
        'pc_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.POLICY_ACTIONS: {
        'pa_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.POLICY_RULES: {
        'pr_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.POLICY_RULE_SETS: {
        'prs_extension': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True,
                          'enforce_policy': True},
    },
    gp.NETWORK_SERVICE_POLICIES: {
        'nsp_extension': {'allow_post': True,
                          'allow_put': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True,
                          'enforce_policy': True},
    },
    gp.EXTERNAL_SEGMENTS: {
        'es_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.EXTERNAL_POLICIES: {
        'ep_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
    gp.NAT_POOLS: {
        'np_extension': {'allow_post': True,
                         'allow_put': True,
                         'default': constants.ATTR_NOT_SPECIFIED,
                         'is_visible': True,
                         'enforce_policy': True},
    },
}


class Test_extension(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "group policy test extension"

    @classmethod
    def get_alias(cls):
        return "test_extension"

    @classmethod
    def get_description(cls):
        return _("Adds test attributes to group policy resources.")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/grouppolicy/test/"
                "test_extension/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2014-10-24T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
