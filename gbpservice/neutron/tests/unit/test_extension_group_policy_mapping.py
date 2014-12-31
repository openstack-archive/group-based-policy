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

from neutron.plugins.common import constants

from gbpservice.neutron.extensions import group_policy as gp
from gbpservice.neutron.extensions import group_policy_mapping as gpm
from gbpservice.neutron.tests.unit import common as cm
from gbpservice.neutron.tests.unit import test_extension_group_policy as tgp


class GroupPolicyMappingExtTestCase(tgp.GroupPolicyExtensionTestCase):
    def setUp(self):
        self._saved_gp_attr_map = {}
        for k, v in gp.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self._saved_gp_attr_map[k] = v.copy()
        self.addCleanup(self._restore_gp_attr_map)

        super(tgp.GroupPolicyExtensionTestCase, self).setUp()

        attr_map = gp.RESOURCE_ATTRIBUTE_MAP
        attr_map[gp.POLICY_TARGETS].update(
            gpm.EXTENDED_ATTRIBUTES_2_0[gp.POLICY_TARGETS])
        attr_map[gp.POLICY_TARGET_GROUPS].update(
            gpm.EXTENDED_ATTRIBUTES_2_0[gp.POLICY_TARGET_GROUPS])
        attr_map[gp.L2_POLICIES].update(
            gpm.EXTENDED_ATTRIBUTES_2_0[gp.L2_POLICIES])
        attr_map[gp.L3_POLICIES].update(
            gpm.EXTENDED_ATTRIBUTES_2_0[gp.L3_POLICIES])
        attr_map[gp.EXTERNAL_SEGMENTS].update(
            gpm.EXTENDED_ATTRIBUTES_2_0[gp.EXTERNAL_SEGMENTS])
        plural_mappings = {'l2_policy': 'l2_policies',
                           'l3_policy': 'l3_policies',
                           'network_service_policy':
                           'network_service_policies',
                           'external_policy':
                           'external_policies'}
        self._setUpExtension(
            tgp.GP_PLUGIN_BASE_NAME, constants.GROUP_POLICY, attr_map,
            gp.Group_policy, tgp.GROUPPOLICY_URI,
            plural_mappings=plural_mappings)
        self.instance = self.plugin.return_value

    def _restore_gp_attr_map(self):
        gp.RESOURCE_ATTRIBUTE_MAP = self._saved_gp_attr_map

    def get_create_policy_target_default_attrs(self):
        attrs = cm.get_create_policy_target_default_attrs()
        attrs.update({'port_id': None})
        return attrs

    def get_create_policy_target_attrs(self):
        attrs = cm.get_create_policy_target_attrs()
        attrs.update({'port_id': tgp._uuid()})
        return attrs

    def get_create_policy_target_group_default_attrs(self):
        attrs = cm.get_create_policy_target_group_default_attrs()
        attrs.update({'subnets': []})
        return attrs

    def get_create_policy_target_group_attrs(self):
        attrs = cm.get_create_policy_target_group_attrs()
        attrs.update({'subnets': [tgp._uuid()]})
        return attrs

    def get_update_policy_target_group_attrs(self):
        attrs = cm.get_update_policy_target_group_attrs()
        attrs.update({'subnets': [tgp._uuid()]})
        return attrs

    def get_create_l2_policy_default_attrs(self):
        attrs = cm.get_create_l2_policy_default_attrs()
        attrs.update({'network_id': None})
        return attrs

    def get_create_l2_policy_attrs(self):
        attrs = cm.get_create_l2_policy_attrs()
        attrs.update({'network_id': tgp._uuid()})
        return attrs

    def get_create_l3_policy_default_attrs(self):
        attrs = cm.get_create_l3_policy_default_attrs()
        attrs.update({'routers': []})
        return attrs

    def get_create_l3_policy_attrs(self):
        attrs = cm.get_create_l3_policy_attrs()
        attrs.update({'routers': [tgp._uuid(), tgp._uuid()]})
        return attrs

    def get_update_l3_policy_attrs(self):
        attrs = cm.get_update_l3_policy_attrs()
        attrs.update({'routers': [tgp._uuid(), tgp._uuid()]})
        return attrs

    def get_create_external_segment_default_attrs(self):
        attrs = cm.get_create_external_segment_default_attrs()
        attrs.update({'subnet_id': None})
        return attrs

    def get_create_external_segment_attrs(self):
        attrs = cm.get_create_external_segment_attrs()
        attrs.update({'subnet_id': tgp._uuid()})
        return attrs
