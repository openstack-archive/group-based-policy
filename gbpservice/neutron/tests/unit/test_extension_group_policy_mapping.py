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

import copy
import six

from neutron.plugins.common import constants
from neutron_lib import constants as n_constants

from gbpservice.neutron.extensions import group_policy as gp
from gbpservice.neutron.extensions import group_policy_mapping as gpm
from gbpservice.neutron.tests.unit import common as cm
from gbpservice.neutron.tests.unit import test_extension_group_policy as tgp


class GroupPolicyMappingExtTestCase(tgp.GroupPolicyExtensionTestCase):
    def setUp(self):
        self._saved_gp_attr_map = {}
        for k, v in six.iteritems(gp.RESOURCE_ATTRIBUTE_MAP):
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

    def get_create_policy_target_default_attrs_and_prj_id(self):
        attrs = cm.get_create_policy_target_default_attrs_and_prj_id()
        attrs.update({'port_id': None})
        return attrs

    def get_create_policy_target_attrs(self):
        attrs = cm.get_create_policy_target_attrs()
        attrs.update({'port_id': tgp._uuid()})
        fixed_ips = [{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                      'ip_address': '11.1.1.1'}]
        attrs.update({'fixed_ips': fixed_ips})
        return attrs

    def get_update_policy_target_attrs(self):
        attrs = cm.get_update_policy_target_attrs()
        fixed_ips = [{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                      'ip_address': '11.1.1.1'}]
        attrs.update({'fixed_ips': fixed_ips})
        return attrs

    def get_create_policy_target_group_default_attrs(self):
        attrs = cm.get_create_policy_target_group_default_attrs()
        attrs.update({'subnets': []})
        return attrs

    def get_create_policy_target_group_default_attrs_and_prj_id(self):
        attrs = cm.get_create_policy_target_group_default_attrs_and_prj_id()
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

    def get_create_l2_policy_default_attrs_and_prj_id(self):
        attrs = cm.get_create_l2_policy_default_attrs_and_prj_id()
        attrs.update({'network_id': None})
        return attrs

    def get_create_l2_policy_attrs(self):
        attrs = cm.get_create_l2_policy_attrs()
        attrs.update({'network_id': tgp._uuid()})
        return attrs

    def get_create_l3_policy_default_attrs(self):
        attrs = cm.get_create_l3_policy_default_attrs()
        attrs.update({'address_scope_v4_id': None})
        attrs.update({'address_scope_v6_id': None})
        attrs.update({'subnetpools_v4': []})
        attrs.update({'subnetpools_v6': []})
        attrs.update({'routers': []})
        return attrs

    def get_create_l3_policy_default_attrs_and_prj_id(self):
        attrs = cm.get_create_l3_policy_default_attrs_and_prj_id()
        attrs.update({'address_scope_v4_id': None})
        attrs.update({'address_scope_v6_id': None})
        attrs.update({'subnetpools_v4': []})
        attrs.update({'subnetpools_v6': []})
        attrs.update({'routers': []})
        return attrs

    def get_create_l3_policy_attrs(self):
        attrs = cm.get_create_l3_policy_attrs()
        attrs.update({'address_scope_v4_id': tgp._uuid()})
        attrs.update({'address_scope_v6_id': tgp._uuid()})
        attrs.update({'subnetpools_v4': [tgp._uuid(), tgp._uuid()]})
        attrs.update({'subnetpools_v6': [tgp._uuid(), tgp._uuid()]})
        attrs.update({'routers': [tgp._uuid(), tgp._uuid()]})
        return attrs

    def get_update_l3_policy_attrs(self):
        attrs = cm.get_update_l3_policy_attrs()
        attrs.update({'subnetpools_v4': [tgp._uuid(), tgp._uuid()]})
        attrs.update({'subnetpools_v6': [tgp._uuid(), tgp._uuid()]})
        attrs.update({'routers': [tgp._uuid(), tgp._uuid()]})
        return attrs

    def get_create_external_segment_default_attrs(self):
        attrs = cm.get_create_external_segment_default_attrs()
        attrs.update({'subnet_id': None})
        return attrs

    def get_create_external_segment_default_attrs_and_prj_id(self):
        attrs = cm.get_create_external_segment_default_attrs_and_prj_id()
        attrs.update({'subnet_id': None})
        return attrs

    def get_create_external_segment_attrs(self):
        attrs = cm.get_create_external_segment_attrs()
        attrs.update({'subnet_id': tgp._uuid()})
        return attrs

    def test_create_policy_target_with_defaults(self):
        policy_target_id = tgp._uuid()
        data = {'policy_target': {'policy_target_group_id': tgp._uuid(),
                                  'tenant_id': tgp._uuid()}}
        default_attrs = (
            self.get_create_policy_target_default_attrs_and_prj_id())
        default_data = copy.copy(data)
        default_data['policy_target'].update(default_attrs)
        expected_value = dict(default_data['policy_target'])
        expected_value['id'] = policy_target_id
        expected_value['fixed_ips'] = n_constants.ATTR_NOT_SPECIFIED

        self._test_create_policy_target(data, expected_value, default_data)
