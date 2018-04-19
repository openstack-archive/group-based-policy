# Copyright (c) 2018 Cisco Systems Inc.
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

from neutron.tests import base

from gbpservice.neutron.extensions import cisco_apic as apic_ext


class TestAttributeValidators(base.BaseTestCase):

    def test_validate_apic_vlan(self):
        self.assertIsNone(apic_ext._validate_apic_vlan(None))
        self.assertIsNone(apic_ext._validate_apic_vlan('10'))
        self.assertIsNone(apic_ext._validate_apic_vlan(10))


class TestAttributeConverters(base.BaseTestCase):

    def test_convert_apic_vlan(self):
        self.assertIsInstance(apic_ext.convert_apic_vlan('2'), int)
        self.assertIsInstance(apic_ext.convert_apic_vlan(2), int)
        self.assertIsNone(apic_ext.convert_apic_vlan(None))

    def test_convert_nested_domain_allowed_vlans(self):
        test_dict_str = "{'vlans_list': [2, 3, 4], " + (
                        "'vlan_ranges': [{'start': 6, 'end': 9}, ") + (
                        "{'start': 11, 'end': 14}]}")
        expt_list = [2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14]
        self.assertItemsEqual(
                apic_ext.convert_nested_domain_allowed_vlans(
                    test_dict_str)['vlans_list'], expt_list)
        test_dict = {'vlans_list': [2, 3, 4],
                     'vlan_ranges': [{'start': 6, 'end': 9},
                                     {'start': 11, 'end': 14}]}
        expt_list = [2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14]
        self.assertItemsEqual(
                apic_ext.convert_nested_domain_allowed_vlans(
                    test_dict)['vlans_list'], expt_list)
        test_dict = {'vlans_list': ['2', '3', '4', '3'],
                     'vlan_ranges': [{'start': '6', 'end': '9'},
                                     {'start': '11', 'end': '14'},
                                     {'start': '6', 'end': '9'}]}
        expt_list = [2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14]
        self.assertItemsEqual(
                apic_ext.convert_nested_domain_allowed_vlans(
                    test_dict)['vlans_list'], expt_list)
        self.assertIsNone(apic_ext.convert_nested_domain_allowed_vlans(None))
