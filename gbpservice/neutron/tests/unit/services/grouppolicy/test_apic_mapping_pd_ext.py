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

from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)


class ExtensionDriverTestCaseMixin(object):

    def test_pt_lifecycle(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        labels = ['red', 'blue']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            segmentation_labels=labels)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        # Updating the object just ignores the extension
        labels = ['green', 'black']
        pt = self.update_policy_target(
            pt['id'], name='somenewname',
            segmentation_labels=labels,
            expected_res_status=200)['policy_target']
        self.assertEqual('somenewname', pt['name'])
        self.assertItemsEqual(labels, pt['segmentation_labels'])


class ExtensionDriverTestCase(test_ext_base.ExtensionDriverTestBase,
                              ExtensionDriverTestCaseMixin):
    _extension_drivers = ['apic_mapping_extension']
    _extension_path = None
