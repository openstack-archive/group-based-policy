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

from neutron.db import api as db_api

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_segmentation_label_db as db)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)


class ExtensionDriverTestCaseMixin(object):

    def test_pt_lifecycle(self):
        ptg = self.create_policy_target_group()['policy_target_group']

        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self.assertEqual([], pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertEqual([], pt['segmentation_labels'])
        self.delete_policy_target(pt['id'], expected_res_status=204)

        labels = []
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            segmentation_labels=labels)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual([], pt['segmentation_labels'])
        self.delete_policy_target(pt['id'], expected_res_status=204)

        labels = ['red', 'blue']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            segmentation_labels=labels)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        labels = ['green', 'black', 'red']
        pt = self.update_policy_target(
            pt['id'], segmentation_labels=labels,
            expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        labels = []
        pt = self.update_policy_target(
            pt['id'], segmentation_labels=labels,
            expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        labels = ['black']
        pt = self.update_policy_target(
            pt['id'], segmentation_labels=labels,
            expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])
        pt = self.show_policy_target(
            pt['id'], expected_res_status=200)['policy_target']
        self.assertItemsEqual(labels, pt['segmentation_labels'])

        self.delete_policy_target(pt['id'], expected_res_status=204)
        session = db_api.get_reader_session()
        rows = (session.query(db.ApicSegmentationLabelDB).filter_by(
                policy_target_id=pt['id']).all())
        self.assertEqual([], rows)


class ExtensionDriverTestCase(test_ext_base.ExtensionDriverTestBase,
                              ExtensionDriverTestCaseMixin):
    _extension_drivers = ['apic_segmentation_label']
    _extension_path = None
