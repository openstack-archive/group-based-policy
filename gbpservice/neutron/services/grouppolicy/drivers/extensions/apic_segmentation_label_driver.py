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

from oslo_log import log as logging

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_segmentation_label_db as db)
from gbpservice.neutron.extensions import apic_segmentation_label as aslext
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class ApicSegmentationLabelExtensionDriver(api.ExtensionDriver,
                                           db.ApicSegmentationLabelDBMixin):
    _supported_extension_alias = aslext.CISCO_APIC_GBP_SEGMENTATION_LABEL_EXT
    _extension_dict = aslext.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.debug("APIC Segmentation Label Extension Driver  __init__")
        self._policy_driver = None

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_policy_target(self, session, data, result):
        pt = data['policy_target']
        if 'segmentation_labels' in pt:
            for label in pt['segmentation_labels']:
                self.add_policy_target_segmentation_label(
                    session, policy_target_id=result['id'],
                    segmentation_label=label)

    def process_update_policy_target(self, session, data, result):
        pt = data['policy_target']
        if not 'segmentation_labels' in pt:
            self.extend_policy_target_dict(session, result)
            return
        rows = self.get_policy_target_segmentation_labels(
            session, policy_target_id=result['id'])
        old_labels = [r.segmentation_label for r in rows]
        add_labels = list(set(pt['segmentation_labels']) - set(old_labels))
        for label in add_labels:
            self.add_policy_target_segmentation_label(
                session, policy_target_id=result['id'],
                segmentation_label=label)
        delete_labels = list(set(old_labels) - set(pt['segmentation_labels']))
        for label in delete_labels:
            self.delete_policy_target_segmentation_label(
                session, policy_target_id=result['id'],
                segmentation_label=label)
        result['segmentation_labels'] = pt['segmentation_labels']

    def extend_policy_target_dict(self, session, result):
        rows = self.get_policy_target_segmentation_labels(
            session, policy_target_id=result['id'])
        labels = [r.segmentation_label for r in rows]
        result['segmentation_labels'] = labels
