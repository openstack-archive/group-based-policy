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

from neutron.db import model_base
import sqlalchemy as sa


class ApicMappingExtensionDB(model_base.BASEV2):
    __tablename__ = 'gp_apic_mapping_segmentation_lablels'
    policy_target_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_targets.id',
                                     ondelete="CASCADE"), primary_key=True)
    segmentation_label = sa.Column(sa.String(512), primary_key=True)


class ApicMappingExtensionDBMixin(object):

    def get_policy_target_segmentation_labels(self, session, policy_target_id):
        rows = (session.query(ApicMappingExtensionDB).filter_by(
                policy_target_id=policy_target_id).all())
        return rows

    def get_policy_target_segmentation_label(self, session, policy_target_id,
                                             segmentation_label):
        row = (session.query(ApicMappingExtensionDB).filter_by(
            policy_target_id=policy_target_id,
            segmentation_label=segmentation_label).one())
        return row

    def add_policy_target_segmentation_label(self, session, policy_target_id,
                                             segmentation_label):
        row = ApicMappingExtensionDB(policy_target_id=policy_target_id,
                                     segmentation_label=segmentation_label)
        session.add(row)

    def delete_policy_target_segmentation_label(
        self, session, policy_target_id, segmentation_label):
        row = self.get_policy_target_segmentation_label(
            session, policy_target_id, segmentation_label)
        session.delete(row)
