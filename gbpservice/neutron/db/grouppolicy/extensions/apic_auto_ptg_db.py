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


class ApicAutoPtgDB(model_base.BASEV2):
    __tablename__ = 'gp_apic_auto_ptg'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete='CASCADE'), primary_key=True)
    is_auto_ptg = sa.Column(sa.Boolean, default=False, nullable=False)


class ApicAutoPtgDBMixin(object):

    def get_is_auto_ptg(self, session, policy_target_group_id):
        row = (session.query(ApicAutoPtgDB).filter_by(
               policy_target_group_id=policy_target_group_id).one())
        return row['is_auto_ptg']

    def set_is_auto_ptg(self, session, policy_target_group_id,
                        is_auto_ptg=False):
        with session.begin(subtransactions=True):
            row = ApicAutoPtgDB(policy_target_group_id=policy_target_group_id,
                                is_auto_ptg=is_auto_ptg)
            session.add(row)
