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

from neutron_lib.db import model_base
import sqlalchemy as sa


class ApicIntraPtgDB(model_base.BASEV2):
    __tablename__ = 'gp_apic_intra_ptg'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete='CASCADE'), primary_key=True)
    intra_ptg_allow = sa.Column(sa.Boolean, default=True, nullable=False)


class ApicIntraPtgDBMixin(object):

    def get_intra_ptg_allow(self, session, policy_target_group_id):
        row = (session.query(ApicIntraPtgDB).filter_by(
               policy_target_group_id=policy_target_group_id).one())
        return row['intra_ptg_allow']

    def set_intra_ptg_allow(self, session, policy_target_group_id,
                            intra_ptg_allow=True):
        with session.begin(subtransactions=True):
            row = (session.query(ApicIntraPtgDB).filter_by(
                policy_target_group_id=policy_target_group_id).first())
            if not row:
                row = ApicIntraPtgDB(
                    policy_target_group_id=policy_target_group_id,
                    intra_ptg_allow=intra_ptg_allow)
                session.add(row)
            else:
                row.update({'intra_ptg_allow': intra_ptg_allow})
