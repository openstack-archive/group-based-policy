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
#

"""Track implicit ownership of Auto PTGs (gpm_auto_ptg_own)

Revision ID: fce38a8588a2
Revises: 5629167be1d1
Create Date: 2016-10-17 16:33:38.199797

"""

# revision identifiers, used by Alembic.
revision = 'fce38a8588a2'
down_revision = '5629167be1d1'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_owned_policy_target_groups',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                name='ipd_auto_ptg_owned_fk',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_group_id')
    )
