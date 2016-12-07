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

"""intra_ptg_allow

Revision ID: fce38a8588a2
Revises: 4af01d620224
Create Date: 2016-12-06 17:01:30.735865

"""

# revision identifiers, used by Alembic.
revision = 'fce38a8588a2'
down_revision = '4af01d620224'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_intra_ptg',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.Column('intra_ptg_allow', sa.Boolean,
                  server_default=sa.sql.true(), nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_target_group_id'], ['gp_policy_target_groups.id'],
            name='gp_apic_intra_ptg_fk_ptgid', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_group_id')
    )


def downgrade():
    pass
