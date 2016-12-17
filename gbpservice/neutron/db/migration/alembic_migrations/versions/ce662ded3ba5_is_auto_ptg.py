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

"""is_auto_ptg

Revision ID: ce662ded3ba5
Revises: ef5a69e5bcc5
Create Date: 2016-12-15 16:13:23.836874

"""

# revision identifiers, used by Alembic.
revision = 'ce662ded3ba5'
down_revision = 'ef5a69e5bcc5'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_auto_ptg',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.Column('is_auto_ptg', sa.Boolean,
                  server_default=sa.sql.false(), nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_target_group_id'], ['gp_policy_target_groups.id'],
            name='gp_apic_auto_ptg_fk_ptgid', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_group_id')
    )


def downgrade():
    pass
