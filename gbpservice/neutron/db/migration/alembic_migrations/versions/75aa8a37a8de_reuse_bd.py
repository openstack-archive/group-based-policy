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

"""Reuse BD

Revision ID: 75aa8a37a8de
Revises: a707faecf518
Create Date: 2016-11-11 17:01:30.735865

"""

# revision identifiers, used by Alembic.
revision = '75aa8a37a8de'
down_revision = 'a707faecf518'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_mapping_reuse_bds',
        sa.Column('l2_policy_id', sa.String(length=36), nullable=False),
        sa.Column('target_l2_policy_id', sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(
            ['l2_policy_id'], ['gp_l2_policies.id'],
            name='gp_apic_mapping_reuse_bd_fk_l2pid',
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['target_l2_policy_id'], ['gp_l2_policies.id'],
            name='gp_apic_mapping_reuse_bd_target_l2p_id_fk_l2pid'),
        sa.PrimaryKeyConstraint('l2_policy_id')
    )


def downgrade():
    pass
