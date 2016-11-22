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

"""proxy address_scope and subnetpool mapping for l3_policies

Revision ID: 0941b4ab781f
Revises: 4af01d620224
Create Date: 2016-08-28 11:35:32.724952

"""

# revision identifiers, used by Alembic.
revision = '0941b4ab781f'
down_revision = 'fce38a8588a2'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_l3_policy_proxy_subnetpool_v4_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['l3_policy_id'], ['gp_proxy_ip_pool_mapping.l3_policy_id'],
            name='gpm_l3p_proxy_subnetpool_v4_assoc_fk_l3pid',
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['subnetpool_id'], ['subnetpools.id'],
            name='gpm_l3p_proxy_subnetpool_v4_assoc_fk_spid'),
        sa.PrimaryKeyConstraint('l3_policy_id', 'subnetpool_id')
    )

    op.create_table(
        'gp_l3_policy_proxy_subnetpool_v6_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['l3_policy_id'], ['gp_proxy_ip_pool_mapping.l3_policy_id'],
            name='gpm_l3p_proxy_subnetpool_v6_assoc_fk_l3pid',
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['subnetpool_id'], ['subnetpools.id'],
            name='gpm_l3p_proxy_subnetpool_v4_assoc_fk_spid'),
        sa.PrimaryKeyConstraint('l3_policy_id', 'subnetpool_id')
    )


def downgrade():
    pass
