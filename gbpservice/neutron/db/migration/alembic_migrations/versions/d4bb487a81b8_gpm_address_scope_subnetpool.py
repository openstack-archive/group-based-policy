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

"""address_scope and subnetpool mapping for l3_policies

Revision ID: d4bb487a81b8
Revises: c1aab79622fe
Create Date: 2016-08-28 11:35:32.724952

"""

# revision identifiers, used by Alembic.
revision = 'd4bb487a81b8'
down_revision = '7afacef00d31'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_l3_policy_subnetpool_v4_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id'],
                                name='gpm_l3p_subnetpool_v4_assoc_fk_l3pid'),
        sa.ForeignKeyConstraint(['subnetpool_id'], ['subnetpools.id'],
                                name='gpm_l3p_subnetpool_v4_assoc_fk_spid'),
        sa.PrimaryKeyConstraint('l3_policy_id', 'subnetpool_id')
    )

    op.create_table(
        'gp_l3_policy_subnetpool_v6_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id'],
                                name='gpm_l3p_subnetpool_v6_assoc_fk_l3pid'),
        sa.ForeignKeyConstraint(['subnetpool_id'], ['subnetpools.id'],
                                name='gpm_l3p_subnetpool_v6_assoc_fk_spid'),
        sa.PrimaryKeyConstraint('l3_policy_id', 'subnetpool_id')
    )

    op.add_column(
        'gp_l3_policies',
        sa.Column('address_scope_v4_id', sa.String(length=36), nullable=True),
    )

    op.add_column(
        'gp_l3_policies',
        sa.Column('address_scope_v6_id', sa.String(length=36), nullable=True),
    )

    op.create_unique_constraint('gpm_l3p_addr_scope_v4_uq',
                                'gp_l3_policies', ['address_scope_v4_id'])
    op.create_unique_constraint('gpm_l3p_addr_scope_v6_uq',
                                'gp_l3_policies', ['address_scope_v6_id'])
    op.create_foreign_key('gpm_l3p_addr_scope_v4_fk',
                          source='gp_l3_policies', referent='address_scopes',
                          local_cols=['address_scope_v4_id'],
                          remote_cols=['id'])
    op.create_foreign_key('gpm_l3p_addr_scope_v6_fk',
                          source='gp_l3_policies', referent='address_scopes',
                          local_cols=['address_scope_v6_id'],
                          remote_cols=['id'])

    op.create_table(
        'gpm_owned_address_scopes',
        sa.Column('address_scope_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['address_scope_id'], ['address_scopes.id'],
            name='rmd_addr_scope_owned_fk', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address_scope_id')
    )

    op.create_table(
        'gpm_owned_subnetpools',
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnetpool_id'], ['subnetpools.id'],
                                name='rmd_subnetpool_owned_fk',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnetpool_id')
    )


def downgrade():
    pass
