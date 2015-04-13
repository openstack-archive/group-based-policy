# Copyright 2014 OpenStack Foundation
#
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

""" gbp_db_network_service_policy

Revision ID: 577bb4469944
"""

# revision identifiers, used by Alembic.
revision = '577bb4469944'
down_revision = '6d76bcf836a7'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_network_service_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_network_service_params',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('param_type', sa.String(length=50), nullable=False),
        sa.Column('param_name', sa.String(length=50), nullable=False),
        sa.Column('param_value', sa.String(length=50), nullable=False),
        sa.Column('network_service_policy_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['network_service_policy_id'],
                                ['gp_network_service_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.add_column(
        'gp_policy_target_groups',
        sa.Column('network_service_policy_id',
                  sa.String(length=36), nullable=True))

    op.create_unique_constraint(None, 'gp_policy_target_groups',
                                ['network_service_policy_id'])

    op.create_foreign_key('gp_policy_target_groups_ibfk_nsp',
                          source='gp_policy_target_groups',
                          referent='gp_network_service_policies',
                          local_cols=['network_service_policy_id'],
                          remote_cols=['id'], ondelete='CASCADE')


def downgrade():

    op.drop_constraint('gp_policy_target_groups_ibfk_nsp',
                       'gp_policy_target_groups',
                       'foreignkey')
    op.drop_column('gp_policy_target_groups', 'network_service_policy_id')
    op.drop_table('gp_network_service_params')
    op.drop_table('gp_network_service_policies')
