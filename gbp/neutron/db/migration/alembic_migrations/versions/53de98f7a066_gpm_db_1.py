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

"""gpm_db_1

Revision ID: 53de98f7a066
Revises: ab64381ee820
Create Date: 2014-07-24 13:58:14.716984

"""

# revision identifiers, used by Alembic.
revision = '53de98f7a066'
down_revision = 'ab64381ee820'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):

    op.create_table(
        'gp_endpoint_group_subnet_associations',
        sa.Column('endpoint_group_id', sa.String(length=36), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['endpoint_group_id'],
                                ['gp_endpoint_groups.id']),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id']),
        sa.PrimaryKeyConstraint('endpoint_group_id', 'subnet_id')
    )

    op.create_table(
        'gp_l3_policy_router_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id']),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.PrimaryKeyConstraint('l3_policy_id', 'router_id')
    )

    op.add_column(
        'gp_endpoint_groups',
        sa.Column('type', sa.String(length=15), nullable=True)
    )

    op.add_column(
        'gp_endpoints',
        sa.Column('type', sa.String(length=15), nullable=True)
    )

    op.add_column(
        'gp_l2_policies',
        sa.Column('type', sa.String(length=15), nullable=True)
    )

    op.add_column(
        'gp_l3_policies',
        sa.Column('type', sa.String(length=15), nullable=True)
    )

    op.add_column(
        'gp_endpoints',
        sa.Column('port_id', sa.String(length=36), nullable=True)
    )
    op.create_unique_constraint(None, 'gp_endpoints', ['port_id'])

    op.add_column(
        'gp_l2_policies',
        sa.Column('network_id', sa.String(length=36), nullable=True)
    )
    op.create_unique_constraint(None, 'gp_l2_policies', ['network_id'])


def downgrade(active_plugins=None, options=None):

    op.drop_constraint(None, 'gp_l2_policies')
    op.drop_column('gp_l2_policies', 'network_id')
    op.drop_constraint(None, 'gp_endpoints')
    op.drop_column('gp_endpoints', 'port_id')
    op.drop_table('gp_l3_policy_router_associations')
    op.drop_table('gp_endpoint_group_subnet_associations')
    op.drop_column('gp_l3_policies', 'type')
    op.drop_column('gp_l2_policies', 'type')
    op.drop_column('gp_endpoints', 'type')
    op.drop_column('gp_endpoint_groups', 'type')
