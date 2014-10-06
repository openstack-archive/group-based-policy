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

""" gbp_db_ep_epg_l2_l3_policy

Revision ID: ab64381ee820
"""

# revision identifiers, used by Alembic.
revision = 'ab64381ee820'
down_revision = None


from alembic import op
import sqlalchemy as sa


def upgrade(neutron_db=None):

    op.create_table(
        'gp_l3_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('ip_version', sa.Integer, nullable=False),
        sa.Column('ip_pool', sa.String(length=64), nullable=False),
        sa.Column('subnet_prefix_length', sa.Integer, nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_DEFAULT_CHARSET='utf8')

    op.create_table(
        'gp_l2_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('l3_policy_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_policy_id'],
                                ['gp_l3_policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        mysql_DEFAULT_CHARSET='utf8')

    op.create_table(
        'gp_endpoint_groups',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('l2_policy_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l2_policy_id'],
                                ['gp_l2_policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        mysql_DEFAULT_CHARSET='utf8')

    op.create_table(
        'gp_endpoints',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('endpoint_group_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['endpoint_group_id'],
                                ['gp_endpoint_groups.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        mysql_DEFAULT_CHARSET='utf8')


def downgrade(neutron_db=None):

    op.drop_table('gp_endpoints')
    op.drop_table('gp_endpoint_groups')
    op.drop_table('gp_l2_policies')
    op.drop_table('gp_l3_policies')
