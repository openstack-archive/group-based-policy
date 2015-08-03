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

"""Proxy Group Mapping

Revision ID: acb613677ffa
"""

# revision identifiers, used by Alembic.
revision = 'acb613677ffa'
down_revision = 'c2a9d04c8cef'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_group_proxy_mappings',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.Column('proxied_group_id', sa.String(length=36)),
        sa.Column('proxy_group_id', sa.String(length=36)),
        sa.Column('proxy_type', sa.String(length=24)),
        sa.PrimaryKeyConstraint('policy_target_group_id'),
        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['proxied_group_id'],
                                ['gp_policy_target_groups.id']),
        sa.ForeignKeyConstraint(['proxy_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='SET NULL')
    )
    op.create_table(
        'gp_proxy_gateway_mappings',
        sa.Column('policy_target_id', sa.String(length=36), nullable=False),
        sa.Column('proxy_gateway', sa.Boolean, nullable=False, default=False),
        sa.Column('group_default_gateway', sa.Boolean, nullable=False,
                  default=False),
        sa.PrimaryKeyConstraint('policy_target_id'),
        sa.ForeignKeyConstraint(['policy_target_id'],
                                ['gp_policy_targets.id'],
                                ondelete='CASCADE',
                                name='group_proxy_mapping_fk_ptg_id'),
    )

    op.create_table(
        'gp_proxy_ip_pool_mapping',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('proxy_ip_pool', sa.String(length=64), nullable=False),
        sa.Column('proxy_subnet_prefix_length', sa.Integer, nullable=False),

        sa.PrimaryKeyConstraint('l3_policy_id'),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id'],
                                ondelete='CASCADE',
                                name='proxy_ip_pool_mapping_fk_l3_policy_id'),
    )


def downgrade():
    pass
