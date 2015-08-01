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
down_revision = '5358a28fb97d'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'group_proxy_mapping',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.Column('proxied_group_id', sa.String(length=36), nullable=False),
        sa.Column('proxy_group_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('policy_target_group_id'),

        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE',
                                name='group_proxy_mapping_fk_ptg_id'),
        sa.ForeignKeyConstraint(['proxied_group_id'],
                                ['gp_policy_target_groups.id'],
                                name='group_proxy_mapping_fk_proxied_ptg_id'),
        sa.ForeignKeyConstraint(['proxy_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='SET NULL',
                                name='group_proxy_mapping_fk_proxy_ptg_id'),
        sa.UniqueConstraint('proxied_group_id', 'proxy_group_id')
    )


def downgrade():
    pass
