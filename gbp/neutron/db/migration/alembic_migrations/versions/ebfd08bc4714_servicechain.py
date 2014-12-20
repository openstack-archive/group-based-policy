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

"""servicechain

Revision ID: ebfd08bc4714
Revises: 53de98f7a066
Create Date: 2014-07-24 16:12:22.610815

"""

# revision identifiers, used by Alembic.
revision = 'ebfd08bc4714'
down_revision = '5c65abe72596'


from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'sc_nodes',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('service_type', sa.String(length=50), nullable=True),
        sa.Column('config', sa.String(length=4096), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sc_specs',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('config_param_names', sa.String(length=4096), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sc_instances',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('config_param_values', sa.String(length=4096),
                  nullable=True),
        sa.Column('provider_ptg_id', sa.String(length=36), nullable=True),
        sa.Column('consumer_ptg_id', sa.String(length=36), nullable=True),
        sa.Column('classifier_id', sa.String(length=36), nullable=True),
        # FixMe(Magesh) If cascade on delete is used, we lose this info !!!
        # sa.ForeignKeyConstraint(['provider_ptg_id'],
        #                         ['gp_policy_target_groups.id'],
        #                         ondelete='CASCADE'),
        # sa.ForeignKeyConstraint(['consumer_ptg_id'],
        #                         ['gp_policy_target_groups.id'],
        #                         ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sc_spec_node_associations',
        sa.Column('servicechain_spec_id',
                  sa.String(length=36),
                  nullable=False),
        sa.Column('node_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['servicechain_spec_id'], ['sc_specs.id']),
        sa.ForeignKeyConstraint(['node_id'], ['sc_nodes.id']),
        sa.PrimaryKeyConstraint('servicechain_spec_id', 'node_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('sc_spec_node_associations')
    op.drop_table('sc_instances')
    op.drop_table('sc_specs')
    op.drop_table('sc_nodes')
