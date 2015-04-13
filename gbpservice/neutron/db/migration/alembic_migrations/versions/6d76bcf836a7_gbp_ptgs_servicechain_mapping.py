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

"""gbp_ptgs_servicechain_mapping

Revision ID: 6d76bcf836a7
Revises: 43443f15fa3f
Create Date: 2014-10-09 17:43:08.98888

"""

# revision identifiers, used by Alembic.
revision = '6d76bcf836a7'
down_revision = '43443f15fa3f'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'gpm_ptgs_servicechain_mapping',
        sa.Column('provider_ptg_id', sa.String(length=36), nullable=False),
        sa.Column('consumer_ptg_id', sa.String(length=36), nullable=False),
        sa.Column('servicechain_instance_id', sa.String(length=36)),
        sa.ForeignKeyConstraint(['provider_ptg_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['consumer_ptg_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['servicechain_instance_id'],
                                ['sc_instances.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('servicechain_instance_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('gpm_ptgs_servicechain_mapping')
