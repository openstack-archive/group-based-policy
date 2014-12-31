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

"""servicechain_instance_stacks

Revision ID: 43443f15fa3f
Revises: ebfd08bc4714
Create Date: 2014-07-28 13:38:12.610815

"""

# revision identifiers, used by Alembic.
revision = '43443f15fa3f'
down_revision = 'ebfd08bc4714'


from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'sc_instance_stacks',
        sa.Column('instance_id', sa.String(length=36), nullable=False),
        sa.Column('stack_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('instance_id'),
        sa.PrimaryKeyConstraint('stack_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('sc_instance_stacks')
