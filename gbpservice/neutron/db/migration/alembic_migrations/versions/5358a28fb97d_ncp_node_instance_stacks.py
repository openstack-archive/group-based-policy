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

"""ncp_node_instance_stacks

Revision ID: 5358a28fb97d
Revises: d08627f64e37

"""

# revision identifiers, used by Alembic.
revision = '5358a28fb97d'
down_revision = 'd08627f64e37'


from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'ncp_node_instance_stacks',
        sa.Column('sc_instance_id', sa.String(length=36), nullable=False),
        sa.Column('sc_node_id', sa.String(length=36), nullable=False),
        sa.Column('stack_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('sc_instance_id', 'sc_node_id', 'stack_id')
    )


def downgrade(active_plugins=None, options=None):
    pass
