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

"""Service chain ordering

Revision ID: e8005b9b1efc

"""

# revision identifiers, used by Alembic.
revision = 'e8005b9b1efc'
down_revision = '8e14fcb1587e'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'sc_spec_node_associations',
        sa.Column('position', sa.Integer(), nullable=False)
    )
    op.add_column(
        'sc_instance_spec_mappings',
        sa.Column('position', sa.Integer(), nullable=False)
    )


def downgrade():

    op.drop_column('sc_instance_spec_mappings', 'position')
    op.drop_column('sc_spec_node_associations', 'position')
