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

# revision identifiers, used by Alembic.
revision = '3791adbf0045'
down_revision = '2f3834ea746b'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'sc_nodes',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'sc_specs',
        sa.Column('shared', sa.Boolean)
    )


def downgrade():
    op.drop_column('sc_nodes', 'shared')
    op.drop_column('sc_specs', 'shared')
