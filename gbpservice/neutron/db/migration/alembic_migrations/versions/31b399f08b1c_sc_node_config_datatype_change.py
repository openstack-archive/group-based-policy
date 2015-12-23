# Copyright 2015 OpenStack Foundation
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

"""sc_node config datatype change

Revision ID: 31b399f08b1c
Revises: 7ef98f287d6
Create Date: 2015-12-22 09:15:44.917899

"""

# revision identifiers, used by Alembic.
revision = '31b399f08b1c'
down_revision = '7ef98f287d6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('sc_nodes', 'config',
                    existing_type=sa.String(4096),
                    type_=sa.dialects.mysql.TEXT)


def downgrade():
    pass
