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

"""apg_shared_attribute

Revision ID: 032f3315c315
Revises: b6e301d5757f
Create Date: 2017-03-20 21:13:08.98888

"""

# revision identifiers, used by Alembic.
revision = '032f3315c315'
down_revision = 'b6e301d5757f'


from alembic import op
import sqlalchemy as sa
from sqlalchemy import sql


def upgrade():

    op.add_column(
        'gp_application_policy_groups',
        sa.Column('shared', sa.Boolean, nullable=True,
                  server_default=sql.false())
    )
