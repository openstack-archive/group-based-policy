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

"""enforce_service_chains attribute for PTGs

Revision ID: 64fa77aca090

"""

# revision identifiers, used by Alembic.
revision = '7afacef00d31'
down_revision = 'c1aab79622fe'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'gp_group_proxy_mappings',
        sa.Column('enforce_service_chains', sa.Boolean,
                  server_default=sa.sql.true())
    )


def downgrade():
    pass
