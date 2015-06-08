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

"""service_management_ptg
"""

# revision identifiers, used by Alembic.
revision = 'dea911257ac6'
down_revision = '5358a28fb97d'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'gp_policy_target_groups',
        sa.Column('service_management', sa.Boolean)
    )

    op.add_column(
        'sc_instances',
        sa.Column('management_ptg_id', sa.String(length=36), nullable=True)
    )


def downgrade():
    pass
