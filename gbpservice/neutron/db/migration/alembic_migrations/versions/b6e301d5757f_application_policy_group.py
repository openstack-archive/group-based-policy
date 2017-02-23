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

"""application_policy_group

Revision ID: b6e301d5757f
Revises: daaa11a358a2
Create Date: 2017-02-10 01:15:32.361753

"""

# revision identifiers, used by Alembic.
revision = 'b6e301d5757f'
down_revision = 'daaa11a358a2'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_application_policy_groups',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('status_details', sa.String(length=4096), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.add_column(
        'gp_policy_target_groups',
        sa.Column('application_policy_group_id', sa.String(length=36),
                  nullable=True))

    op.create_foreign_key('gp_application_policy_group_ibfk_1',
                          source='gp_policy_target_groups',
                          referent='gp_application_policy_groups',
                          local_cols=['application_policy_group_id'],
                          remote_cols=['id'])


def downgrade():
    pass
