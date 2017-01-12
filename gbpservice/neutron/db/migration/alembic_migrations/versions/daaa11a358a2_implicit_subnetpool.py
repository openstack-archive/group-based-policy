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

"""implicit_subnetpool

Revision ID: daaa11a358a2
Revises: 8cd6d095d7d3
Create Date: 2017-12-01 17:01:30.735865

"""

# revision identifiers, used by Alembic.
revision = 'daaa11a358a2'
down_revision = '8cd6d095d7d3'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'implicit_subnetpools',
        sa.Column('subnetpool_id', sa.String(length=36), nullable=False),
        sa.Column('is_implicit', sa.Boolean,
                  server_default=sa.sql.false(), nullable=False),
        sa.ForeignKeyConstraint(
            ['subnetpool_id'], ['subnetpools.id'],
            name='gp_impl_sp_fk_sp_id', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnetpool_id')
    )


def downgrade():
    pass
