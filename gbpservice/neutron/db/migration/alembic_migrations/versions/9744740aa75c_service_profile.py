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

"""service_profile
"""

# revision identifiers, used by Alembic.
revision = '9744740aa75c'
down_revision = 'fd98aa15958d'


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'service_profiles',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('vendor', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('shared', sa.Boolean),
        sa.Column('insertion_mode', sa.String(length=50), nullable=True),
        sa.Column('service_type', sa.String(length=50), nullable=True),
        sa.Column('service_flavor', sa.String(length=1024), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.add_column(
        'sc_nodes',
        sa.Column('service_profile_id', sa.String(36), nullable=True)
    )

    op.create_foreign_key('sc_nodes_ibfk_profile', source='sc_nodes',
                          referent='service_profiles',
                          local_cols=['service_profile_id'],
                          remote_cols=['id'])

    op.alter_column("sc_nodes", "service_type",
                    existing_type=sa.String(length=50), nullable=True)


def downgrade():
    pass