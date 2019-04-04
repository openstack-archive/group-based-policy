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

"""VM names acquired from Nova API

Revision ID: 4f70135dc089
Revises: 4967af35820f
Create Date: 2019-01-08 14:18:11.909757

"""

# revision identifiers, used by Alembic.
revision = '4f70135dc089'
down_revision = '4967af35820f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_aim_vm_names',
        sa.Column('device_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('device_id'),
        sa.Column('vm_name', sa.String(64), nullable=False),
    )
    op.create_table(
        'apic_aim_vm_name_updates',
        sa.Column('purpose', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('purpose'),
        sa.Column('host_id', sa.String(36), nullable=False),
        sa.Column('last_incremental_update_time', sa.DateTime()),
        sa.Column('last_full_update_time', sa.DateTime()),
    )


def downgrade():
    pass
