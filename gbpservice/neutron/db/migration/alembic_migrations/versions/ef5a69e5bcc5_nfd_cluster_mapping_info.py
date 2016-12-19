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

"""nfd_cluster_mapping_info

Revision ID: ef5a69e5bcc5
Revises: fce38a8588a2
Create Date: 2016-11-23 21:17:53.858242

"""


# revision identifiers, used by Alembic.
revision = 'ef5a69e5bcc5'
down_revision = 'fce38a8588a2'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'nfd_cluster_mapping_info',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('network_function_device_id',
                  sa.String(length=36), nullable=True),
        sa.Column('cluster_group', sa.Integer(), nullable=True),
        sa.Column('virtual_ip', sa.String(length=36), nullable=True),
        sa.Column('multicast_ip', sa.String(length=36), nullable=True),
        sa.Column('cluster_name', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['network_function_device_id'],
                                ['nfp_network_function_devices.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )

    op.add_column(
        'nfp_network_function_devices',
        sa.Column('provider_metadata', sa.String(length=1024), nullable=True)
    )


def downgrade():
    pass
