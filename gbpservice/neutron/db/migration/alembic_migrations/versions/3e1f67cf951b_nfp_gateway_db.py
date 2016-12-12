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

"""nfp gateway db

Revision ID: 3e1f67cf951b
Revises: ce662ded3ba5
Create Date: 2016-11-28 04:07:43.928878

"""

# revision identifiers, used by Alembic.
revision = '3e1f67cf951b'
down_revision = 'ce662ded3ba5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('nfp_service_gateway_info',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('network_function_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('gateway_ptg', sa.String(length=36),
                              nullable=False),
                    sa.Column('primary_instance_gw_pt', sa.String(length=36),
                              nullable=False),
                    sa.Column('secondary_instance_gw_pt', sa.String(length=36),
                              nullable=True),
                    sa.Column('primary_gw_vip_pt', sa.String(length=36),
                              nullable=True),
                    sa.Column('secondary_gw_vip_pt', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['network_function_id'],
                                            ['nfp_network_functions.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id', 'network_function_id')
                    )

    op.add_column('nfp_network_function_devices', sa.Column('gateway_port',
                  sa.String(length=36), nullable=True))


def downgrade():
    pass
