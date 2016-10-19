# Copyright (c) 2016 Cisco Systems
# All Rights Reserved.
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

"""Create port endpoint table

Revision ID: 44fab36aee11
Revises: 7afacef00d31
Create Date: 2016-07-22 17:05:31.709885

"""

# revision identifiers, used by Alembic.
revision = '44fab36aee11'
down_revision = '7afacef00d31'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'gp_apic_port_endpoints',
        sa.Column('port_id', sa.String(36), primary_key=True),
        sa.Column('endpoint', sa.LargeBinary),
        sa.Column('up_to_date', sa.Boolean, server_default=sa.sql.false()),
        sa.PrimaryKeyConstraint('port_id'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], name='fk_port_id',
                                ondelete='CASCADE'))


def downgrade():
    pass
