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

"""svi

Revision ID: 5fe2285071fd
Revises: facc1ababba1
Create Date: 2018-01-05 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '5fe2285071fd'
down_revision = 'facc1ababba1'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_aim_network_svi_extensions',
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('svi', sa.Boolean),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                name='apic_aim_network_svi_fk_network',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.add_column('apic_aim_network_mappings',
                  sa.Column('l3out_name', sa.String(64), nullable=True))
    op.add_column('apic_aim_network_mappings',
                  sa.Column('l3out_ext_net_name', sa.String(64),
                            nullable=True))
    op.add_column('apic_aim_network_mappings',
                  sa.Column('l3out_tenant_name', sa.String(64),
                            nullable=True))


def downgrade():
    pass
