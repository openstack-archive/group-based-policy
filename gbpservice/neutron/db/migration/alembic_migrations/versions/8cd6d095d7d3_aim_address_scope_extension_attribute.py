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
"""Table for AIM address-scope extension attribute

Revision ID: 8cd6d095d7d3
Revises: 3e1f67cf951b
Create Date: 2017-01-05 19:17:45.088969

"""

# revision identifiers, used by Alembic.
revision = '8cd6d095d7d3'
down_revision = '3e1f67cf951b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_aim_addr_scope_extensions',
        sa.Column('address_scope_id', sa.String(36), nullable=False),
        sa.Column('vrf_dn', sa.String(1024)),
        sa.ForeignKeyConstraint(['address_scope_id'], ['address_scopes.id'],
                                name='apic_aim_addr_scope_extn_fk_addr_scope',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address_scope_id')
    )


def downgrade():
    pass
