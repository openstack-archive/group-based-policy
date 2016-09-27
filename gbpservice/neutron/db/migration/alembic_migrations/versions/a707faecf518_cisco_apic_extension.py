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

"""Tables for cisco_apic extension attributes

Revision ID: a707faecf518
Revises: 9cedbcd3e9ee
Create Date: 2016-10-04 14:18:11.909757

"""

# revision identifiers, used by Alembic.
revision = 'a707faecf518'
down_revision = '9cedbcd3e9ee'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'apic_aim_network_extensions',
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('external_network_dn', sa.String(1024)),
        sa.Column('nat_type', sa.Enum('distributed', 'edge', '')),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                name='apic_aim_network_extn_fk_network',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.create_table(
        'apic_aim_subnet_extensions',
        sa.Column('subnet_id', sa.String(36), nullable=False),
        sa.Column('snat_host_pool', sa.Boolean),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                name='apic_aim_subnet_extn_fk_subnet',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id')
    )

    op.create_table(
        'apic_aim_network_external_cidrs',
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('cidr', sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                name='apic_aim_network_cidr_extn_fk_network',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'cidr')
    )

    op.create_table(
        'apic_aim_router_external_contracts',
        sa.Column('router_id', sa.String(36), nullable=False),
        sa.Column('contract_name', sa.String(64), nullable=False),
        sa.Column('provides', sa.Boolean, nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                name='apic_aim_router_contract_extn_fk_router',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id', 'contract_name', 'provides')
    )


def downgrade():
    pass
