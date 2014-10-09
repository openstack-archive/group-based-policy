# Copyright 2014 OpenStack Foundation
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
#

"""Group Policy Resource Mapping Driver (gpm_rmd_1)

Revision ID: 1bf7555fa01a
Revises: 23b6c4d703c7
Create Date: 2014-07-24 16:12:22.610815

"""

# revision identifiers, used by Alembic.
revision = '1bf7555fa01a'
down_revision = '23b6c4d703c7'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_owned_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )

    op.create_table(
        'gpm_owned_ports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id')
    )

    op.create_table(
        'gpm_owned_subnets',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id')
    )

    op.create_table(
        'gpm_owned_routers',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id')
    )


def downgrade():

    op.drop_table('gpm_owned_routers')
    op.drop_table('gpm_owned_subnets')
    op.drop_table('gpm_owned_ports')
    op.drop_table('gpm_owned_networks')
