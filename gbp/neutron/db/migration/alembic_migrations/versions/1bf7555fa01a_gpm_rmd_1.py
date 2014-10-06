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


def upgrade(neutron_db=None):

    op.create_table(
        'gpm_owned_networks',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('network_id'),
        mysql_DEFAULT_CHARSET='utf8'
    )

    op.create_foreign_key('gpm_owned_networks_ibfk_1',
                          source='gpm_owned_networks',
                          referent='networks',
                          local_cols=['network_id'], remote_cols=['id'],
                          ondelete='CASCADE', referent_schema=neutron_db)

    op.create_table(
        'gpm_owned_ports',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('port_id'),
        mysql_DEFAULT_CHARSET='utf8'
    )

    op.create_foreign_key('gpm_owned_ports_ibfk_1',
                          source='gpm_owned_ports',
                          referent='ports',
                          local_cols=['port_id'], remote_cols=['id'],
                          ondelete='CASCADE', referent_schema=neutron_db)

    op.create_table(
        'gpm_owned_subnets',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('subnet_id'),
        mysql_DEFAULT_CHARSET='utf8'
    )

    op.create_foreign_key('gpm_owned_subnets_ibfk_1',
                          source='gpm_owned_subnets',
                          referent='subnets',
                          local_cols=['subnet_id'], remote_cols=['id'],
                          ondelete='CASCADE', referent_schema=neutron_db)

    op.create_table(
        'gpm_owned_routers',
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('router_id'),
        mysql_DEFAULT_CHARSET='utf8'
    )
    op.create_foreign_key('gpm_owned_routers_ibfk_1',
                          source='gpm_owned_routers',
                          referent='routers',
                          local_cols=['router_id'], remote_cols=['id'],
                          ondelete='CASCADE', referent_schema=neutron_db)


def downgrade(neutron_db=None):

    op.drop_table('gpm_owned_routers')
    op.drop_table('gpm_owned_subnets')
    op.drop_table('gpm_owned_ports')
    op.drop_table('gpm_owned_networks')
