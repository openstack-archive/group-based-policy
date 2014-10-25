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

"""gbp_rule_servicechain_mapping

Revision ID: ceba6e091b2a
Revises: 577bb4469944
Create Date: 2014-10-09 17:43:08.98888

"""

# revision identifiers, used by Alembic.
revision = 'ceba6e091b2a'
down_revision = '577bb4469944'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'gpm_service_policy_ipaddress_mapping',
        sa.Column('service_policy_id', sa.String(length=36), nullable=False),
        sa.Column('ipaddress', sa.String(length=36)),
        sa.Column('endpoint_group', sa.String(length=36)),
        sa.PrimaryKeyConstraint('endpoint_group'),
        sa.ForeignKeyConstraint(['endpoint_group'],
                                ['gp_endpoint_groups.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('service_policy_id'),
        sa.ForeignKeyConstraint(['service_policy_id'],
                                ['gp_network_service_policies.id'],
                                ondelete='CASCADE'),
    )
    


def downgrade(active_plugins=None, options=None):
    op.drop_table('gpm_service_policy_ipaddress_mapping')
