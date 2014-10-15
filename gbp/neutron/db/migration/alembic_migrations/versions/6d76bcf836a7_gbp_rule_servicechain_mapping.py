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

Revision ID: 6d76bcf836a7
Revises: 5c65abe72596
Create Date: 2014-10-09 17:43:08.98888

"""

# revision identifiers, used by Alembic.
revision = '6d76bcf836a7'
down_revision = 'ebfd08bc4714'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'gpm_rule_servicechain_mapping',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('servicechain_instance_id', sa.String(length=36)),
        sa.ForeignKeyConstraint(['rule_id'], ['gp_policy_rules.id']),
        sa.ForeignKeyConstraint(['servicechain_instance_id'], ['sc_instances.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('rule_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('gpm_rule_servicechain_mapping')
