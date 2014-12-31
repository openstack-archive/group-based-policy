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

"""gbp_security_group_mapping

Revision ID: 5c65abe72596
Revises: 3ef186997b02
Create Date: 2014-08-21 14:30:23.68888

"""

# revision identifiers, used by Alembic.
revision = '5c65abe72596'
down_revision = '3ef186997b02'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_policy_rule_set_sg_mapping',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=False),
        sa.Column('provided_sg_id', sa.String(length=36)),
        sa.Column('consumed_sg_id', sa.String(length=36)),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['provided_sg_id'], ['securitygroups.id']),
        sa.ForeignKeyConstraint(['consumed_sg_id'], ['securitygroups.id']),
        sa.PrimaryKeyConstraint('policy_rule_set_id')
    )


def downgrade():

    op.drop_table('gpm_policy_rule_set_sg_mapping')
