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

"""Group Policy Implicit Policy Driver (gpm_ipd_1)

Revision ID: 23b6c4d703c7
Revises: 53de98f7a066
Create Date: 2014-07-24 15:33:34.751659

"""

# revision identifiers, used by Alembic.
revision = '23b6c4d703c7'
down_revision = '53de98f7a066'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_owned_l3_policies',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('l3_policy_id')
    )

    op.create_table(
        'gpm_owned_l2_policies',
        sa.Column('l2_policy_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['l2_policy_id'], ['gp_l2_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('l2_policy_id')
    )


def downgrade():

    op.drop_table('gpm_owned_l2_policies')
    op.drop_table('gpm_owned_l3_policies')
