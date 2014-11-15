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

"""gbp_shared_attribute

Revision ID: f4d890a9c126
Revises: d595542cf3f5
Create Date: 2014-11-12 21:13:08.98888

"""

# revision identifiers, used by Alembic.
revision = 'f4d890a9c126'
down_revision = 'd595542cf3f5'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'gp_policy_target_groups',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_l2_policies',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_l3_policies',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_policy_rule_sets',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_policy_rules',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_policy_classifiers',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_policy_actions',
        sa.Column('shared', sa.Boolean)
    )

    op.add_column(
        'gp_network_service_policies',
        sa.Column('shared', sa.Boolean)
    )


def downgrade():
    op.drop_column('gp_network_service_policies', 'shared')
    op.drop_column('gp_policy_actions', 'shared')
    op.drop_column('gp_policy_classifiers', 'shared')
    op.drop_column('gp_policy_rules', 'shared')
    op.drop_column('gp_policy_rule_sets', 'shared')
    op.drop_column('gp_l3_policies', 'shared')
    op.drop_column('gp_l2_policies', 'shared')
    op.drop_column('gp_policy_target_groups', 'shared')
