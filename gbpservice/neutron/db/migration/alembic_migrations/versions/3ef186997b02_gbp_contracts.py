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

"""gbp_policy_rule_sets

Revision ID: 3ef186997b02
Create Date: 2014-07-30 14:48:49.838182

"""

# revision identifiers, used by Alembic.
revision = '3ef186997b02'
down_revision = '4ae51f13395a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'gp_policy_rule_sets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('parent_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['parent_id'],
                                ['gp_policy_rule_sets.id']),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_ptg_to_prs_providing_associations',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_set_id',
                                'policy_target_group_id'))

    op.create_table(
        'gp_ptg_to_prs_consuming_associations',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_set_id',
                                'policy_target_group_id'))

    op.create_table(
        'gp_prs_to_pr_associations',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.Column('policy_rule_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_id'],
                                ['gp_policy_rules.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_set_id', 'policy_rule_id'))


def downgrade():
    op.drop_table('gp_ptg_to_prs_consuming_associations')
    op.drop_table('gp_ptg_to_prs_providing_associations')
    op.drop_table('gp_prs_to_pr_associations')
    op.drop_table('gp_policy_rule_sets')
