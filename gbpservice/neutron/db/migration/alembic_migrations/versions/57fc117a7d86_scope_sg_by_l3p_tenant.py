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

"""Scope SG by L3P and Tenant (gpm_db_1)
"""

revision = '57fc117a7d86'
down_revision = '3791adbf0045'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_policy_rule_set_remote_sg_mapping',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=False),
        sa.Column('provided_sg_id', sa.String(length=36)),
        sa.Column('consumed_sg_id', sa.String(length=36)),
        sa.Column('l3_policy_id', sa.String(length=36)),
        sa.Column('tenant_id', sa.String(length=255)),
        sa.Column('reference_count', sa.Integer),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['provided_sg_id'], ['securitygroups.id'],
                                name='gp_sg_remote_mapping_ibfk_1'),
        sa.ForeignKeyConstraint(['consumed_sg_id'], ['securitygroups.id'],
                                name='gp_sg_remote_mapping_ibfk_2'),
        sa.ForeignKeyConstraint(['l3_policy_id'], ['gp_l3_policies.id'],
                                name='gp_sg_mapping_ibfk_3'),
        sa.PrimaryKeyConstraint('policy_rule_set_id', 'tenant_id',
                                'l3_policy_id')
    )


def downgrade():
    pass
