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

"""initial_qos_via_nsp

Revision ID: da6a25bbcfa8
Revises: cc09261e0fb5
Create Date: 2017-03-27 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'da6a25bbcfa8'
down_revision = 'cc09261e0fb5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'gpm_qos_policy_mappings',
        sa.Column('service_policy_id', sa.String(length=36), nullable=False),
        sa.Column('qos_policy_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('service_policy_id'),
        sa.ForeignKeyConstraint(['service_policy_id'],
                                ['gp_network_service_policies.id'],
                                ondelete='CASCADE',
                                name='gbp_qos_policy_mapping_nsp_fk'),
        sa.ForeignKeyConstraint(['qos_policy_id'],
                                ['qos_policies.id'],
                                ondelete='RESTRICT',
                                name='gbp_qos_policy_mapping_qosp_fk')
    )


def downgrade():
    op.drop_table('gpm_qos_policy_mappings')
