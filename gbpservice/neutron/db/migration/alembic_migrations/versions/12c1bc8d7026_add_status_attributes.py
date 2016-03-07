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

"""add status attributes

Revision ID: 12c1bc8d7026
Revises: 31b399f08b1c
Create Date: 2016-03-08 15:28:57.170563

"""

# revision identifiers, used by Alembic.
revision = '12c1bc8d7026'
down_revision = '31b399f08b1c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    table_names = ['gp_policy_targets', 'gp_policy_target_groups',
                   'gp_l2_policies', 'gp_l3_policies', 'gp_policy_rules',
                   'gp_policy_classifiers', 'gp_policy_actions',
                   'gp_policy_rule_sets', 'gp_nat_pools',
                   'gp_network_service_policies',
                   'gp_external_segments', 'gp_external_policies', 'sc_nodes',
                   'sc_instances', 'sc_specs', 'service_profiles']

    for tname in table_names:
        op.add_column(tname, sa.Column('status', sa.String(length=16),
                                       nullable=True))
        op.add_column(tname, sa.Column('status_details',
                                       sa.String(length=4096), nullable=True))


def downgrade():
    pass
