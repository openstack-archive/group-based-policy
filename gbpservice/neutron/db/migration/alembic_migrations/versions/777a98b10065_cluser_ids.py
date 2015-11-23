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

""" cluster ids
"""

# revision identifiers, used by Alembic.
revision = '777a98b10065'
down_revision = '5a24894af57c'


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('gp_policy_targets', 'cluster_id')
    op.create_table(
        'gp_pt_to_cluster_associations',
        sa.Column('policy_target_id', sa.String(length=36),
                  nullable=False),
        sa.Column('cluster_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['policy_target_id'],
                                ['gp_policy_targets.id']),
        sa.PrimaryKeyConstraint('policy_target_id', 'cluster_id')
    )


def downgrade():
    pass
