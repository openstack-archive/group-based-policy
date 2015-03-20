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

"""PT FloatingIP Mapping

Revision ID: fd98aa15958d

"""

# revision identifiers, used by Alembic.
revision = 'fd98aa15958d'
down_revision = 'e8005b9b1efc'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_pt_floatingip_mappings',
        sa.Column('policy_target_id', sa.String(length=36), nullable=False),
        sa.Column('floatingip_id', sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint('policy_target_id'),
        sa.ForeignKeyConstraint(['policy_target_id'],
                                ['gp_policy_targets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['floatingip_id'],
                                ['floatingips.id'],
                                ondelete='CASCADE'),
    )


def downgrade():

    op.drop_table('gp_pt_floatingip_mappings')
