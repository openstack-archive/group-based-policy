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

"""segmentation labels for PT (apic)

Revision ID: 092e4b1aeb0a
Revises: d4bb487a81b8
Create Date: 2016-09-18 18:58:26.810742

"""

# revision identifiers, used by Alembic.
revision = '092e4b1aeb0a'
down_revision = 'd4bb487a81b8'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_mapping_segmentation_labels',
        sa.Column('policy_target_id', sa.String(length=36), nullable=False),
        sa.Column('segmentation_label', sa.String(length=255),
                  nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_target_id'], ['gp_policy_targets.id'],
            name='gp_apic_mapping_segmentation_lablel_fk_ptid',
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_id', 'segmentation_label')
    )


def downgrade():
    pass
