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

"""FloatingIP Mapping

Revision ID: fd98aa15958d

"""

# revision identifiers, used by Alembic.
revision = 'fd98aa15958d'
down_revision = '3791adbf0045'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gpm_pt_floatingip_mappings',
        sa.Column('policy_target_id', sa.String(length=36), nullable=False),
        sa.Column('floatingip_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('policy_target_id', 'floatingip_id'),
        sa.ForeignKeyConstraint(['policy_target_id'],
                                ['gp_policy_targets.id'],
                                ondelete='CASCADE',
                                name='gpm_pt_fip_map_fk_pt'),
        sa.ForeignKeyConstraint(['floatingip_id'],
                                ['floatingips.id'],
                                ondelete='CASCADE',
                                name='gpm_pt_fip_map_fk_fip'),
    )

    op.create_table(
        'gpm_service_policy_fip_mappings',
        sa.Column('service_policy_id', sa.String(length=36), nullable=False),
        sa.Column('policy_target_group_id',
                  sa.String(length=36),
                  nullable=False),
        sa.Column('floatingip_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('policy_target_group_id',
                                'service_policy_id',
                                'floatingip_id',
                                name='gpm_nsp_fip_map_pk_ptg_nsp_fip'),
        sa.ForeignKeyConstraint(['policy_target_group_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE',
                                name='gpm_nsp_fip_map_fk_ptg'),
        sa.ForeignKeyConstraint(['service_policy_id'],
                                ['gp_network_service_policies.id'],
                                ondelete='CASCADE',
                                name='gpm_nsp_fip_map_fk_nsp'),
        sa.ForeignKeyConstraint(['floatingip_id'],
                                ['floatingips.id'],
                                ondelete='CASCADE',
                                name='gpm_nsp_fip_map_fk_fip'),
    )


def downgrade():

    op.drop_table('gpm_service_policy_fip_mappings')
    op.drop_table('gpm_pt_floatingip_mappings')
