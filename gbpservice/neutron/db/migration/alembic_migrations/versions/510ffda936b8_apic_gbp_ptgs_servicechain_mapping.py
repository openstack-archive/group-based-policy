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

# revision identifiers, used by Alembic.
revision = '510ffda936b8'
down_revision = 'c2a9d04c8cef'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'gpm_apic_ptgs_servicechain_mapping',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('provider_ptg_id', sa.String(length=36), nullable=False),
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=False),
        sa.Column('servicechain_instance_id', sa.String(length=36)),
        sa.ForeignKeyConstraint(['provider_ptg_id'],
                                ['gp_policy_target_groups.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['servicechain_instance_id'],
                                ['sc_instances.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('servicechain_instance_id',
                                'policy_rule_set_id', 'provider_ptg_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('gpm_apic_ptgs_servicechain_mapping')
