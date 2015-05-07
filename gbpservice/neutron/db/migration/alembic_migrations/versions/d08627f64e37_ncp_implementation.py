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

"""ncp_implementation
"""

# revision identifiers, used by Alembic.
revision = 'd08627f64e37'
down_revision = '9744740aa75c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ncp_node_to_driver_mapping',
        sa.Column('servicechain_node_id', sa.String(length=36),
                  nullable=False),
        sa.Column('driver_name', sa.String(length=36)),
        sa.Column('servicechain_instance_id', sa.String(length=36)),
        sa.PrimaryKeyConstraint(
            'servicechain_node_id', 'servicechain_instance_id'),
        sa.ForeignKeyConstraint(['servicechain_node_id'],
                                ['sc_nodes.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['servicechain_instance_id'],
                                ['sc_instances.id'], ondelete='CASCADE')
    )

    op.create_table(
        'ncp_service_targets',
        sa.Column('servicechain_node_id', sa.String(length=36),
                  nullable=False),
        sa.Column('servicechain_instance_id', sa.String(length=36)),
        sa.Column('policy_target_id', sa.String(length=36)),
        sa.Column('relationship', sa.String(length=25)),
        sa.Column('position', sa.Integer),

        sa.PrimaryKeyConstraint(
            'servicechain_node_id', 'servicechain_instance_id',
            'policy_target_id'),
        sa.ForeignKeyConstraint(['policy_target_id'],
                                ['gp_policy_targets.id'], ondelete='CASCADE')
    )


def downgrade():
    pass
