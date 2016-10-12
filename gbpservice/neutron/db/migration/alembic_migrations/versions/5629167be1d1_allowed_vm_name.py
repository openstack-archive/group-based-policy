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

"""allowed_vm_names

Revision ID: 5629167be1d1
Revises: 092e4b1aeb0a
Create Date: 2016-10-11 14:14:06.648609

"""

# revision identifiers, used by Alembic.
revision = '5629167be1d1'
down_revision = '092e4b1aeb0a'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_mapping_allowed_vm_names',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=False),
        sa.Column('allowed_vm_name', sa.String(length=255),
                  nullable=False),
        sa.ForeignKeyConstraint(
            ['l3_policy_id'], ['gp_l3_policies.id'],
            name='gp_apic_mapping_allowed_vm_name_fk_l3pid',
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('l3_policy_id', 'allowed_vm_name')
    )


def downgrade():
    pass
