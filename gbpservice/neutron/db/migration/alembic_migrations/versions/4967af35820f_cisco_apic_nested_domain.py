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

"""nested domain attributes in cisco_apic extension

Revision ID: 4967af35820f
Revises: 1c564e737f9f
Create Date: 2018-04-19 14:18:11.909757

"""

# revision identifiers, used by Alembic.
revision = '4967af35820f'
down_revision = '1c564e737f9f'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column('apic_aim_network_extensions',
                  sa.Column('nested_domain_name', sa.String(1024),
                      nullable=True))
    op.add_column('apic_aim_network_extensions',
                  sa.Column('nested_domain_type', sa.String(1024),
                      nullable=True))
    op.add_column('apic_aim_network_extensions',
                  sa.Column('nested_domain_infra_vlan', sa.Integer,
                      nullable=True))
    op.add_column('apic_aim_network_extensions',
                  sa.Column('nested_domain_service_vlan', sa.Integer,
                      nullable=True))
    op.add_column('apic_aim_network_extensions',
                  sa.Column('nested_domain_node_network_vlan', sa.Integer,
                      nullable=True))

    op.create_table(
        'apic_aim_network_nested_domain_allowed_vlans',
        sa.Column('vlan', sa.Integer, nullable=False),
        sa.PrimaryKeyConstraint('vlan'),
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                name='apic_aim_network_nested_extn_fk_network',
                                ondelete='CASCADE')
    )


def downgrade():
    pass
