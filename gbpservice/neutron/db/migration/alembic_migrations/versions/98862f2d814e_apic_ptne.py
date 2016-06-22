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

"""apic_per-tenant-nat-epg

Revision ID: 98862f2d814e
Revises: 12c1bc8d7026
Create Date: 2016-06-22 17:36:28.386526

"""

# revision identifiers, used by Alembic.
revision = '98862f2d814e'
down_revision = '12c1bc8d7026'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'gp_apic_tenant_specific_nat_epg',
        sa.Column('external_segment_id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('external_segment_id', 'tenant_id'),
        sa.ForeignKeyConstraint(['external_segment_id'],
                                ['gp_external_segments.id'],
                                ondelete='CASCADE',
                                name='gp_apic_ptne_fk_es'))


def downgrade():
    op.drop_table('gp_apic_tenant_specific_nat_epg')
