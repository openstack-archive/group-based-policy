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

"""alter project_id column length in gp_apic_tenant_specific_nat_epg

Revision ID: cb5b16acbeb0
Revises: cc09261e0fb5
Create Date: 2017-06-10 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'cb5b16acbeb0'
down_revision = 'cc09261e0fb5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('gp_apic_tenant_specific_nat_epg',
                    'project_id',
                    existing_type=sa.String(36),
                    type_=sa.String(255), nullable=False)


def downgrade():
    pass
