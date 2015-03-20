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

"""Admin owns SCI (admin_owns_sci)

Revision ID: c2a9d04c8cef

"""

# revision identifiers, used by Alembic.
revision = 'c2a9d04c8cef'
down_revision = '1fadeb573886'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'gpm_ptgs_servicechain_mapping',
        sa.Column('tenant_id', sa.String(length=255), nullable=True)
    )


def downgrade():
    op.drop_column('gpm_ptgs_servicechain_mapping', 'tenant_id')
