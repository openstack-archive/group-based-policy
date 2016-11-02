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
"""ip_pool & subnet_prefix_length nullable

Revision ID: 4af01d620224
Revises: 75aa8a37a8de
Create Date: 2016-11-27 21:33:13.384981

"""

# revision identifiers, used by Alembic.
revision = '4af01d620224'
down_revision = '75aa8a37a8de'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('gp_l3_policies', 'ip_pool', nullable=True,
                    existing_nullable=False,
                    existing_type=sa.String(length=64))
    op.alter_column('gp_l3_policies', 'subnet_prefix_length', nullable=True,
                    existing_nullable=False, existing_type=sa.Integer)


def downgrade():
    pass
