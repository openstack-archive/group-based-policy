# Copyright 2017 OpenStack Foundation
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

"""l3p ip pool size

Revision ID: 27b724002081
Revises: bff1774e749e
Create Date: 2017-07-06 17:34:18.856803

"""

# revision identifiers, used by Alembic.
revision = '27b724002081'
down_revision = 'bff1774e749e'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('gp_l3_policies', 'ip_pool',
                    existing_type=sa.String(length=64),
                    type_=sa.String(length=255))


def downgrade():
    pass
