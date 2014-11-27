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

"""servicechain_parameters_rename

Revision ID: fc4df4023903
Create Date: 2014-11-27 10:51:20

"""

# revision identifiers, used by Alembic.
revision = 'fc4df4023903'
down_revision = 'd595542cf3f5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('sc_instances', 'provider_ptg',
                    new_column_name='provider_ptg_id',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)

    op.alter_column('sc_instances', 'consumer_ptg',
                    new_column_name='consumer_ptg_id',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)

    op.alter_column('sc_instances', 'classifier',
                    new_column_name='classifier_id',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)


def downgrade():
    op.alter_column('sc_instances', 'provider_ptg_id',
                    new_column_name='provider_ptg',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)

    op.alter_column('sc_instances', 'consumer_ptg_id',
                    new_column_name='consumer_ptg',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)

    op.alter_column('sc_instances', 'classifier_id',
                    new_column_name='classifier',
                    existing_type=sa.String(length=36),
                    existing_nullable=True)
