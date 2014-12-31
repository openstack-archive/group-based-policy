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

"""Group Policy Mapping DB (gpm_db_1)

Revision ID: 64fa77aca090

"""

# revision identifiers, used by Alembic.
revision = '64fa77aca090'
down_revision = 'f16efdc10a71'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.add_column(
        'gp_external_segments',
        sa.Column('subnet_id', sa.String(length=36), nullable=True)
    )
    op.add_column(
        'gp_external_segments',
        sa.Column('type', sa.String(length=15), nullable=True)
    )
    op.create_unique_constraint(None, 'gp_external_segments', ['subnet_id'])
    op.create_foreign_key('gp_external_segment_ibfk_2',
                          source='gp_external_segments', referent='subnets',
                          local_cols=['subnet_id'], remote_cols=['id'])


def downgrade():

    op.drop_constraint('gp_external_segment_ibfk_2', 'gp_external_segments',
                       'foreignkey')
    op.drop_column('gp_external_segments', 'type')
    op.drop_column('gp_external_segments', 'subnet_id')
