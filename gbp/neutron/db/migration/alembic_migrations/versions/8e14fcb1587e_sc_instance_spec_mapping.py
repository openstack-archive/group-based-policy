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

"""sc_instance_spec_mapping
"""

# revision identifiers, used by Alembic.
revision = '8e14fcb1587e'
down_revision = '64fa77aca090'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'sc_instance_spec_mappings',
        sa.Column('servicechain_spec_id',
                  sa.String(length=36),
                  nullable=False),
        sa.Column('servicechain_instance_id',
                  sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['servicechain_spec_id'], ['sc_specs.id']),
        sa.ForeignKeyConstraint(['servicechain_instance_id'],
                                ['sc_instances.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('servicechain_instance_id',
                                'servicechain_spec_id')
    )


def downgrade(active_plugins=None, options=None):
    op.drop_table('sc_instance_spec_mappings')
