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


"""es_ip_allocation_fix_constraints
"""

# revision identifiers, used by Alembic.
revision = '1fadeb573886'
down_revision = '81d13acfbb80'

from alembic import op
from neutron.db import migration
from sqlalchemy.engine import reflection


def upgrade(active_plugins=None, options=None):
    inspector = reflection.Inspector.from_engine(op.get_bind())
    unique_constraints = inspector.get_unique_constraints(
        'gp_es_to_l3p_associations')
    for constraint in unique_constraints:
        if constraint['column_names'] == ['external_segment_id',
                                          'allocated_address']:
            with migration.remove_fks_from_table(
                    'gp_es_to_l3p_associations'):
                op.drop_constraint(constraint['name'],
                                   'gp_es_to_l3p_associations',
                                   'unique')
            break


def downgrade(active_plugins=None, options=None):
    pass
