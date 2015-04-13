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


"""nsp_fix_constraints
"""

# revision identifiers, used by Alembic.
revision = '97ac978118c6'
down_revision = 'e8005b9b1efc'

from alembic import op
from neutron.db import migration
from sqlalchemy.engine import reflection


def upgrade(active_plugins=None, options=None):
    inspector = reflection.Inspector.from_engine(op.get_bind())
    unique_constraints = inspector.get_unique_constraints(
                                        'gp_policy_target_groups')
    op.drop_constraint('gp_policy_target_groups_ibfk_nsp',
                       'gp_policy_target_groups',
                       'foreignkey')
    for constraint in unique_constraints:
        if constraint['column_names'] == ['network_service_policy_id']:
            op.drop_constraint(constraint['name'],
                               'gp_policy_target_groups',
                               'unique')
            break
    op.create_foreign_key('gp_policy_target_groups_ibfk_nsp',
                          source='gp_policy_target_groups',
                          referent='gp_network_service_policies',
                          local_cols=['network_service_policy_id'],
                          remote_cols=['id'])
    with migration.remove_fks_from_table(
                                'gpm_service_policy_ipaddress_mappings'):
        op.drop_constraint(
                None,
                table_name='gpm_service_policy_ipaddress_mappings',
                type_='primary')
        op.create_primary_key(
                name='pk_policytargetgroup_servicepolicyid',
                table_name='gpm_service_policy_ipaddress_mappings',
                cols=['policy_target_group', 'service_policy_id'])


def downgrade(active_plugins=None, options=None):
    # Downgrade would require deleting duplicate entries resulting in data
    # loss. So skip applying back the unique constraint and change in
    # primary key
    pass
