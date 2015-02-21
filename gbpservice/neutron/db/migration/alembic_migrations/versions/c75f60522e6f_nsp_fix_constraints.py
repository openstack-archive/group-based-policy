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
revision = 'c75f60522e6f'
down_revision = 'e8005b9b1efc'

from alembic import op
from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    op.drop_constraint('gp_policy_target_groups_ibfk_nsp',
                       'gp_policy_target_groups',
                       'foreignkey')
    op.drop_constraint('network_service_policy_id',
                       'gp_policy_target_groups',
                       'unique')
    op.create_foreign_key('gp_policy_target_groups_ibfk_nsp',
                          source='gp_policy_target_groups',
                          referent='gp_network_service_policies',
                          local_cols=['network_service_policy_id'],
                          remote_cols=['id'], ondelete='CASCADE')
    with migration.remove_fks_from_table(
                                'gpm_service_policy_ipaddress_mappings'):
        op.drop_constraint(
                None,
                table_name='gpm_service_policy_ipaddress_mappings',
                type_='primary')
        op.create_primary_key(
                name=None,
                table_name='gpm_service_policy_ipaddress_mappings',
                cols=['policy_target_group', 'service_policy_id'])


def downgrade(active_plugins=None, options=None):
    op.create_unique_constraint(None, 'gp_policy_target_groups',
                                ['network_service_policy_id'])
    with migration.remove_fks_from_table(
                'gpm_service_policy_ipaddress_mappings'):
        op.drop_constraint(
                None,
                'gpm_service_policy_ipaddress_mappings',
                type_='primary')
        op.create_primary_key(
                name=None,
                table_name='gpm_service_policy_ipaddress_mappings',
                cols=['service_policy_id'])
