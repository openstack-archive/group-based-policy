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

"""ep_redirect_action
"""

# revision identifiers, used by Alembic.
revision = '2f3834ea746b'
down_revision = 'e8005b9b1efc'

from alembic import op
from sqlalchemy.engine import reflection


def upgrade(active_plugins=None, options=None):
    inspector = reflection.Inspector.from_engine(op.get_bind())
    fk_name = [fk['name'] for fk in
               inspector.get_foreign_keys('gpm_ptgs_servicechain_mapping')
               if 'consumer_ptg_id' in fk['constrained_columns']]
    op.drop_constraint(fk_name[0], 'gpm_ptgs_servicechain_mapping',
                       'foreignkey')


def downgrade(active_plugins=None, options=None):
    op.create_foreign_key(
        name=None,
        source='gpm_ptgs_servicechain_mapping',
        referent='gp_policy_target_groups',
        local_cols=['consumer_ptg_id'], remote_cols=['id'], ondelete='CASCADE')
