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
"""ncp_sci_nf_status

Revision ID: bff1774e749e
Revises: cb5b16acbeb0
Create Date: 2017-02-24 00:16:12.276236

"""

# revision identifiers, used by Alembic.
revision = 'bff1774e749e'
down_revision = 'cb5b16acbeb0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_constraint('PRIMARY',
                       'ncp_node_instance_network_function_mappings',
                       type_='primary')
    op.create_primary_key("ncp_node_instance_network_function_mappings_pk",
                          "ncp_node_instance_network_function_mappings",
                          ['sc_instance_id', 'sc_node_id'])
    op.alter_column('ncp_node_instance_network_function_mappings',
                    'network_function_id',
                    nullable=True, existing_type=sa.String(length=36))
    op.add_column('ncp_node_instance_network_function_mappings',
                  sa.Column('status', sa.String(length=50), nullable=True))
    op.add_column('ncp_node_instance_network_function_mappings',
                  sa.Column('status_details', sa.String(length=4096),
                      nullable=True))


def downgrade():
    pass
