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

"""HA IP address to Port ID association

Revision ID: 4c0c1e2c0160
Revises: 27b724002081
Create Date: 2015-10-19 02:08:54.252877

"""

# revision identifiers, used by Alembic.
revision = '4c0c1e2c0160'
down_revision = '27b724002081'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if not migration.schema_has_table('apic_ml2_ha_ipaddress_to_port_owner'):
        op.create_table(
            'apic_ml2_ha_ipaddress_to_port_owner',
            sa.Column('ha_ip_address', sa.String(length=64), nullable=False),
            sa.Column('port_id', sa.String(length=64), nullable=False),
            sa.ForeignKeyConstraint(
                ['port_id'], ['ports.id'], ondelete='CASCADE',
                name='apic_ml2_ha_ipaddress_to_port_owner_fk_port_id'),
            sa.PrimaryKeyConstraint('ha_ip_address', 'port_id'))
