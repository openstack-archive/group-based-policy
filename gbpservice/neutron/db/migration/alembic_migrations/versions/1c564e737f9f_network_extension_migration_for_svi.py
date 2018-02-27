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

"""network_migration_for_svi

Revision ID: 1c564e737f9f
Revises: 804d991a3564
Create Date: 2018-02-27 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '1c564e737f9f'
down_revision = '804d991a3564'

from alembic import op
from alembic import util
from neutron.db import models_v2
import sqlalchemy as sa
from sqlalchemy.orm import lazyload


NetworkExtensionDb = sa.Table(
    'apic_aim_network_extensions', sa.MetaData(),
    sa.Column('network_id', sa.String(36), nullable=False),
    sa.Column('external_network_dn', sa.String(1024)),
    sa.Column('nat_type', sa.Enum('distributed', 'edge', '')),
    sa.Column('svi', sa.Boolean),
    sa.Column('bgp_enable', sa.Boolean,
              server_default=sa.false(), nullable=False),
    sa.Column('bgp_type', sa.Enum('default_export', ''),
              server_default="default_export", nullable=False),
    sa.Column('bgp_asn', sa.String(64),
              server_default="0", nullable=False))


def upgrade():
    session = sa.orm.Session(bind=op.get_bind(), autocommit=True)
    with session.begin(subtransactions=True):
        # Migrate networks.
        net_dbs = (session.query(models_v2.Network)
                   .options(lazyload('*')).all())
        for net_db in net_dbs:
            util.msg("Migrating network: %s" % net_db)
            # If this update is successful then it means its an external
            # network with its DN set.
            res = session.execute(NetworkExtensionDb.update().values(
                svi=False).where(NetworkExtensionDb.c.network_id == net_db.id))
            if res.rowcount == 0:
                session.execute(NetworkExtensionDb.insert().values(
                    network_id=net_db.id, svi=False))


def downgrade():
    pass
