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

"""apic_aim_security_group

Revision ID: 123cbc863d34
Revises: d978a7a73785
Create Date: 2017-09-28 17:34:18.856803

"""

# revision identifiers, used by Alembic.
revision = '123cbc863d34'
down_revision = 'd978a7a73785'

from alembic import op
from alembic import util
import sqlalchemy as sa


def upgrade():
    # See if AIM is being used, and if so, create those default arp rules
    bind = op.get_bind()
    insp = sa.engine.reflection.Inspector.from_engine(bind)
    if 'aim_tenants' in insp.get_table_names():
        try:
            # Note - this cannot be imported unless we know the
            # apic_aim mechanism driver is deployed, since the AIM
            # library may not be installed.
            from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
                data_migrations)

            session = sa.orm.Session(bind=bind, autocommit=True)
            data_migrations.setup_default_arp_security_group_rules(session)
        except Exception as e:
            util.warn("Caught exception while creating default arp SG rules: "
                      "%s" % e)


def downgrade():
    pass
