# Copyright (c) 2017 Cisco Systems Inc.
# All Rights Reserved.
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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from alembic import util as alembic_util
from neutron.db.models import address_scope as as_db

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db


def apic_aim_persist(session):
    alembic_util.msg("Migrating data for apic_aim persistence.")

    db_mixin = db.DbMixin()
    aim = aim_manager.AimManager()
    aim_ctx = aim_context.AimContext(session)
    mapper = apic_mapper.APICNameMapper()

    with session.begin(subtransactions=True):
        scope_dbs = (session.query(as_db.AddressScope).
                     all())
        for scope_db in scope_dbs:
            alembic_util.msg(
                "Migrating address scope: %s" % scope_db)
            aname = mapper.address_scope(session, scope_db.id)
            vrfs = aim.find(aim_ctx, aim_resource.VRF, name=aname)
            if vrfs:
                db_mixin._add_address_scope_mapping(
                    session, scope_db.id, vrfs[0])
            else:
                alembic_util.err(
                    "No AIM VRF found for address scope: %s" % scope_db)
