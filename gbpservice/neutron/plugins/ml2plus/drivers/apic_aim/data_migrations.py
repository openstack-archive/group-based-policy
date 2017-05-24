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

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from alembic import util as alembic_util
from neutron.db.models import address_scope as as_db
from neutron.db import models_v2
from neutron_lib.db import model_base
import sqlalchemy as sa

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import extension_db


class DefunctAddressScopeExtensionDb(model_base.BASEV2):
    # REVISIT: This DB model class is used only for the
    # apic_aim_persist data migration, after which this table is
    # dropped.

    __tablename__ = 'apic_aim_addr_scope_extensions'

    address_scope_id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id', ondelete="CASCADE"),
        primary_key=True)
    vrf_dn = sa.Column(sa.String(1024))


def do_apic_aim_persist_migration(session):
    alembic_util.msg(
        "Starting data migration for apic_aim mechanism driver persistence.")

    db_mixin = db.DbMixin()
    aim = aim_manager.AimManager()
    aim_ctx = aim_context.AimContext(session)
    mapper = apic_mapper.APICNameMapper()

    with session.begin(subtransactions=True):
        # Migrate address scopes.
        scope_dbs = (session.query(as_db.AddressScope).
                     all())
        for scope_db in scope_dbs:
            alembic_util.msg("Migrating address scope: %s" % scope_db)
            vrf = None
            ext_db = (session.query(DefunctAddressScopeExtensionDb).
                      filter_by(address_scope_id=scope_db.id).
                      one_or_none())
            if ext_db:
                # It has a pre-existing VRF.
                vrf = aim_resource.VRF.from_dn(ext_db.vrf_dn)
                # REVISIT: Get VRF to verify it exists?
                vrf_owned = False
            if not vrf:
                # It does not have a pre-existing VRF.
                aname = mapper.address_scope(session, scope_db.id)
                vrfs = aim.find(
                    aim_ctx, aim_resource.VRF,
                    name=aname)
                if vrfs:
                    vrf = vrfs[0]
                    vrf_owned = True
            if vrf:
                db_mixin._add_address_scope_mapping(
                    session, scope_db.id, vrf, vrf_owned)
            else:
                alembic_util.warn(
                    "No AIM VRF found for address scope: %s" % scope_db)

        # Migrate networks.
        net_dbs = (session.query(models_v2.Network).
                   all())
        for net_db in net_dbs:
            alembic_util.msg("Migrating network: %s" % net_db)
            bd = None
            epg = None
            vrf = None
            ext_db = (session.query(extension_db.NetworkExtensionDb).
                      filter_by(network_id=net_db.id).
                      one_or_none())
            if ext_db and ext_db.external_network_dn:
                # Its a managed external network.
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    ext_db.external_network_dn)
                # REVISIT: Get ExternalNetwork to verify it exists?
                l3out = aim_resource.L3Outside(
                    tenant_name=ext_net.tenant_name,
                    name=ext_net.l3out_name)
                if ext_db.nat_type == '':
                    ns_cls = nat_strategy.NoNatStrategy
                elif ext_db.nat_type == 'edge':
                    ns_cls = nat_strategy.EdgeNatStrategy
                else:
                    ns_cls = nat_strategy.DistributedNatStrategy
                ns = ns_cls(aim)
                ns.app_profile_name = 'OpenStack'
                for resource in ns.get_l3outside_resources(aim_ctx, l3out):
                    if isinstance(resource, aim_resource.BridgeDomain):
                        bd = resource
                    elif isinstance(resource, aim_resource.EndpointGroup):
                        epg = resource
                    elif isinstance(resource, aim_resource.VRF):
                        vrf = resource
            if not bd:
                # It must be a normal network.
                aname = mapper.network(session, net_db.id)
                bds = aim.find(
                    aim_ctx, aim_resource.BridgeDomain,
                    name=aname)
                if bds:
                    bd = bds[0]
                epgs = aim.find(
                    aim_ctx, aim_resource.EndpointGroup,
                    name=aname)
                if epgs:
                    epg = epgs[0]
                if bd:
                    vrfs = (
                        aim.find(
                            aim_ctx, aim_resource.VRF,
                            tenant_name=bd.tenant_name,
                            name=bd.vrf_name) or
                        aim.find(
                            aim_ctx, aim_resource.VRF,
                            tenant_name='common',
                            name=bd.vrf_name))
                    if vrfs:
                        vrf = vrfs[0]
            if bd and epg and vrf:
                db_mixin._add_network_mapping(
                    session, net_db.id, bd, epg, vrf)
            elif not net_db.external:
                alembic_util.warn(
                    "AIM BD, EPG or VRF not found for network: %s" % net_db)

    alembic_util.msg(
        "Finished data migration for apic_aim mechanism driver persistence.")
