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

# Note: This module should be treated as legacy and should not be extended to
# add any new data migrations. New data migrations should be added
# directly to the alembic migration script along with the table definitions
# that are being referenced.
# For reference see how its done here:
# https://github.com/openstack/neutron/blob/
# 625de54de3936b0da8760c3da76d2d315d05f94e/neutron/db/migration/
# alembic_migrations/versions/newton/contract/
# 3b935b28e7a0_migrate_to_pluggable_ipam.py

import netaddr

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from aim import utils as aim_utils
from alembic import util as alembic_util
from neutron.db.models import address_scope as as_db
from neutron.db.models import securitygroup as sg_models
from neutron.db.migration.cli import *  # noqa
from neutron.db import models_v2
from neutron.db import segments_db  # noqa
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy.orm import lazyload

from gbpservice.neutron.extensions import cisco_apic as ext
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper


# The following definitions have been taken from commit:
# 9b4b7276ad8a0f181c9be12ba5a0192432aa5027
# and is frozen for the data migration script that was included
# in this module. It should not be changed in this module.
NetworkExtensionDb = sa.Table(
        'apic_aim_network_extensions', sa.MetaData(),
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('external_network_dn', sa.String(1024)),
        sa.Column('nat_type', sa.Enum('distributed', 'edge', '')))


NetworkExtensionCidrDb = sa.Table(
        'apic_aim_network_external_cidrs', sa.MetaData(),
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('cidr', sa.String(64), nullable=False))


AddressScopeMapping = sa.Table(
        'apic_aim_address_scope_mappings', sa.MetaData(),
        sa.Column('scope_id', sa.String(36)),
        sa.Column('vrf_name', sa.String(64)),
        sa.Column('vrf_tenant_name', sa.String(64)),
        sa.Column('vrf_owned', sa.Boolean, nullable=False))


# The following definition has been taken from commit:
# f8b41855acbbb7e59a0bab439445c198fc6aa146
# and is frozen for the data migration script that was included
# in this module. It should not be changed in this module.
NetworkMapping = sa.Table(
        'apic_aim_network_mappings', sa.MetaData(),
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('bd_name', sa.String(64), nullable=True),
        sa.Column('bd_tenant_name', sa.String(64), nullable=True),
        sa.Column('epg_name', sa.String(64), nullable=True),
        sa.Column('epg_tenant_name', sa.String(64), nullable=True),
        sa.Column('epg_app_profile_name', sa.String(64), nullable=True),
        sa.Column('vrf_name', sa.String(64), nullable=True),
        sa.Column('vrf_tenant_name', sa.String(64), nullable=True))


class DefunctAddressScopeExtensionDb(model_base.BASEV2):
    # REVISIT: This DB model class is used only for the
    # apic_aim_persist data migration, after which this table is
    # dropped.

    __tablename__ = 'apic_aim_addr_scope_extensions'

    address_scope_id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id', ondelete="CASCADE"),
        primary_key=True)
    vrf_dn = sa.Column(sa.String(1024))


def _add_address_scope_mapping(session, scope_id, vrf, vrf_owned=True):
    session.execute(AddressScopeMapping.insert().values(
        scope_id=scope_id, vrf_name=vrf.name, vrf_tenant_name=vrf.tenant_name,
        vrf_owned=vrf_owned))


def _add_network_mapping(session, network_id, bd, epg, vrf, ext_net=None):
    if not ext_net:
        session.execute(NetworkMapping.insert().values(
            network_id=network_id, bd_name=bd.name,
            bd_tenant_name=bd.tenant_name, epg_name=epg.name,
            epg_app_profile_name=epg.app_profile_name,
            epg_tenant_name=epg.tenant_name, vrf_name=vrf.name,
            vrf_tenant_name=vrf.tenant_name))


def do_apic_aim_persist_migration(session):
    alembic_util.msg(
        "Starting data migration for apic_aim mechanism driver persistence.")

    aim = aim_manager.AimManager()
    aim_ctx = aim_context.AimContext(session)
    mapper = apic_mapper.APICNameMapper()

    with session.begin(subtransactions=True):
        # Migrate address scopes.
        scope_dbs = (session.query(as_db.AddressScope)
                     .options(lazyload('*')).all())
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
                _add_address_scope_mapping(
                    session, scope_db.id, vrf, vrf_owned)
            else:
                alembic_util.warn(
                    "No AIM VRF found for address scope: %s" % scope_db)

        # Migrate networks.
        net_dbs = (session.query(models_v2.Network)
                   .options(lazyload('*')).all())
        for net_db in net_dbs:
            alembic_util.msg("Migrating network: %s" % net_db)
            bd = None
            epg = None
            vrf = None
            ext_db = (session.query(NetworkExtensionDb).
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
                _add_network_mapping(session, net_db.id, bd, epg, vrf)
            elif not net_db.external:
                alembic_util.warn(
                    "AIM BD, EPG or VRF not found for network: %s" % net_db)

    alembic_util.msg(
        "Finished data migration for apic_aim mechanism driver persistence.")


def _get_network_extn_db(session, network_id):
    netres = (session.query(NetworkExtensionDb).filter_by(
              network_id=network_id).first())

    if netres:
        _, ext_net_dn, nat_type = netres
        db_cidrs = (session.query(NetworkExtensionCidrDb).filter_by(
                    network_id=network_id).all())
        result = {}
        if ext_net_dn is not None:
            result[ext.EXTERNAL_NETWORK] = ext_net_dn
        if nat_type is not None:
            result[ext.NAT_TYPE] = nat_type
        if result.get(ext.EXTERNAL_NETWORK):
            result[ext.EXTERNAL_CIDRS] = [c for _, c in db_cidrs]
        return result


def do_ap_name_change(session, conf=None):
    alembic_util.msg("Starting data migration for apic_aim ap name change.")
    cfg = conf or CONF
    aim = aim_manager.AimManager()
    aim_ctx = aim_context.AimContext(session)
    system_id = cfg.apic_system_id
    alembic_util.msg("APIC System ID: %s" % system_id)
    with session.begin(subtransactions=True):
        net_dbs = session.query(models_v2.Network).options(lazyload('*')).all()
        for net_db in net_dbs:
            ext_db = _get_network_extn_db(session, net_db.id)
            if ext_db and ext_db.get(ext.EXTERNAL_NETWORK):
                alembic_util.msg("Migrating external network: %s" % net_db)
                # Its a managed external network.
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    ext_db[ext.EXTERNAL_NETWORK])
                ext_net = aim.get(aim_ctx, ext_net)
                l3out = aim_resource.L3Outside(tenant_name=ext_net.tenant_name,
                                               name=ext_net.l3out_name)
                if ext_db[ext.NAT_TYPE] == '':
                    ns_cls = nat_strategy.NoNatStrategy
                elif ext_db[ext.NAT_TYPE] == 'edge':
                    ns_cls = nat_strategy.EdgeNatStrategy
                else:
                    ns_cls = nat_strategy.DistributedNatStrategy
                clone_ext_nets = {}
                ns = ns_cls(aim)
                ns.app_profile_name = 'OpenStack'
                ns.common_scope = None
                # Start Cleanup
                if not isinstance(ns, nat_strategy.NoNatStrategy):
                    l3out_clones = ns.db.get_clones(aim_ctx, l3out)
                    # Retrieve External Networks
                    for l3out_clone in l3out_clones:
                        for extc in aim.find(
                                aim_ctx, aim_resource.ExternalNetwork,
                                tenant_name=l3out_clone[0],
                                l3out_name=l3out_clone[1]):
                            clone_ext_nets[(l3out.tenant_name,
                                            l3out.name,
                                            extc.name)] = extc
                vrfs = ns.read_vrfs(aim_ctx, ext_net)
                session.execute(NetworkMapping.delete().where(
                    NetworkMapping.c.network_id == net_db.id))
                for vrf in vrfs:
                    ns.disconnect_vrf(aim_ctx, ext_net, vrf)
                ns.delete_external_network(aim_ctx, ext_net)
                ns.delete_l3outside(aim_ctx, l3out)
                # Recreate
                ns.common_scope = system_id
                ns.create_l3outside(aim_ctx, l3out)
                ns.create_external_network(aim_ctx, ext_net)
                ns.update_external_cidrs(aim_ctx, ext_net,
                                         ext_db[ext.EXTERNAL_CIDRS])
                for subnet in net_db.subnets:
                    aim_subnet = aim_resource.Subnet.to_gw_ip_mask(
                        subnet.gateway_ip, int(subnet.cidr.split('/')[1]))
                    ns.create_subnet(aim_ctx, l3out, aim_subnet)
                for resource in ns.get_l3outside_resources(aim_ctx, l3out):
                    if isinstance(resource, aim_resource.BridgeDomain):
                        bd = resource
                    elif isinstance(resource, aim_resource.EndpointGroup):
                        epg = resource
                    elif isinstance(resource, aim_resource.VRF):
                        vrf = resource
                _add_network_mapping(session, net_db.id, bd, epg, vrf)
                eid = (ext_net.tenant_name, ext_net.l3out_name, ext_net.name)
                for vrf in vrfs:
                    if eid in clone_ext_nets:
                        ext_net.provided_contract_names = clone_ext_nets[
                            eid].provided_contract_names
                        ext_net.consumed_contract_names = clone_ext_nets[
                            eid].consumed_contract_names
                    ns.connect_vrf(aim_ctx, ext_net, vrf)


def do_apic_aim_security_group_migration(session):
    alembic_util.msg(
        "Starting data migration for SGs and its rules.")

    aim = aim_manager.AimManager()
    aim_ctx = aim_context.AimContext(session)
    mapper = apic_mapper.APICNameMapper()
    with session.begin(subtransactions=True):
        # Migrate SG.
        sg_dbs = (session.query(sg_models.SecurityGroup).
                  options(lazyload('*')).all())
        for sg_db in sg_dbs:
            alembic_util.msg("Migrating SG: %s" % sg_db)
            tenant_aname = mapper.project(session, sg_db['tenant_id'])
            sg_aim = aim_resource.SecurityGroup(
                tenant_name=tenant_aname, name=sg_db['id'],
                display_name=aim_utils.sanitize_display_name(sg_db['name']))
            aim.create(aim_ctx, sg_aim, overwrite=True)
            # Always create this default subject
            sg_subject = aim_resource.SecurityGroupSubject(
                tenant_name=tenant_aname,
                security_group_name=sg_db['id'], name='default')
            aim.create(aim_ctx, sg_subject, overwrite=True)

        # Migrate SG rules.
        sg_rule_dbs = (session.query(sg_models.SecurityGroupRule).
                       options(lazyload('*')).all())
        for sg_rule_db in sg_rule_dbs:
            tenant_aname = mapper.project(session, sg_rule_db['tenant_id'])
            if sg_rule_db.get('remote_group_id'):
                ip_version = 0
                if sg_rule_db['ethertype'] == 'IPv4':
                    ip_version = 4
                elif sg_rule_db['ethertype'] == 'IPv6':
                    ip_version = 6
                remote_ips = []
                sg_ports = (session.query(models_v2.Port).
                            join(sg_models.SecurityGroupPortBinding,
                                 sg_models.SecurityGroupPortBinding.port_id ==
                                 models_v2.Port.id).
                            filter(sg_models.SecurityGroupPortBinding.
                                   security_group_id ==
                                   sg_rule_db['remote_group_id']).
                            options(lazyload('*')).all())
                for sg_port in sg_ports:
                    for fixed_ip in sg_port['fixed_ips']:
                        if ip_version == netaddr.IPAddress(
                                fixed_ip['ip_address']).version:
                            remote_ips.append(fixed_ip['ip_address'])
            else:
                remote_ips = ([sg_rule_db['remote_ip_prefix']]
                              if sg_rule_db['remote_ip_prefix'] else '')
            sg_rule_aim = aim_resource.SecurityGroupRule(
                tenant_name=tenant_aname,
                security_group_name=sg_rule_db['security_group_id'],
                security_group_subject_name='default',
                name=sg_rule_db['id'],
                direction=sg_rule_db['direction'],
                ethertype=sg_rule_db['ethertype'].lower(),
                ip_protocol=(sg_rule_db['protocol'] if sg_rule_db['protocol']
                             else 'unspecified'),
                remote_ips=remote_ips,
                from_port=(sg_rule_db['port_range_min']
                           if sg_rule_db['port_range_min'] else 'unspecified'),
                to_port=(sg_rule_db['port_range_max']
                         if sg_rule_db['port_range_max'] else 'unspecified'))
            aim.create(aim_ctx, sg_rule_aim, overwrite=True)

    alembic_util.msg(
        "Finished data migration for SGs and its rules.")
