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

from aim.api import resource as aim_resource
from neutron.db.models import address_scope as as_db
from neutron.db import models_v2
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class AddressScopeMapping(model_base.BASEV2):
    __tablename__ = 'apic_aim_address_scope_mappings'

    scope_id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id', ondelete='CASCADE'),
        primary_key=True)

    address_scope = orm.relationship(
        as_db.AddressScope, lazy='joined',
        backref=orm.backref(
            'aim_mapping', lazy='joined', uselist=False, cascade='delete'))

    vrf_name = sa.Column(sa.String(64))
    vrf_tenant_name = sa.Column(sa.String(64))
    vrf_owned = sa.Column(sa.Boolean, nullable=False)


class NetworkMapping(model_base.BASEV2):
    __tablename__ = 'apic_aim_network_mappings'

    network_id = sa.Column(
        sa.String(36), sa.ForeignKey('networks.id', ondelete='CASCADE'),
        primary_key=True)

    network = orm.relationship(
        models_v2.Network, lazy='joined',
        backref=orm.backref(
            'aim_mapping', lazy='joined', uselist=False, cascade='delete'))

    bd_name = sa.Column(sa.String(64))
    bd_tenant_name = sa.Column(sa.String(64))

    epg_name = sa.Column(sa.String(64))
    epg_app_profile_name = sa.Column(sa.String(64))
    epg_tenant_name = sa.Column(sa.String(64))

    l3out_name = sa.Column(sa.String(64))
    l3out_ext_net_name = sa.Column(sa.String(64))
    l3out_tenant_name = sa.Column(sa.String(64))

    vrf_name = sa.Column(sa.String(64))
    vrf_tenant_name = sa.Column(sa.String(64))


class DbMixin(object):
    def _add_address_scope_mapping(self, session, scope_id, vrf,
                                   vrf_owned=True, update_scope=True):
        mapping = AddressScopeMapping(
            scope_id=scope_id,
            vrf_name=vrf.name,
            vrf_tenant_name=vrf.tenant_name,
            vrf_owned=vrf_owned)
        session.add(mapping)
        if update_scope:
            # The AddressScope instance should already be in the
            # session cache, so this should not add another DB
            # roundtrip. It needs to be updated in case something
            # within the same transaction tries to access its
            # aim_mapping relationship after retrieving the
            # AddressScope record from the session cache.
            scope = (session.query(as_db.AddressScope).
                     filter_by(id=scope_id).
                     one_or_none())
            scope.aim_mapping = mapping
        return mapping

    def _get_address_scope_mapping(self, session, scope_id):
        return (session.query(AddressScopeMapping).
                filter_by(scope_id=scope_id).
                one_or_none())

    def _get_address_scope_mappings_for_vrf(self, session, vrf):
        return (session.query(AddressScopeMapping).
                filter_by(vrf_tenant_name=vrf.tenant_name,
                          vrf_name=vrf.name).
                all())

    def _get_address_scopes_owning_vrf(self, session, vrf):
        return (session.query(as_db.AddressScope).
                join(AddressScopeMapping,
                     AddressScopeMapping.scope_id == as_db.AddressScope.id).
                filter(AddressScopeMapping.vrf_tenant_name ==
                       vrf.tenant_name,
                       AddressScopeMapping.vrf_name == vrf.name,
                       AddressScopeMapping.vrf_owned).
                order_by(as_db.AddressScope.ip_version).
                all())

    def _get_address_scope_vrf(self, mapping):
        return aim_resource.VRF(
            tenant_name=mapping.vrf_tenant_name,
            name=mapping.vrf_name)

    def _add_network_mapping(self, session, network_id, bd, epg, vrf,
                             ext_net=None, update_network=True):
        if not ext_net:
            mapping = NetworkMapping(
                network_id=network_id,
                bd_name=bd.name,
                bd_tenant_name=bd.tenant_name,
                epg_name=epg.name,
                epg_app_profile_name=epg.app_profile_name,
                epg_tenant_name=epg.tenant_name,
                vrf_name=vrf.name,
                vrf_tenant_name=vrf.tenant_name)
        else:
            mapping = NetworkMapping(
                network_id=network_id,
                l3out_name=ext_net.l3out_name,
                l3out_ext_net_name=ext_net.name,
                l3out_tenant_name=ext_net.tenant_name,
                vrf_name=vrf.name,
                vrf_tenant_name=vrf.tenant_name)
        session.add(mapping)
        if update_network:
            # The Network instance should already be in the session
            # cache, so this should not add another DB roundtrip. It
            # needs to be updated in case something within the same
            # transaction tries to access its aim_mapping relationship
            # after retrieving the Network record from the session
            # cache.
            net = (session.query(models_v2.Network).
                   filter_by(id=network_id).
                   one_or_none())
            net.aim_mapping = mapping
        return mapping

    def _get_network_mapping(self, session, network_id):
        return (session.query(NetworkMapping).
                filter_by(network_id=network_id).
                one_or_none())

    def _get_network_mapping_bulk(self, session, network_ids):
        return session.query(NetworkMapping).filter(
            NetworkMapping.network_id.in_(network_ids)).all()

    def _get_network_mappings_for_vrf(self, session, vrf):
        return (session.query(NetworkMapping).
                filter_by(vrf_tenant_name=vrf.tenant_name,
                          vrf_name=vrf.name).
                all())

    def _get_network_mappings_for_bd(self, session, bd):
        return (session.query(NetworkMapping).
                filter_by(bd_tenant_name=bd.tenant_name,
                          bd_name=bd.name).
                all())

    def _is_vrf_used_by_networks(self, session, vrf):
        return (session.query(NetworkMapping.network_id).
                filter_by(vrf_tenant_name=vrf.tenant_name,
                          vrf_name=vrf.name).
                first() is not None)

    def _get_network_bd(self, mapping):
        return aim_resource.BridgeDomain(
            tenant_name=mapping.bd_tenant_name,
            name=mapping.bd_name)

    def _get_network_epg(self, mapping):
        return aim_resource.EndpointGroup(
            tenant_name=mapping.epg_tenant_name,
            app_profile_name=mapping.epg_app_profile_name,
            name=mapping.epg_name)

    def _get_network_l3out(self, mapping):
        if not mapping:
            # REVISIT: Is this still needed now that
            # _add_network_mapping updates the Network instance's
            # aim_mapping? If so, the test should probably be moved to
            # the caller to make all these
            # _get_<neutron-resource>_<aim-resource> methods more
            # consistent.
            return None
        return aim_resource.L3Outside(
            tenant_name=mapping.l3out_tenant_name,
            name=mapping.l3out_name)

    def _get_network_l3out_ext_net(self, mapping):
        return aim_resource.ExternalNetwork(
            tenant_name=mapping.l3out_tenant_name,
            l3out_name=mapping.l3out_name, name=mapping.l3out_ext_net_name)

    def _get_network_l3out_default_ext_subnetv4(self, mapping):
        return aim_resource.ExternalSubnet(
            tenant_name=mapping.l3out_tenant_name,
            l3out_name=mapping.l3out_name,
            external_network_name=mapping.l3out_ext_net_name,
            cidr="0.0.0.0/0")

    def _get_network_l3out_default_ext_subnetv6(self, mapping):
        return aim_resource.ExternalSubnet(
            tenant_name=mapping.l3out_tenant_name,
            l3out_name=mapping.l3out_name,
            external_network_name=mapping.l3out_ext_net_name,
            cidr="::/0")

    def _get_network_vrf(self, mapping):
        return aim_resource.VRF(
            tenant_name=mapping.vrf_tenant_name,
            name=mapping.vrf_name)

    def _set_network_bd(self, mapping, bd):
        mapping.bd_tenant_name = bd.tenant_name
        mapping.bd_name = bd.name

    def _set_network_epg(self, mapping, epg):
        mapping.epg_tenant_name = epg.tenant_name
        mapping.epg_app_profile_name = epg.app_profile_name
        mapping.epg_name = epg.name

    def _set_network_l3out(self, mapping, l3out):
        mapping.l3out_tenant_name = l3out.tenant_name
        mapping.l3out_name = l3out.name

    def _set_network_vrf(self, mapping, vrf):
        mapping.vrf_tenant_name = vrf.tenant_name
        mapping.vrf_name = vrf.name
