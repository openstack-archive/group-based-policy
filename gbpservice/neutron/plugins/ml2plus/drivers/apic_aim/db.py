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
from neutron.db import api as db_api
from neutron.db.models import address_scope as as_db
from neutron.db import models_v2
from neutron_lib import context as n_context
from neutron_lib.db import model_base
from oslo_db import exception as db_exc
from oslo_log import log
import sqlalchemy as sa
from sqlalchemy.ext import baked
from sqlalchemy import orm

VM_UPDATE_PURPOSE = 'VmUpdate'

LOG = log.getLogger(__name__)

BAKERY = baked.bakery()


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


class HAIPAddressToPortAssociation(model_base.BASEV2):

    """Port Owner for HA IP Address.

    This table is used to store the mapping between the HA IP Address
    and the Port ID of the Neutron Port which currently owns this
    IP Address.
    """

    __tablename__ = 'apic_ml2_ha_ipaddress_to_port_owner'

    ha_ip_address = sa.Column(sa.String(64), nullable=False,
                              primary_key=True)
    port_id = sa.Column(sa.String(64), sa.ForeignKey('ports.id',
                                                     ondelete='CASCADE'),
                        nullable=False, primary_key=True)


class VMName(model_base.BASEV2):
    __tablename__ = 'apic_aim_vm_names'

    device_id = sa.Column(sa.String(36), primary_key=True)
    vm_name = sa.Column(sa.String(64))


# At any point of time, there should only be one entry in this table.
# We will enforce that by using the same value for the purpose column which
# is the primary key. That entry is used to make sure only one controller is
# actively updating the VMName table.
class VMNameUpdate(model_base.BASEV2):
    __tablename__ = 'apic_aim_vm_name_updates'

    purpose = sa.Column(sa.String(36), primary_key=True)
    host_id = sa.Column(sa.String(36))
    last_incremental_update_time = sa.Column(sa.DateTime)
    last_full_update_time = sa.Column(sa.DateTime)


class DbMixin(object):

    # AddressScopeMapping functions.

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
            query = BAKERY(lambda s: s.query(
                as_db.AddressScope))
            query += lambda q: q.filter_by(
                id=sa.bindparam('scope_id'))
            scope = query(session).params(
                scope_id=scope_id).one_or_none()

            scope.aim_mapping = mapping
        return mapping

    def _get_address_scope_mapping(self, session, scope_id):
        query = BAKERY(lambda s: s.query(
            AddressScopeMapping))
        query += lambda q: q.filter_by(
            scope_id=sa.bindparam('scope_id'))
        return query(session).params(
            scope_id=scope_id).one_or_none()

    def _get_address_scope_mappings_for_vrf(self, session, vrf):
        query = BAKERY(lambda s: s.query(
            AddressScopeMapping))
        query += lambda q: q.filter_by(
            vrf_tenant_name=sa.bindparam('tenant_name'),
            vrf_name=sa.bindparam('name'))
        return query(session).params(
            tenant_name=vrf.tenant_name,
            name=vrf.name).all()

    def _get_address_scopes_owning_vrf(self, session, vrf):
        query = BAKERY(lambda s: s.query(
            as_db.AddressScope))
        query += lambda q: q.join(
            AddressScopeMapping,
            AddressScopeMapping.scope_id == as_db.AddressScope.id)
        query += lambda q: q.filter(
            AddressScopeMapping.vrf_tenant_name == sa.bindparam('tenant_name'),
            AddressScopeMapping.vrf_name == sa.bindparam('name'),
            AddressScopeMapping.vrf_owned)
        query += lambda q: q.order_by(
            as_db.AddressScope.ip_version)
        return query(session).params(
            tenant_name=vrf.tenant_name,
            name=vrf.name).all()

    def _get_address_scope_vrf(self, mapping):
        return aim_resource.VRF(
            tenant_name=mapping.vrf_tenant_name,
            name=mapping.vrf_name)

    # NetworkMapping functions.

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
            query = BAKERY(lambda s: s.query(
                models_v2.Network))
            query += lambda q: q.filter_by(
                id=sa.bindparam('network_id'))
            net = query(session).params(
                network_id=network_id).one_or_none()

            net.aim_mapping = mapping
        return mapping

    def _get_network_mapping(self, session, network_id):
        query = BAKERY(lambda s: s.query(
            NetworkMapping))
        query += lambda q: q.filter_by(
            network_id=sa.bindparam('network_id'))
        return query(session).params(
            network_id=network_id).one_or_none()

    def _get_network_mappings_for_vrf(self, session, vrf):
        query = BAKERY(lambda s: s.query(
            NetworkMapping))
        query += lambda q: q.filter_by(
            vrf_tenant_name=sa.bindparam('vrf_tenant_name'),
            vrf_name=sa.bindparam('vrf_name'))
        return query(session).params(
            vrf_tenant_name=vrf.tenant_name,
            vrf_name=vrf.name).all()

    def _is_vrf_used_by_networks(self, session, vrf):
        query = BAKERY(lambda s: s.query(
            NetworkMapping.network_id))
        query += lambda q: q.filter_by(
            vrf_tenant_name=sa.bindparam('vrf_tenant_name'),
            vrf_name=sa.bindparam('vrf_name'))
        return query(session).params(
            vrf_tenant_name=vrf.tenant_name,
            vrf_name=vrf.name).first() is not None

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

    # HAIPAddressToPortAssociation functions.

    def _get_ha_ipaddress(self, port_id, ipaddress, session=None):
        session = session or db_api.get_reader_session()

        query = BAKERY(lambda s: s.query(
            HAIPAddressToPortAssociation))
        query += lambda q: q.filter_by(
            port_id=sa.bindparam('port_id'),
            ha_ip_address=sa.bindparam('ipaddress'))
        return query(session).params(
            port_id=port_id, ipaddress=ipaddress).first()

    def get_port_for_ha_ipaddress(self, ipaddress, network_id,
                                  session=None):
        """Returns the Neutron Port ID for the HA IP Addresss."""
        session = session or db_api.get_reader_session()
        query = BAKERY(lambda s: s.query(
            HAIPAddressToPortAssociation))
        query += lambda q: q.join(
            models_v2.Port,
            models_v2.Port.id == HAIPAddressToPortAssociation.port_id)
        query += lambda q: q.filter(
            HAIPAddressToPortAssociation.ha_ip_address ==
            sa.bindparam('ipaddress'))
        query += lambda q: q.filter(
            models_v2.Port.network_id == sa.bindparam('network_id'))
        port_ha_ip = query(session).params(
            ipaddress=ipaddress, network_id=network_id).first()
        return port_ha_ip

    def get_ha_ipaddresses_for_port(self, port_id, session=None):
        """Returns the HA IP Addressses associated with a Port."""
        session = session or db_api.get_reader_session()

        query = BAKERY(lambda s: s.query(
            HAIPAddressToPortAssociation))
        query += lambda q: q.filter_by(
            port_id=sa.bindparam('port_id'))
        objs = query(session).params(
            port_id=port_id).all()

        # REVISIT: Do the sorting in the UT?
        return sorted([x['ha_ip_address'] for x in objs])

    def set_port_id_for_ha_ipaddress(self, port_id, ipaddress, session=None):
        """Stores a Neutron Port Id as owner of HA IP Addr (idempotent API)."""
        session = session or db_api.get_writer_session()
        try:
            with session.begin(subtransactions=True):
                obj = self._get_ha_ipaddress(port_id, ipaddress, session)
                if obj:
                    return obj
                else:
                    obj = HAIPAddressToPortAssociation(
                        port_id=port_id, ha_ip_address=ipaddress)
                    session.add(obj)
                    return obj
        except db_exc.DBDuplicateEntry:
            LOG.debug('Duplicate IP ownership entry for tuple %s',
                      (port_id, ipaddress))

    def delete_port_id_for_ha_ipaddress(self, port_id, ipaddress,
                                        session=None):
        session = session or db_api.get_writer_session()
        with session.begin(subtransactions=True):
            try:
                # REVISIT: Can this query be baked? The
                # sqlalchemy.ext.baked.Result class does not have a
                # delete() method, and adding delete() to the baked
                # query before executing it seems to result in the
                # params() not being evaluated.
                return session.query(
                    HAIPAddressToPortAssociation).filter_by(
                        port_id=port_id,
                        ha_ip_address=ipaddress).delete()
            except orm.exc.NoResultFound:
                return

    # REVISIT: This method is only called from unit tests.
    def get_ha_port_associations(self):
        session = db_api.get_reader_session()

        query = BAKERY(lambda s: s.query(
            HAIPAddressToPortAssociation))
        return query(session).all()

    # REVISIT: Move this method to the mechanism_driver or rpc module,
    # as it is above the DB level. This will also require some rework
    # of its unit tests.
    def update_ip_owner(self, ip_owner_info):
        ports_to_update = set()
        port_id = ip_owner_info.get('port')
        ipv4 = ip_owner_info.get('ip_address_v4')
        ipv6 = ip_owner_info.get('ip_address_v6')
        network_id = ip_owner_info.get('network_id')
        if not port_id or (not ipv4 and not ipv6):
            return ports_to_update
        LOG.debug("Got IP owner update: %s", ip_owner_info)
        # REVISIT: Just use SQLAlchemy session and models_v2.Port?
        port = self.plugin.get_port(n_context.get_admin_context(), port_id)
        if not port:
            LOG.debug("Ignoring update for non-existent port: %s", port_id)
            return ports_to_update
        ports_to_update.add(port_id)
        for ipa in [ipv4, ipv6]:
            if not ipa:
                continue
            try:
                # REVISIT: Why isn't this a single transaction at the
                # top-level, so that the port itself is guaranteed to
                # still exist.
                session = db_api.get_writer_session()
                with session.begin(subtransactions=True):
                    old_owner = self.get_port_for_ha_ipaddress(
                        ipa, network_id or port['network_id'], session=session)
                    self.set_port_id_for_ha_ipaddress(port_id, ipa, session)
                    if old_owner and old_owner['port_id'] != port_id:
                        self.delete_port_id_for_ha_ipaddress(
                            old_owner['port_id'], ipa, session=session)
                        ports_to_update.add(old_owner['port_id'])
            except db_exc.DBReferenceError as dbe:
                LOG.debug("Ignoring FK error for port %s: %s", port_id, dbe)
        return ports_to_update

    # VMName functions.

    def _get_vm_name(self, session, device_id, is_detailed=False):
        if is_detailed:
            query = BAKERY(lambda s: s.query(VMName))
        else:
            query = BAKERY(lambda s: s.query(VMName.vm_name))
        query += lambda q: q.filter_by(
            device_id=sa.bindparam('device_id'))
        return query(session).params(
            device_id=device_id).one_or_none()

    def _get_vm_names(self, session):
        query = BAKERY(lambda s: s.query(VMName.device_id,
                                         VMName.vm_name))
        return query(session).all()

    def _set_vm_name(self, session, device_id, vm_name):
        with session.begin(subtransactions=True):
            db_obj = self._get_vm_name(session, device_id,
                                       is_detailed=True)
            if db_obj:
                db_obj.vm_name = vm_name
            else:
                db_obj = VMName(device_id=device_id, vm_name=vm_name)
            session.add(db_obj)

    def _delete_vm_name(self, session, device_id):
        with session.begin(subtransactions=True):
            db_obj = self._get_vm_name(session, device_id,
                                       is_detailed=True)
            if db_obj:
                session.delete(db_obj)

    # VMNameUpdate functions.

    def _get_vm_name_update(self, session):
        query = BAKERY(lambda s: s.query(VMNameUpdate))
        return query(session).one_or_none()

    def _set_vm_name_update(self, session, db_obj, host_id,
                            last_incremental_update_time,
                            last_full_update_time=None):
        with session.begin(subtransactions=True):
            if db_obj:
                db_obj.host_id = host_id
                db_obj.last_incremental_update_time = (
                                    last_incremental_update_time)
                if last_full_update_time:
                    db_obj.last_full_update_time = last_full_update_time
            else:
                db_obj = VMNameUpdate(
                    purpose=VM_UPDATE_PURPOSE, host_id=host_id,
                    last_incremental_update_time=last_incremental_update_time,
                    last_full_update_time=last_full_update_time)
            session.add(db_obj)
