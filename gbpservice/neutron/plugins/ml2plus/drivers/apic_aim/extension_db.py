# Copyright (c) 2016 Cisco Systems Inc.
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

from neutron.db import models_v2
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_l3


class NetworkExtensionDb(model_base.BASEV2):

    __tablename__ = 'apic_aim_network_extensions'

    network_id = sa.Column(
        sa.String(36), sa.ForeignKey('networks.id', ondelete="CASCADE"),
        primary_key=True)
    external_network_dn = sa.Column(sa.String(1024))
    nat_type = sa.Column(sa.Enum('distributed', 'edge', ''))
    svi = sa.Column(sa.Boolean)
    bgp_enable = sa.Column(sa.Boolean, default=False, nullable=False)
    bgp_type = sa.Column(sa.Enum('default_export', ''),
                         default='default_export',
                         nullable=False)
    bgp_asn = sa.Column(sa.String(64), default='0', nullable=False)

    network = orm.relationship(models_v2.Network,
                               backref=orm.backref(
                                   'aim_extension_mapping', lazy='joined',
                                   uselist=False, cascade='delete'))


class NetworkExtensionCidrDb(model_base.BASEV2):

    __tablename__ = 'apic_aim_network_external_cidrs'

    network_id = sa.Column(
        sa.String(36), sa.ForeignKey('networks.id', ondelete="CASCADE"),
        primary_key=True)
    cidr = sa.Column(sa.String(64), primary_key=True)


class SubnetExtensionDb(model_base.BASEV2):

    __tablename__ = 'apic_aim_subnet_extensions'

    subnet_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnets.id', ondelete="CASCADE"),
        primary_key=True)
    snat_host_pool = sa.Column(sa.Boolean)


class RouterExtensionContractDb(model_base.BASEV2):

    __tablename__ = 'apic_aim_router_external_contracts'

    router_id = sa.Column(
        sa.String(36), sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    contract_name = sa.Column(sa.String(64), primary_key=True)
    provides = sa.Column(sa.Boolean, primary_key=True)


class ExtensionDbMixin(object):

    def _set_if_not_none(self, res_dict, res_attr, db_attr):
        if db_attr is not None:
            res_dict[res_attr] = db_attr

    def get_network_extn_db(self, session, network_id):
        db_obj = (session.query(NetworkExtensionDb).filter_by(
                  network_id=network_id).first())
        db_cidrs = (session.query(NetworkExtensionCidrDb).filter_by(
                    network_id=network_id).all())
        result = {}
        if db_obj:
            self._set_if_not_none(result, cisco_apic.EXTERNAL_NETWORK,
                                  db_obj['external_network_dn'])
            self._set_if_not_none(result, cisco_apic.NAT_TYPE,
                                  db_obj['nat_type'])
            self._set_if_not_none(result, cisco_apic.SVI, db_obj['svi'])
            result[cisco_apic.BGP] = db_obj['bgp_enable']
            result[cisco_apic.BGP_TYPE] = db_obj['bgp_type']
            result[cisco_apic.BGP_ASN] = db_obj['bgp_asn']
        if result.get(cisco_apic.EXTERNAL_NETWORK):
            result[cisco_apic.EXTERNAL_CIDRS] = [c['cidr'] for c in db_cidrs]

        return result

    def set_network_extn_db(self, session, network_id, res_dict):
        with session.begin(subtransactions=True):
            db_obj = (session.query(NetworkExtensionDb).filter_by(
                      network_id=network_id).first())
            db_obj = db_obj or NetworkExtensionDb(network_id=network_id)
            if cisco_apic.EXTERNAL_NETWORK in res_dict:
                db_obj['external_network_dn'] = (
                    res_dict[cisco_apic.EXTERNAL_NETWORK])
            if cisco_apic.NAT_TYPE in res_dict:
                db_obj['nat_type'] = res_dict[cisco_apic.NAT_TYPE]
            if cisco_apic.SVI in res_dict:
                db_obj['svi'] = res_dict[cisco_apic.SVI]
            if cisco_apic.BGP in res_dict:
                db_obj['bgp_enable'] = res_dict[cisco_apic.BGP]
            if cisco_apic.BGP_TYPE in res_dict:
                db_obj['bgp_type'] = res_dict[cisco_apic.BGP_TYPE]
            if cisco_apic.BGP_ASN in res_dict:
                db_obj['bgp_asn'] = res_dict[cisco_apic.BGP_ASN]
            session.add(db_obj)

            if cisco_apic.EXTERNAL_CIDRS in res_dict:
                self._update_list_attr(session, NetworkExtensionCidrDb, 'cidr',
                                       res_dict[cisco_apic.EXTERNAL_CIDRS],
                                       network_id=network_id)

    def get_network_ids_by_ext_net_dn(self, session, dn, lock_update=False):
        ids = session.query(NetworkExtensionDb.network_id).filter_by(
            external_network_dn=dn)
        if lock_update:
            ids = ids.with_lockmode('update')
        return [i[0] for i in ids]

    def get_network_ids_by_l3out_dn(self, session, dn, lock_update=False):
        ids = session.query(NetworkExtensionDb.network_id).filter(
            NetworkExtensionDb.external_network_dn.like(dn + "/%"))
        if lock_update:
            ids = ids.with_lockmode('update')
        return [i[0] for i in ids]

    def get_external_cidrs_by_ext_net_dn(self, session, dn, lock_update=False):
        ctab = NetworkExtensionCidrDb
        ntab = NetworkExtensionDb
        cidrs = session.query(ctab.cidr).join(
            ntab, ntab.network_id == ctab.network_id).filter(
                    ntab.external_network_dn == dn).distinct()
        if lock_update:
            cidrs = cidrs.with_lockmode('update')
        return [c[0] for c in cidrs]

    def get_subnet_extn_db(self, session, subnet_id):
        db_obj = (session.query(SubnetExtensionDb).filter_by(
                  subnet_id=subnet_id).first())
        result = {}
        if db_obj:
            self._set_if_not_none(result, cisco_apic.SNAT_HOST_POOL,
                                  db_obj['snat_host_pool'])
        return result

    def set_subnet_extn_db(self, session, subnet_id, res_dict):
        db_obj = (session.query(SubnetExtensionDb).filter_by(
                  subnet_id=subnet_id).first())
        db_obj = db_obj or SubnetExtensionDb(subnet_id=subnet_id)
        if cisco_apic.SNAT_HOST_POOL in res_dict:
            db_obj['snat_host_pool'] = res_dict[cisco_apic.SNAT_HOST_POOL]
        session.add(db_obj)

    def get_router_extn_db(self, session, router_id):
        db_contracts = (session.query(RouterExtensionContractDb).filter_by(
                        router_id=router_id).all())
        return {cisco_apic_l3.EXTERNAL_PROVIDED_CONTRACTS:
                [c['contract_name'] for c in db_contracts if c['provides']],
                cisco_apic_l3.EXTERNAL_CONSUMED_CONTRACTS:
                [c['contract_name'] for c in db_contracts
                 if not c['provides']]}

    def _update_list_attr(self, session, db_model, column,
                          new_values, **filters):
        rows = session.query(db_model).filter_by(**filters).all()
        new_values = set(new_values)
        for r in rows:
            if r[column] in new_values:
                new_values.discard(r[column])
            else:
                session.delete(r)
        for v in new_values:
            attr = {column: v}
            attr.update(filters)
            db_obj = db_model(**attr)
            session.add(db_obj)

    def set_router_extn_db(self, session, router_id, res_dict):
        with session.begin(subtransactions=True):
            if cisco_apic_l3.EXTERNAL_PROVIDED_CONTRACTS in res_dict:
                self._update_list_attr(session, RouterExtensionContractDb,
                   'contract_name',
                   res_dict[cisco_apic_l3.EXTERNAL_PROVIDED_CONTRACTS],
                   router_id=router_id, provides=True)
            if cisco_apic_l3.EXTERNAL_CONSUMED_CONTRACTS in res_dict:
                self._update_list_attr(session, RouterExtensionContractDb,
                    'contract_name',
                    res_dict[cisco_apic_l3.EXTERNAL_CONSUMED_CONTRACTS],
                    router_id=router_id, provides=False)
