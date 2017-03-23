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
from neutron.db import address_scope_db
from neutron.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class AddressScopeMapping(model_base.BASEV2):
    __tablename__ = 'apic_aim_address_scope_mapping'

    id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id', ondelete='CASCADE'),
        primary_key=True)

    address_scope = orm.relationship(
        address_scope_db.AddressScope, lazy='joined',
        backref=orm.backref(
            'aim_mapping', lazy='joined', uselist=False, cascade='delete'))

    vrf_name = sa.Column(sa.String(64))
    vrf_tenant_name = sa.Column(sa.String(64))
    vrf_owned = sa.Column(sa.Boolean)


class DbMixin(object):
    def _add_address_scope_mapping(self, session, id, vrf, vrf_owned=True):
        mapping = AddressScopeMapping(
            id=id,
            vrf_name=vrf.name,
            vrf_tenant_name=vrf.tenant_name,
            vrf_owned=vrf_owned)
        session.add(mapping)
        return mapping

    def _get_address_scope_mapping(self, session, id):
        return (session.query(AddressScopeMapping).
                filter_by(id=id).
                one_or_none())

    def _get_address_scope_mappings_for_vrf(self, session, vrf):
        return (session.query(AddressScopeMapping).
                filter_by(vrf_tenant_name=vrf.tenant_name,
                          vrf_name=vrf.name).
                all())

    def _address_scope_vrf(self, mapping):
        return aim_resource.VRF(tenant_name=mapping.vrf_tenant_name,
                                name=mapping.vrf_name)
