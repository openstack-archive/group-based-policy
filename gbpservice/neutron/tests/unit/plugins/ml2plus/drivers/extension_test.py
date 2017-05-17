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

from neutron.api import extensions
from neutron.db.models import address_scope as as_db
from neutron.db import models_v2
from neutron.objects import address_scope as as_object
from neutron_lib.api import validators
from neutron_lib.db import model_base
import oslo_db.sqlalchemy.session
import sqlalchemy as sa
from sqlalchemy import orm

from gbpservice.neutron.plugins.ml2plus import driver_api
from gbpservice.neutron.tests.unit.plugins.ml2plus import (
    extensions as test_extensions)


class TestExtensionDriverBase(driver_api.ExtensionDriver):
    _supported_extension_aliases = 'ml2plus_fake_extension'

    def initialize(self):
        # REVISIT(rkukura): Needed?
        extensions.append_api_extensions_path(test_extensions.__path__)

    @property
    def extension_alias(self):
        return self._supported_extension_aliases


class TestExtensionDriver(TestExtensionDriverBase):
    def initialize(self):
        super(TestExtensionDriver, self).initialize()
        self.subnetpool_extension = 'Test_SubnetPool_Extension'
        self.address_scope_extension = 'Test_AddressScope_Extension'

    def _check_create(self, session, data, result):
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(data, dict))
        assert('id' not in data)
        assert(isinstance(result, dict))
        assert(result['id'] is not None)

    def _check_update(self, session, data, result):
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(data, dict))
        assert(isinstance(result, dict))
        assert(result['id'] is not None)

    def _check_extend(self, session, result, db_entry,
                      expected_db_entry_class):
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(result, dict))
        assert(result['id'] is not None)
        assert(isinstance(db_entry, expected_db_entry_class))
        assert(db_entry.id == result['id'])

    def process_create_subnetpool(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_create(session, data, result)
        result['subnetpool_extension'] = self.subnetpool_extension + '_create'

    def process_update_subnetpool(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_update(session, data, result)
        self.subnetpool_extension = data['subnetpool_extension']
        result['subnetpool_extension'] = self.subnetpool_extension + '_update'

    def extend_subnetpool_dict(self, session, subnetpool_db, result):
        self._check_extend(session, result, subnetpool_db,
                           models_v2.SubnetPool)
        result['subnetpool_extension'] = self.subnetpool_extension + '_extend'

    def process_create_address_scope(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_create(session, data, result)
        result['address_scope_extension'] = (self.address_scope_extension +
                                             '_create')

    def process_update_address_scope(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_update(session, data, result)
        self.address_scope_extension = data['address_scope_extension']
        result['address_scope_extension'] = (self.address_scope_extension +
                                             '_update')

    def extend_address_scope_dict(self, session, address_scope, result):
        self._check_extend(session, result, address_scope,
                           as_object.AddressScope)
        result['address_scope_extension'] = (self.address_scope_extension +
                                             '_extend')


class TestSubnetPoolExtension(model_base.BASEV2):
    subnetpool_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnetpools.id',
                                            ondelete="CASCADE"),
                              primary_key=True)
    value = sa.Column(sa.String(64))
    subnetpool = orm.relationship(
        models_v2.SubnetPool,
        backref=orm.backref('extension', cascade='delete', uselist=False))


class TestAddressScopeExtension(model_base.BASEV2):
    address_scope_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('address_scopes.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    value = sa.Column(sa.String(64))
    address_scope = orm.relationship(
        as_db.AddressScope,
        backref=orm.backref('extension', cascade='delete', uselist=False))


class TestDBExtensionDriver(TestExtensionDriverBase):
    def _get_value(self, data, key):
        value = data[key]
        if not validators.is_attr_set(value):
            value = ''
        return value

    def process_create_subnetpool(self, plugin_context, data, result):
        session = plugin_context.session
        value = self._get_value(data, 'subnetpool_extension')
        record = TestSubnetPoolExtension(subnetpool_id=result['id'],
                                         value=value)
        session.add(record)
        result['subnetpool_extension'] = value

    def process_update_subnetpool(self, plugin_context, data, result):
        session = plugin_context.session
        record = (session.query(TestSubnetPoolExtension).
                  filter_by(subnetpool_id=result['id']).one())
        value = data.get('subnetpool_extension')
        if value and value != record.value:
            record.value = value
        result['subnetpool_extension'] = record.value

    def extend_subnetpool_dict(self, session, subnetpool_db, result):
        record = (session.query(TestSubnetPoolExtension).
                 filter_by(subnetpool_id=result['id']).one_or_none())
        result['subnetpool_extension'] = record.value if record else ''

    def process_create_address_scope(self, plugin_context, data, result):
        session = plugin_context.session
        value = self._get_value(data, 'address_scope_extension')
        record = TestAddressScopeExtension(address_scope_id=result['id'],
                                           value=value)
        session.add(record)
        result['address_scope_extension'] = value

    def process_update_address_scope(self, plugin_context, data, result):
        session = plugin_context.session
        record = (session.query(TestAddressScopeExtension).
                  filter_by(address_scope_id=result['id']).one())
        value = data.get('address_scope_extension')
        if value and value != record.value:
            record.value = value
        result['address_scope_extension'] = record.value

    def extend_address_scope_dict(self, session, address_scope, result):
        record = (session.query(TestAddressScopeExtension).
                 filter_by(address_scope_id=result['id']).one_or_none())
        result['address_scope_extension'] = record.value if record else ''
