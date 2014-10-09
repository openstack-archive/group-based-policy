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

import sqlalchemy as sa

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.db import model_base

from gbp.neutron.services.grouppolicy import config
from gbp.neutron.services.grouppolicy import group_policy_driver_api as api
from gbp.neutron.tests.unit.services.grouppolicy import extensions as test_ext
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin


class ExtensionDriverTestCase(
        test_grouppolicy_plugin.GroupPolicyPluginTestCase):

    _extension_drivers = ['test']

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='group_policy')
        super(ExtensionDriverTestCase, self).setUp()

    def test_pt_attr(self):
        # Test create with default value.
        pt = self.create_policy_target()
        pt_id = pt['policy_target']['id']
        val = pt['policy_target']['pt_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_targets', pt_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        pt = self.create_policy_target(pt_extension="abc")
        pt_id = pt['policy_target']['id']
        val = pt['policy_target']['pt_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_targets', pt_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_target': {'pt_extension': "def"}}
        req = self.new_update_request('policy_targets', data, pt_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_targets', pt_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("def", val)

    def test_ptg_attr(self):
        # Test create with default value.
        ptg = self.create_policy_target_group()
        ptg_id = ptg['policy_target_group']['id']
        val = ptg['policy_target_group']['ptg_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_target_groups', ptg_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        ptg = self.create_policy_target_group(ptg_extension="abc")
        ptg_id = ptg['policy_target_group']['id']
        val = ptg['policy_target_group']['ptg_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_target_groups', ptg_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_target_group': {'ptg_extension': "def"}}
        req = self.new_update_request('policy_target_groups', data, ptg_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_target_groups', ptg_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("def", val)

    def test_l2p_attr(self):
        # Test create with default value.
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        val = l2p['l2_policy']['l2p_extension']
        self.assertEqual("", val)
        req = self.new_show_request('l2_policies', l2p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        l2p = self.create_l2_policy(l2p_extension="abc")
        l2p_id = l2p['l2_policy']['id']
        val = l2p['l2_policy']['l2p_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('l2_policies', l2p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'l2_policy': {'l2p_extension': "def"}}
        req = self.new_update_request('l2_policies', data, l2p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('l2_policies', l2p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("def", val)

    def test_l3p_attr(self):
        # Test create with default value.
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']
        val = l3p['l3_policy']['l3p_extension']
        self.assertEqual("", val)
        req = self.new_show_request('l3_policies', l3p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        l3p = self.create_l3_policy(l3p_extension="abc")
        l3p_id = l3p['l3_policy']['id']
        val = l3p['l3_policy']['l3p_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('l3_policies', l3p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'l3_policy': {'l3p_extension': "def"}}
        req = self.new_update_request('l3_policies', data, l3p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('l3_policies', l3p_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("def", val)


class TestPolicyTargetExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_target_extension'
    pt_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_targets.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestPolicyTargetGroupExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_target_group_extension'
    ptg_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    value = sa.Column(sa.String(64))


class TestL2PolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_l2_policy_extension'
    l2p_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_l2_policies.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    value = sa.Column(sa.String(64))


class TestL3PolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_l3_policy_extension'
    l3p_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_l3_policies.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    value = sa.Column(sa.String(64))


class TestExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'test_extension'

    def initialize(self):
        # self.network_extension = 'Test_Network_Extension'
        # self.subnet_extension = 'Test_Subnet_Extension'
        # self.port_extension = 'Test_Port_Extension'
        extensions.append_api_extensions_path(test_ext.__path__)

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_policy_target(self, session, data, result):
        value = data['policy_target']['pt_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyTargetExtension(pt_id=result['id'],
                                           value=value)
        session.add(record)
        result['pt_extension'] = value

    def process_update_policy_target(self, session, data, result):
        record = (session.query(TestPolicyTargetExtension).
                  filter_by(pt_id=result['id']).
                  one())
        value = data['policy_target'].get('pt_extension')
        if value and value != record.value:
            record.value = value
        result['pt_extension'] = record.value

    def extend_policy_target_dict(self, session, result):
        record = (session.query(TestPolicyTargetExtension).
                  filter_by(pt_id=result['id']).
                  one())
        result['pt_extension'] = record.value

    def process_create_policy_target_group(self, session, data, result):
        value = data['policy_target_group']['ptg_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyTargetGroupExtension(ptg_id=result['id'],
                                                value=value)
        session.add(record)
        result['ptg_extension'] = value

    def process_update_policy_target_group(self, session, data, result):
        record = (session.query(TestPolicyTargetGroupExtension).
                  filter_by(ptg_id=result['id']).
                  one())
        value = data['policy_target_group'].get('ptg_extension')
        if value and value != record.value:
            record.value = value
        result['ptg_extension'] = record.value

    def extend_policy_target_group_dict(self, session, result):
        record = (session.query(TestPolicyTargetGroupExtension).
                  filter_by(ptg_id=result['id']).
                  one())
        result['ptg_extension'] = record.value

    def process_create_l2_policy(self, session, data, result):
        value = data['l2_policy']['l2p_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestL2PolicyExtension(l2p_id=result['id'], value=value)
        session.add(record)
        result['l2p_extension'] = value

    def process_update_l2_policy(self, session, data, result):
        record = (session.query(TestL2PolicyExtension).
                  filter_by(l2p_id=result['id']).
                  one())
        value = data['l2_policy'].get('l2p_extension')
        if value and value != record.value:
            record.value = value
        result['l2p_extension'] = record.value

    def extend_l2_policy_dict(self, session, result):
        record = (session.query(TestL2PolicyExtension).
                  filter_by(l2p_id=result['id']).
                  one())
        result['l2p_extension'] = record.value

    def process_create_l3_policy(self, session, data, result):
        value = data['l3_policy']['l3p_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestL3PolicyExtension(l3p_id=result['id'], value=value)
        session.add(record)
        result['l3p_extension'] = value

    def process_update_l3_policy(self, session, data, result):
        record = (session.query(TestL3PolicyExtension).
                  filter_by(l3p_id=result['id']).
                  one())
        value = data['l3_policy'].get('l3p_extension')
        if value and value != record.value:
            record.value = value
        result['l3p_extension'] = record.value

    def extend_l3_policy_dict(self, session, result):
        record = (session.query(TestL3PolicyExtension).
                  filter_by(l3p_id=result['id']).
                  one())
        result['l3p_extension'] = record.value
