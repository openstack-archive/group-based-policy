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

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit import common as cm
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    extensions as test_ext)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_plugin)


class ExtensionDriverTestCase(
        test_plugin.GroupPolicyPluginTestCase):

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

        # Test list.
        res = self._list('policy_targets')
        val = res['policy_targets'][0]['pt_extension']
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

        # Test list.
        res = self._list('policy_target_groups')
        val = res['policy_target_groups'][0]['ptg_extension']
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

        # Test list.
        res = self._list('l2_policies')
        val = res['l2_policies'][0]['l2p_extension']
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

        # Test list.
        res = self._list('l3_policies')
        val = res['l3_policies'][0]['l3p_extension']
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

    def test_pc_attr(self):
        # Test create with default value.
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        val = pc['policy_classifier']['pc_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_classifiers', pc_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list('policy_classifiers')
        val = res['policy_classifiers'][0]['pc_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        pc = self.create_policy_classifier(pc_extension="abc")
        pc_id = pc['policy_classifier']['id']
        val = pc['policy_classifier']['pc_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_classifiers', pc_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_classifier': {'pc_extension': "def"}}
        req = self.new_update_request('policy_classifiers', data, pc_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_classifiers', pc_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("def", val)

    def test_pa_attr(self):
        # Test create with default value.
        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']
        val = pa['policy_action']['pa_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_actions', pa_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list('policy_actions')
        val = res['policy_actions'][0]['pa_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        pa = self.create_policy_action(pa_extension="abc")
        pa_id = pa['policy_action']['id']
        val = pa['policy_action']['pa_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_actions', pa_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_action': {'pa_extension': "def"}}
        req = self.new_update_request('policy_actions', data, pa_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_actions', pa_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("def", val)

    def test_pr_attr(self):
        # Create necessary parameters.
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="out",
            port_range="50:100")
        classifier_id = classifier['policy_classifier']['id']

        # Test create with default value.
        pr = self.create_policy_rule(policy_classifier_id=classifier_id)
        pr_id = pr['policy_rule']['id']
        val = pr['policy_rule']['pr_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_rules', pr_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list('policy_rules')
        val = res['policy_rules'][0]['pr_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        pr = self.create_policy_rule(policy_classifier_id=classifier_id,
                                     pr_extension="abc")
        pr_id = pr['policy_rule']['id']
        val = pr['policy_rule']['pr_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_rules', pr_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_rule': {'pr_extension': "def"}}
        req = self.new_update_request('policy_rules', data, pr_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_rules', pr_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("def", val)

    def test_prs_attr(self):
        # Test create with default value.
        prs = self.create_policy_rule_set(policy_rules=[])
        prs_id = prs['policy_rule_set']['id']
        val = prs['policy_rule_set']['prs_extension']
        self.assertEqual("", val)
        req = self.new_show_request('policy_rule_sets', prs_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list('policy_rule_sets')
        val = res['policy_rule_sets'][0]['prs_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        prs = self.create_policy_rule_set(policy_rules=[], prs_extension="abc")
        prs_id = prs['policy_rule_set']['id']
        val = prs['policy_rule_set']['prs_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_rule_sets', prs_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_rule_set': {'prs_extension': "def"}}
        req = self.new_update_request('policy_rule_sets', data, prs_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_rule_sets', prs_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("def", val)

    def test_nsp_attr(self):
        # Test create with default value.
        nsp = self.create_network_service_policy()
        nsp_id = nsp['network_service_policy']['id']
        val = nsp['network_service_policy']['nsp_extension']
        self.assertEqual("", val)
        req = self.new_show_request('network_service_policies', nsp_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list('network_service_policies')
        val = res['network_service_policies'][0]['nsp_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        nsp = self.create_network_service_policy(nsp_extension="abc")
        nsp_id = nsp['network_service_policy']['id']
        val = nsp['network_service_policy']['nsp_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('network_service_policies', nsp_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'network_service_policy': {'nsp_extension': "def"}}
        req = self.new_update_request('network_service_policies', data, nsp_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('network_service_policies', nsp_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("def", val)

    def test_es_attr(self):
        self._test_attr('external_segment')

    def test_ep_attr(self):
        self._test_attr('external_policy')

    def test_np_attr(self):
        self._test_attr('nat_pool')

    def _test_attr(self, type):
        # Test create with default value.
        acronim = _acronim(type)
        plural = cm.get_resource_plural(type)
        obj = getattr(self, 'create_%s' % type)()
        id = obj[type]['id']
        val = obj[type][acronim + '_extension']
        self.assertEqual("", val)
        req = self.new_show_request(plural, id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res[type][acronim + '_extension']
        self.assertEqual("", val)

        # Test list.
        res = self._list(plural)
        val = res[plural][0][acronim + '_extension']
        self.assertEqual("", val)

        # Test create with explict value.
        kwargs = {acronim + '_extension': "abc"}
        obj = getattr(self, 'create_%s' % type)(**kwargs)
        id = obj[type]['id']
        val = obj[type][acronim + '_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request(plural, id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res[type][acronim + '_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {type: {acronim + '_extension': "def"}}
        req = self.new_update_request(plural, data, id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res[type][acronim + '_extension']
        self.assertEqual("def", val)
        req = self.new_show_request(plural, id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res[type][acronim + '_extension']
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


class TestPolicyClassifierExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_classifier_extension'
    pc_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_classifiers.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestPolicyActionExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_action_extension'
    pa_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_actions.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestPolicyRuleExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_rule_extension'
    pr_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_rules.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestPolicyRuleSetExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_rule_set_extension'
    prs_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_policy_rule_sets.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    value = sa.Column(sa.String(64))


class TestNetworkServicePolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_network_service_policy_extension'
    nsp_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_network_service_policies.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    value = sa.Column(sa.String(64))


class TestExternalSegmentExtension(model_base.BASEV2):
    __tablename__ = 'test_external_segment_extension'
    es_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_external_segments.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestExternalPolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_external_policy_extension'
    ep_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_external_policies.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    value = sa.Column(sa.String(64))


class TestNatPoolExtension(model_base.BASEV2):
    __tablename__ = 'test_nat_pool_extension'
    np_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_nat_pools.id',
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

    def process_create_policy_classifier(self, session, data, result):
        value = data['policy_classifier']['pc_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyClassifierExtension(pc_id=result['id'], value=value)
        session.add(record)
        result['pc_extension'] = value

    def process_update_policy_classifier(self, session, data, result):
        record = (session.query(TestPolicyClassifierExtension).
                  filter_by(pc_id=result['id']).
                  one())
        value = data['policy_classifier'].get('pc_extension')
        if value and value != record.value:
            record.value = value
        result['pc_extension'] = record.value

    def extend_policy_classifier_dict(self, session, result):
        record = (session.query(TestPolicyClassifierExtension).
                  filter_by(pc_id=result['id']).
                  one())
        result['pc_extension'] = record.value

    def process_create_policy_action(self, session, data, result):
        value = data['policy_action']['pa_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyActionExtension(pa_id=result['id'], value=value)
        session.add(record)
        result['pa_extension'] = value

    def process_update_policy_action(self, session, data, result):
        record = (session.query(TestPolicyActionExtension).
                  filter_by(pa_id=result['id']).
                  one())
        value = data['policy_action'].get('pa_extension')
        if value and value != record.value:
            record.value = value
        result['pa_extension'] = record.value

    def extend_policy_action_dict(self, session, result):
        record = (session.query(TestPolicyActionExtension).
                  filter_by(pa_id=result['id']).
                  one())
        result['pa_extension'] = record.value

    def process_create_policy_rule(self, session, data, result):
        value = data['policy_rule']['pr_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyRuleExtension(pr_id=result['id'], value=value)
        session.add(record)
        result['pr_extension'] = value

    def process_update_policy_rule(self, session, data, result):
        record = (session.query(TestPolicyRuleExtension).
                  filter_by(pr_id=result['id']).
                  one())
        value = data['policy_rule'].get('pr_extension')
        if value and value != record.value:
            record.value = value
        result['pr_extension'] = record.value

    def extend_policy_rule_dict(self, session, result):
        record = (session.query(TestPolicyRuleExtension).
                  filter_by(pr_id=result['id']).
                  one())
        result['pr_extension'] = record.value

    def process_create_policy_rule_set(self, session, data, result):
        value = data['policy_rule_set']['prs_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestPolicyRuleSetExtension(prs_id=result['id'], value=value)
        session.add(record)
        result['prs_extension'] = value

    def process_update_policy_rule_set(self, session, data, result):
        record = (session.query(TestPolicyRuleSetExtension).
                  filter_by(prs_id=result['id']).
                  one())
        value = data['policy_rule_set'].get('prs_extension')
        if value and value != record.value:
            record.value = value
        result['prs_extension'] = record.value

    def extend_policy_rule_set_dict(self, session, result):
        record = (session.query(TestPolicyRuleSetExtension).
                  filter_by(prs_id=result['id']).
                  one())
        result['prs_extension'] = record.value

    def process_create_network_service_policy(self, session, data, result):
        value = data['network_service_policy']['nsp_extension']
        if not attributes.is_attr_set(value):
            value = ''
        record = TestNetworkServicePolicyExtension(nsp_id=result['id'],
                                                   value=value)
        session.add(record)
        result['nsp_extension'] = value

    def process_update_network_service_policy(self, session, data, result):
        record = (session.query(TestNetworkServicePolicyExtension).
                  filter_by(nsp_id=result['id']).
                  one())
        value = data['network_service_policy'].get('nsp_extension')
        if value and value != record.value:
            record.value = value
        result['nsp_extension'] = record.value

    def extend_network_service_policy_dict(self, session, result):
        record = (session.query(TestNetworkServicePolicyExtension).
                  filter_by(nsp_id=result['id']).
                  one())
        result['nsp_extension'] = record.value

    def process_create_external_segment(self, session, data, result):
        self._process_create(session, data, result, 'external_segment',
                             TestExternalSegmentExtension)

    def process_update_external_segment(self, session, data, result):
        self._process_update(session, data, result, 'external_segment',
                             TestExternalSegmentExtension)

    def extend_external_segment_dict(self, session, result):
        self._extend(session, result, 'external_segment',
                     TestExternalSegmentExtension)

    def process_create_external_policy(self, session, data, result):
        self._process_create(session, data, result, 'external_policy',
                             TestExternalPolicyExtension)

    def process_update_external_policy(self, session, data, result):
        self._process_update(session, data, result, 'external_policy',
                             TestExternalPolicyExtension)

    def extend_external_policy_dict(self, session, result):
        self._extend(session, result, 'external_policy',
                     TestExternalPolicyExtension)

    def process_create_nat_pool(self, session, data, result):
        self._process_create(session, data, result, 'nat_pool',
                             TestNatPoolExtension)

    def process_update_nat_pool(self, session, data, result):
        self._process_update(session, data, result, 'nat_pool',
                             TestNatPoolExtension)

    def extend_nat_pool_dict(self, session, result):
        self._extend(session, result, 'nat_pool', TestNatPoolExtension)

    def _process_create(self, session, data, result, type, klass):
        acronim = _acronim(type)
        value = data[type][acronim + '_extension']
        if not attributes.is_attr_set(value):
            value = ''
        kwargs = {acronim + '_id': result['id'], 'value': value}
        record = klass(**kwargs)
        session.add(record)
        result[acronim + '_extension'] = value

    def _process_update(self, session, data, result, type, klass):
        acronim = _acronim(type)
        kwargs = {acronim + '_id': result['id']}
        record = session.query(klass).filter_by(**kwargs).one()
        value = data[type].get(acronim + '_extension')
        if value and value != record.value:
            record.value = value
        result[acronim + '_extension'] = record.value

    def _extend(self, session, result, type, klass):
        acronim = _acronim(type)
        kwargs = {acronim + '_id': result['id']}
        record = session.query(klass).filter_by(**kwargs).one()
        result[acronim + '_extension'] = record.value


def _acronim(type):
    return ''.join([x[0] for x in type.split('_')])
