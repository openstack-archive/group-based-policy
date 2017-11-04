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

import os

from neutron.common import config as neutron_config  # noqa

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit import common as cm
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    extensions as test_ext)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_plugin)


class ExtensionDriverTestBase(test_plugin.GroupPolicyPluginTestCase):
    _extension_drivers = ['test']
    _extension_path = os.path.dirname(os.path.abspath(test_ext.__file__))

    def setUp(self, policy_drivers=None, core_plugin=None,
              l3_plugin=None, ml2_options=None,
              sc_plugin=None, trunk_plugin=None):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='group_policy')
        if self._extension_path:
            config.cfg.CONF.set_override(
                'api_extensions_path', self._extension_path)
        super(ExtensionDriverTestBase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin,
            ml2_options=ml2_options, sc_plugin=sc_plugin,
            trunk_plugin=trunk_plugin)


class ExtensionDriverTestCase(ExtensionDriverTestBase):

    def test_pt_attr(self):
        # Test create with default value.
        pt = self.create_policy_target()
        policy_target_id = pt['policy_target']['id']
        val = pt['policy_target']['pt_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_targets', policy_target_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_targets')
        val = res['policy_targets'][0]['pt_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        pt = self.create_policy_target(pt_extension="abc")
        policy_target_id = pt['policy_target']['id']
        val = pt['policy_target']['pt_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_targets', policy_target_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_target': {'pt_extension': "def"}}
        req = self.new_update_request('policy_targets', data, policy_target_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_targets', policy_target_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target']['pt_extension']
        self.assertEqual("def", val)

    def test_ptg_attr(self):
        # Test create with default value.
        ptg = self.create_policy_target_group()
        policy_target_group_id = ptg['policy_target_group']['id']
        val = ptg['policy_target_group']['ptg_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_target_groups',
                                    policy_target_group_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_target_groups')
        val = res['policy_target_groups'][0]['ptg_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        ptg = self.create_policy_target_group(ptg_extension="abc")
        policy_target_group_id = ptg['policy_target_group']['id']
        val = ptg['policy_target_group']['ptg_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_target_groups',
                                    policy_target_group_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_target_group': {'ptg_extension': "def"}}
        req = self.new_update_request('policy_target_groups', data,
                                      policy_target_group_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_target_groups',
                                    policy_target_group_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_target_group']['ptg_extension']
        self.assertEqual("def", val)

    def test_l2p_attr(self):
        # Test create with default value.
        l2p = self.create_l2_policy()
        l2_policy_id = l2p['l2_policy']['id']
        val = l2p['l2_policy']['l2p_extension']
        self.assertIsNone(val)
        req = self.new_show_request('l2_policies', l2_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('l2_policies')
        val = res['l2_policies'][0]['l2p_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        l2p = self.create_l2_policy(l2p_extension="abc")
        l2_policy_id = l2p['l2_policy']['id']
        val = l2p['l2_policy']['l2p_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('l2_policies', l2_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'l2_policy': {'l2p_extension': "def"}}
        req = self.new_update_request('l2_policies', data, l2_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('l2_policies', l2_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l2_policy']['l2p_extension']
        self.assertEqual("def", val)

    def test_l3p_attr(self):
        # Test create with default value.
        l3p = self.create_l3_policy()
        l3_policy_id = l3p['l3_policy']['id']
        val = l3p['l3_policy']['l3p_extension']
        self.assertIsNone(val)
        req = self.new_show_request('l3_policies', l3_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('l3_policies')
        val = res['l3_policies'][0]['l3p_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        l3p = self.create_l3_policy(l3p_extension="abc")
        l3_policy_id = l3p['l3_policy']['id']
        val = l3p['l3_policy']['l3p_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('l3_policies', l3_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'l3_policy': {'l3p_extension': "def"}}
        req = self.new_update_request('l3_policies', data, l3_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('l3_policies', l3_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['l3_policy']['l3p_extension']
        self.assertEqual("def", val)

    def test_pc_attr(self):
        # Test create with default value.
        pc = self.create_policy_classifier()
        policy_classifier_id = pc['policy_classifier']['id']
        val = pc['policy_classifier']['pc_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_classifiers', policy_classifier_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_classifiers')
        val = res['policy_classifiers'][0]['pc_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        pc = self.create_policy_classifier(pc_extension="abc")
        policy_classifier_id = pc['policy_classifier']['id']
        val = pc['policy_classifier']['pc_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_classifiers', policy_classifier_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_classifier': {'pc_extension': "def"}}
        req = self.new_update_request('policy_classifiers', data,
                                      policy_classifier_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_classifiers', policy_classifier_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_classifier']['pc_extension']
        self.assertEqual("def", val)

    def test_pa_attr(self):
        # Test create with default value.
        pa = self.create_policy_action()
        policy_action_id = pa['policy_action']['id']
        val = pa['policy_action']['pa_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_actions', policy_action_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_actions')
        val = res['policy_actions'][0]['pa_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        pa = self.create_policy_action(pa_extension="abc")
        policy_action_id = pa['policy_action']['id']
        val = pa['policy_action']['pa_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_actions', policy_action_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_action': {'pa_extension': "def"}}
        req = self.new_update_request('policy_actions', data, policy_action_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_action']['pa_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_actions', policy_action_id)
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
        policy_rule_id = pr['policy_rule']['id']
        val = pr['policy_rule']['pr_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_rules', policy_rule_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_rules')
        val = res['policy_rules'][0]['pr_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        pr = self.create_policy_rule(policy_classifier_id=classifier_id,
                                     pr_extension="abc")
        policy_rule_id = pr['policy_rule']['id']
        val = pr['policy_rule']['pr_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_rules', policy_rule_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_rule': {'pr_extension': "def"}}
        req = self.new_update_request('policy_rules', data, policy_rule_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_rules', policy_rule_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule']['pr_extension']
        self.assertEqual("def", val)

    def test_prs_attr(self):
        # Test create with default value.
        prs = self.create_policy_rule_set(policy_rules=[])
        policy_rule_set_id = prs['policy_rule_set']['id']
        val = prs['policy_rule_set']['prs_extension']
        self.assertIsNone(val)
        req = self.new_show_request('policy_rule_sets', policy_rule_set_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('policy_rule_sets')
        val = res['policy_rule_sets'][0]['prs_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        prs = self.create_policy_rule_set(policy_rules=[], prs_extension="abc")
        policy_rule_set_id = prs['policy_rule_set']['id']
        val = prs['policy_rule_set']['prs_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('policy_rule_sets', policy_rule_set_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'policy_rule_set': {'prs_extension': "def"}}
        req = self.new_update_request('policy_rule_sets', data,
                                      policy_rule_set_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('policy_rule_sets', policy_rule_set_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['policy_rule_set']['prs_extension']
        self.assertEqual("def", val)

    def test_nsp_attr(self):
        # Test create with default value.
        nsp = self.create_network_service_policy()
        network_service_policy_id = nsp['network_service_policy']['id']
        val = nsp['network_service_policy']['nsp_extension']
        self.assertIsNone(val)
        req = self.new_show_request('network_service_policies',
                                    network_service_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list('network_service_policies')
        val = res['network_service_policies'][0]['nsp_extension']
        self.assertIsNone(val)

        # Test create with explict value.
        nsp = self.create_network_service_policy(nsp_extension="abc")
        network_service_policy_id = nsp['network_service_policy']['id']
        val = nsp['network_service_policy']['nsp_extension']
        self.assertEqual("abc", val)
        req = self.new_show_request('network_service_policies',
                                    network_service_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("abc", val)

        # Test update.
        data = {'network_service_policy': {'nsp_extension': "def"}}
        req = self.new_update_request('network_service_policies', data,
                                      network_service_policy_id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res['network_service_policy']['nsp_extension']
        self.assertEqual("def", val)
        req = self.new_show_request('network_service_policies',
                                    network_service_policy_id)
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
        self.assertIsNone(val)
        req = self.new_show_request(plural, id)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        val = res[type][acronim + '_extension']
        self.assertIsNone(val)

        # Test list.
        res = self._list(plural)
        val = res[plural][0][acronim + '_extension']
        self.assertIsNone(val)

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


def _acronim(type):
    return ''.join([x[0] for x in type.split('_')])
