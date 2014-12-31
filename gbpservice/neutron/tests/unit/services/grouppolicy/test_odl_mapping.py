# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron.tests.unit.ml2 import test_ml2_plugin

from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_plugin)


TENANT_ID = '33336c48e9b84dcfb3a70813bb3b3333'


class NoPluginContextError(gpexc.GroupPolicyBadRequest):
    message = _("Missing Plugin Context")


class FakeCorePlugin(object):

    def __init__(self):
        self._networks = {}
        self._subnets = {}
        self._ports = {}

    def add_network(self, net_id, net):
        self._networks[net_id] = net

    def get_network(self, plugin_context, net_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._networks[net_id]

    def add_subnet(self, subnet_id, subnet):
        self._subnets[subnet_id] = subnet

    def get_subnet(self, plugin_context, subnet_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._subnets[subnet_id]

    def add_port(self, port_id, port):
        self._ports[port_id] = port

    def get_port(self, plugin_context, port_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._ports[port_id]


class FakeGBPPlugin(object):
    def __init__(self):
        self._l3ps = {}
        self._l2ps = {}
        self._groups = {}
        self._eps = {}
        self._classifiers = {}
        self._actions = {}
        self._rules = {}
        self._rule_sets = {}

    def add_l3_policy(self, l3p_id, l3p):
        self._l3ps[l3p_id] = l3p

    def get_l3_policy(self, plugin_context, l3p_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._l3ps[l3p_id]

    def add_l2_policy(self, l2p_id, l2p):
        self._l2ps[l2p_id] = l2p

    def get_l2_policy(self, plugin_context, l2p_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._l2ps[l2p_id]

    def add_policy_target_group(self, group_id, group):
        self._groups[group_id] = group

    def get_policy_target_group(self, plugin_context, group_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._groups[group_id]

    def add_policy_target(self, ep_id, ep):
        self._eps[ep_id] = ep

    def get_policy_target(self, plugin_context, ep_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._eps[ep_id]

    def add_policy_classifier(self, classifier_id, classifier):
        self._classifiers[classifier_id] = classifier

    def get_policy_classifier(self, plugin_context, classifier_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._classifiers[classifier_id]

    def add_policy_action(self, action_id, action):
        self._actions[action_id] = action

    def get_policy_action(self, plugin_context, action_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._actions[action_id]

    def add_policy_rule(self, rule_id, rule):
        self._rules[rule_id] = rule

    def get_policy_rule(self, plugin_context, rule_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._rules[rule_id]

    def add_policy_rule_set(self, rule_set_id, rule_set):
        self._rule_sets[rule_set_id] = rule_set

    def get_policy_rule_set(self, plugin_context, rule_set_id):
        if not plugin_context:
            raise NoPluginContextError()
        return self._rule_sets[rule_set_id]


class OdlMappingTestCase(test_plugin.GroupPolicyPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'odl'],
                                     group='group_policy')
        super(OdlMappingTestCase, self).setUp(
            core_plugin=test_ml2_plugin.PLUGIN_NAME)


class TestL3Policy(OdlMappingTestCase):

    def setUp(self):
        super(TestL3Policy, self).setUp()
        self._gbp_plugin = FakeGBPPlugin()

        l3p_id = '3333ba05-3333-45ba-ace2-765706b23333'
        l3p = {
            'id': l3p_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_l3p_name',
            'description': 'Fake l3 policy for L3P test'
        }
        self._gbp_plugin.add_l3_policy(l3p_id, l3p)
        self._l3p_id = l3p_id

    def _get_l3_policy_operation_context(self):
        current = self._gbp_plugin.get_l3_policy(
            "test_l3p_context", self._l3p_id
        )
        context = mock.Mock(current=current)
        return context


class TestL2Policy(OdlMappingTestCase):

    def setUp(self):
        super(TestL2Policy, self).setUp()
        self._gbp_plugin = FakeGBPPlugin()

        l2p_id = '2222bdbd-eb07-45ba-ace2-765706b22222'
        l2p = {
            'id': l2p_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_l2p_name',
            'description': 'Fake l2 policy for L2P test',
            'l3_policy_id': '3333ba05-eb07-45ba-ace2-765706b23333',
            'network_id': '2222eded-eb07-45ba-ace2-765706b22222'
        }
        self._gbp_plugin.add_l2_policy(l2p_id, l2p)
        self._l2p_id = l2p_id

    def _get_l2_policy_operation_context(self):
        current = self._gbp_plugin.get_l2_policy(
            "test_l2p_context", self._l2p_id
        )
        _plugin_context = 'fake_plugin_context_for_l2p_test'
        context = mock.Mock(current=current,
                            _plugin_context=_plugin_context)
        return context


class TestPolicyClassifier(OdlMappingTestCase):

    def setUp(self):
        super(TestPolicyClassifier, self).setUp()
        self._gbp_plugin = FakeGBPPlugin()

        classifier_id = '2222bdbd-6666-1111-ace2-765706b22222'
        classifier = {
            'id': classifier_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_http_classifier_name',
            'description': 'Fake policy classifier for http traffic',
            'protocol': 'tcp',
            'port_range': '80',
            'direction': 'in'
        }
        self._gbp_plugin.add_policy_classifier(classifier_id, classifier)
        self._classifier_id = classifier_id

    def _get_policy_classifier_context(self):
        current = self._gbp_plugin.get_policy_classifier(
            "test_pc_context", self._classifier_id
        )
        context = mock.Mock(current=current)
        return context


class TestPolicyTargetGroup(OdlMappingTestCase):
    def setUp(self):
        super(TestPolicyTargetGroup, self).setUp()
        self._gbp_plugin = FakeGBPPlugin()
        self._core_plugin = FakeCorePlugin()

        action_id = "2222bdbd-6666-2222-ace2-765706b22222"
        action = {
            'id': action_id,
            'tenant_id': TENANT_ID,
            'name': "fake_allow_action_name",
            'description': "Fake policy action to allow",
            'action_type': g_const.GP_ACTION_ALLOW
        }
        self._gbp_plugin.add_policy_action(action_id, action)
        self._action_id = action_id

        http_classifier_id = "2222bdbd-6666-1111-ace2-765706b22222"
        http_classifier = {
            'id': http_classifier_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_http_classifier_name',
            'description': 'Fake policy classifier for http traffic',
            'protocol': 'tcp',
            'port_range': '80',
            'direction': 'in'
        }
        self._gbp_plugin.add_policy_classifier(http_classifier_id,
                                               http_classifier)
        self._http_classifier_id = http_classifier_id

        http_rule_id = "2222bdbd-6666-3333-ace2-765706b22222"
        http_rule = {
            'id': http_rule_id,
            'tenant_id': TENANT_ID,
            'name': "fake_web_policy_rule",
            'description': "Fake policy rule to allow http traffic",
            'policy_classifier_id': http_classifier_id,
            'policy_actions': [action_id]
        }
        self._gbp_plugin.add_policy_rule(http_rule_id, http_rule)
        self._http_rule_id = http_rule_id

        icmp_classifier_id = "2222bdbd-6666-5555-ace2-765706b22222"
        icmp_classifier = {
            'id': icmp_classifier_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_icmp_classifier_name',
            'description': 'Fake policy classifier for icmp traffic',
            'protocol': 'icmp',
            'direction': 'bi'
        }
        self._gbp_plugin.add_policy_classifier(icmp_classifier_id,
                                               icmp_classifier)
        self._icmp_classifier_id = icmp_classifier_id

        icmp_rule_id = "2222bdbd-6666-6666-ace2-765706b22222"
        icmp_rule = {
            'id': icmp_rule_id,
            'tenant_id': TENANT_ID,
            'name': "fake_icmp_policy_rule",
            'description': "Fake policy rule to allow icmp traffic",
            'policy_classifier_id': icmp_classifier_id,
            'policy_actions': [action_id]
        }
        self._gbp_plugin.add_policy_rule(icmp_rule_id, icmp_rule)
        self._icmp_rule_id = icmp_rule_id

        icmp_rule_set_id = "2222bdbd-7777-6666-ace2-765706b22222"
        icmp_rule_set = {
            'id': icmp_rule_set_id,
            'tenant_id': TENANT_ID,
            'name': "fake_icmp_rule_set_name",
            'description': "Fake policy rule set for icmp",
            'policy_rules': [icmp_rule_id]
        }
        self._gbp_plugin.add_policy_rule_set(icmp_rule_set_id,
                                             icmp_rule_set)
        self._icmp_rule_set_id = icmp_rule_set_id

        http_rule_set_id = "2222bdbd-7777-3333-ace2-765706b22222"
        http_rule_set = {
            'id': http_rule_set_id,
            'tenant_id': TENANT_ID,
            'name': "fake_http_rule_set_name",
            'description': "Fake policy rule set for http",
            'policy_rules': [http_rule_id]
        }
        self._gbp_plugin.add_policy_rule_set(http_rule_set_id,
                                             http_rule_set)
        self._http_rule_set_id = http_rule_set_id

        network_id = "ed2e3c10-2222-1111-9006-2863a2d1abbc"
        network = {
            'id': network_id,
            'name': "fake_network_for_PTG_test"
        }
        self._core_plugin.add_network(network_id, network)
        self._network_id = network_id

        subnet_id = "ed2e3c10-2222-2222-9006-2863a2d1abbc"
        subnet = {
            'id': subnet_id,
            'cidr': "10.10.0.0/24",
            'network_id': network_id,
            'gatewat_ip': "10.10.0.1"
        }
        self._core_plugin.add_subnet(subnet_id, subnet)
        self._subnet_id = subnet_id

        l3p_id = '3333ba05-3333-45ba-ace2-765706b23333'
        l3p = {
            'id': l3p_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_l3p_name',
            'description': 'Fake l3 policy for PTG test'
        }
        self._gbp_plugin.add_l3_policy(l3p_id, l3p)

        l2p_id = '2222bdbd-eb07-45ba-ace2-765706b22222'
        l2p = {
            'id': l2p_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_l2p_name',
            'description': 'Fake l2 policy for PTG test',
            'l3_policy_id': l3p_id,
            'network_id': network_id
        }
        self._gbp_plugin.add_l2_policy(l2p_id, l2p)

        group_id = '1111bdbd-eb07-45ba-ace2-765706b21111'
        group = {
            'id': group_id,
            'tenant_id': TENANT_ID,
            'name': 'fake_ptg_name',
            'description': 'Fake PTG for ptg test',
            'l2_policy_id': l2p_id,
            'subnets': [subnet_id],
            'provided_policy_rule_sets': [http_rule_set_id],
            'consumed_policy_rule_sets': [icmp_rule_set_id]
        }
        self._gbp_plugin.add_policy_target_group(group_id, group)
        self._group_id = group_id

    def _get_policy_target_group_context(self):
        current = self._gbp_plugin.get_policy_target_group(
            "test_ptg_context", self._group_id
        )
        _plugin_context = "fake_plugin_context_for_ptg_test"
        _plugin = self._gbp_plugin
        context = mock.Mock(
            current=current,
            _plugin_context=_plugin_context,
            _plugin=_plugin
        )
        return context
