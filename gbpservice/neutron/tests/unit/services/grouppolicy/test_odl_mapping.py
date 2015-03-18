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
import uuid

from gbpservice.neutron.services.grouppolicy.common import constants
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.odl import odl_manager
from gbpservice.neutron.services.grouppolicy.drivers.odl import odl_mapping
from gbpservice.neutron.services.grouppolicy.drivers import resource_mapping
from gbpservice.neutron.services.grouppolicy import plugin as g_plugin
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_gp_plugin)
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin

TENANT_ID = 'aaaabbbbccccaaaabbbbccccaaaabbbb'
TENANT_UUID = 'aaaabbbb-cccc-aaaa-bbbb-ccccaaaabbbb'

ACTION_1_ID = '1111aaaa-1111-1111-1111-1111bbbb1111'
ACTION_1_NAME = 'fake_name_for_action_1'
ACTION_1_DESC = 'Fake policy action 1'
ACTION_1_TYPE = constants.GP_ACTION_ALLOW

ACTION_2_ID = '1111aaaa-1111-2222-1111-1111bbbb1111'
ACTION_2_NAME = 'fake_name_for_action_2'
ACTION_2_DESC = 'Fake policy action 2'
ACTION_2_TYPE = constants.GP_ACTION_ALLOW

# ACTION_3 is used for negative testing as this action
# is not supported at the moment
ACTION_3_ID = '1111aaaa-1111-3333-1111-1111bbbb1111'
ACTION_3_NAME = 'fake_name_for_action_3'
ACTION_3_DESC = 'Fake policy action 3'
ACTION_3_TYPE = constants.GP_ACTION_REDIRECT

CLASSIFIER_1_ID = '1111aaaa-2222-1111-1111-1111bbbb1111'
CLASSIFIER_1_NAME = 'fake_name_for_classifier_1'
CLASSIFIER_1_DESC = 'Fake policy classifier 1'
CLASSIFIER_1_PROTOCOL = 'tcp'
CLASSIFIER_1_PORT = '321'
CLASSIFIER_1_DIRECTION = 'bi'
CLASSIFIER_1_DEFINITION_ID = '4250ab32-e8b8-445a-aebb-e1bd2cdd291f'

CLASSIFIER_2_ID = '1111aaaa-2222-2222-1111-1111bbbb1111'
CLASSIFIER_2_NAME = 'fake_name_for_classifier_2'
CLASSIFIER_2_DESC = 'Fake policy classifier 2'
CLASSIFIER_2_PROTOCOL = 'tcp'
CLASSIFIER_2_PORT = '123'
CLASSIFIER_2_DIRECTION = 'in'
CLASSIFIER_2_DEFINITION_ID = '4250ab32-e8b8-445a-aebb-e1bd2cdd291f'

CLASSIFIER_3_ID = '1111aaaa-2222-3333-1111-1111bbbb1111'
CLASSIFIER_3_NAME = 'fake_name_for_classifier_3'
CLASSIFIER_3_DESC = 'Fake policy classifier 3'
CLASSIFIER_3_PROTOCOL = 'icmp'
CLASSIFIER_3_DIRECTION = 'bi'
CLASSIFIER_3_DEFINITION_ID = '79c6fdb2-1e1a-4832-af57-c65baf5c2335'

RULE_1_ID = '1111aaaa-3333-1111-1111-1111bbbb1111'
RULE_1_NAME = 'fake_name_for_policy_rule_1'
RULE_1_DESC = 'Fake policy rule 1'

RULE_2_ID = '1111aaaa-3333-2222-1111-1111bbbb1111'
RULE_2_NAME = 'fake_name_for_policy_rule_2'
RULE_2_DESC = 'Fake policy rule 2'

RULE_3_ID = '1111aaaa-3333-3333-1111-1111bbbb1111'
RULE_3_NAME = 'fake_name_for_policy_rule_3'
RULE_3_DESC = 'Fake policy rule 3'

RULE_SET_1_ID = '1111aaaa-4444-1111-1111-1111bbbb1111'
RULE_SET_1_NAME = 'fake_name_for_rule_set_1'
RULE_SET_1_DESC = 'Fake policy rule set 1'

RULE_SET_2_ID = '1111aaaa-4444-2222-1111-1111bbbb1111'
RULE_SET_2_NAME = 'fake_name_for_rule_set_2'
RULE_SET_2_DESC = 'Fake policy rule set 2'

L3P_ID = '2222bbbb-1111-1111-1111-1111cccc1111'
L3P_NAME = 'fake_name_for_l3_policy'
L3P_DESC = 'Fake L3 policy'

NETWORK_ID = '2222bbbb-2222-1111-1111-1111cccc1111'
NETWORK_NAME = 'fake_name_for_network'

L2P_ID = '2222bbbb-3333-1111-1111-1111cccc1111'
L2P_NAME = 'fake_name_for_l2_policy'
L2P_DESC = 'Fake L2 policy'

SUBNET_ID = '2222bbbb-4444-1111-1111-1111cccc1111'
SUBNET_CIDR = '10.10.1.0/24'
SUBNET_GATEWAY_IP = '10.10.1.1'

GROUP_ID = '2222bbbb-5555-1111-1111-1111cccc1111'
GROUP_NAME = 'fake_name_for_ptg'
GROUP_DESC = 'Fake PTG'

PORT_ID = '3333cccc-1111-1111-1111-1111dddd1111'
PORT_MAC = 'fa:33:33:11:11:11'
PORT_IP = '10.10.1.11'
NEUTRON_PORT_ID = 'tap3333cccc-11'

POLICY_TARGET_ID = '3333cccc-2222-1111-1111-1111dddd1111'
POLICY_TARGET_NAME = 'fake_name_for_policy_target'
POLICY_TARGET_DESC = 'Fake Policy Target'

FAKE_CONTEXT = 'fake_context'
FAKE_PLUGIN_CONTEXT = 'fake_plugin_context'


class FakeCorePlugin(object):
    """ A fake plugin to simulate the ML2 plugin

    This plugin provides a minimum set of methods that
    will be used during testing
    """

    def __init__(self):
        self._networks = {}
        self._subnets = {}
        self._ports = {}

    def add_network(self, net_id, net):
        self._networks[net_id] = net

    def get_network(self, plugin_context, net_id):
        return self._networks[net_id]

    def add_subnet(self, subnet_id, subnet):
        self._subnets[subnet_id] = subnet

    def get_subnet(self, plugin_context, subnet_id):
        return self._subnets[subnet_id]

    def add_port(self, port_id, port):
        self._ports[port_id] = port

    def get_port(self, plugin_context, port_id):
        return self._ports[port_id]


class FakeGBPPlugin(object):
    """ A fake plugin to simulate the GBP plugin

    This plugin provides a minimum set of methods that
    will be used during testing
    """

    def __init__(self):
        self._l3ps = {}
        self._l2ps = {}
        self._ptgs = {}
        self._pts = {}
        self._classifiers = {}
        self._actions = {}
        self._rules = {}
        self._rule_sets = {}

    def add_l3_policy(self, l3p_id, l3p):
        self._l3ps[l3p_id] = l3p

    def get_l3_policy(self, plugin_context, l3p_id):
        return self._l3ps[l3p_id]

    def add_l2_policy(self, l2p_id, l2p):
        self._l2ps[l2p_id] = l2p

    def get_l2_policy(self, plugin_context, l2p_id):
        return self._l2ps[l2p_id]

    def add_policy_target_group(self, ptg_id, ptg):
        self._ptgs[ptg_id] = ptg

    def get_policy_target_group(self, plugin_context, ptg_id):
        return self._ptgs[ptg_id]

    def add_policy_target(self, pt_id, pt):
        self._pts[pt_id] = pt

    def get_policy_target(self, plugin_context, pt_id):
        return self._pts[pt_id]

    def add_policy_classifier(self, classifier_id, classifier):
        self._classifiers[classifier_id] = classifier

    def get_policy_classifier(self, plugin_context, classifier_id):
        return self._classifiers[classifier_id]

    def add_policy_action(self, action_id, action):
        self._actions[action_id] = action

    def get_policy_action(self, plugin_context, action_id):
        return self._actions[action_id]

    def add_policy_rule(self, rule_id, rule):
        self._rules[rule_id] = rule

    def get_policy_rule(self, plugin_context, rule_id):
        return self._rules[rule_id]

    def add_policy_rule_set(self, rule_set_id, rule_set):
        self._rule_sets[rule_set_id] = rule_set

    def get_policy_rule_set(self, plugin_context, rule_set_id):
        return self._rule_sets[rule_set_id]


class OdlMappingTestCase(
        test_gp_plugin.GroupPolicyPluginTestCase):
    """ Base test case for ODL mapping driver testing

    Set up the common testing environment
    """

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'odl'],
                                     group='group_policy')
        super(OdlMappingTestCase, self).setUp(
            core_plugin=test_plugin.PLUGIN_NAME)

        self.fake_core_plugin = FakeCorePlugin()
        self.fake_gbp_plugin = FakeGBPPlugin()
        self.driver = odl_mapping.OdlMappingDriver.get_initialized_instance()

        self.fake_gbp_plugin.add_policy_action(
            ACTION_1_ID,
            {
                'id': ACTION_1_ID,
                'tenant_id': TENANT_ID,
                'name': ACTION_1_NAME,
                'description': ACTION_1_DESC,
                'action_type': ACTION_1_TYPE,
            }
        )

        self.fake_gbp_plugin.add_policy_action(
            ACTION_2_ID,
            {
                'id': ACTION_2_ID,
                'tenant_id': TENANT_ID,
                'name': ACTION_2_NAME,
                'description': ACTION_2_DESC,
                'action_type': ACTION_2_TYPE,
            }
        )

        self.fake_gbp_plugin.add_policy_action(
            ACTION_3_ID,
            {
                'id': ACTION_3_ID,
                'tenant_id': TENANT_ID,
                'name': ACTION_3_NAME,
                'description': ACTION_3_DESC,
                'action_type': ACTION_3_TYPE,
            }
        )

        self.fake_gbp_plugin.add_policy_classifier(
            CLASSIFIER_1_ID,
            {
                'id': CLASSIFIER_1_ID,
                'tenant_id': TENANT_ID,
                'name': CLASSIFIER_1_NAME,
                'description': CLASSIFIER_1_DESC,
                'protocol': CLASSIFIER_1_PROTOCOL,
                'port_range': CLASSIFIER_1_PORT,
                'direction': CLASSIFIER_1_DIRECTION
            }
        )

        self.fake_gbp_plugin.add_policy_classifier(
            CLASSIFIER_2_ID,
            {
                'id': CLASSIFIER_2_ID,
                'tenant_id': TENANT_ID,
                'name': CLASSIFIER_2_NAME,
                'description': CLASSIFIER_2_DESC,
                'protocol': CLASSIFIER_2_PROTOCOL,
                'port_range': CLASSIFIER_2_PORT,
                'direction': CLASSIFIER_2_DIRECTION
            }
        )

        self.fake_gbp_plugin.add_policy_classifier(
            CLASSIFIER_3_ID,
            {
                'id': CLASSIFIER_3_ID,
                'tenant_id': TENANT_ID,
                'name': CLASSIFIER_3_NAME,
                'description': CLASSIFIER_3_DESC,
                'protocol': CLASSIFIER_3_PROTOCOL,
                'direction': CLASSIFIER_3_DIRECTION
            }
        )

        self.fake_gbp_plugin.add_policy_rule(
            RULE_1_ID,
            {
                'id': RULE_1_ID,
                'tenant_id': TENANT_ID,
                'name': RULE_1_NAME,
                'description': RULE_1_DESC,
                'policy_classifier_id': CLASSIFIER_1_ID,
                'policy_actions': [ACTION_1_ID]
            }
        )

        self.fake_gbp_plugin.add_policy_rule(
            RULE_2_ID,
            {
                'id': RULE_2_ID,
                'tenant_id': TENANT_ID,
                'name': RULE_2_NAME,
                'description': RULE_2_DESC,
                'policy_classifier_id': CLASSIFIER_2_ID,
                'policy_actions': [ACTION_2_ID]
            }
        )

        self.fake_gbp_plugin.add_policy_rule(
            RULE_3_ID,
            {
                'id': RULE_3_ID,
                'tenant_id': TENANT_ID,
                'name': RULE_3_NAME,
                'description': RULE_3_DESC,
                'policy_classifier_id': CLASSIFIER_1_ID,
                'policy_actions': [ACTION_1_ID, ACTION_2_ID]
            }
        )

        self.fake_gbp_plugin.add_policy_rule_set(
            RULE_SET_1_ID,
            {
                'id': RULE_SET_1_ID,
                'tenant_id': TENANT_ID,
                'name': RULE_SET_1_NAME,
                'description': RULE_SET_1_DESC,
                'policy_rules': [RULE_1_ID]
            }
        )

        self.fake_gbp_plugin.add_policy_rule_set(
            RULE_SET_2_ID,
            {
                'id': RULE_SET_2_ID,
                'tenant_id': TENANT_ID,
                'name': RULE_SET_2_NAME,
                'description': RULE_SET_2_DESC,
                'policy_rules': [RULE_2_ID]
            }
        )

        self.fake_gbp_plugin.add_l3_policy(
            L3P_ID,
            {
                'id': L3P_ID,
                'tenant_id': TENANT_ID,
                'name': L3P_NAME,
                'description': L3P_DESC
            }
        )

        self.fake_core_plugin.add_network(
            NETWORK_ID,
            {
                'id': NETWORK_ID,
                'name': NETWORK_NAME
            }
        )

        self.fake_gbp_plugin.add_l2_policy(
            L2P_ID,
            {
                'id': L2P_ID,
                'tenant_id': TENANT_ID,
                'name': L2P_NAME,
                'description': L2P_DESC,
                'l3_policy_id': L3P_ID,
                'network_id': NETWORK_ID

            }
        )

        self.fake_core_plugin.add_subnet(
            SUBNET_ID,
            {
                'id': SUBNET_ID,
                'cidr': SUBNET_CIDR,
                'network_id': NETWORK_ID,
                'gateway_ip': SUBNET_GATEWAY_IP
            }
        )

        self.fake_gbp_plugin.add_policy_target_group(
            GROUP_ID,
            {
                'id': GROUP_ID,
                'tenant_id': TENANT_ID,
                'name': GROUP_NAME,
                'description': GROUP_DESC,
                'l2_policy_id': L2P_ID,
                'subnets': [SUBNET_ID],
                'provided_policy_rule_sets': [RULE_SET_1_ID],
                'consumed_policy_rule_sets': [RULE_SET_2_ID]
            }
        )

        self.fake_core_plugin.add_port(
            PORT_ID,
            {
                'id': PORT_ID,
                'mac_address': PORT_MAC,
                'fixed_ips': [
                    {
                        'ip_address': PORT_IP,
                        'subnet_id': SUBNET_ID
                    }
                ],
                'network_id': NETWORK_ID
            }
        )

        self.fake_gbp_plugin.add_policy_target(
            POLICY_TARGET_ID,
            {
                'id': POLICY_TARGET_ID,
                'tenant_id': TENANT_ID,
                'name': POLICY_TARGET_NAME,
                'description': POLICY_TARGET_DESC,
                'policy_target_group_id': GROUP_ID,
                'port_id': PORT_ID
            }
        )


class ExternalSegmentTestCase(OdlMappingTestCase):
    """ Test case related with external segment operations

    Currently, ODL cannot handle any external segment operations,
    and should throw an exception in these cases.
    """

    def setUp(self):
        super(ExternalSegmentTestCase, self).setUp()

    def _test_exception_handling(self, method):
        func = getattr(self.driver, method)
        self.assertRaises(
            odl_mapping.ExternalSegmentNotSupportedOnOdlDriver,
            func,
            FAKE_CONTEXT
        )

    def test_create_external_segment_precommit(self):
        self._test_exception_handling('create_external_segment_precommit')

    def test_update_external_segment_precommit(self):
        self._test_exception_handling('update_external_segment_precommit')

    def test_delete_external_segment_precommit(self):
        self._test_exception_handling('delete_external_segment_precommit')

    def test_create_external_policy_precommit(self):
        self._test_exception_handling('create_external_policy_precommit')

    def test_update_external_policy_precommit(self):
        self._test_exception_handling('update_external_policy_precommit')

    def test_delete_external_policy_precommit(self):
        self._test_exception_handling('delete_external_policy_precommit')

    def test_create_nat_pool_precommit(self):
        self._test_exception_handling('create_nat_pool_precommit')

    def test_update_nat_pool_precommit(self):
        self._test_exception_handling('update_nat_pool_precommit')

    def test_delete_nat_pool_precommit(self):
        self._test_exception_handling('delete_nat_pool_precommit')


class PolicyTargetTestCase(OdlMappingTestCase):
    """ Test case for policy target operations
    """

    def setUp(self):
        super(PolicyTargetTestCase, self).setUp()
        self.context = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_target(
                FAKE_CONTEXT,
                POLICY_TARGET_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_l2_policy')
    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_target_group')
    @mock.patch.object(ml2_plugin.Ml2Plugin, 'get_port')
    @mock.patch.object(odl_manager.OdlManager, 'register_endpoints')
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                  'create_policy_target_postcommit')
    def test_create_policy_target_postcommit(
            self,
            mock_create_policy_target_commit,
            mock_register_endpoints,
            mock_get_port,
            mock_get_policy_target_group,
            mock_get_l2_policy):

        # core_plugin and gbp_plugin are mocked and simulated by
        # the fake core plugin and fake gbp plugin
        mock_get_port.side_effect = self.fake_core_plugin.get_port
        mock_get_policy_target_group.side_effect = (
            self.fake_gbp_plugin.get_policy_target_group)
        mock_get_l2_policy.side_effect = self.fake_gbp_plugin.get_l2_policy
        ep = {
            "endpoint-group": GROUP_ID,
            "l2-context": L2P_ID,
            "l3-address": [
                {
                    "ip-address": PORT_IP,
                    "l3-context": L3P_ID
                }
            ],
            "mac-address": PORT_MAC,
            "port-name": NEUTRON_PORT_ID,
            "tenant": TENANT_UUID
        }

        self.driver.create_policy_target_postcommit(self.context)
        mock_create_policy_target_commit.assert_called_once_with(self.context)
        mock_register_endpoints.assert_called_once_with([ep])

    def test_update_policy_target_precommit(self):
        self.assertRaises(
            odl_mapping.UpdatePTNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_policy_target_precommit'),
            self.context
        )

    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_l2_policy')
    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_target_group')
    @mock.patch.object(ml2_plugin.Ml2Plugin, 'get_port')
    @mock.patch.object(odl_manager.OdlManager, 'unregister_endpoints')
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'delete_policy_target_postcommit')
    def test_delete_policy_target_postcommit(
            self,
            mock_delete_policy_target_commit,
            mock_unregister_endpoints,
            mock_get_port,
            mock_get_policy_target_group,
            mock_get_l2_policy):

        # core_plugin and gbp_plugin are mocked and simulated by
        # the fake core plugin and fake gbp plugin
        mock_get_port.side_effect = self.fake_core_plugin.get_port
        mock_get_policy_target_group.side_effect = (
            self.fake_gbp_plugin.get_policy_target_group)
        mock_get_l2_policy.side_effect = self.fake_gbp_plugin.get_l2_policy
        ep = {
            "l2": [
                {
                    "l2-context": L2P_ID,
                    "mac-address": PORT_MAC
                }
            ],
            "l3": [
                {
                    "ip-address": PORT_IP,
                    "l3-context": L3P_ID
                }
            ],
        }

        self.driver.delete_policy_target_postcommit(self.context)
        mock_delete_policy_target_commit.assert_called_once_with(self.context)
        mock_unregister_endpoints.assert_called_once_with([ep])


class L3PolicyTestCase(OdlMappingTestCase):
    """ Test case for L3 policy operations
    """

    def setUp(self):
        super(L3PolicyTestCase, self).setUp()
        self.context = mock.Mock(
            current=self.fake_gbp_plugin.get_l3_policy(
                FAKE_CONTEXT,
                L3P_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    @mock.patch.object(odl_manager.OdlManager, 'create_update_l3_context')
    def test_create_l3_policy_postcommit(
            self,
            mock_create_update_l3_context):

        l3ctx = {
            "id": L3P_ID,
            "name": L3P_NAME,
            "description": L3P_DESC
        }

        self.driver.create_l3_policy_postcommit(self.context)
        mock_create_update_l3_context.assert_called_once_with(
            TENANT_UUID, l3ctx)

    def test_update_l3_policy_precommit(self):
        self.assertRaises(
            odl_mapping.UpdateL3PolicyNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_l3_policy_precommit'),
            self.context
        )

    @mock.patch.object(odl_manager.OdlManager, 'delete_l3_context')
    def test_delete_l3_policy_postcommit(
            self,
            mock_delete_l3_context):

        l3ctx = {
            "id": L3P_ID,
        }

        self.driver.delete_l3_policy_postcommit(self.context)
        mock_delete_l3_context.assert_called_once_with(TENANT_UUID, l3ctx)


class L2PolicyTestCase(OdlMappingTestCase):
    """ Test case for L2 policy operations
    """
    def setUp(self):
        super(L2PolicyTestCase, self).setUp()
        self.context = mock.Mock(
            current=self.fake_gbp_plugin.get_l2_policy(
                FAKE_CONTEXT,
                L2P_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    @mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network')
    @mock.patch.object(odl_manager.OdlManager,
                       'create_update_l2_flood_domain')
    @mock.patch.object(odl_manager.OdlManager,
                       'create_update_l2_bridge_domain')
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'create_l2_policy_postcommit')
    def test_create_l2_policy_postcommit(
            self,
            mock_create_l2_policy_postcommit,
            mock_create_update_l2_bridge_domain,
            mock_create_update_l2_flood_domain,
            mock_get_network):

        # core_plugin is mocked and simulated by the fake core plugin
        mock_get_network.side_effect = self.fake_core_plugin.get_network
        l2bd = {
            "id": L2P_ID,
            "name": L2P_NAME,
            "description": L2P_DESC,
            "parent": L3P_ID
        }
        l2fd = {
            "id": NETWORK_ID,
            "name": NETWORK_NAME,
            "parent": L2P_ID
        }

        self.driver.create_l2_policy_postcommit(self.context)
        mock_create_l2_policy_postcommit.assert_called_once_with(self.context)
        mock_create_update_l2_bridge_domain.assert_called_once_with(
            TENANT_UUID, l2bd)
        mock_create_update_l2_flood_domain.assert_called_with(TENANT_UUID,
                                                              l2fd)

    def test_update_l2_policy_precommit(self):
        self.assertRaises(
            odl_mapping.UpdateL2PolicyNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_l2_policy_precommit'),
            self.context
        )

    @mock.patch.object(odl_manager.OdlManager, 'delete_l2_flood_domain')
    @mock.patch.object(odl_manager.OdlManager, 'delete_l2_bridge_domain')
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'delete_l2_policy_postcommit')
    def test_delete_l2_policy_postcommit(
            self,
            mock_delete_l2_policy_postcommit,
            mock_delete_l2_bridge_domain,
            mock_delete_l2_flood_domain):

        l2bd = {
            "id": L2P_ID,
        }
        l2fd = {
            "id": NETWORK_ID,
        }

        self.driver.delete_l2_policy_postcommit(self.context)
        mock_delete_l2_policy_postcommit.assert_called_once_with(self.context)
        mock_delete_l2_bridge_domain.assert_called_once_with(TENANT_UUID,
                                                             l2bd)
        mock_delete_l2_flood_domain.assert_called_with(TENANT_UUID, l2fd)


class PolicyTargetGroupTestCase(OdlMappingTestCase):
    """ Test case for policy target group operations
    """

    def setUp(self):
        super(PolicyTargetGroupTestCase, self).setUp()
        self.context = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_target_group(
                FAKE_CONTEXT,
                GROUP_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_action')
    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_classifier')
    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_rule')
    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'get_policy_rule_set')
    @mock.patch.object(ml2_plugin.Ml2Plugin, 'get_subnet')
    @mock.patch.object(odl_manager.OdlManager, 'create_update_subnet')
    @mock.patch.object(odl_manager.OdlManager, 'create_update_endpoint_group')
    @mock.patch.object(odl_manager.OdlManager, 'create_update_contract')
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'create_policy_target_group_postcommit')
    def test_create_policy_target_postcommit(
            self,
            mock_create_policy_target_group_postcommit,
            mock_create_update_contract,
            mock_create_update_endpoint_group,
            mock_create_update_subnet,
            mock_get_subnet,
            mock_get_policy_rule_set,
            mock_get_policy_rule,
            mock_get_policy_classifier,
            mock_get_policy_action):

        # core_plugin and gbp_plugin are mocked and simulated by
        # the fake core plugin and fake gbp plugin
        mock_get_subnet.side_effect = self.fake_core_plugin.get_subnet
        mock_get_policy_rule_set.side_effect = (self.fake_gbp_plugin.
                                                get_policy_rule_set)
        mock_get_policy_rule.side_effect = (self.fake_gbp_plugin.
                                            get_policy_rule)
        mock_get_policy_classifier.side_effect = (self.fake_gbp_plugin.
                                                  get_policy_classifier)
        mock_get_policy_action.side_effect = (self.fake_gbp_plugin.
                                              get_policy_action)

        provided_contract_id = (
            uuid.uuid3(uuid.NAMESPACE_DNS, RULE_SET_1_NAME).urn[9:])
        provided_contract = {
            "id": provided_contract_id,
            "clause": [
                {
                    "name": RULE_SET_1_NAME,
                    "subject-refs": [RULE_SET_1_NAME]
                }
            ],
            "subject": [
                {
                    "name": RULE_SET_1_NAME,
                    "rule": [
                        {
                            "name": RULE_1_NAME,
                            "classifier-ref": [
                                {
                                    "name": CLASSIFIER_1_NAME + '-sourceport'
                                },
                                {
                                    "name": CLASSIFIER_1_NAME + '-destport'
                                }
                            ]
                        }

                    ]
                }
            ]
        }
        consumed_contract_id = (
            uuid.uuid3(uuid.NAMESPACE_DNS, RULE_SET_2_NAME).urn[9:])
        consumed_contract = {
            "id": consumed_contract_id,
            "clause": [
                {
                    "name": RULE_SET_2_NAME,
                    "subject-refs": [RULE_SET_2_NAME]
                }
            ],
            "subject": [
                {
                    "name": RULE_SET_2_NAME,
                    "rule": [
                        {
                            "name": RULE_2_NAME,
                            "classifier-ref": [
                                {
                                    "name": CLASSIFIER_2_NAME + '-sourceport',
                                    "direction": 'out'
                                },
                                {
                                    "name": CLASSIFIER_2_NAME + '-destport',
                                    "direction": 'in'
                                },
                            ]
                        }

                    ]
                }
            ]
        }
        epg = {
            "id": GROUP_ID,
            "name": GROUP_NAME,
            "network-domain": SUBNET_ID,
            "provider-named-selector": {
                "name": 'Contract-' + provided_contract_id,
                "contract": provided_contract_id
            },
            "consumer-named-selector": {
                "name": 'Contract-' + consumed_contract_id,
                "contract": consumed_contract_id
            }
        }
        odl_subnet = {
            "id": SUBNET_ID,
            "ip-prefix": SUBNET_CIDR,
            "parent": NETWORK_ID,
            "virtual-router-ip": SUBNET_GATEWAY_IP
        }

        self.driver.create_policy_target_group_postcommit(self.context)
        mock_create_policy_target_group_postcommit.assert_called_once_with(
            self.context)
        mock_create_update_contract.assert_any_call(TENANT_UUID,
                                                    provided_contract)
        mock_create_update_contract.assert_any_call(TENANT_UUID,
                                                    consumed_contract)
        mock_create_update_endpoint_group.assert_called_once_with(TENANT_UUID,
                                                                  epg)
        mock_create_update_subnet.assert_called_once_with(TENANT_UUID,
                                                          odl_subnet)

    def test_update_policy_target_group_precommit(self):
        self.assertRaises(
            odl_mapping.UpdatePTGNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_policy_target_group_precommit'),
            self.context
        )

    @mock.patch.object(odl_mapping.OdlMappingDriver, '_cleanup_subnet')
    @mock.patch.object(odl_manager.OdlManager, 'delete_endpoint_group')
    @mock.patch.object(odl_manager.OdlManager, 'delete_subnet')
    def test_delete_policy_target_group_postcommit(
            self,
            mock_delete_subnet,
            mock_delete_endpoint_group,
            mock__cleanup_subnet):

        odl_subnet = {
            "id": SUBNET_ID
        }
        epg = {
            "id": GROUP_ID
        }

        self.driver.delete_policy_target_group_postcommit(self.context)
        mock_delete_subnet.assert_called_once_with(TENANT_UUID, odl_subnet)
        mock_delete_endpoint_group.assert_called_once_with(TENANT_UUID, epg)
        mock__cleanup_subnet.assert_called_once_with(
            self.context._plugin_context, SUBNET_ID, None)


class PolicyActionTestCase(OdlMappingTestCase):
    """ Test case for policy action operations
    """

    def setUp(self):
        super(PolicyActionTestCase, self).setUp()
        self.context_1 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_action(
                FAKE_CONTEXT,
                ACTION_1_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )
        self.context_3 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_action(
                FAKE_CONTEXT,
                ACTION_3_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    def test_create_policy_action_precommit(self):
        # No exception should be raised
        self.driver.create_policy_action_precommit(self.context_1)

        # Exception should be raised only when ACTION is redirect
        self.assertRaises(
            odl_mapping.RedirectActionNotSupportedOnOdlDriver,
            getattr(self.driver, 'create_policy_action_precommit'),
            self.context_3
        )

    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'create_policy_action_postcommit')
    def test_create_policy_action_postcommit(
            self,
            mock_create_policy_action_postcommit):

        # Exception should be raised only when ACTION is redirect
        self.driver.create_policy_action_postcommit(self.context_1)
        mock_create_policy_action_postcommit.assert_called_once_with(
            self.context_1)
        self.assertRaises(
            odl_mapping.OnlyAllowActionSupportedOnOdlDriver,
            getattr(self.driver, 'create_policy_action_postcommit'),
            self.context_3
        )

    def test_update_policy_action_precommit(self):
        self.assertRaises(
            odl_mapping.UpdatePolicyActionNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_policy_action_precommit'),
            self.context_1
        )

    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       'delete_policy_action_postcommit')
    def test_delete_policy_action_postcommit(
            self,
            mock_delete_policy_action_postcommit):
        self.driver.delete_policy_action_postcommit(self.context_1)
        mock_delete_policy_action_postcommit.assert_called_once_with(
            self.context_1)


class PolicyClassifierTestCase(OdlMappingTestCase):
    """ Test case for policy classifier operations
    """

    def setUp(self):
        super(PolicyClassifierTestCase, self).setUp()
        self.context_1 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_classifier(
                FAKE_CONTEXT,
                CLASSIFIER_1_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )
        self.context_3 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_classifier(
                FAKE_CONTEXT,
                CLASSIFIER_3_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    @mock.patch.object(odl_manager.OdlManager, 'create_classifier')
    def test_create_policy_classifier_postcommit(
            self,
            mock_create_classifier):

        # Ensure two classifiers are created in ODL for TCP
        classifier_instance_1_dest = {
            "classifier-definition-id": CLASSIFIER_1_DEFINITION_ID,
            "name": CLASSIFIER_1_NAME + "-destport",
            "parameter-value": [
                {
                    "name": "type",
                    "string-value": CLASSIFIER_1_PROTOCOL
                },
                {
                    "name": "destport",
                    "int-value": CLASSIFIER_1_PORT
                }
            ]
        }
        classifier_instance_1_source = {
            "classifier-definition-id": CLASSIFIER_1_DEFINITION_ID,
            "name": CLASSIFIER_1_NAME + "-sourceport",
            "parameter-value": [
                {
                    "name": "type",
                    "string-value": CLASSIFIER_1_PROTOCOL
                },
                {
                    "name": "sourceport",
                    "int-value": CLASSIFIER_1_PORT
                }
            ]
        }
        self.driver.create_policy_classifier_postcommit(self.context_1)
        mock_create_classifier.assert_any_call(TENANT_UUID,
                                               classifier_instance_1_source)
        mock_create_classifier.assert_any_call(TENANT_UUID,
                                               classifier_instance_1_dest)
        mock_create_classifier.reset_mock()

        # only one classifier for ICMP
        classifier_instance_3 = {
            "classifier-definition-id": CLASSIFIER_3_DEFINITION_ID,
            "name": CLASSIFIER_3_NAME,
            "parameter-value": [
                {
                    "name": "proto",
                    "int-value": 1
                }
            ]
        }
        self.driver.create_policy_classifier_postcommit(self.context_3)
        mock_create_classifier.assert_called_once_with(TENANT_UUID,
                                                       classifier_instance_3)

    def test_update_policy_classifier_precommit(self):
        self.assertRaises(
            odl_mapping.UpdateClassifierNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_policy_classifier_precommit'),
            self.context_1
        )

    @mock.patch.object(odl_manager.OdlManager, 'delete_classifier')
    def test_delete_policy_classifier_postcommit(
            self,
            mock_delete_classifier):

        # Ensure both classifiers are deleted for TCP/UDP
        classifier_instance_1_dest = {
            "name": CLASSIFIER_1_NAME + "-destport"
        }
        classifier_instance_1_source = {
            "name": CLASSIFIER_1_NAME + "-sourceport"
        }
        self.driver.delete_policy_classifier_postcommit(self.context_1)
        mock_delete_classifier.assert_any_call(TENANT_UUID,
                                               classifier_instance_1_source)
        mock_delete_classifier.assert_any_call(TENANT_UUID,
                                               classifier_instance_1_dest)
        mock_delete_classifier.reset_mock()

        # Ensure only one classifier is deleted for ICMP
        classifier_instance_3 = {
            "name": CLASSIFIER_3_NAME,
        }
        self.driver.delete_policy_classifier_postcommit(self.context_3)
        mock_delete_classifier.assert_called_once_with(TENANT_UUID,
                                                       classifier_instance_3)


class PolicyRuleTestCase(OdlMappingTestCase):
    """ Test case for policy rule operations
    """
    def setUp(self):
        super(PolicyRuleTestCase, self).setUp()
        self.context_1 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_rule(
                FAKE_CONTEXT,
                RULE_1_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )
        self.context_3 = mock.Mock(
            current=self.fake_gbp_plugin.get_policy_rule(
                FAKE_CONTEXT,
                RULE_3_ID
            ),
            _plugin_context=FAKE_PLUGIN_CONTEXT,
            _plugin=self.fake_gbp_plugin
        )

    def test_create_policy_rule_precommit(self):
        # No exception should be raised
        self.driver.create_policy_rule_precommit(self.context_1)

        # Ensure exception be raised only when multiple actions appear
        self.assertRaises(
            odl_mapping.ExactlyOneActionPerRuleIsSupportedOnOdlDriver,
            getattr(self.driver, 'create_policy_rule_precommit'),
            self.context_3
        )

    def test_update_policy_rule_precommit(self):
        self.assertRaises(
            odl_mapping.PolicyRuleUpdateNotSupportedOnOdlDriver,
            getattr(self.driver, 'update_policy_rule_precommit'),
            self.context_1
        )


class DHCPTestCase(OdlMappingTestCase):
    """ Test case for DHCP related operations
    """

    def setUp(self):
        super(DHCPTestCase, self).setUp()
        mock_sql = mock.Mock()
        mock_sql.query.return_value = mock_sql
        mock_sql.join.return_value = mock_sql
        mock_sql.filter.return_value = mock_sql
        mock_sql.first.return_value = {
            "id": GROUP_ID,
            "name": GROUP_NAME
        }
        self.plugin_context = mock.Mock(
            session=mock_sql
        )
        self.port = {
            "id": PORT_ID,
            "network_id": NETWORK_ID,
            "tenant_id": TENANT_ID
        }

    @mock.patch.object(g_plugin.GroupPolicyPlugin, 'create_policy_target')
    @mock.patch.object(odl_mapping.OdlMappingDriver, '_port_is_owned')
    @mock.patch.object(ml2_plugin.Ml2Plugin, '_get_subnets_by_network')
    def test_create_dhcp_policy_target_if_needed(
            self,
            mock_get_subnets_by_network,
            mock_port_is_owned,
            mock_create_policy_target):

        mock_get_subnets_by_network.return_value = [
            {
                "id": SUBNET_ID
            }
        ]
        attrs = {
            "policy_target": {
                "tenant_id": TENANT_ID,
                "name": 'dhcp-' + GROUP_ID,
                "description": "Implicitly created DHCP policy target",
                "policy_target_group_id": GROUP_ID,
                "port_id": PORT_ID
            }
        }

        # Test that gbp_plugin.create_policy_target was NOT called
        mock_port_is_owned.return_value = True
        self.driver.create_dhcp_policy_target_if_needed(self.plugin_context,
                                                        self.port)
        self.assertFalse(mock_create_policy_target.called,
                         'Failed not to create DHCP PT when not needed')

        # Test that gbp_plugin.create_policy_target was called indeed
        mock_port_is_owned.return_value = False
        self.driver.create_dhcp_policy_target_if_needed(self.plugin_context,
                                                        self.port)
        mock_create_policy_target.assert_called_once_with(self.plugin_context,
                                                          attrs)
