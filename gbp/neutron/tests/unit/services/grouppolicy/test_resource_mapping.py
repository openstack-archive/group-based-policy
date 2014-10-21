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

import contextlib
import mock
import webob.exc

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.extensions import securitygroup as ext_sg
from neutron.notifiers import nova
from neutron.openstack.common import uuidutils
from neutron.tests.unit import test_extension_security_group
from neutron.tests.unit import test_l3_plugin

from gbp.neutron.db import servicechain_db
from gbp.neutron.services.grouppolicy.common import constants as gconst
from gbp.neutron.services.grouppolicy import config
from gbp.neutron.services.grouppolicy.drivers import resource_mapping
from gbp.neutron.services.servicechain import servicechain_plugin
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin


class NoL3NatSGTestPlugin(test_l3_plugin.TestNoL3NatPlugin,
                  test_extension_security_group.SecurityGroupTestPlugin):

    supported_extension_aliases = ["external-net", "security-group"]


CORE_PLUGIN = ('gbp.neutron.tests.unit.services.grouppolicy.'
               'test_resource_mapping.NoL3NatSGTestPlugin')


class ResourceMappingTestCase(
        test_grouppolicy_plugin.GroupPolicyPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'resource_mapping'],
                                     group='group_policy')
        super(ResourceMappingTestCase, self).setUp(core_plugin=CORE_PLUGIN)


class TestEndpoint(ResourceMappingTestCase):

    def test_implicit_port_lifecycle(self):
        # Create endpoint group.
        epg = self.create_endpoint_group(name="epg1")
        epg_id = epg['endpoint_group']['id']

        # Create endpoint with implicit port.
        ep = self.create_endpoint(name="ep1", endpoint_group_id=epg_id)
        ep_id = ep['endpoint']['id']
        port_id = ep['endpoint']['port_id']
        self.assertIsNotNone(port_id)

        # TODO(rkukura): Verify implicit port belongs to endpoint
        # group's subnet.

        # Verify deleting endpoint cleans up port.
        req = self.new_delete_request('endpoints', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('ports', port_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_port_lifecycle(self):
        # Create endpoint group.
        epg = self.create_endpoint_group(name="epg1")
        epg_id = epg['endpoint_group']['id']
        subnet_id = epg['endpoint_group']['subnets'][0]
        req = self.new_show_request('subnets', subnet_id)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))

        # Create endpoint with explicit port.
        with self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            ep = self.create_endpoint(name="ep1", endpoint_group_id=epg_id,
                                      port_id=port_id)
            ep_id = ep['endpoint']['id']
            self.assertEqual(port_id, ep['endpoint']['port_id'])

            # Verify deleting endpoint does not cleanup port.
            req = self.new_delete_request('endpoints', ep_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('ports', port_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_missing_epg_rejected(self):
        data = self.create_endpoint(name="ep1",
                                    expected_res_status=
                                    webob.exc.HTTPBadRequest.code)
        self.assertEqual('EndpointRequiresEndpointGroup',
                         data['NeutronError']['type'])

    def test_epg_update_rejected(self):
        # Create two endpoint groups.
        epg1 = self.create_endpoint_group(name="epg1")
        epg1_id = epg1['endpoint_group']['id']
        epg2 = self.create_endpoint_group(name="epg2")
        epg2_id = epg2['endpoint_group']['id']

        # Create endpoint.
        ep = self.create_endpoint(name="ep1", endpoint_group_id=epg1_id)
        ep_id = ep['endpoint']['id']

        # Verify updating endpoint group rejected.
        data = {'endpoint': {'endpoint_group_id': epg2_id}}
        req = self.new_update_request('endpoints', data, ep_id)
        data = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('EndpointEndpointGroupUpdateNotSupported',
                         data['NeutronError']['type'])


class TestEndpointGroup(ResourceMappingTestCase):

    def test_implicit_subnet_lifecycle(self):
        # Use explicit L2 policy so network and subnet not deleted
        # with endpoint group.
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']

        # Create endpoint group with implicit subnet.
        epg = self.create_endpoint_group(name="epg1", l2_policy_id=l2p_id)
        epg_id = epg['endpoint_group']['id']
        subnets = epg['endpoint_group']['subnets']
        self.assertIsNotNone(subnets)
        self.assertEqual(len(subnets), 1)
        subnet_id = subnets[0]

        # TODO(rkukura): Verify implicit subnet belongs to L2 policy's
        # network, is within L3 policy's ip_pool, and was added as
        # router interface.

        # Verify deleting endpoint group cleans up subnet.
        req = self.new_delete_request('endpoint_groups', epg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # TODO(rkukura): Verify implicit subnet was removed as router
        # interface.

    def test_explicit_subnet_lifecycle(self):
        # Create L3 policy.
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']

        # Create L2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))

        # Create endpoint group with explicit subnet.
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet:
            subnet_id = subnet['subnet']['id']
            epg = self.create_endpoint_group(name="epg1", l2_policy_id=l2p_id,
                                             subnets=[subnet_id])
            epg_id = epg['endpoint_group']['id']
            subnets = epg['endpoint_group']['subnets']
            self.assertIsNotNone(subnets)
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnet_id, subnets[0])

            # TODO(rkukura): Verify explicit subnet was added as
            # router interface.

            # Verify deleting endpoint group does not cleanup subnet.
            req = self.new_delete_request('endpoint_groups', epg_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

            # TODO(rkukura): Verify explicit subnet was removed as
            # router interface.

    def test_add_subnet(self):
        # Create L3 policy.
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']

        # Create L2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))

        # Create endpoint group with explicit subnet.
        with contextlib.nested(
                self.subnet(network=network, cidr='10.10.1.0/24'),
                self.subnet(network=network, cidr='10.10.2.0/24')
        ) as (subnet1, subnet2):
            subnet1_id = subnet1['subnet']['id']
            subnet2_id = subnet2['subnet']['id']
            subnets = [subnet1_id]
            epg = self.create_endpoint_group(l2_policy_id=l2p_id,
                                             subnets=subnets)
            epg_id = epg['endpoint_group']['id']

            # Add subnet.
            subnets = [subnet1_id, subnet2_id]
            data = {'endpoint_group': {'subnets': subnets}}
            req = self.new_update_request('endpoint_groups', data, epg_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_remove_subnet_rejected(self):
        # Create L3 policy.
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']

        # Create L2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))

        # Create endpoint group with explicit subnets.
        with contextlib.nested(
                self.subnet(network=network, cidr='10.10.1.0/24'),
                self.subnet(network=network, cidr='10.10.2.0/24')
        ) as (subnet1, subnet2):
            subnet1_id = subnet1['subnet']['id']
            subnet2_id = subnet2['subnet']['id']
            subnets = [subnet1_id, subnet2_id]
            epg = self.create_endpoint_group(l2_policy_id=l2p_id,
                                             subnets=subnets)
            epg_id = epg['endpoint_group']['id']

            # Verify removing subnet rejected.
            data = {'endpoint_group': {'subnets': [subnet2_id]}}
            req = self.new_update_request('endpoint_groups', data, epg_id)
            data = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual('EndpointGroupSubnetRemovalNotSupported',
                             data['NeutronError']['type'])

    def test_subnet_allocation(self):
        epg1 = self.create_endpoint_group(name="epg1")
        subnets = epg1['endpoint_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet1 = self.deserialize(self.fmt, req.get_response(self.api))

        epg2 = self.create_endpoint_group(name="epg2")
        subnets = epg2['endpoint_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet2 = self.deserialize(self.fmt, req.get_response(self.api))

        self.assertNotEqual(subnet1['subnet']['cidr'],
                            subnet2['subnet']['cidr'])

    # TODO(rkukura): Test ip_pool exhaustion.


class TestL2Policy(ResourceMappingTestCase):

    def test_implicit_network_lifecycle(self):
        # Create L2 policy with implicit network.
        l2p = self.create_l2_policy(name="l2p1")
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        self.assertIsNotNone(network_id)

        # Verify deleting L2 policy cleans up network.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_network_lifecycle(self):
        # Create L2 policy with explicit network.
        with self.network() as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(name="l2p1", network_id=network_id)
            l2p_id = l2p['l2_policy']['id']
            self.assertEqual(network_id, l2p['l2_policy']['network_id'])

            # Verify deleting L2 policy does not cleanup network.
            req = self.new_delete_request('l2_policies', l2p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('networks', network_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)


class TestL3Policy(ResourceMappingTestCase):

    def test_implicit_router_lifecycle(self):
        # Create L3 policy with implicit router.
        l3p = self.create_l3_policy(name="l3p1")
        l3p_id = l3p['l3_policy']['id']
        routers = l3p['l3_policy']['routers']
        self.assertIsNotNone(routers)
        self.assertEqual(len(routers), 1)
        router_id = routers[0]

        # Verify deleting L3 policy cleans up router.
        req = self.new_delete_request('l3_policies', l3p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('routers', router_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_router_lifecycle(self):
        # Create L3 policy with explicit router.
        with self.router() as router:
            router_id = router['router']['id']
            l3p = self.create_l3_policy(name="l3p1", routers=[router_id])
            l3p_id = l3p['l3_policy']['id']
            routers = l3p['l3_policy']['routers']
            self.assertIsNotNone(routers)
            self.assertEqual(len(routers), 1)
            self.assertEqual(router_id, routers[0])

            # Verify deleting L3 policy does not cleanup router.
            req = self.new_delete_request('l3_policies', l3p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('routers', router_id, fmt=self.fmt)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_multiple_routers_rejected(self):
        # Verify update l3 policy with explicit router rejected.
        with contextlib.nested(self.router(),
                               self.router()) as (router1, router2):
            router1_id = router1['router']['id']
            router2_id = router2['router']['id']
            data = self.create_l3_policy(name="l3p1",
                                         routers=[router1_id, router2_id],
                                         expected_res_status=
                                         webob.exc.HTTPBadRequest.code)
            self.assertEqual('L3PolicyMultipleRoutersNotSupported',
                             data['NeutronError']['type'])

    def test_router_update_rejected(self):
        # Create L3 policy with implicit router.
        l3p = self.create_l3_policy(name="l3p1")
        l3p_id = l3p['l3_policy']['id']

        # Verify update l3 policy with explicit router rejected.
        with self.router() as router:
            router_id = router['router']['id']
            data = {'l3_policy': {'routers': [router_id]}}
            req = self.new_update_request('l3_policies', data, l3p_id)
            data = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual('L3PolicyRoutersUpdateNotSupported',
                             data['NeutronError']['type'])


class NotificationTest(ResourceMappingTestCase):

    def test_dhcp_notifier(self):
        with mock.patch.object(dhcp_rpc_agent_api.DhcpAgentNotifyAPI,
                               'notify') as dhcp_notifier:
            epg = self.create_endpoint_group(name="epg1")
            epg_id = epg['endpoint_group']['id']
            ep = self.create_endpoint(name="ep1", endpoint_group_id=epg_id)
            self.assertEqual(ep['endpoint']['endpoint_group_id'], epg_id)
            # REVISIT(rkukura): Check dictionaries for correct id, etc..
            dhcp_notifier.assert_any_call(mock.ANY, mock.ANY,
                                          "router.create.end")
            dhcp_notifier.assert_any_call(mock.ANY, mock.ANY,
                                          "network.create.end")
            dhcp_notifier.assert_any_call(mock.ANY, mock.ANY,
                                          "subnet.create.end")
            dhcp_notifier.assert_any_call(mock.ANY, mock.ANY,
                                          "port.create.end")

    def test_nova_notifier(self):
        with mock.patch.object(nova.Notifier,
                               'send_network_change') as nova_notifier:
            epg = self.create_endpoint_group(name="epg1")
            epg_id = epg['endpoint_group']['id']
            ep = self.create_endpoint(name="ep1", endpoint_group_id=epg_id)
            self.assertEqual(ep['endpoint']['endpoint_group_id'], epg_id)
            # REVISIT(rkukura): Check dictionaries for correct id, etc..
            nova_notifier.assert_any_call("create_router", {}, mock.ANY)
            nova_notifier.assert_any_call("create_network", {}, mock.ANY)
            nova_notifier.assert_any_call("create_subnet", {}, mock.ANY)
            nova_notifier.assert_any_call("create_port", {}, mock.ANY)


# TODO(ivar): We need a UT that verifies that the EP's ports have the default
# SG when there are no contracts involved, that the default SG is properly
# created and shared, and that it has the right content.
class TestContract(ResourceMappingTestCase):

    def test_contract_creation(self):
        # Create contracts
        classifier = self.create_policy_classifier(name="class1",
                protocol="tcp", direction="out", port_range="50:100")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1")
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(name='pr1',
                policy_classifier_id=classifier_id,
                policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        contract = self.create_contract(name="c1",
                policy_rules=policy_rule_list)
        contract_id = contract['contract']['id']
        epg = self.create_endpoint_group(name="epg1",
                provided_contracts={contract_id: None})
        epg_id = epg['endpoint_group']['id']
        ep = self.create_endpoint(name="ep1", endpoint_group_id=epg_id)

        # verify SG bind to port
        port_id = ep['endpoint']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

    # TODO(ivar): we also need to verify that those security groups have the
    # right rules
    def test_consumed_contract(self):
        classifier = self.create_policy_classifier(name="class1",
                protocol="tcp", direction="in", port_range="20:90")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(name='pr1',
                policy_classifier_id=classifier_id,
                policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        contract = self.create_contract(name="c1",
                policy_rules=policy_rule_list)
        contract_id = contract['contract']['id']
        self.create_endpoint_group(name="epg1",
                                   provided_contracts={contract_id: None})
        consumed_epg = self.create_endpoint_group(name="epg2",
                            consumed_contracts={contract_id: None})
        epg_id = consumed_epg['endpoint_group']['id']
        ep = self.create_endpoint(name="ep2", endpoint_group_id=epg_id)

        # verify SG bind to port
        port_id = ep['endpoint']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

    # Test update and delete of EPG, how it affects SG mapping
    def test_endpoint_group_update(self):
        # create two contracts: bind one to an EPG, update with
        # adding another one (increase SG count on EP on EPG)
        classifier1 = self.create_policy_classifier(name="class1",
                protocol="tcp", direction="bi", port_range="30:80")
        classifier2 = self.create_policy_classifier(name="class2",
                protocol="udp", direction="out", port_range="20:30")
        classifier1_id = classifier1['policy_classifier']['id']
        classifier2_id = classifier2['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule1 = self.create_policy_rule(name='pr1',
                policy_classifier_id=classifier1_id,
                policy_actions=action_id_list)
        policy_rule2 = self.create_policy_rule(name='pr2',
                policy_classifier_id=classifier2_id,
                policy_actions=action_id_list)
        policy_rule1_id = policy_rule1['policy_rule']['id']
        policy_rule1_list = [policy_rule1_id]
        policy_rule2_id = policy_rule2['policy_rule']['id']
        policy_rule2_list = [policy_rule2_id]
        contract1 = self.create_contract(name="c1",
                policy_rules=policy_rule1_list)
        contract1_id = contract1['contract']['id']
        contract2 = self.create_contract(name="c2",
                policy_rules=policy_rule2_list)
        contract2_id = contract2['contract']['id']
        epg1 = self.create_endpoint_group(name="epg1",
                            provided_contracts={contract1_id: None})
        epg2 = self.create_endpoint_group(name="epg2",
                            consumed_contracts={contract1_id: None})
        epg1_id = epg1['endpoint_group']['id']
        epg2_id = epg2['endpoint_group']['id']

        # endpoint ep1 now with epg2 consumes contract1_id
        ep1 = self.create_endpoint(name="ep1",
                                   endpoint_group_id=epg2_id)
        # ep1's port should have 2 SG associated
        port_id = ep1['endpoint']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

        # now add a contract to EPG
        # First we update contract2 to be provided by consumed_epg
        data = {'endpoint_group': {'provided_contracts': {contract2_id: None}}}
        req = self.new_update_request('endpoint_groups', data, epg2_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        # set epg1 to provide contract1 and consume contract2
        # contract2 now maps to SG which has epg2's subnet as CIDR on rules
        data = {'endpoint_group': {'consumed_contracts': {contract2_id: None}}}
        req = self.new_update_request('endpoint_groups', data, epg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        port_id = ep1['endpoint']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 3)

    def test_redirect_to_chain(self):
        classifier = self.create_policy_classifier(name="class1",
                protocol="tcp", direction="in", port_range="20:90")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(
                                name="action1",
                                action_type=gconst.GP_ACTION_REDIRECT,
                                action_value=uuidutils.generate_uuid())
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(name='pr1',
                policy_classifier_id=classifier_id,
                policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        contract = self.create_contract(name="c1",
                policy_rules=policy_rule_list)
        contract_id = contract['contract']['id']
        self.create_endpoint_group(name="epg1",
                                   provided_contracts={contract_id: None})

        create_chain_instance = mock.patch.object(
                                    servicechain_plugin.ServiceChainPlugin,
                                    'create_servicechain_instance')
        create_chain_instance = create_chain_instance.start()
        chain_instance_id = uuidutils.generate_uuid()
        create_chain_instance.return_value = {'id': chain_instance_id}

        with mock.patch.object(
                resource_mapping.ResourceMappingDriver,
                '_set_rule_servicechain_instance_mapping') as set_rule:
            with mock.patch.object(servicechain_db.ServiceChainDbPlugin,
                                   'get_servicechain_spec') as sc_spec_get:
                sc_spec_get.return_value = {'servicechain_spec': {}}
                self.create_endpoint_group(name="epg2", consumed_contracts={
                                                        contract_id: "None"})
                set_rule.assert_called_once_with(mock.ANY, policy_rule_id,
                                                 chain_instance_id)
        #TODO(Magesh): Enable the delete test after Bug#1378530 is fixed
        #Use contextlib.nested rather than nested with blocks
        '''
        with mock.patch.object(servicechain_plugin.ServiceChainPlugin,
                               'delete_servicechain_instance') as del_sc_inst:
            with mock.patch.object(
                            resource_mapping.ResourceMappingDriver,
                            '_get_rule_servicechain_mapping') as get_rule:
                r_sc_map = resource_mapping.RuleServiceChainInstanceMapping()
                r_sc_map.rule_id = policy_rule_id
                r_sc_map.servicechain_instance_id = chain_instance_id
                get_rule.return_value = r_sc_map
                get_chain_inst = mock.patch.object(
                                        servicechain_db.ServiceChainDbPlugin,
                                        'get_servicechain_instance')
                get_chain_inst.start()
                get_chain_inst.return_value = {
                                        "servicechain_instance": {
                                                    'id': chain_instance_id}}
                req = self.new_delete_request(
                                        'endpoint_groups',
                                        consumed_epg['endpoint_group']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        '''
