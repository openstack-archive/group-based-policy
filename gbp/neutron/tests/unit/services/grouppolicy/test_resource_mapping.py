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
from neutron.notifiers import nova

from gbp.neutron.services.grouppolicy import config
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin


CORE_PLUGIN = 'neutron.tests.unit.test_l3_plugin.TestNoL3NatPlugin'


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
