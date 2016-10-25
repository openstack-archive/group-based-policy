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

import netaddr
import neutron.common  # noqa

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_group_proxy_extension as test_gp_ext)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_resource_mapping)


class ResourceMappingProxyGroupGBPTestCase(
        test_resource_mapping.ResourceMappingTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     ['proxy_group'],
                                     group='group_policy')
        super(ResourceMappingProxyGroupGBPTestCase, self).setUp()

    def _get_l3p_from_ptg(self, ptg):
        l2p = self.show_l2_policy(ptg['l2_policy_id'])['l2_policy']
        return self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']

    def _is_router_attached_to_any_subnet(self, router_ports, subnet_ids):
        subnet_ids = set(subnet_ids)
        for port in router_ports:
            if any([x for x in port['fixed_ips']
                    if x['subnet_id'] in subnet_ids]):
                return True
        return False

    def _is_router_attached_to_all_subnets(self, router_ports, subnet_ids):
        subnet_ids = set(subnet_ids)
        for port in router_ports:
            for subnet_id in [x['subnet_id'] for x in port['fixed_ips'] if
                              x['subnet_id'] in subnet_ids]:
                subnet_ids.remove(subnet_id)
        return not bool(subnet_ids)

    def _ptg_to_cidrs(self, ptg):
        cidrs = []
        for sub_id in ptg['subnets']:
            cidrs.append(
                self._get_object(
                    'subnets', sub_id, self.api)['subnet']['cidr'])
        return cidrs

    def _are_subnets_same(self, ptg1, ptg2):
        cidrs1 = netaddr.IPSet(iterable=self._ptg_to_cidrs(ptg1))
        cidrs2 = netaddr.IPSet(iterable=self._ptg_to_cidrs(ptg2))
        return cidrs1 == cidrs2

    def _are_subnets_disjoint(self, ptg1, ptg2):
        cidrs1 = netaddr.IPSet(iterable=self._ptg_to_cidrs(ptg1))
        cidrs2 = netaddr.IPSet(iterable=self._ptg_to_cidrs(ptg2))
        return len(cidrs1 & cidrs2) == 0

    def _ptg_gateway_pt(self, ptg):
        pt_list = self._list('policy_targets',
            query_params='proxy_gateway=True&policy_target_group_id=%s' %
                         ptg['id'])
        if pt_list['policy_targets']:
            return pt_list['policy_targets'][0]

    def _get_pt_ip(self, pt):
        port = self._get_object('ports', pt['port_id'], self.api)['port']
        return port['fixed_ips'][0]['ip_address']

    def _get_ptg_subnets(self, ptg):
        return [self._get_object('subnets', x, self.api)['subnet']
                for x in ptg['subnets']]

    def _are_cidr_routed_in_ptg_via_pt(self, ptg, pt, cidrs):
        nexthop = self._get_pt_ip(pt)
        subnets = self._get_ptg_subnets(ptg)
        expected_routes = set((destination, nexthop) for destination in cidrs)
        for subnet in subnets:
            expected_routes = (
                expected_routes - set((x['destination'], x['nexthop'])
                                      for x in subnet['host_routes']))
        return not expected_routes

    def _are_cidr_routed_in_router_via_pt(self, router, pt, cidrs):
        nexthop = self._get_pt_ip(pt)
        expected_routes = set((destination, nexthop) for destination in cidrs)
        routes = set((x['destination'], x['nexthop'])
                     for x in router['routes'])
        return not expected_routes - routes

    def _verify_correct_proxy_chain(self, original_ptg_id,
                                    expected_chain_length=None):
        original_ptg = self.show_policy_target_group(
            original_ptg_id)['policy_target_group']
        l3p = self._get_l3p_from_ptg(original_ptg)
        router = self._get_object(
            'routers', l3p['routers'][0], self.ext_api)['router']
        router_ports = self._list(
            'ports', query_params='device_id=%s' % router['id'])['ports']
        cumulative_cidrs = set()
        curr = original_ptg
        chain_length = 1
        while curr['proxy_group_id']:
            chain_length += 1
            proxy = self.show_policy_target_group(
                curr['proxy_group_id'])['policy_target_group']
            # Current PTG is not proxied, therefore it mustn't be attached to
            # the L3P router
            self.assertFalse(
                self._is_router_attached_to_any_subnet(
                    router_ports, curr),
                "Some ports are still attached to the PTG "
                "subnets:\nports:\n%s\nsubnets:\n%s" %
                (router_ports, curr['subnets']))
            # If L3 proxy, all subnets must be on different CIDRs
            if proxy['proxy_type'] == 'l2':
                self.assertTrue(
                    self._are_subnets_same(proxy, curr),
                    "PTG cidrs don't overlap on L2 proxy"
                    ":\nproxy_cidrs:\n%s\nproxied_cidrs:\n%s\n" %
                    (self._ptg_to_cidrs(proxy), (self._ptg_to_cidrs(curr))))
            else:
                self.assertTrue(
                    self._are_subnets_disjoint(proxy, curr),
                    "PTG cidrs overlap on L3 proxy"
                    ":\nproxy_cidrs:\n%s\nproxied_cidrs:\n%s\n" %
                    (self._ptg_to_cidrs(proxy), (self._ptg_to_cidrs(curr))))
            # Check that routes are correctly set
            curr_gateway_pt = self._ptg_gateway_pt(curr)
            if curr_gateway_pt:
                # Cumulated subnets are routed in current PTG subnets
                self.assertTrue(
                    self._are_cidr_routed_in_ptg_via_pt(curr, curr_gateway_pt,
                                                        cumulative_cidrs),
                    "PTG is not routing all the chained subnets:"
                    "\nPTG subnets:\n%s\nExpected routed CIDRs:%s\nExpected "
                    "nexthop:%s" % (self._get_ptg_subnets(curr),
                                    cumulative_cidrs,
                                    self._get_pt_ip(curr_gateway_pt)))
            cumulative_cidrs.update(self._ptg_to_cidrs(curr))
            curr = proxy
        # The last PTG of the proxy chain is fully connected to the router
        self.assertTrue(
            self._is_router_attached_to_all_subnets(
                router_ports, curr['subnets']),
            "Some ports are not attached to the PTG "
            "subnets:\nports:\n%s\nsubnets:\n%s" % (router_ports,
                                                    curr['subnets']))
        # Verify last PTG routes
        curr_gateway_pt = self._ptg_gateway_pt(curr)
        if curr_gateway_pt:
            # Cumulated subnets are routed in current PTG subnets
            self.assertTrue(
                self._are_cidr_routed_in_ptg_via_pt(curr, curr_gateway_pt,
                                                    cumulative_cidrs),
                "PTG is not routing all the chained subnets:"
                "\nPTG subnets:\n%s\nExpected routed CIDRs:%s\nExpected "
                "nexthop:%s" % (self._get_ptg_subnets(curr),
                                cumulative_cidrs,
                                self._get_pt_ip(curr_gateway_pt)))
            # Cumulated subnets are routed in L3P
            self.assertTrue(
                self._are_cidr_routed_in_router_via_pt(
                    router, curr_gateway_pt, cumulative_cidrs),
                "Router is not routing all the chained subnets:"
                "\nRouter:\n%s\nExpected routed CIDRs:%s\nExpected "
                "nexthop:%s" % (router, cumulative_cidrs,
                                self._get_pt_ip(curr_gateway_pt)))

        if expected_chain_length:
            self.assertEqual(expected_chain_length, chain_length)


class TestProxyGroupSubnetPrefixRMD(ResourceMappingProxyGroupGBPTestCase):

    def setUp(self):
        config.cfg.CONF.set_override(
                'default_proxy_subnet_prefix_length', '26',
                group='group_policy_proxy_group')
        config.cfg.CONF.set_override(
                'default_proxy_ip_pool', '192.168.1.0/24',
                group='group_policy_proxy_group')
        super(TestProxyGroupSubnetPrefixRMD, self).setUp()

    def test_proxy_group_updated_prefix_length(self):
        l3p = self.create_l3_policy(ip_pool='11.0.0.0/8')['l3_policy']
        self.assertEqual('192.168.1.0/24', l3p['proxy_ip_pool'])
        self.assertEqual(26, l3p['proxy_subnet_prefix_length'])

        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        l2p2 = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            l2_policy_id=l2p2['id'])['policy_target_group']

        subnet = self._get_object('subnets', ptg_proxy['subnets'][0],
                                  self.api)['subnet']
        self.assertEqual(str(l3p['proxy_subnet_prefix_length']),
                         subnet['cidr'].split('/')[1])


class TestProxyGroupRMD(ResourceMappingProxyGroupGBPTestCase,
                        test_gp_ext.ExtensionDriverTestCaseMixin):

    def test_proxy_group_extension(self):
        l3p = self.create_l3_policy(ip_pool='11.0.0.0/8')['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(28, l3p['proxy_subnet_prefix_length'])

        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.assertIsNone(ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])
        self.assertIsNone(ptg['proxy_type'])

        # Verify Default L3P pool mapping on show
        l3p = self.show_l3_policy(l3p['id'])['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(28, l3p['proxy_subnet_prefix_length'])

        l2p2 = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            l2_policy_id=l2p2['id'])['policy_target_group']
        self.assertIsNone(ptg_proxy['proxy_group_id'])
        self.assertEqual(ptg['id'], ptg_proxy['proxied_group_id'])
        self.assertEqual('l3', ptg_proxy['proxy_type'])

        subnet = self._get_object('subnets', ptg_proxy['subnets'][0],
                                  self.api)['subnet']
        self.assertEqual(str(l3p['proxy_subnet_prefix_length']),
                         subnet['cidr'].split('/')[1])

        # Verify relationship added
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg_proxy['id'], ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])

        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'])['policy_target']
        self.assertFalse(pt['proxy_gateway'])
        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'],
            proxy_gateway=True)['policy_target']
        self.assertTrue(pt['proxy_gateway'])
        pt = self.show_policy_target(pt['id'])['policy_target']
        self.assertTrue(pt['proxy_gateway'])


class TestPolicyTarget(ResourceMappingProxyGroupGBPTestCase,
                       test_resource_mapping.TestPolicyTarget):

    def test_proxy_gateway(self):
        # Verify that L3 Proxy is correctly stitched
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l3')['policy_target_group']
        self.create_policy_target(policy_target_group_id=proxy['id'],
                                  proxy_gateway=True)
        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=2)

        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy['id'],
            proxy_type='l3')['policy_target_group']
        self.create_policy_target(policy_target_group_id=proxy2['id'],
                                  proxy_gateway=True)

        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=3)

    def test_group_default_gateway(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l3')

        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            group_default_gateway=True)['policy_target']
        port = self._get_object('ports', pt['port_id'], self.api)['port']
        self.assertTrue(len(port['fixed_ips']) > 0)
        for fixed_ip in port['fixed_ips']:
            subnet = self._get_object('subnets', fixed_ip['subnet_id'],
                                      self.api)['subnet']
            self.assertEqual(subnet['gateway_ip'], fixed_ip['ip_address'])

    def test_group_default_gateway_fails(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        self.create_policy_target(policy_target_group_id=ptg['id'],
                                  group_default_gateway=True,
                                  expected_res_status=409)

    def test_proxy_gateway_deleted(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l3')['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=proxy['id'],
            proxy_gateway=True)['policy_target']
        nexthop = self._get_pt_ip(pt)
        l3p = self._get_l3p_from_ptg(ptg)
        router = self._get_object(
            'routers', l3p['routers'][0], self.ext_api)['router']
        subnet = self._get_object(
            'subnets', proxy['subnets'][0], self.api)['subnet']

        self.assertTrue(
            any([x for x in router['routes'] if x['nexthop'] == nexthop]),
            "No routes in router with "
            "nexthop %s:\n%s" % (nexthop, router['routes']))
        self.assertTrue(
            any([x for x in subnet['host_routes'] if x['nexthop'] == nexthop]),
            "No routes in PTG with "
            "nexthop %s:\n%s" % (nexthop, subnet['host_routes']))

        self.delete_policy_target(pt['id'])
        # Verify routes deleted for that PT
        router = self._get_object(
            'routers', l3p['routers'][0], self.ext_api)['router']
        subnet = self._get_object(
            'subnets', ptg['subnets'][0], self.api)['subnet']
        self.assertFalse(
            any([x for x in router['routes'] if x['nexthop'] == nexthop]),
            "Some routes still remains in router with "
            "nexthop %s:\n%s" % (nexthop, router['routes']))
        self.assertFalse(
            any([x for x in subnet['host_routes'] if x['nexthop'] == nexthop]),
            "Some routes still remains in subnet with "
            "nexthop %s:\n%s" % (nexthop, subnet['host_routes']))

    def test_implicit_port_lifecycle(self):
        super(TestPolicyTarget, self).test_implicit_port_lifecycle(
            proxy_ip_pool='182.169.0.0/16')

    def test_weird_port_extra_attributes_ignored(self):
        super(TestPolicyTarget, self).test_weird_port_extra_attributes_ignored(
            extra={'proxy_gateway': False, 'group_default_gateway': False})

    def test_port_extra_attributes(self):
        super(TestPolicyTarget, self).test_port_extra_attributes(
            extra={'proxy_gateway': False, 'group_default_gateway': False})

    def test_port_extra_attributes_fixed_ips(self):
        super(TestPolicyTarget, self).test_port_extra_attributes_fixed_ips(
            extra={'proxy_gateway': False, 'group_default_gateway': False})

    def test_port_extra_attributes_implicit(self):
        super(TestPolicyTarget, self).test_port_extra_attributes_implicit(
            extra={'proxy_gateway': False, 'group_default_gateway': False})


class TestPolicyTargetGroup(ResourceMappingProxyGroupGBPTestCase,
                            test_resource_mapping.TestPolicyTargetGroup):

    def test_l3_proxy_stitching(self):
        # Verify that L3 Proxy is correctly stitched
        ptg = self.create_policy_target_group()['policy_target_group']
        self.create_policy_target_group(proxied_group_id=ptg['id'],
                                        proxy_type='l3')
        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=2)

    def test_l2_proxy_stitching(self):
        # Verify that L2 Proxy is correctly stitched
        ptg = self.create_policy_target_group()['policy_target_group']
        self.create_policy_target_group(proxied_group_id=ptg['id'],
                                        proxy_type='l2')
        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=2)

    def test_multi_type_stitcing(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy1 = self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l3')['policy_target_group']
        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy1['id'],
            proxy_type='l2')['policy_target_group']
        self.assertEqual('l2', proxy2['proxy_type'])
        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=3)

        # Add L3 proxy in front of the chain
        proxy3 = self.create_policy_target_group(
            proxied_group_id=proxy2['id'],
            proxy_type='l3')['policy_target_group']
        self.assertEqual('l3', proxy3['proxy_type'])
        self._verify_correct_proxy_chain(ptg['id'], expected_chain_length=4)

    def test_multi_type_stitcing_delete_head(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy1 = self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l3')['policy_target_group']
        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy1['id'],
            proxy_type='l2')['policy_target_group']

        # Add L3 proxy in front of the chain
        proxy3 = self.create_policy_target_group(
            proxied_group_id=proxy2['id'],
            proxy_type='l3')['policy_target_group']
        self.delete_policy_target_group(ptg['id'], expected_res_status=204)
        self.show_policy_target_group(proxy1['id'], expected_res_status=404)
        self.show_policy_target_group(proxy2['id'], expected_res_status=404)
        self.show_policy_target_group(proxy3['id'], expected_res_status=404)

    def test_proxy_creation_different_l3p(self):
        l3p1 = self.create_l3_policy()['l3_policy']
        l2p1 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p1['id'])['policy_target_group']

        l3p2 = self.create_l3_policy(
            ip_pool='11.0.0.0/8', proxy_ip_pool='192.169.0.0/26')['l3_policy']
        l2p2 = self.create_l2_policy(l3_policy_id=l3p2['id'])['l2_policy']
        res = self.create_policy_target_group(
            l2_policy_id=l2p2['id'], proxied_group_id=ptg['id'],
            expected_res_status=400)
        self.assertEqual('InvalidProxiedGroupL3P', res['NeutronError']['type'])

    def test_l2_proxy_creation_same_l2p(self):
        l3p1 = self.create_l3_policy()['l3_policy']
        l2p1 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p1['id'])['policy_target_group']
        res = self.create_policy_target_group(
            l2_policy_id=l2p1['id'], proxied_group_id=ptg['id'],
            proxy_type='l2', expected_res_status=400)
        self.assertEqual('InvalidProxiedGroupL2P', res['NeutronError']['type'])

    def test_l3_proxy_creation_same_l2p(self):
        l3p1 = self.create_l3_policy()['l3_policy']
        l2p1 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p1['id'])['policy_target_group']
        self.create_policy_target_group(
            l2_policy_id=l2p1['id'], proxied_group_id=ptg['id'],
            proxy_type='l3', expected_res_status=201)

    def test_proxy_creation_implicit_l2p(self):
        l3p = self.create_l3_policy(
            name='nondefault', ip_pool='11.0.0.0/8',
            proxy_ip_pool='193.168.0.0/16')['l3_policy']
        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        # Create a normal group with implicit L2P, will be created in the
        # default context
        group_noproxy = self.create_policy_target_group(
            l2_policy_id=None)['policy_target_group']
        l2p = self.show_l2_policy(group_noproxy['l2_policy_id'])['l2_policy']
        self.assertNotEqual(l3p['id'], l2p['l3_policy_id'])

        # Create a proxy group with implicit L2P, will be created in the
        # default context
        group_proxy = self.create_policy_target_group(
            l2_policy_id=None,
            proxied_group_id=ptg['id'])['policy_target_group']
        l2p = self.show_l2_policy(group_proxy['l2_policy_id'])['l2_policy']
        self.assertEqual(l3p['id'], l2p['l3_policy_id'])


class TestL2Policy(ResourceMappingProxyGroupGBPTestCase,
                   test_resource_mapping.TestL2Policy):

    def test_l3p_update_rejected(self):
        super(TestL2Policy, self).test_l3p_update_rejected(
            proxy_ip_pool='182.169.0.0/16')


class TestL3Policy(ResourceMappingProxyGroupGBPTestCase,
                   test_resource_mapping.TestL3Policy):

    def test_implicit_l3p_proxy_pool(self):
        default_proxy_pool = '192.168.0.0/16'
        default_proxy_subnet_prefix_length = 28
        l2p = self.create_l2_policy()['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        self.assertEqual(default_proxy_pool, l3p['proxy_ip_pool'])
        self.assertEqual(default_proxy_subnet_prefix_length,
                         l3p['proxy_subnet_prefix_length'])


class TestPolicyRuleSet(ResourceMappingProxyGroupGBPTestCase,
                        test_resource_mapping.TestPolicyRuleSet):
    pass


class TestPolicyAction(ResourceMappingProxyGroupGBPTestCase,
                       test_resource_mapping.TestPolicyAction):
    pass


class TestPolicyRule(ResourceMappingProxyGroupGBPTestCase,
                     test_resource_mapping.TestPolicyRule):
    pass


class TestExternalSegment(ResourceMappingProxyGroupGBPTestCase,
                          test_resource_mapping.TestExternalSegment):
    def test_update(self):
        super(TestExternalSegment, self).test_update(
            proxy_ip_pool1='182.169.0.0/16',
            proxy_ip_pool2='172.169.0.0/16')


class TestExternalPolicy(ResourceMappingProxyGroupGBPTestCase,
                         test_resource_mapping.TestExternalPolicy):
    pass
