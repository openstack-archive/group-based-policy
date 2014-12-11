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
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as cst
from neutron import context as nctx
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.openstack.common import uuidutils
from neutron.tests.unit import test_extension_security_group
from neutron.tests.unit import test_l3_plugin
import webob.exc

from gbp.neutron.db import servicechain_db
from gbp.neutron.services.grouppolicy.common import constants as gconst
from gbp.neutron.services.grouppolicy import config
from gbp.neutron.services.grouppolicy.drivers import resource_mapping
from gbp.neutron.services.servicechain import servicechain_plugin
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin


class NoL3NatSGTestPlugin(
        test_l3_plugin.TestNoL3NatPlugin,
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
        config.cfg.CONF.set_override('allow_overlapping_ips', True)
        super(ResourceMappingTestCase, self).setUp(core_plugin=CORE_PLUGIN)
        self.__plugin = manager.NeutronManager.get_plugin()
        self.__context = nctx.get_admin_context()

    def get_plugin_context(self):
        return self.__plugin, self.__context


class TestPolicyTarget(ResourceMappingTestCase):

    def test_implicit_port_lifecycle(self):
        # Create policy_target group.
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']

        # Create policy_target with implicit port.
        pt = self.create_policy_target(name="pt1",
                                       policy_target_group_id=ptg_id)
        pt_id = pt['policy_target']['id']
        port_id = pt['policy_target']['port_id']
        self.assertIsNotNone(port_id)

        # Create policy_target in shared policy_target group
        l3p = self.create_l3_policy(shared=True)
        l2p = self.create_l2_policy(l3_policy_id=l3p['l3_policy']['id'],
                                    shared=True)
        s_ptg = self.create_policy_target_group(name="s_ptg", shared=True,
                                           l2_policy_id=l2p['l2_policy']['id'])
        s_ptg_id = s_ptg['policy_target_group']['id']
        pt = self.create_policy_target(name="ep1",
                                       policy_target_group_id=s_ptg_id)
        self.assertIsNotNone(pt['policy_target']['port_id'])

        # TODO(rkukura): Verify implicit port belongs to policy_target
        # group's subnet.

        # Verify deleting policy_target cleans up port.
        req = self.new_delete_request('policy_targets', pt_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('ports', port_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_port_lifecycle(self):
        # Create policy_target group.
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        subnet_id = ptg['policy_target_group']['subnets'][0]
        req = self.new_show_request('subnets', subnet_id)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))

        # Create policy_target with explicit port.
        with self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            pt = self.create_policy_target(
                name="pt1", policy_target_group_id=ptg_id, port_id=port_id)
            pt_id = pt['policy_target']['id']
            self.assertEqual(port_id, pt['policy_target']['port_id'])

            # Verify deleting policy_target does not cleanup port.
            req = self.new_delete_request('policy_targets', pt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('ports', port_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_explicit_port_deleted(self):
        # Create policy_target group.
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        subnet_id = ptg['policy_target_group']['subnets'][0]
        req = self.new_show_request('subnets', subnet_id)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))

        # Create policy_target with explicit port.
        with self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            pt = self.create_policy_target(
                name="pt1", policy_target_group_id=ptg_id, port_id=port_id)
            pt_id = pt['policy_target']['id']

            req = self.new_delete_request('ports', port_id)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            # Verify deleting policy_target does not cleanup port.
            req = self.new_delete_request('policy_targets', pt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_missing_ptg_rejected(self):
        data = self.create_policy_target(
            name="pt1", expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('PolicyTargetRequiresPolicyTargetGroup',
                         data['NeutronError']['type'])

    def test_explicit_port_subnet_mismatches_ptg_subnet_rejected(self):
        ptg1 = self.create_policy_target_group(name="ptg1")
        ptg1_id = ptg1['policy_target_group']['id']

        # Create a subnet that is different from ptg1 subnet (by
        # creating a new L2 policy and subnet)
        l2p = self.create_l2_policy(name="l2p1")
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet:
            with self.port(subnet=subnet) as port:
                port_id = port['port']['id']

                data = self.create_policy_target(name="ep1",
                        policy_target_group_id=ptg1_id,
                        port_id=port_id,
                        expected_res_status=webob.exc.HTTPBadRequest.code)

                self.assertEqual('InvalidPortForPTG',
                         data['NeutronError']['type'])

    def test_missing_explicit_port_ptg_rejected(self):
        ptg1 = self.create_policy_target_group(name="ptg1")
        ptg1_id = ptg1['policy_target_group']['id']

        port_id = uuidutils.generate_uuid()
        data = self.create_policy_target(name="pt1",
                        policy_target_group_id=ptg1_id,
                        port_id=port_id,
                        expected_res_status=webob.exc.HTTPServerError.code)

        # TODO(krishna-sunitha): Need to change the below to the correct
        # exception after
        # https://bugs.launchpad.net/group-based-policy/+bug/1394000 is fixed
        self.assertEqual('HTTPInternalServerError',
                         data['NeutronError']['type'])

    def test_ptg_update_rejected(self):
        # Create two policy_target groups.
        ptg1 = self.create_policy_target_group(name="ptg1")
        ptg1_id = ptg1['policy_target_group']['id']
        ptg2 = self.create_policy_target_group(name="ptg2")
        ptg2_id = ptg2['policy_target_group']['id']

        # Create policy_target.
        pt = self.create_policy_target(name="pt1",
                                       policy_target_group_id=ptg1_id)
        pt_id = pt['policy_target']['id']

        # Verify updating policy_target group rejected.
        data = {'policy_target': {'policy_target_group_id': ptg2_id}}
        req = self.new_update_request('policy_targets', data, pt_id)
        data = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('PolicyTargetGroupUpdateOfPolicyTargetNotSupported',
                         data['NeutronError']['type'])


class TestPolicyTargetGroup(ResourceMappingTestCase):

    def _test_implicit_subnet_lifecycle(self, shared=False):
        # Use explicit L2 policy so network and subnet not deleted
        # with policy_target group.
        l2p = self.create_l2_policy(shared=shared)
        l2p_id = l2p['l2_policy']['id']

        # Create policy_target group with implicit subnet.
        ptg = self.create_policy_target_group(name="ptg1", l2_policy_id=l2p_id,
                                         shared=shared)
        ptg_id = ptg['policy_target_group']['id']
        subnets = ptg['policy_target_group']['subnets']
        self.assertIsNotNone(subnets)
        self.assertEqual(len(subnets), 1)
        subnet_id = subnets[0]

        # TODO(rkukura): Verify implicit subnet belongs to L2 policy's
        # network, is within L3 policy's ip_pool, and was added as
        # router interface.

        # Verify deleting policy_target group cleans up subnet.
        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # TODO(rkukura): Verify implicit subnet was removed as router
        # interface.

    def test_implicit_subnet_lifecycle(self):
        self._test_implicit_subnet_lifecycle()

    def test_implicit_subnet_lifecycle_shared(self):
        self._test_implicit_subnet_lifecycle(True)

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

        # Create policy_target group with explicit subnet.
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet:
            subnet_id = subnet['subnet']['id']
            ptg = self.create_policy_target_group(
                name="ptg1", l2_policy_id=l2p_id, subnets=[subnet_id])
            ptg_id = ptg['policy_target_group']['id']
            subnets = ptg['policy_target_group']['subnets']
            self.assertIsNotNone(subnets)
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnet_id, subnets[0])

            # TODO(rkukura): Verify explicit subnet was added as
            # router interface.

            # Verify deleting policy_target group does not cleanup subnet.
            req = self.new_delete_request('policy_target_groups', ptg_id)
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

        # Create policy_target group with explicit subnet.
        with contextlib.nested(
                self.subnet(network=network, cidr='10.10.1.0/24'),
                self.subnet(network=network, cidr='10.10.2.0/24')
        ) as (subnet1, subnet2):
            subnet1_id = subnet1['subnet']['id']
            subnet2_id = subnet2['subnet']['id']
            subnets = [subnet1_id]
            ptg = self.create_policy_target_group(
                l2_policy_id=l2p_id, subnets=subnets)
            ptg_id = ptg['policy_target_group']['id']

            # Add subnet.
            subnets = [subnet1_id, subnet2_id]
            data = {'policy_target_group': {'subnets': subnets}}
            req = self.new_update_request('policy_target_groups', data, ptg_id)
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

        # Create policy_target group with explicit subnets.
        with contextlib.nested(
                self.subnet(network=network, cidr='10.10.1.0/24'),
                self.subnet(network=network, cidr='10.10.2.0/24')
        ) as (subnet1, subnet2):
            subnet1_id = subnet1['subnet']['id']
            subnet2_id = subnet2['subnet']['id']
            subnets = [subnet1_id, subnet2_id]
            ptg = self.create_policy_target_group(
                l2_policy_id=l2p_id, subnets=subnets)
            ptg_id = ptg['policy_target_group']['id']

            # Verify removing subnet rejected.
            data = {'policy_target_group': {'subnets': [subnet2_id]}}
            req = self.new_update_request('policy_target_groups', data, ptg_id)
            data = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual('PolicyTargetGroupSubnetRemovalNotSupported',
                             data['NeutronError']['type'])

    def test_subnet_allocation(self):
        ptg1 = self.create_policy_target_group(name="ptg1")
        subnets = ptg1['policy_target_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet1 = self.deserialize(self.fmt, req.get_response(self.api))

        ptg2 = self.create_policy_target_group(name="ptg2")
        subnets = ptg2['policy_target_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet2 = self.deserialize(self.fmt, req.get_response(self.api))

        self.assertNotEqual(subnet1['subnet']['cidr'],
                            subnet2['subnet']['cidr'])

    def test_no_extra_subnets_created(self):
        count = len(self._get_all_subnets())
        self.create_policy_target_group()
        self.create_policy_target_group()
        new_count = len(self._get_all_subnets())
        self.assertEqual(count + 2, new_count)

    def _get_all_subnets(self):
        req = self.new_list_request('subnets', fmt=self.fmt)
        return self.deserialize(self.fmt,
                                req.get_response(self.api))['subnets']

    def test_default_security_group_allows_intra_ptg(self):
        # Create PTG and retrieve subnet
        ptg = self.create_policy_target_group()['policy_target_group']
        subnets = ptg['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt,
                                  req.get_response(self.api))['subnet']
        #Create PT and retrieve port
        pt = self.create_policy_target(ptg['id'])['policy_target']
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        port = self.deserialize(self.fmt, req.get_response(self.api))['port']

        ip_v = {4: cst.IPv4, 6: cst.IPv6}

        # Verify Port's SG has all the right rules
        # Allow all ingress traffic from same ptg subnet
        filters = {'tenant_id': [ptg['tenant_id']],
                   'security_group_id': [port['security_groups'][0]],
                   'ethertype': [ip_v[subnet['ip_version']]],
                   'remote_ip_prefix': [subnet['cidr']],
                   'direction': ['ingress']}
        sg_rule = self._get_sg_rule(**filters)
        self.assertTrue(len(sg_rule) == 1)
        self.assertIsNone(sg_rule[0]['protocol'])
        self.assertIsNone(sg_rule[0]['port_range_max'])
        self.assertIsNone(sg_rule[0]['port_range_min'])

    def test_default_security_group_allows_intra_ptg_update(self):
        # Create ptg and retrieve subnet and network
        ptg = self.create_policy_target_group()['policy_target_group']
        subnets = ptg['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet1 = self.deserialize(self.fmt,
                                   req.get_response(self.api))['subnet']
        req = self.new_show_request('networks', subnet1['network_id'],
                                    fmt=self.fmt)
        network = self.deserialize(self.fmt,
                                   req.get_response(self.api))
        with self.subnet(network=network, cidr='9.8.7.0/5') as subnet2:
            # Add subnet
            subnet2 = subnet2['subnet']
            subnets = [subnet1['id'], subnet2['id']]
            data = {'policy_target_group': {'subnets': subnets}}
            req = self.new_update_request('policy_target_groups', data,
                                          ptg['id'])
            ptg = self.deserialize(
                self.fmt, req.get_response(
                    self.ext_api))['policy_target_group']
            #Create PT and retrieve port
            pt = self.create_policy_target(ptg['id'])['policy_target']
            req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
            port = self.deserialize(self.fmt,
                                    req.get_response(self.api))['port']
            ip_v = {4: cst.IPv4, 6: cst.IPv6}
            # Verify all the expected rules are set
            for subnet in [subnet1, subnet2]:
                filters = {'tenant_id': [ptg['tenant_id']],
                           'security_group_id': [port['security_groups'][0]],
                           'ethertype': [ip_v[subnet['ip_version']]],
                           'remote_ip_prefix': [subnet['cidr']],
                           'direction': ['ingress']}
                sg_rule = self._get_sg_rule(**filters)
                self.assertTrue(len(sg_rule) == 1)
                self.assertIsNone(sg_rule[0]['protocol'])
                self.assertIsNone(sg_rule[0]['port_range_max'])
                self.assertIsNone(sg_rule[0]['port_range_min'])

    def _get_sg_rule(self, **filters):
        plugin = manager.NeutronManager.get_plugin()
        context = nctx.get_admin_context()
        return plugin.get_security_group_rules(
            context, filters)

    def test_shared_ptg_create_negative(self):
        l2p = self.create_l2_policy(shared=True)
        l2p_id = l2p['l2_policy']['id']
        for shared in [True, False]:
            res = self.create_policy_target_group(
                name="ptg1", tenant_id='other', l2_policy_id=l2p_id,
                shared=shared, expected_res_status=400)

            self.assertEqual(
                'CrossTenantPolicyTargetGroupL2PolicyNotSupported',
                res['NeutronError']['type'])

    # TODO(rkukura): Test ip_pool exhaustion.


class TestL2Policy(ResourceMappingTestCase):

    def _test_implicit_network_lifecycle(self, shared=False):
        l3p = self.create_l3_policy(shared=shared)
        # Create L2 policy with implicit network.
        l2p = self.create_l2_policy(name="l2p1",
                                    l3_policy_id=l3p['l3_policy']['id'],
                                    shared=shared)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        self.assertIsNotNone(network_id)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(shared, res['network']['shared'])

        # Verify deleting L2 policy cleans up network.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def _test_explicit_network_lifecycle(self, shared=False):
        # Create L2 policy with explicit network.
        with self.network(shared=shared) as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(name="l2p1", network_id=network_id,
                                        shared=shared)
            l2p_id = l2p['l2_policy']['id']
            self.assertEqual(network_id, l2p['l2_policy']['network_id'])

            # Verify deleting L2 policy does not cleanup network.
            req = self.new_delete_request('l2_policies', l2p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            req = self.new_show_request('networks', network_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_implicit_network_lifecycle(self):
        self._test_implicit_network_lifecycle()

    def test_implicit_network_lifecycle_shared(self):
        self._test_implicit_network_lifecycle(True)

    def test_explicit_network_lifecycle(self):
        self._test_explicit_network_lifecycle()

    def test_explicit_network_lifecycle_shared(self):
        self._test_explicit_network_lifecycle(True)

    def test_shared_l2_policy_create_negative(self):
        l3p = self.create_l3_policy(shared=True)
        for shared in [True, False]:
            res = self.create_l2_policy(name="l2p1", tenant_id='other',
                                        l3_policy_id=l3p['l3_policy']['id'],
                                        shared=shared, expected_res_status=400)
            self.assertEqual('CrossTenantL2PolicyL3PolicyNotSupported',
                             res['NeutronError']['type'])

        with self.network() as network:
            network_id = network['network']['id']
            res = self.create_l2_policy(name="l2p1", network_id=network_id,
                                        shared=True, expected_res_status=400)
            self.assertEqual('NonSharedNetworkOnSharedL2PolicyNotSupported',
                             res['NeutronError']['type'])


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

    def test_overlapping_pools_per_tenant(self):
        # Verify overlaps are ok on different tenant
        ip_pool = '192.168.0.0/16'
        self.create_l3_policy(ip_pool=ip_pool, tenant_id='Tweedledum',
                              expected_res_status=201)
        self.create_l3_policy(ip_pool=ip_pool, tenant_id='Tweedledee',
                              expected_res_status=201)
        # Verify overlap fails on same tenant
        super_ip_pool = '192.160.0.0/8'
        sub_ip_pool = '192.168.10.0/24'
        for ip_pool in sub_ip_pool, super_ip_pool:
            res = self.create_l3_policy(
                ip_pool=ip_pool, tenant_id='Tweedledum',
                expected_res_status=400)
            self.assertEqual('OverlappingIPPoolsInSameTenantNotAllowed',
                             res['NeutronError']['type'])


class NotificationTest(ResourceMappingTestCase):

    def test_dhcp_notifier(self):
        with mock.patch.object(dhcp_rpc_agent_api.DhcpAgentNotifyAPI,
                               'notify') as dhcp_notifier:
            ptg = self.create_policy_target_group(name="ptg1")
            ptg_id = ptg['policy_target_group']['id']
            pt = self.create_policy_target(
                name="pt1", policy_target_group_id=ptg_id)
            self.assertEqual(
                pt['policy_target']['policy_target_group_id'], ptg_id)
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
            ptg = self.create_policy_target_group(name="ptg1")
            ptg_id = ptg['policy_target_group']['id']
            pt = self.create_policy_target(
                name="pt1", policy_target_group_id=ptg_id)
            self.assertEqual(
                pt['policy_target']['policy_target_group_id'], ptg_id)
            # REVISIT(rkukura): Check dictionaries for correct id, etc..
            nova_notifier.assert_any_call("create_router", {}, mock.ANY)
            nova_notifier.assert_any_call("create_network", {}, mock.ANY)
            nova_notifier.assert_any_call("create_subnet", {}, mock.ANY)
            nova_notifier.assert_any_call("create_port", {}, mock.ANY)


# TODO(ivar): We need a UT that verifies that the PT's ports have the default
# SG when there are no policy_rule_sets involved, that the default SG is
# properly # created and shared, and that it has the right content.
class TestPolicyRuleSet(ResourceMappingTestCase):

    def _get_sg(self, sg_id):
        plugin, context = self.get_plugin_context()
        return plugin.get_security_group(context, sg_id)

    def test_policy_rule_set_creation(self):
        # Create policy_rule_sets
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="out",
            port_range="50:100")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1")
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        ptg = self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={
                policy_rule_set_id: None})
        ptg_id = ptg['policy_target_group']['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)

        # verify SG bind to port
        port_id = pt['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

    # TODO(ivar): we also need to verify that those security groups have the
    # right rules
    def test_consumed_policy_rule_set(self):
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="in", port_range="20:90")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={policy_rule_set_id: None})
        consumed_ptg = self.create_policy_target_group(
            name="ptg2", consumed_policy_rule_sets={policy_rule_set_id: None})
        ptg_id = consumed_ptg['policy_target_group']['id']
        pt = self.create_policy_target(
            name="pt2", policy_target_group_id=ptg_id)

        # verify SG bind to port
        port_id = pt['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

    # Test update and delete of PTG, how it affects SG mapping
    def test_policy_target_group_update(self):
        # create two policy_rule_sets: bind one to an PTG, update with
        # adding another one (increase SG count on PT on PTG)
        classifier1 = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="bi", port_range="30:80")
        classifier2 = self.create_policy_classifier(
            name="class2", protocol="udp", direction="out", port_range="20:30")
        classifier1_id = classifier1['policy_classifier']['id']
        classifier2_id = classifier2['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule1 = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier1_id,
            policy_actions=action_id_list)
        policy_rule2 = self.create_policy_rule(
            name='pr2', policy_classifier_id=classifier2_id,
            policy_actions=action_id_list)
        policy_rule1_id = policy_rule1['policy_rule']['id']
        policy_rule1_list = [policy_rule1_id]
        policy_rule2_id = policy_rule2['policy_rule']['id']
        policy_rule2_list = [policy_rule2_id]
        policy_rule_set1 = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule1_list)
        policy_rule_set1_id = policy_rule_set1['policy_rule_set']['id']
        policy_rule_set2 = self.create_policy_rule_set(
            name="c2", policy_rules=policy_rule2_list)
        policy_rule_set2_id = policy_rule_set2['policy_rule_set']['id']
        ptg1 = self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={policy_rule_set1_id: None})
        ptg2 = self.create_policy_target_group(
            name="ptg2", consumed_policy_rule_sets={policy_rule_set1_id: None})
        ptg1_id = ptg1['policy_target_group']['id']
        ptg2_id = ptg2['policy_target_group']['id']

        # policy_target pt1 now with ptg2 consumes policy_rule_set1_id
        pt1 = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg2_id)
        # pt1's port should have 2 SG associated
        port_id = pt1['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 2)

        # now add a policy_rule_set to PTG
        # First we update policy_rule_set2 to be provided by consumed_ptg
        data = {'policy_target_group':
                {'provided_policy_rule_sets': {policy_rule_set2_id: None}}}
        req = self.new_update_request('policy_target_groups', data, ptg2_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        # set ptg1 to provide policy_rule_set1 and consume policy_rule_set2
        # policy_rule_set2 now maps to SG which has ptg2's subnet as CIDR on
        # rules
        data = {'policy_target_group':
                {'consumed_policy_rule_sets': {policy_rule_set2_id: None}}}
        req = self.new_update_request('policy_target_groups', data, ptg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        port_id = pt1['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(len(security_groups), 3)

    # Test update of policy rules
    def test_policy_rule_update(self):
        classifier1 = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="bi", port_range="50:100")
        classifier2 = self.create_policy_classifier(
            name="class2", protocol="udp", direction="out",
            port_range="30:100")
        classifier1_id = classifier1['policy_classifier']['id']
        classifier2_id = classifier2['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier1_id,
            policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        ptg = self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={policy_rule_set_id: None})
        ptg_id = ptg['policy_target_group']['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)

        # now updates the policy rule with new classifier
        data = {'policy_rule':
                {'policy_classifier_id': classifier2_id}}
        req = self.new_update_request('policy_rules', data, policy_rule_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        port_id = pt['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port']['security_groups']
        udp_rules = []
        for sgid in security_groups:
            sg = self._get_sg(sgid)
            sg_rules = sg['security_group_rules']
            udp_rules.extend([r for r in sg_rules if r['protocol'] == 'udp'])

        self.assertEqual(len(udp_rules), 1)
        udp_rule = udp_rules[0]
        self.assertEqual(udp_rule['port_range_min'], 30)
        self.assertEqual(udp_rule['port_range_max'], 100)

    # Test update of policy classifier
    def test_policy_classifier_update(self):
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="bi", port_range="30:100")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        ptg = self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={policy_rule_set_id: None})
        ptg_id = ptg['policy_target_group']['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)

        # now updates the policy classifier with new protocol field
        data = {'policy_classifier':
                {'protocol': 'udp', 'port_range': '50:150'}}
        req = self.new_update_request('policy_classifiers', data,
            classifier_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)
        port_id = pt['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port']['security_groups']
        udp_rules = []
        for sgid in security_groups:
            sg = self._get_sg(sgid)
            sg_rules = sg['security_group_rules']
            udp_rules.extend([r for r in sg_rules if r['protocol'] == 'udp'])

        self.assertEqual(len(udp_rules), 1)
        udp_rule = udp_rules[0]
        self.assertEqual(udp_rule['port_range_min'], 50)
        self.assertEqual(udp_rule['port_range_max'], 150)

    def test_redirect_to_chain(self):
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="in", port_range="20:90")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(
            name="action1", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=uuidutils.generate_uuid())
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=action_id_list)
        policy_rule_id = policy_rule['policy_rule']['id']
        policy_rule_list = [policy_rule_id]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets={policy_rule_set_id: None})
        create_chain_instance = mock.patch.object(
            servicechain_plugin.ServiceChainPlugin,
            'create_servicechain_instance')
        create_chain_instance = create_chain_instance.start()
        chain_instance_id = uuidutils.generate_uuid()
        create_chain_instance.return_value = {'id': chain_instance_id}
        # TODO(Magesh):Add tests which verifies that provide/consumer PTGs
        # are set correctly for the SCI
        with mock.patch.object(
                resource_mapping.ResourceMappingDriver,
                '_set_rule_servicechain_instance_mapping') as set_rule:
            with mock.patch.object(servicechain_db.ServiceChainDbPlugin,
                                   'get_servicechain_spec') as sc_spec_get:
                sc_spec_get.return_value = {'servicechain_spec': {}}
                consumer_ptg = self.create_policy_target_group(
                    name="ptg2",
                    consumed_policy_rule_sets={policy_rule_set_id: None})
                consumer_ptg_id = consumer_ptg['policy_target_group']['id']
                set_rule.assert_called_once_with(mock.ANY, policy_rule_id,
                                                 chain_instance_id)
        with mock.patch.object(servicechain_plugin.ServiceChainPlugin,
                               'delete_servicechain_instance'):
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
                    "servicechain_instance": {'id': chain_instance_id}}
                req = self.new_delete_request(
                    'policy_target_groups', consumer_ptg_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_shared_policy_rule_set_create_negative(self):
        self.create_policy_rule_set(shared=True, expected_res_status=400)


class TestPolicyAction(ResourceMappingTestCase):

    def test_shared_create_reject_non_shared_spec(self):
        with mock.patch.object(servicechain_db.ServiceChainDbPlugin,
                               'get_servicechain_specs') as sc_spec_get:
            uuid = uuidutils.generate_uuid()
            sc_spec_get.return_value = [{'id': uuid}]
            res = self.create_policy_action(expected_res_status=400,
                                            shared=True,
                                            action_value=uuid)
            self.assertEqual('InvalidSharedResource',
                             res['NeutronError']['type'])