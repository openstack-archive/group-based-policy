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

import webob.exc

from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbpservice.neutron.tests.unit.db.grouppolicy import (
    test_group_policy_db as tgpdb)


class GroupPolicyMappingDBTestPlugin(gpmdb.GroupPolicyMappingDbPlugin):

    supported_extension_aliases = ['group-policy', 'group-policy-mapping']


DB_GP_PLUGIN_KLASS = (GroupPolicyMappingDBTestPlugin.__module__ + '.' +
                      GroupPolicyMappingDBTestPlugin.__name__)

SC_PLUGIN_KLASS = (
    "gbpservice.neutron.services.servicechain.plugins.msc.plugin."
    "ServiceChainPlugin")


class GroupPolicyMappingDbTestCase(tgpdb.GroupPolicyDbTestCase,
                                   test_l3.L3NatTestCaseMixin):

    def setUp(self, core_plugin=None, gp_plugin=None, service_plugins=None):
        testlib_api.SqlTestCase._TABLES_ESTABLISHED = False
        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        if not service_plugins:
            service_plugins = {'l3_plugin_name': "router",
                               'gp_plugin_name': gp_plugin,
                               'servicechain_plugin': SC_PLUGIN_KLASS}
        super(GroupPolicyMappingDbTestCase, self).setUp(
            core_plugin=core_plugin, gp_plugin=gp_plugin,
            service_plugins=service_plugins
        )


class TestMappedGroupResources(GroupPolicyMappingDbTestCase,
                               tgpdb.TestGroupResources):
    pass


class TestMappedGroupResourceAttrs(GroupPolicyMappingDbTestCase):

    def test_create_delete_policy_target_with_port(self):
        with self.port() as port:
            port_id = port['port']['id']
            pt = self.create_policy_target(port_id=port_id)
            pt_id = pt['policy_target']['id']
            self.assertEqual(port_id, pt['policy_target']['port_id'])
            req = self.new_show_request('policy_targets', pt_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(port_id, res['policy_target']['port_id'])
            req = self.new_delete_request('policy_targets', pt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_create_delete_policy_target_group_with_subnets(self):
        with self.subnet(cidr='10.10.1.0/24') as subnet1:
            with self.subnet(cidr='10.10.2.0/24') as subnet2:
                subnets = [subnet1['subnet']['id'], subnet2['subnet']['id']]
                ptg = self.create_policy_target_group(subnets=subnets)
                ptg_id = ptg['policy_target_group']['id']
                self.assertEqual(sorted(subnets),
                                 sorted(ptg['policy_target_group']['subnets']))
                req = self.new_show_request('policy_target_groups', ptg_id,
                                            fmt=self.fmt)
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api))
                self.assertEqual(sorted(subnets),
                                 sorted(res['policy_target_group']['subnets']))
                req = self.new_delete_request('policy_target_groups', ptg_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_update_policy_target_group_subnets(self):
        with self.subnet(cidr='10.10.1.0/24') as subnet1:
            with self.subnet(cidr='10.10.2.0/24') as subnet2:
                with self.subnet(cidr='10.10.3.0/24') as subnet3:
                    orig_subnets = [subnet1['subnet']['id'],
                                    subnet2['subnet']['id']]
                    ptg = self.create_policy_target_group(subnets=orig_subnets)
                    ptg_id = ptg['policy_target_group']['id']
                    self.assertEqual(
                        sorted(orig_subnets),
                        sorted(ptg['policy_target_group']['subnets']))
                    new_subnets = [subnet1['subnet']['id'],
                                   subnet3['subnet']['id']]
                    data = {'policy_target_group': {'subnets': new_subnets}}
                    req = self.new_update_request('policy_target_groups', data,
                                                  ptg_id)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    self.assertEqual(
                        sorted(new_subnets),
                        sorted(res['policy_target_group']['subnets']))
                    req = self.new_show_request('policy_target_groups', ptg_id,
                                                fmt=self.fmt)
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api))
                    self.assertEqual(
                        sorted(new_subnets),
                        sorted(res['policy_target_group']['subnets']))
                    # REVISIT(rkukura): Remove delete once subnet() context
                    # manager is replaced with a function that does not delete
                    # the resource(s) that are created.
                    req = self.new_delete_request('policy_target_groups',
                                                  ptg_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(
                        res.status_int, webob.exc.HTTPNoContent.code)

    def test_create_delete_l2_policy_with_network(self):
        with self.network() as network:
            network_id = network['network']['id']
            l2p = self.create_l2_policy(network_id=network_id)
            l2p_id = l2p['l2_policy']['id']
            self.assertEqual(network_id, l2p['l2_policy']['network_id'])
            req = self.new_show_request('l2_policies', l2p_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(network_id, res['l2_policy']['network_id'])
            req = self.new_delete_request('l2_policies', l2p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_create_delete_l3_policy_with_routers(self):
        with self.router() as router1:
            with self.router() as router2:
                routers = [router1['router']['id'], router2['router']['id']]
                l3p = self.create_l3_policy(routers=routers)
                l3p_id = l3p['l3_policy']['id']
                self.assertEqual(sorted(routers),
                                 sorted(l3p['l3_policy']['routers']))
                req = self.new_show_request('l3_policies', l3p_id,
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(sorted(routers),
                                 sorted(res['l3_policy']['routers']))
                req = self.new_delete_request('l3_policies', l3p_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_update_l3_policy_routers(self):
        with self.router() as router1:
            with self.router() as router2:
                with self.router() as router3:
                    orig_routers = [router1['router']['id'],
                                    router2['router']['id']]
                    l3p = self.create_l3_policy(routers=orig_routers)
                    l3p_id = l3p['l3_policy']['id']
                    self.assertEqual(sorted(orig_routers),
                                     sorted(l3p['l3_policy']['routers']))
                    new_routers = [router1['router']['id'],
                                   router3['router']['id']]
                    data = {'l3_policy': {'routers': new_routers}}
                    req = self.new_update_request('l3_policies', data, l3p_id)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    self.assertEqual(sorted(new_routers),
                                     sorted(res['l3_policy']['routers']))
                    req = self.new_show_request('l3_policies',
                                                l3p_id, fmt=self.fmt)
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api))
                    self.assertEqual(sorted(new_routers),
                                     sorted(res['l3_policy']['routers']))
                    # REVISIT(rkukura): Remove delete once router() context
                    # manager is replaced with a function that does not delete
                    # the resource(s) that are created.
                    req = self.new_delete_request('l3_policies', l3p_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPNoContent.code)

    def test_create_delete_es_with_subnet(self):
        with self.subnet(cidr='10.10.1.0/24') as subnet:
            subnet_id = subnet['subnet']['id']
            es = self.create_external_segment(subnet_id=subnet_id,
                                              expected_res_status=201)
            self.assertEqual(subnet_id, es['external_segment']['subnet_id'])
            es_id = es['external_segment']['id']
            req = self.new_show_request('external_segments', es_id,
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(subnet_id, res['external_segment']['subnet_id'])
            req = self.new_delete_request('external_segments', es_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_list_policy_targets(self):
        with self.port() as port1:
            with self.port() as port2:
                ports = [port1['port']['id'], port2['port']['id']]
                pts = [self.create_policy_target(port_id=ports[0]),
                       self.create_policy_target(port_id=ports[1])]
                self._test_list_resources('policy_target', [pts[0]],
                                          query_params='port_id=' + ports[0])

    def test_list_l2_policies(self):
        with self.network() as network1:
            with self.network() as network2:
                networks = [network1['network']['id'],
                            network2['network']['id']]
                l2_policies = [self.create_l2_policy(network_id=networks[0]),
                               self.create_l2_policy(network_id=networks[1])]
                self._test_list_resources(
                                'l2_policy', [l2_policies[0]],
                                query_params='network_id=' + networks[0])

    def test_list_es(self):
        with self.subnet(cidr='10.10.1.0/24') as subnet1:
            with self.subnet(cidr='10.10.2.0/24') as subnet2:
                subnets = [subnet1['subnet']['id'], subnet2['subnet']['id']]
                external_segments = [
                            self.create_external_segment(subnet_id=subnets[0]),
                            self.create_external_segment(subnet_id=subnets[1])]
                self._test_list_resources(
                            'external_segment', [external_segments[0]],
                            query_params='subnet_id=' + subnets[0])
