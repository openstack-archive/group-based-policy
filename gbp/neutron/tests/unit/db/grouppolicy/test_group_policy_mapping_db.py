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
import webob.exc

from neutron.tests.unit import test_l3_plugin

from gbp.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbp.neutron.tests.unit.db.grouppolicy import test_group_policy_db as tgpdb


class GroupPolicyMappingDBTestPlugin(gpmdb.GroupPolicyMappingDbPlugin):

    supported_extension_aliases = ['group-policy', 'group-policy-mapping']


DB_GP_PLUGIN_KLASS = (GroupPolicyMappingDBTestPlugin.__module__ + '.' +
                      GroupPolicyMappingDBTestPlugin.__name__)


class GroupPolicyMappingDbTestCase(tgpdb.GroupPolicyDbTestCase,
                                   test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self, core_plugin=None, gp_plugin=None, service_plugins=None):
        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        if not service_plugins:
            service_plugins = {'l3_plugin_name': "router",
                               'gp_plugin_name': gp_plugin}
        super(GroupPolicyMappingDbTestCase, self).setUp(
            core_plugin=core_plugin, gp_plugin=gp_plugin,
            service_plugins=service_plugins
        )

    def _get_test_endpoint_attrs(self, name='ep1', description='test ep',
                                 endpoint_group_id=None, port_id=None):
        attrs = (super(GroupPolicyMappingDbTestCase, self).
                 _get_test_endpoint_attrs(name, description,
                                          endpoint_group_id))
        attrs.update({'port_id': port_id})
        return attrs

    def _get_test_endpoint_group_attrs(self, name='epg1',
                                       description='test epg',
                                       l2_policy_id=None,
                                       provided_contracts=None,
                                       consumed_contracts=None, subnets=None):
        attrs = (super(GroupPolicyMappingDbTestCase, self).
                 _get_test_endpoint_group_attrs(name, description,
                                                l2_policy_id,
                                                provided_contracts,
                                                consumed_contracts))
        attrs.update({'subnets': subnets or []})
        return attrs

    def _get_test_l2_policy_attrs(self, name='l2p1',
                                  description='test l2_policy',
                                  l3_policy_id=None, network_id=None):
        attrs = (super(GroupPolicyMappingDbTestCase, self).
                 _get_test_l2_policy_attrs(name, description, l3_policy_id))
        attrs.update({'network_id': network_id})
        return attrs

    def _get_test_l3_policy_attrs(self, name='l3p1',
                                  description='test l3_policy',
                                  ip_version=4, ip_pool='10.0.0.0/8',
                                  subnet_prefix_length=24, routers=None):
        attrs = (super(GroupPolicyMappingDbTestCase, self).
                 _get_test_l3_policy_attrs(name, description, ip_version,
                                           ip_pool, subnet_prefix_length))
        attrs.update({'routers': routers or []})
        return attrs


class TestMappedGroupResources(GroupPolicyMappingDbTestCase,
                               tgpdb.TestGroupResources):
    pass


class TestMappedGroupResourceAttrs(GroupPolicyMappingDbTestCase):

    def test_create_delete_endpoint_with_port(self):
        with self.port() as port:
            port_id = port['port']['id']
            ep = self.create_endpoint(port_id=port_id)
            ep_id = ep['endpoint']['id']
            self.assertEqual(port_id, ep['endpoint']['port_id'])
            req = self.new_show_request('endpoints', ep_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(port_id, res['endpoint']['port_id'])
            req = self.new_delete_request('endpoints', ep_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_create_delete_endpoint_group_with_subnets(self):
        with contextlib.nested(self.subnet(cidr='10.10.1.0/24'),
                               self.subnet(cidr='10.10.2.0/24')) as (
                                   subnet1, subnet2):
            subnets = [subnet1['subnet']['id'], subnet2['subnet']['id']]
            epg = self.create_endpoint_group(subnets=subnets)
            epg_id = epg['endpoint_group']['id']
            self.assertEqual(sorted(subnets),
                             sorted(epg['endpoint_group']['subnets']))
            req = self.new_show_request('endpoint_groups', epg_id,
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(subnets),
                             sorted(res['endpoint_group']['subnets']))
            req = self.new_delete_request('endpoint_groups', epg_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_update_endpoint_group_subnets(self):
        with contextlib.nested(self.subnet(cidr='10.10.1.0/24'),
                               self.subnet(cidr='10.10.2.0/24'),
                               self.subnet(cidr='10.10.3.0/24')) as (
                                   subnet1, subnet2, subnet3):
            orig_subnets = [subnet1['subnet']['id'], subnet2['subnet']['id']]
            epg = self.create_endpoint_group(subnets=orig_subnets)
            epg_id = epg['endpoint_group']['id']
            self.assertEqual(sorted(orig_subnets),
                             sorted(epg['endpoint_group']['subnets']))
            new_subnets = [subnet1['subnet']['id'], subnet3['subnet']['id']]
            data = {'endpoint_group': {'subnets': new_subnets}}
            req = self.new_update_request('endpoint_groups', data, epg_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(new_subnets),
                             sorted(res['endpoint_group']['subnets']))
            req = self.new_show_request('endpoint_groups', epg_id,
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(new_subnets),
                             sorted(res['endpoint_group']['subnets']))
            # REVISIT(rkukura): Remove delete once subnet() context
            # manager is replaced with a function that does not delete
            # the resource(s) that are created.
            req = self.new_delete_request('endpoint_groups', epg_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

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
        with contextlib.nested(self.router(), self.router()) as (router1,
                                                                 router2):
            routers = [router1['router']['id'], router2['router']['id']]
            l3p = self.create_l3_policy(routers=routers)
            l3p_id = l3p['l3_policy']['id']
            self.assertEqual(sorted(routers),
                             sorted(l3p['l3_policy']['routers']))
            req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(routers),
                             sorted(res['l3_policy']['routers']))
            req = self.new_delete_request('l3_policies', l3p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_update_l3_policy_routers(self):
        with contextlib.nested(self.router(), self.router(),
                               self.router()) as (router1, router2, router3):
            orig_routers = [router1['router']['id'], router2['router']['id']]
            l3p = self.create_l3_policy(routers=orig_routers)
            l3p_id = l3p['l3_policy']['id']
            self.assertEqual(sorted(orig_routers),
                             sorted(l3p['l3_policy']['routers']))
            new_routers = [router1['router']['id'], router3['router']['id']]
            data = {'l3_policy': {'routers': new_routers}}
            req = self.new_update_request('l3_policies', data, l3p_id)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(new_routers),
                             sorted(res['l3_policy']['routers']))
            req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(sorted(new_routers),
                             sorted(res['l3_policy']['routers']))
            # REVISIT(rkukura): Remove delete once router() context
            # manager is replaced with a function that does not delete
            # the resource(s) that are created.
            req = self.new_delete_request('l3_policies', l3p_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
