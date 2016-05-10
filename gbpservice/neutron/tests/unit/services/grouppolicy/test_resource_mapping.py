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

import copy
import itertools

from keystonemiddleware import auth_token  # noqa
import mock
import netaddr
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as cst
from neutron import context as nctx
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.extensions import external_net as external_net
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.plugins.common import constants as pconst
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup
from neutron.tests.unit.plugins.ml2 import test_plugin as n_test_plugin
from oslo_utils import uuidutils
import webob.exc

from gbpservice.common import utils
from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db import servicechain_db
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers import chain_mapping
from gbpservice.neutron.services.grouppolicy.drivers import nsp_manager
from gbpservice.neutron.services.grouppolicy.drivers import resource_mapping
from gbpservice.neutron.services.servicechain.plugins.msc import (
    config as sc_cfg)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_plugin)


SERVICE_PROFILES = 'servicechain/service_profiles'
SERVICECHAIN_NODES = 'servicechain/servicechain_nodes'
SERVICECHAIN_SPECS = 'servicechain/servicechain_specs'
SERVICECHAIN_INSTANCES = 'servicechain/servicechain_instances'
CHAIN_TENANT_ID = 'chain_owner'


class NoL3NatSGTestPlugin(
        test_l3.TestNoL3NatPlugin,
        test_securitygroup.SecurityGroupTestPlugin):

    _supported_extension_aliases = ["external-net", "security-group"]


CORE_PLUGIN = ('gbpservice.neutron.tests.unit.services.grouppolicy.'
               'test_resource_mapping.NoL3NatSGTestPlugin')


class ResourceMappingTestCase(test_plugin.GroupPolicyPluginTestCase):

    def setUp(self, policy_drivers=None,
              core_plugin=n_test_plugin.PLUGIN_NAME, ml2_options=None,
              sc_plugin=None):
        policy_drivers = policy_drivers or ['implicit_policy',
                                            'resource_mapping',
                                            'chain_mapping']
        config.cfg.CONF.set_override('policy_drivers',
                                     policy_drivers,
                                     group='group_policy')
        sc_cfg.cfg.CONF.set_override('servicechain_drivers',
                                     ['dummy'], group='servicechain')
        config.cfg.CONF.set_override('allow_overlapping_ips', True)
        super(ResourceMappingTestCase, self).setUp(core_plugin=core_plugin,
                                                   ml2_options=ml2_options,
                                                   sc_plugin=sc_plugin)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)
        res = mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                         '_check_router_needs_rescheduling').start()
        res.return_value = None
        self._plugin = manager.NeutronManager.get_plugin()
        self._plugin.remove_networks_from_down_agents = mock.Mock()
        self._plugin.is_agent_down = mock.Mock(return_value=False)
        self._context = nctx.get_admin_context()
        plugins = manager.NeutronManager.get_service_plugins()
        self._gbp_plugin = plugins.get(pconst.GROUP_POLICY)
        self._l3_plugin = plugins.get(pconst.L3_ROUTER_NAT)

    def get_plugin_context(self):
        return self._plugin, self._context

    def _create_provider_consumer_ptgs(self, prs_id=None):
        policy_rule_set_dict = {prs_id: None} if prs_id else {}
        provider_ptg = self.create_policy_target_group(
            name="ptg1", provided_policy_rule_sets=policy_rule_set_dict)
        provider_ptg_id = provider_ptg['policy_target_group']['id']
        consumer_ptg = self.create_policy_target_group(
            name="ptg2",
            consumed_policy_rule_sets=policy_rule_set_dict)
        consumer_ptg_id = consumer_ptg['policy_target_group']['id']
        return (provider_ptg_id, consumer_ptg_id)

    def _assert_proper_chain_instance(self, sc_instance, provider_ptg_id,
                                      consumer_ptg_id, scs_id_list,
                                      classifier_id=None):
        self.assertEqual(sc_instance['provider_ptg_id'], provider_ptg_id)
        self.assertEqual(sc_instance['consumer_ptg_id'], 'N/A')
        self.assertEqual(scs_id_list, sc_instance['servicechain_specs'])
        if classifier_id:
            self.assertEqual(sc_instance['classifier_id'], classifier_id)

    def _verify_ptg_delete_cleanup_chain(self, ptg_id):
        self.delete_policy_target_group(
            ptg_id, expected_res_status=webob.exc.HTTPNoContent.code)
        sc_instance_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_instance_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def _verify_ptg_prs_unset_cleansup_chain(self, ptg_id, prs_ids):
        self.update_policy_target_group(
                            ptg_id,
                            provided_policy_rule_sets={},
                            consumed_policy_rule_sets={},
                            expected_res_status=200)
        for prs_id in prs_ids:
            self._verify_prs_rules(prs_id)
        sc_instance_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_instance_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

    def _create_network(self, fmt, name, admin_state_up, **kwargs):
        """Override the routine for allowing the router:external attribute."""
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = new_args.pop('arg_list', ()) + (external_net.EXTERNAL,)
        return super(ResourceMappingTestCase, self)._create_network(
            fmt, name, admin_state_up, arg_list=arg_list, **new_args)

    def _show_subnet(self, id):
        req = self.new_show_request('subnets', id, fmt=self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def _get_sg_rule(self, **filters):
        plugin = manager.NeutronManager.get_plugin()
        context = nctx.get_admin_context()
        return plugin.get_security_group_rules(
            context, filters)

    def _get_prs_mapping(self, prs_id):
        ctx = nctx.get_admin_context()
        return (resource_mapping.ResourceMappingDriver.
                _get_policy_rule_set_sg_mapping(ctx.session, prs_id))

    def _create_ssh_allow_rule(self):
        return self._create_tcp_allow_rule('22')

    def _create_http_allow_rule(self):
        return self._create_tcp_allow_rule('80')

    def _create_tcp_allow_rule(self, port_range):
        action = self.create_policy_action(
            action_type='allow')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range=port_range,
            direction='bi')['policy_classifier']
        return self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action['id']])['policy_rule']

    def _create_tcp_redirect_rule(self, port_range, servicechain_spec_id):
        action = self.create_policy_action(
            action_type='redirect',
            action_value=servicechain_spec_id)['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range=port_range,
            direction='bi')['policy_classifier']
        policy_rule = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action['id']])['policy_rule']
        return (action['id'], classifier['id'], policy_rule['id'])

    def _calculate_expected_external_cidrs(self, es, l3p_list):
        external_ipset = netaddr.IPSet([x['destination']
                                        for x in es['external_routes']])
        if l3p_list:
            result = external_ipset - netaddr.IPSet([x['ip_pool']
                                                     for x in l3p_list])
        else:
            result = external_ipset

        return set(str(x) for x in result.iter_cidrs())

    def _get_cidrs_from_ptgs(self, ptgs):
        subnet_ids = []
        for ptg in ptgs:
            subnet_ids += self.show_policy_target_group(
                ptg)['policy_target_group']['subnets']
        cidrs = set()
        for sid in subnet_ids:
            req = self.new_show_request('subnets', sid, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.api))
            cidrs.add(res['subnet']['cidr'])
        return cidrs

    def _get_cidrs_from_ep(self, eps, l3ps):
        es_ids = []
        for ep in eps:
            es_ids += self.show_external_policy(
                ep)['external_policy']['external_segments']
        cidrs = set()
        for es_id in es_ids:
            cidrs |= self._calculate_expected_external_cidrs(
                self.show_external_segment(es_id)['external_segment'], l3ps)
        return cidrs

    def _get_tenant_l3ps(self, ptg):
        res = self._list('l3_policies',
                         query_params='tenant_id=' + ptg['tenant_id'])
        return res['l3_policies']

    def _get_prs_enforced_rules(self, prs):
        # Filter with parent if needed
        if prs['parent_id']:
            parent = self.show_policy_rule_set(
                prs['parent_id'])['policy_rule_set']
            parent_policy_rules = [self.show_policy_rule(
                                    policy_rule_id)['policy_rule'] for
                                   policy_rule_id in parent["policy_rules"]]
            subset_rules = [self.show_policy_rule(
                            policy_rule_id)['policy_rule'] for
                            policy_rule_id in prs['policy_rules']]

            parent_classifier_ids = [x['policy_classifier_id']
                                     for x in parent_policy_rules]
            policy_rules = [x['id'] for x in subset_rules
                            if x['policy_classifier_id']
                            in set(parent_classifier_ids)]
            return [self.show_policy_rule(
                    policy_rule_id)['policy_rule'] for
                    policy_rule_id in policy_rules]
        else:
            return [self.show_policy_rule(x)['policy_rule']
                    for x in prs['policy_rules']]

    def _generate_expected_sg_rules(self, prs):
        """Returns a list of expected provider sg rules given a PTG."""
        # Get all the needed cidrs:
        prs = self._gbp_plugin.get_policy_rule_set(self._context, prs)

        providing_ptg_cidrs = self._get_cidrs_from_ptgs(
            prs['providing_policy_target_groups'])
        if len(prs['providing_policy_target_groups']):
            self.assertTrue(len(providing_ptg_cidrs))

        consuming_ptg_cidrs = self._get_cidrs_from_ptgs(
            prs['consuming_policy_target_groups'])
        if len(prs['consuming_policy_target_groups']):
            self.assertTrue(len(consuming_ptg_cidrs))

        l3p_cidrs = self._get_tenant_l3ps(prs)

        providing_ep_cidrs = self._get_cidrs_from_ep(
            prs['providing_external_policies'], l3p_cidrs)

        consuming_ep_cidrs = self._get_cidrs_from_ep(
            prs['consuming_external_policies'], l3p_cidrs)

        consumers = consuming_ep_cidrs | consuming_ptg_cidrs
        providers = providing_ptg_cidrs | providing_ep_cidrs

        mapping = self._get_prs_mapping(prs['id'])
        provided_sg = mapping.provided_sg_id
        consumed_sg = mapping.consumed_sg_id
        # IN: from consumer to provider
        # OUT: from provider to consumer
        # Egress rules are always generic (to 0.0.0.0/0)
        # Igress rules are filtered by subnet
        # Only allow rules are verified
        prules = self._get_prs_enforced_rules(prs)
        expected_rules = []
        in_bi = [gconst.GP_DIRECTION_IN, gconst.GP_DIRECTION_BI]
        out_bi = [gconst.GP_DIRECTION_OUT, gconst.GP_DIRECTION_BI]
        # Redirect action is treated as implicit allow
        allow_action_types = [gconst.GP_ACTION_ALLOW,
                              gconst.GP_ACTION_REDIRECT]
        for pr in prules:
            if any(self.show_policy_action(x)['policy_action']['action_type']
                   in allow_action_types for x in pr['policy_actions']):
                classifier = self.show_policy_classifier(
                    pr['policy_classifier_id'])['policy_classifier']
                protocol = classifier['protocol']
                if classifier['port_range']:
                    port_min, port_max = (
                        gpdb.GroupPolicyDbPlugin._get_min_max_ports_from_range(
                            classifier['port_range']))
                else:
                    port_min, port_max = None, None
                if classifier['direction'] in in_bi:
                    # If direction IN/BI, consumer cidrs go into provider SG
                    for cidr in consumers:
                        attrs = {'security_group_id': [provided_sg],
                                 'direction': ['ingress'],
                                 'protocol': [protocol],
                                 'remote_ip_prefix': [cidr]}
                        if port_min is not None:
                            attrs['port_range_min'] = [port_min]
                        if port_max is not None:
                            attrs['port_range_max'] = [port_max]
                        expected_rules.append(attrs)
                    # And consumer SG have egress allowed
                    for cidr in providers:
                        attrs = {'security_group_id': [consumed_sg],
                                 'direction': ['egress'],
                                 'protocol': [protocol],
                                 'remote_ip_prefix': [cidr]}
                        if port_min is not None:
                            attrs['port_range_min'] = [port_min]
                        if port_max is not None:
                            attrs['port_range_max'] = [port_max]
                        expected_rules.append(attrs)
                if classifier['direction'] in out_bi:
                    # If direction OUT/BI, provider CIDRs go into consumer SG
                    for cidr in providers:
                        attrs = {'security_group_id': [consumed_sg],
                                 'direction': ['ingress'],
                                 'protocol': [protocol],
                                 'remote_ip_prefix': [cidr]}
                        if port_min is not None:
                            attrs['port_range_min'] = [port_min]
                        if port_max is not None:
                            attrs['port_range_max'] = [port_max]
                        expected_rules.append(attrs)
                    # And provider SG have egress allowed
                    for cidr in consumers:
                        attrs = {'security_group_id': [provided_sg],
                                 'direction': ['egress'],
                                 'protocol': [protocol],
                                 'remote_ip_prefix': [cidr]}
                        if port_min is not None:
                            attrs['port_range_min'] = [port_min]
                        if port_max is not None:
                            attrs['port_range_max'] = [port_max]
                        expected_rules.append(attrs)
        return expected_rules

    def _verify_prs_rules(self, prs):
        # Refresh prs
        mapping = self._get_prs_mapping(prs)
        existing = [
            x for x in self._get_sg_rule(
                security_group_id=[mapping.provided_sg_id,
                                   mapping.consumed_sg_id])]
        existing_copy = copy.deepcopy(existing)
        expected = self._generate_expected_sg_rules(prs)
        for rule in expected:
            # Verify the rule exists
            r = self._get_sg_rule(**rule)
            self.assertTrue(len(r) == 1,
                            "Rule not found, expected:\n%s\n\nfound:%s\n"
                            "Missing:%s\n" % (expected, existing_copy, rule))
            existing.remove(r[0])
        self.assertTrue(len(existing) == 0,
                        "Unexpected additional rules are configured:\n%s"
                        % str(existing))
        return expected

    def _get_nsp_ptg_fip_mapping(self, ptg_id):
        ctx = nctx.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            return (ctx.session.query(
                        nsp_manager.ServicePolicyPTGFipMapping).
                    filter_by(policy_target_group_id=ptg_id).
                    all())

    def _create_service_profile(self, node_type='LOADBALANCER', shared=False):
        data = {'service_type': node_type, 'shared': shared}
        profile = self.create_service_profile(expected_res_status=201,
                                              is_admin_context=shared,
                                              **data)
        scp_id = profile['service_profile']['id']
        return scp_id

    def _create_servicechain_node(self, node_type="LOADBALANCER",
                                  shared=False):
        profile_id = self._create_service_profile(node_type, shared=shared)
        data = {'service_profile_id': profile_id,
                'config': "{}", 'shared': shared}
        node = self.create_servicechain_node(expected_res_status=201,
                                             is_admin_context=shared,
                                             **data)
        scn_id = node['servicechain_node']['id']
        return scn_id

    def _create_servicechain_spec(self, node_types=None, shared=False):
        node_types = node_types or ['LOADBALANCER']
        node_ids = []
        for node_type in node_types:
            node_ids.append(self._create_servicechain_node(
                node_type, shared=shared))
        data = {'nodes': node_ids, 'shared': shared}
        spec = self.create_servicechain_spec(expected_res_status=201,
                                             is_admin_context=shared,
                                             **data)
        scs_id = spec['servicechain_spec']['id']
        return scs_id


class TestClusterIdMixin(object):

    def test_cluster_invalid_id(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        res = self.create_policy_target(policy_target_group_id=ptg_id,
                                        cluster_id='SomeInvalidCluster',
                                        expected_res_status=400)
        self.assertEqual('InvalidClusterId',
                         res['NeutronError']['type'])

    def test_invalid_cluster_head_deletion(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_id)['policy_target']
        self.create_policy_target(
            policy_target_group_id=ptg_id, cluster_id=master['id'],
            expected_res_status=201)
        res = self.delete_policy_target(master['id'],
                                        expected_res_status=400)
        self.assertEqual('PolicyTargetInUse',
                         res['NeutronError']['type'])

    def test_cluster_invalid_ptg(self):
        ptg_1 = self.create_policy_target_group()['policy_target_group']['id']
        ptg_2 = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_1)['policy_target']
        # Cluster member belonging to a different PTG.
        res = self.create_policy_target(
            policy_target_group_id=ptg_2, cluster_id=master['id'],
            expected_res_status=400)
        self.assertEqual('InvalidClusterPtg',
                         res['NeutronError']['type'])

    def test_cluster_self_deletion(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_id)['policy_target']
        member = self.create_policy_target(
            policy_target_group_id=ptg_id, cluster_id=master['id'],
            expected_res_status=201)['policy_target']
        # Use self id as cluster ID
        self.update_policy_target(master['id'], cluster_id=master['id'])

        self.delete_policy_target(master['id'], expected_res_status=400)
        self.delete_policy_target(member['id'], expected_res_status=204)

        # Deletion doesn't fail now that master is the only cluster  member
        self.delete_policy_target(master['id'], expected_res_status=204)

    def test_cluster_id_create(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_id)['policy_target']
        member = self.create_policy_target(
            policy_target_group_id=ptg_id, cluster_id=master['id'],
            expected_res_status=201)['policy_target']
        master_port = self._get_object('ports', master['port_id'],
                                       self.api)['port']
        member_port = self._get_object('ports', member['port_id'],
                                       self.api)['port']
        self.assertEqual(
            [{'mac_address': master_port['mac_address'],
              'ip_address': master_port['fixed_ips'][0]['ip_address']}],
            member_port['allowed_address_pairs'])

    def test_cluster_id_update_add(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_id)['policy_target']
        member = self.create_policy_target(
            policy_target_group_id=ptg_id,
            expected_res_status=201)['policy_target']
        self.update_policy_target(member['id'], cluster_id=master['id'])

        master_port = self._get_object('ports', master['port_id'],
                                       self.api)['port']
        member_port = self._get_object('ports', member['port_id'],
                                       self.api)['port']
        self.assertEqual(
            [{'mac_address': master_port['mac_address'],
              'ip_address': master_port['fixed_ips'][0]['ip_address']}],
            member_port['allowed_address_pairs'])

    def test_cluster_id_update_remove(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        master = self.create_policy_target(
            policy_target_group_id=ptg_id)['policy_target']
        member = self.create_policy_target(
            policy_target_group_id=ptg_id, cluster_id=master['id'],
            expected_res_status=201)['policy_target']

        self.update_policy_target(member['id'], cluster_id='')
        member_port = self._get_object('ports', member['port_id'],
                                       self.api)['port']
        self.assertEqual([], member_port['allowed_address_pairs'])


class TestPolicyTarget(ResourceMappingTestCase, TestClusterIdMixin):

    def test_implicit_port_lifecycle(self, proxy_ip_pool=None):
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
        if proxy_ip_pool:
            l3p = self.create_l3_policy(
                shared=True, ip_pool='11.0.0.0/8', proxy_ip_pool=proxy_ip_pool)
        else:
            l3p = self.create_l3_policy(shared=True, ip_pool='11.0.0.0/8')

        l2p = self.create_l2_policy(l3_policy_id=l3p['l3_policy']['id'],
                                    shared=True)
        s_ptg = self.create_policy_target_group(
            name="s_ptg", shared=True,
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

    def test_create_policy_target_with_fixed_ip(self):
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet1:
            fixed_ips = [{'subnet_id': subnet1['subnet']['id'],
                          'ip_address': '10.10.1.5'}]
            ptg = self.create_policy_target_group(
                l2_policy_id=l2p_id,
                subnets=[subnet1['subnet']['id']])['policy_target_group']
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'],
                fixed_ips=fixed_ips)['policy_target']
            port = self._get_object('ports', pt['port_id'],
                                    self.api)['port']
            self.assertEqual(1, len(port['fixed_ips']))
            ip = port['fixed_ips'][0]['ip_address']
            self.assertEqual('10.10.1.5', ip)

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
            policy_target_group_id=None,
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

    def test_ptg_same_l2p(self):
        l2p = self.create_l2_policy()['l2_policy']
        ptg1 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        ptg2 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        sub1 = self._get_object('subnets', ptg1['subnets'][0],
                                self.api)['subnet']
        sub2 = self._get_object('subnets', ptg2['subnets'][0],
                                self.api)['subnet']

        pt1 = self.create_policy_target(
            policy_target_group_id=ptg1['id'])['policy_target']
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg2['id'])['policy_target']

        port1 = self._get_object('ports', pt1['port_id'], self.api)['port']
        port2 = self._get_object('ports', pt2['port_id'], self.api)['port']

        ip1 = port1['fixed_ips'][0]['ip_address']
        cidr1 = sub1['cidr']
        self.assertTrue(
            netaddr.IPAddress(ip1) in netaddr.IPNetwork(cidr1),
            "IP %s not in CIDR %s" % (ip1, cidr1))

        ip2 = port2['fixed_ips'][0]['ip_address']
        cidr2 = sub2['cidr']
        self.assertTrue(
            netaddr.IPAddress(ip2) in netaddr.IPNetwork(cidr2),
            "IP %s not in CIDR %s" % (ip2, cidr2))

    def test_ptg_multiple_subnets(self):
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']

        # Create L2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))

        # Create policy_target group with explicit subnet.
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet1:
            with self.subnet(network=network, cidr='10.10.2.0/24') as subnet2:
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p_id,
                    subnets=[subnet1['subnet']['id'],
                             subnet2['subnet']['id']])['policy_target_group']
                pt = self.create_policy_target(
                    policy_target_group_id=ptg['id'])['policy_target']
                port = self._get_object('ports', pt['port_id'],
                                        self.api)['port']
                self.assertEqual(1, len(port['fixed_ips']))
                ip = port['fixed_ips'][0]['ip_address']
                cidr1 = subnet1['subnet']['cidr']
                cidr2 = subnet2['subnet']['cidr']
                self.assertTrue(
                    (netaddr.IPAddress(ip) in netaddr.IPNetwork(cidr1)) or
                    (netaddr.IPAddress(ip) in netaddr.IPNetwork(cidr2)),
                    "IP %s neither in CIDR %s nor in CIDR %s" % (ip, cidr1,
                                                                 cidr2))

    def test_ptg_multiple_subnets_fallback(self):
        l3p = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/8')
        l3p_id = l3p['l3_policy']['id']

        # Create L2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        req = self.new_show_request('networks', network_id)
        network = self.deserialize(self.fmt, req.get_response(self.api))

        # Create policy_target group with explicit subnet.
        with self.subnet(network=network, cidr='10.10.1.0/30') as subnet1:
            with self.subnet(network=network, cidr='10.10.2.0/29') as subnet2:
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p_id,
                    subnets=[subnet1['subnet']['id'],
                             subnet2['subnet']['id']])['policy_target_group']
                # Only 5 PTs can be created, and both in subnet2
                # (subnet1 is full)
                ports = []
                for x in range(6):
                    pt = self.create_policy_target(
                        policy_target_group_id=ptg['id'],
                        expected_res_status=201)['policy_target']
                    port = self._get_object('ports', pt['port_id'],
                                            self.api)['port']
                    ports.append(port)
                    self.assertEqual(1, len(port['fixed_ips']))
                # sadly, we expect a 500 being a postcommit Neutron raised
                # exception
                self.create_policy_target(
                    policy_target_group_id=ptg['id'], expected_res_status=500)

    def test_port_extra_attributes(self, extra=None):
        extra = extra or {}
        ptg = self.create_policy_target_group()['policy_target_group']
        # Issue internal call
        ctx = nctx.get_admin_context()
        data = {'description': '', 'name': '',
                'port_id': None, 'cluster_id': '',
                'policy_target_group_id': ptg['id'],
                'port_attributes': {'mac_address':
                                    'aa:bb:cc:dd:ee:ff'},
                'tenant_id': self._tenant_id}
        data.update(extra)
        pt = self._gbp_plugin.create_policy_target(
            ctx, {'policy_target': data})
        port = self._get_object('ports', pt['port_id'], self.api)['port']
        self.assertEqual('aa:bb:cc:dd:ee:ff', port['mac_address'])

    def test_weird_port_extra_attributes_ignored(self, extra=None):
        extra = extra or {}
        ptg = self.create_policy_target_group()['policy_target_group']
        # Calling an internal API, all additional weird attributes are ignored.
        # This will change once we go to a separated server
        ctx = nctx.get_admin_context()
        data = {'description': '', 'name': '',
                'port_id': None, 'cluster_id': '',
                'policy_target_group_id': ptg['id'],
                'port_attributes': {'non_port_attribute': ''},
                'tenant_id': self._tenant_id}
        data.update(extra)
        pt = self._gbp_plugin.create_policy_target(
            ctx, {'policy_target': data})
        self.assertIsNotNone(pt['id'])

    def test_port_extra_attributes_fixed_ips(self, extra=None):
        extra = extra or {}
        l2p = self.create_l2_policy()['l2_policy']
        network = self._get_object('networks', l2p['network_id'], self.api)
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet:
            subnet = subnet['subnet']
            ptg = self.create_policy_target_group(
                subnets=[subnet['id']],
                l2_policy_id=l2p['id'])['policy_target_group']
            fixed_ips = [{'subnet_id': subnet['id'],
                          'ip_address': '10.10.1.10'}]
            ctx = nctx.get_admin_context()
            data = {'description': '', 'name': '',
                    'port_id': None, 'cluster_id': '',
                    'policy_target_group_id': ptg['id'],
                    'port_attributes': {'fixed_ips': fixed_ips},
                    'tenant_id': self._tenant_id}
            data.update(extra)
            pt = self._gbp_plugin.create_policy_target(
                ctx, {'policy_target': data})
            port = self._get_object('ports', pt['port_id'], self.api)['port']
            self.assertEqual(fixed_ips, port['fixed_ips'])

            # Now use a different subnet
            ctx = nctx.get_admin_context()
            data = {'description': '', 'name': '', 'port_id': None,
                    'cluster_id': '', 'policy_target_group_id': ptg['id'],
                    'port_attributes': {'fixed_ips': [{
                        'subnet_id': 'not_in_ptg',
                        'ip_address': '10.10.1.10'}]},
                    'tenant_id': self._tenant_id}
            data.update(extra)
            self.assertRaises(gpexc.InvalidPortExtraAttributes,
                              self._gbp_plugin.create_policy_target,
                              ctx, {'policy_target': data})

    def test_port_extra_attributes_implicit(self, extra=None):
        extra = extra or {}
        ptg = self.create_policy_target_group()['policy_target_group']
        ctx = nctx.get_admin_context()
        data = {'description': '', 'name': '',
                'port_id': None, 'cluster_id': '',
                'policy_target_group_id': ptg['id'],
                'port_attributes': {'mac_address':
                                    'aa:bb:cc:dd:ee:ff'},
                'tenant_id': self._tenant_id}
        data.update(extra)
        pt = self._gbp_plugin.create_policy_target(
            ctx, {'policy_target': data})
        # Port exists
        self._get_object('ports', pt['port_id'], self.api,
                         expected_res_status=200)

        self.delete_policy_target(pt['id'], expected_res_status=204)
        # Port is gone since owned by GBP
        self._get_object('ports', pt['port_id'], self.api,
                         expected_res_status=404)


class TestPolicyTargetGroupWithDNSConfiguration(ResourceMappingTestCase):

    def setUp(self):
        self.dns_servers = ['8.8.8.7', '8.8.8.8']
        config.cfg.CONF.set_override('dns_nameservers', self.dns_servers,
                                     group='resource_mapping')
        super(TestPolicyTargetGroupWithDNSConfiguration, self).setUp()

    def test_subnet_create(self):
        ptg = self.create_policy_target_group(name="ptg1")
        subnets = ptg['policy_target_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(self.dns_servers, subnet['subnet']['dns_nameservers'])


class TestPolicyTargetGroupWithoutDNSConfiguration(ResourceMappingTestCase):

    def test_subnet_create(self):
        ptg = self.create_policy_target_group(name="ptg1")
        subnets = ptg['policy_target_group']['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual([], subnet['subnet']['dns_nameservers'])


class TestPolicyTargetGroup(ResourceMappingTestCase):

    def _test_implicit_subnet_lifecycle(self, shared=False):
        # Use explicit L2 policy so network and subnet not deleted
        # with policy_target group.
        l2p = self.create_l2_policy(shared=shared)
        l2p_id = l2p['l2_policy']['id']

        # Create policy_target group with implicit subnet.
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_id,
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
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet1:
            with self.subnet(network=network, cidr='10.10.2.0/24') as subnet2:
                subnet1_id = subnet1['subnet']['id']
                subnet2_id = subnet2['subnet']['id']
                subnets = [subnet1_id]
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p_id, subnets=subnets)
                ptg_id = ptg['policy_target_group']['id']

                # Add subnet.
                subnets = [subnet1_id, subnet2_id]
                data = {'policy_target_group': {'subnets': subnets}}
                req = self.new_update_request('policy_target_groups', data,
                                              ptg_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_add_subnet_negative(self):
        # Create L2P
        l2p = self.create_l2_policy()['l2_policy']

        with self.network() as net:
            with self.subnet(network=net) as sub:
                # Asserted just for clarity
                self.assertNotEqual(net['network']['id'], l2p['network_id'])
                res = self.create_policy_target_group(
                    l2_policy_id=l2p['id'], subnets=[sub['subnet']['id']],
                    expected_res_status=400)
                self.assertEqual('InvalidSubnetForPTG',
                                 res['NeutronError']['type'])
                # Create valid PTG
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p['id'],
                    expected_res_status=201)['policy_target_group']
                res = self.update_policy_target_group(
                    ptg['id'], expected_res_status=400,
                    subnets=ptg['subnets'] + [sub['subnet']['id']])
                self.assertEqual('InvalidSubnetForPTG',
                                 res['NeutronError']['type'])

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
        with self.subnet(network=network, cidr='10.10.1.0/24') as subnet1:
            with self.subnet(network=network, cidr='10.10.2.0/24') as subnet2:
                subnet1_id = subnet1['subnet']['id']
                subnet2_id = subnet2['subnet']['id']
                subnets = [subnet1_id, subnet2_id]
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p_id, subnets=subnets)
                ptg_id = ptg['policy_target_group']['id']

                # Verify removing subnet rejected.
                data = {'policy_target_group': {'subnets': [subnet2_id]}}
                req = self.new_update_request('policy_target_groups', data,
                                              ptg_id)
                data = self.deserialize(self.fmt, req.get_response(
                    self.ext_api))
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

    # Test update of PTG with PT that doesnt have port association
    def test_policy_target_group_update_with_unbound_pt(self):
        ptg = self.create_policy_target_group(name="ptg")
        ptg_id = ptg['policy_target_group']['id']

        pt1 = self.create_policy_target(name="pt",
                                        policy_target_group_id=ptg_id)
        port_id = pt1['policy_target']['port_id']
        self.new_delete_request('ports', port_id).get_response(self.api)
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="bi")
        classifier_id = classifier['policy_classifier']['id']
        action = self.create_policy_action(name="action1",
                                           action_type=gconst.GP_ACTION_ALLOW)
        action_id = action['policy_action']['id']
        action_id_list = [action_id]
        policy_rule = self.create_policy_rule(
            name='pr', policy_classifier_id=classifier_id,
            policy_actions=action_id_list)
        policy_rule_list = [policy_rule['policy_rule']['id']]
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=policy_rule_list)
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        ptg = self.create_policy_target_group(name="ptg",
            provided_policy_rule_sets={policy_rule_set_id: ''})
        # now add a policy_rule_set to PTG
        data = {'policy_target_group':
                {'provided_policy_rule_sets': {policy_rule_set_id: None}}}
        req = self.new_update_request('policy_target_groups', data, ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_default_security_group_egress_rules(self):
        # Create PTG and retrieve self subnet
        ptg = self.create_policy_target_group()['policy_target_group']
        subnets = ptg['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt,
                                  req.get_response(self.api))['subnet']
        # Create PT and retrieve port to get SG
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        port = self.deserialize(self.fmt, req.get_response(self.api))['port']

        sg_id = port['security_groups'][0]
        ip_v = {4: cst.IPv4, 6: cst.IPv6}
        filters = {'tenant_id': [ptg['tenant_id']],
                   'security_group_id': [sg_id],
                   'ethertype': [ip_v[subnet['ip_version']]],
                   'direction': ['egress'],
                   'remote_ip_prefix': [subnet['cidr']]}

        sg_rule = self._get_sg_rule(**filters)
        self.assertTrue(len(sg_rule) == 1)
        del filters['remote_ip_prefix']
        filters['ethertype'] = [ip_v[4]]
        sg_rule = self._get_sg_rule(**filters)
        self.assertTrue(len(sg_rule) == 4)
        filters['port_range_min'] = [53]
        filters['port_range_max'] = [53]
        for ether_type in ip_v:
            for proto in ['tcp', 'udp']:
                filters['ethertype'] = [ip_v[ether_type]]
                filters['protocol'] = [proto]
                sg_rule = self._get_sg_rule(**filters)
                self.assertTrue(len(sg_rule) == 1)

    def test_default_security_group_allows_intra_ptg(self):
        # Create PTG and retrieve subnet
        ptg = self.create_policy_target_group()['policy_target_group']
        subnets = ptg['subnets']
        req = self.new_show_request('subnets', subnets[0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt,
                                  req.get_response(self.api))['subnet']
        #Create PT and retrieve port
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        port = self.deserialize(self.fmt, req.get_response(self.api))['port']

        ip_v = {4: cst.IPv4, 6: cst.IPv6}

        # Verify Port's SG has all the right rules
        # Allow all ingress traffic from same ptg subnet
        def verify_rule(filters):
            sg_rule = self._get_sg_rule(**filters)
            self.assertTrue(len(sg_rule) == 1)
            self.assertIsNone(sg_rule[0]['protocol'])
            self.assertIsNone(sg_rule[0]['port_range_max'])
            self.assertIsNone(sg_rule[0]['port_range_min'])

        filters = {'tenant_id': [ptg['tenant_id']],
                   'security_group_id': [port['security_groups'][0]],
                   'ethertype': [ip_v[subnet['ip_version']]],
                   'remote_ip_prefix': [subnet['cidr']],
                   'direction': ['ingress']}
        verify_rule(filters)
        filters.update({'direction': ['egress']})
        verify_rule(filters)
        filters = {'tenant_id': [ptg['tenant_id']],
                   'security_group_id': [port['security_groups'][0]],
                   'remote_ip_prefix': ['0.0.0.0/0']}
        # No wide rule applied
        sg_rule = self._get_sg_rule(**filters)
        self.assertTrue(len(sg_rule) == 0)

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
        with self.subnet(network=network, cidr='192.168.0.0/24') as subnet2:
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
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'])['policy_target']
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

    def _test_cross_tenant_prs(self, admin=False):
        status = {False: 404, True: 201}
        prs = self.create_policy_rule_set(tenant_id='admin_tenant',
                                          is_admin_context=admin,
                                          expected_res_status=201)
        res = self.create_policy_target_group(
            is_admin_context=admin,
            provided_policy_rule_sets={prs['policy_rule_set']['id']: ''},
            tenant_id='anothertenant', expected_res_status=status[admin])
        if not admin:
            self.assertEqual(
                'PolicyRuleSetNotFound', res['NeutronError']['type'])

        # Verify Update
        ptg = self.create_policy_target_group(
            is_admin_context=admin,
            tenant_id='anothertenant', expected_res_status=201)
        res = self.update_policy_target_group(
            ptg['policy_target_group']['id'], is_admin_context=admin,
            tenant_id='anothertenant',
            provided_policy_rule_sets={prs['policy_rule_set']['id']: ''},
            expected_res_status=status[admin] if not admin else 200)
        if not admin:
            self.assertEqual(
                'PolicyRuleSetNotFound', res['NeutronError']['type'])

    def test_cross_tenant_prs_fails(self):
        self._test_cross_tenant_prs()

    def test_cross_tenant_prs_admin(self):
        self._test_cross_tenant_prs(admin=True)

    def test_l2p_update_rejected(self):
        # Create two l2 policies.
        l2p1 = self.create_l2_policy(name="l2p1")
        l2p1_id = l2p1['l2_policy']['id']
        l2p2 = self.create_l2_policy(name="l2p2")
        l2p2_id = l2p2['l2_policy']['id']

        # Create policy target group.
        ptg = self.create_policy_target_group(name="ptg1",
                                              l2_policy_id=l2p1_id)
        ptg_id = ptg['policy_target_group']['id']

        # Verify updating l2_policy rejected.
        data = {'policy_target_group': {'l2_policy_id': l2p2_id}}
        req = self.new_update_request('policy_target_groups', data, ptg_id)
        data = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('L2PolicyUpdateOfPolicyTargetGroupNotSupported',
                         data['NeutronError']['type'])

    def test_ip_pool_exhaustion(self):
        # Create L3P with only a single subnet in pool, and an L2P
        # using this L3P.
        l3p = self.create_l3_policy(name="l3p", ip_pool="10.0.0.0/24",
                                    subnet_prefix_length=24)
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy(name="l2p", l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']

        # Create PTG, which will be allocated this subnet.
        self.create_policy_target_group(name="ptg1", l2_policy_id=l2p_id)

        # Create 2nd PTG, which should fail due to subnet exhaustion.
        res = self.create_policy_target_group(name="ptg2", l2_policy_id=l2p_id,
                                              expected_res_status=503)
        self.assertEqual('NoSubnetAvailable',
                         res['NeutronError']['type'])

        # Verify 2nd PTG was not created.
        self.assertFalse(self._list('policy_target_groups',
                                    query_params='name=ptg2')
                         ['policy_target_groups'])

    def test_unbound_ports_deletion(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        pt = self.create_policy_target(policy_target_group_id=ptg['id'])
        port = self._get_object('ports', pt['policy_target']['port_id'],
                                self.api)
        self._bind_port_to_host(port['port']['id'], 'h1')
        self.delete_policy_target_group(ptg['id'],
                                        expected_res_status=400)
        self._unbind_port(port['port']['id'])
        self.delete_policy_target_group(ptg['id'], expected_res_status=204)


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

    def test_create_l2p_using_different_tenant_network_rejected(self):
        with self.network(tenant_id='tenant1') as net1:
            network_id = net1['network']['id']
            res = self.create_l2_policy(name="l2p1",
                                        network_id=network_id,
                                        tenant_id='tenant2',
                                        expected_res_status=
                                        webob.exc.HTTPBadRequest.code)
            self.assertEqual('InvalidNetworkAccess',
                             res['NeutronError']['type'])

    def test_l2_policy_create_unset_inject_default_route_reject(self):
        res = self.create_l2_policy(inject_default_route='False',
                                    expected_res_status=400)
        self.assertEqual('UnsettingInjectDefaultRouteOfL2PolicyNotSupported',
                         res['NeutronError']['type'])

    def test_shared_l2_policy_create_negative(self):
        l3p = self.create_l3_policy(shared=True)
        for shared in [True, False]:
            res = self.create_l2_policy(name="l2p1", tenant_id='other',
                                        l3_policy_id=l3p['l3_policy']['id'],
                                        shared=shared,
                                        expected_res_status=400)
            self.assertEqual('CrossTenantL2PolicyL3PolicyNotSupported',
                             res['NeutronError']['type'])

        with self.network() as network:
            network_id = network['network']['id']
            res = self.create_l2_policy(name="l2p1", network_id=network_id,
                                        shared=True,
                                        expected_res_status=400)
            self.assertEqual('NonSharedNetworkOnSharedL2PolicyNotSupported',
                             res['NeutronError']['type'])

    def test_l3p_update_rejected(self, proxy_ip_pool=None):
        # Create two l3 policies.
        l3p1 = self.create_l3_policy(name="l3p1", ip_pool='10.0.0.0/16')
        l3p1_id = l3p1['l3_policy']['id']
        if proxy_ip_pool:
            l3p2 = self.create_l3_policy(name="l3p2", ip_pool='10.1.0.0/16',
                                         proxy_ip_pool=proxy_ip_pool)
        else:
            l3p2 = self.create_l3_policy(name="l3p2", ip_pool='10.1.0.0/16')
        l3p2_id = l3p2['l3_policy']['id']

        # Create l2 policy.
        l2p = self.create_l2_policy(name="l2p1", l3_policy_id=l3p1_id)
        l2p_id = l2p['l2_policy']['id']

        # Verify updating l3_policy rejected.
        data = {'l2_policy': {'l3_policy_id': l3p2_id}}
        req = self.new_update_request('l2_policies', data, l2p_id)
        data = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('L3PolicyUpdateOfL2PolicyNotSupported',
                         data['NeutronError']['type'])

    def test_l2_policy_update_inject_default_route_reject(self):
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']

        data = {'l2_policy': {'inject_default_route': False}}
        req = self.new_update_request('l2_policies', data, l2p_id)
        data = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('UnsettingInjectDefaultRouteOfL2PolicyNotSupported',
                         data['NeutronError']['type'])


class TestL3Policy(ResourceMappingTestCase):

    def test_implicit_router_lifecycle(self):
        # Create L3 policy with implicit router.
        l3p = self.create_l3_policy(name="l3p1")
        l3p_id = l3p['l3_policy']['id']
        routers = l3p['l3_policy']['routers']
        self.assertIsNotNone(routers)
        self.assertEqual(len(routers), 1)
        router_id = routers[0]
        # Verify router name
        router = self._get_object('routers', router_id, self.ext_api)['router']
        self.assertEqual('l3p_l3p1', router['name'])

        # Verify deleting L3 policy cleans up router.
        req = self.new_delete_request('l3_policies', l3p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('routers', router_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_router_lifecycle(self):
        # Create L3 policy with explicit router.
        with self.router(tenant_id='tenant1') as router:
            router_id = router['router']['id']
            l3p = self.create_l3_policy(name="l3p1", tenant_id='tenant1',
                                        routers=[router_id])
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
        with self.router() as router1:
            with self.router() as router2:
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

    def test_implicit_creation_failure(self):
        # Create non-default L3Policy that uses the default IP pool.
        self.create_l3_policy(name="l3p1")

        # Create L2Policy that needs implicit L3Policy. Creation of
        # L3Policy should fail due to default IP pool already being
        # used, causing creation of L2Policy to fail. Make sure we get
        # the original exception.
        #
        # REVISIT(rkukura): Overlapping pools per tenant might
        # eventually be allowed, which would break this test. Rather
        # than depending on this exception being raised, we could
        # instead patch the RMD's create_l3_policy_postcommit to raise
        # an exception. This approach could also be applied to other
        # resource types, and could be moved to the IPD's test cases
        # where it belongs. See bug 1432791.
        res = self.create_l2_policy(name="l2p", expected_res_status=400)
        self.assertEqual('OverlappingIPPoolsInSameTenantNotAllowed',
                         res['NeutronError']['type'])

        # Verify L2Policy was not created.
        self.assertFalse(self._list('l2_policies',
                                    query_params='name=l2p')['l2_policies'])

    def test_create_l3p_es(self):
        # Simple test to verify l3p created with 1-N ES
        with self.network(router__external=True) as net1:
            with self.network(router__external=True) as net2:
                with self.subnet(cidr='10.10.1.0/24', network=net1) as sub1:
                    with self.subnet(cidr='10.10.2.0/24',
                                     network=net2) as sub2:
                        es1 = self.create_external_segment(
                            subnet_id=sub1['subnet']['id'])['external_segment']
                        es2 = self.create_external_segment(
                            subnet_id=sub2['subnet']['id'])['external_segment']
                        external_segments = {es1['id']: []}
                        l3p = self.create_l3_policy(
                            ip_pool='192.168.0.0/16', expected_res_status=201,
                            external_segments=external_segments)
                        # IP address is set in the API
                        self.assertEqual(1, len(
                            l3p['l3_policy']['external_segments'][es1['id']]))
                        req = self.new_delete_request('l3_policies',
                                                      l3p['l3_policy']['id'])
                        req.get_response(self.ext_api)
                        external_segments.update({es2['id']: []})
                        res = self.create_l3_policy(
                            ip_pool='192.168.0.0/16', expected_res_status=400,
                            external_segments=external_segments)
                        self.assertEqual('MultipleESPerL3PolicyNotSupported',
                                         res['NeutronError']['type'])

    def test_update_l3p_es(self):
        # Simple test to verify l3p updated with 1-N ES
        with self.network(router__external=True) as net1:
            with self.network(router__external=True) as net2:
                with self.subnet(cidr='10.10.1.0/24', network=net1) as sub1:
                    with self.subnet(cidr='10.10.2.0/24',
                                     network=net2) as sub2:
                        es1 = self.create_external_segment(
                            subnet_id=sub1['subnet']['id'])['external_segment']
                        es2 = self.create_external_segment(
                            subnet_id=sub2['subnet']['id'])['external_segment']
                        # None to es1, es1 to es2
                        l3p = self.create_l3_policy(
                            ip_pool='192.168.0.0/16')['l3_policy']
                        for external_segments in [{es1['id']: []}, {es2['id']:
                                                                    []}]:
                            l3p = self.update_l3_policy(
                                l3p['id'], expected_res_status=200,
                                external_segments=external_segments)[
                                    'l3_policy']
                            self.assertEqual(
                                1, len(l3p['external_segments'][
                                    external_segments.keys()[0]]))
                        # es2 to [es1, es2]
                        external_segments = {es2['id']: [], es1['id']: []}
                        res = self.update_l3_policy(
                            l3p['id'], expected_res_status=400,
                            external_segments=external_segments)
                        self.assertEqual('MultipleESPerL3PolicyNotSupported',
                                         res['NeutronError']['type'])

    def test_es_router_plumbing(self):
        with self.network(router__external=True) as net1:
            with self.network(router__external=True) as net2:
                with self.subnet(cidr='10.10.1.0/24', network=net1) as sub1:
                    with self.subnet(cidr='10.10.2.0/24',
                                     network=net2) as sub2:
                        subnet1 = sub1['subnet']
                        subnet2 = sub2['subnet']
                        es1 = self.create_external_segment(
                            subnet_id=subnet1['id'])['external_segment']
                        es2 = self.create_external_segment(
                            subnet_id=subnet2['id'])['external_segment']
                        es_dict = {es1['id']: ['10.10.1.3']}
                        l3p = self.create_l3_policy(
                            ip_pool='192.168.0.0/16',
                            external_segments=es_dict)['l3_policy']
                        req = self.new_show_request('routers',
                                                    l3p['routers'][0],
                                                    fmt=self.fmt)
                        res = self.deserialize(self.fmt, req.get_response(
                            self.ext_api))['router']
                        self.assertEqual(
                            subnet1['network_id'],
                            res['external_gateway_info']['network_id'])
                        # Verify auto assigned addresses propagated to L3P
                        es_dict = {es2['id']: ['']}
                        l3p = self.update_l3_policy(
                            l3p['id'], external_segments=es_dict,
                            expected_res_status=200)['l3_policy']
                        req = self.new_show_request('routers',
                                                    l3p['routers'][0],
                                                    fmt=self.fmt)
                        res = self.deserialize(self.fmt, req.get_response(
                            self.ext_api))['router']
                        self.assertEqual(
                            subnet2['network_id'],
                            res['external_gateway_info']['network_id'])
                        self.assertEqual(
                            [x['ip_address'] for x in
                             res['external_gateway_info'][
                                 'external_fixed_ips']],
                            l3p['external_segments'][es2['id']])
                        # Verify that the implicit assignment is persisted
                        req = self.new_show_request('l3_policies', l3p['id'],
                                                    fmt=self.fmt)
                        l3p = self.deserialize(self.fmt, req.get_response(
                            self.ext_api))['l3_policy']
                        self.assertEqual(
                            [x['ip_address'] for x in
                             res['external_gateway_info'][
                                 'external_fixed_ips']],
                            l3p['external_segments'][es2['id']])

    def test_es_routes(self):
        routes1 = [{'destination': '0.0.0.0/0', 'nexthop': '10.10.1.1'},
                   {'destination': '172.0.0.0/16', 'nexthop': '10.10.1.1'}]
        routes2 = [{'destination': '0.0.0.0/0', 'nexthop': '10.10.2.1'},
                   {'destination': '172.0.0.0/16', 'nexthop': '10.10.2.1'}]
        with self.network(router__external=True) as net1:
            with self.network(router__external=True) as net2:
                with self.subnet(cidr='10.10.1.0/24', network=net1) as sub1:
                    with self.subnet(cidr='10.10.2.0/24',
                                     network=net2) as sub2:
                        es1 = self.create_external_segment(
                            cidr='10.10.1.0/24',
                            subnet_id=sub1['subnet']['id'],
                            external_routes=routes1)['external_segment']
                        es2 = self.create_external_segment(
                            cidr='10.10.2.0/24',
                            subnet_id=sub2['subnet']['id'],
                            external_routes=routes2)['external_segment']
                        es_dict = {es1['id']: []}
                        l3p = self.create_l3_policy(
                            ip_pool='192.168.0.0/16',
                            external_segments=es_dict,
                            expected_res_status=201)['l3_policy']
                        req = self.new_show_request('routers',
                                                    l3p['routers'][0],
                                                    fmt=self.fmt)
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(routes1, res['router']['routes'])
                        es_dict = {es2['id']: []}
                        self.update_l3_policy(l3p['id'],
                                              external_segments=es_dict,
                                              expected_res_status=200)
                        req = self.new_show_request('routers',
                                                    l3p['routers'][0],
                                                    fmt=self.fmt)
                        res = self.deserialize(self.fmt,
                                               req.get_response(self.ext_api))
                        self.assertEqual(routes2, res['router']['routes'])

    def test_create_l3p_using_different_tenant_router_rejected(self):
        with self.router() as router1:
            router1_id = router1['router']['id']
            res = self.create_l3_policy(name="l3p1",
                                        tenant_id='tenant2',
                                        routers=[router1_id],
                                        expected_res_status=400)
            self.assertEqual('InvalidRouterAccess',
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
        self._verify_prs_rules(policy_rule_set_id)

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
        self._verify_prs_rules(policy_rule_set_id)

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
        self._verify_prs_rules(policy_rule_set1_id)
        self._verify_prs_rules(policy_rule_set2_id)

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
        self._verify_prs_rules(policy_rule_set1_id)
        self._verify_prs_rules(policy_rule_set2_id)

        # Now verify all rules are removed correctly when PRS are disassociated
        self.update_policy_target_group(ptg1_id, provided_policy_rule_sets={},
                                        consumed_policy_rule_sets={},
                                        expected_res_status=200)
        self.update_policy_target_group(ptg2_id, provided_policy_rule_sets={},
                                        consumed_policy_rule_sets={},
                                        expected_res_status=200)
        self._verify_prs_rules(policy_rule_set1_id)
        self._verify_prs_rules(policy_rule_set2_id)

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
        # Need a consumer for rules to exist
        self.create_policy_target_group(
            name="ptg2", consumed_policy_rule_sets={policy_rule_set_id: None})
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
            udp_rules.extend([r for r in sg_rules if (
                r['protocol'] == 'udp') and (r['port_range_min'] == 30) and (
                    r['port_range_max'] == 100) and (
                        r['direction'] == 'egress')])

        # Classifier 2 direction in 'out', so one egress rule exists
        # in addition to the default egree rule(s)
        self.assertEqual(1, len(udp_rules))
        self._verify_prs_rules(policy_rule_set_id)

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

        self._verify_prs_rules(policy_rule_set_id)

    def test_policy_classifier_update_using_protocol_number(self):
        classifier = self.create_policy_classifier(
            name="class1", protocol="tcp", direction="bi")
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
        self.create_policy_target_group(
            name="ptg2", consumed_policy_rule_sets={policy_rule_set_id: None})
        self._verify_prs_rules(policy_rule_set_id)

        # now updates the policy classifier with new protocol field
        data = {'policy_classifier':
                {'protocol': '50', 'direction': 'bi'}}
        req = self.new_update_request('policy_classifiers', data,
            classifier_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

        self._verify_prs_rules(policy_rule_set_id)

    def test_shared_policy_rule_set_create_negative(self):
        self.create_policy_rule_set(shared=True,
                                    expected_res_status=400)

    def test_external_rules_set(self):
        # Define the routes
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        pr = self._create_ssh_allow_rule()
        prs = self.create_policy_rule_set(
            policy_rules=[pr['id']])['policy_rule_set']
        with self.network(router__external=True) as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub:
                es = self.create_external_segment(
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes)['external_segment']
                self.create_l3_policy(
                    ip_pool='192.168.0.0/16',
                    external_segments={es['id']: []})
                self.create_external_policy(
                    external_segments=[es['id']],
                    provided_policy_rule_sets={prs['id']: ''})
                # Since EP provides, the consumed SG will have ingress rules
                # based on the difference between the L3P and the external
                # world
                self._verify_prs_rules(prs['id'])

                # Add one rule to the PRS
                pr2 = self._create_http_allow_rule()
                self.update_policy_rule_set(prs['id'], expected_res_status=200,
                                            policy_rules=[pr['id'], pr2['id']])
                # Verify new rules correctly set
                current_rules = self._verify_prs_rules(prs['id'])

                # Remove all the rules, verify that none exist any more
                self.update_policy_rule_set(
                    prs['id'], expected_res_status=200, policy_rules=[])
                self.assertTrue(len(current_rules) > 0)
                for rule in current_rules:
                    self.assertFalse(self._get_sg_rule(**rule))

    def test_hierarchical_prs(self):
        pr1 = self._create_ssh_allow_rule()
        pr2 = self._create_http_allow_rule()

        child = self.create_policy_rule_set(
            expected_res_status=201,
            policy_rules=[pr1['id'], pr2['id']])['policy_rule_set']

        parent = self.create_policy_rule_set(
            expected_res_status=201, policy_rules=[pr1['id']],
            child_policy_rule_sets=[child['id']])['policy_rule_set']

        self.create_policy_target_group(
            provided_policy_rule_sets={child['id']: None})

        self.create_policy_target_group(
            consumed_policy_rule_sets={child['id']: None})

        # Verify all the rules are correctly set
        self._verify_prs_rules(child['id'])

        # Add rule to parent
        self.update_policy_rule_set(parent['id'], expected_res_status=200,
                                    policy_rules=[pr1['id'], pr2['id']])
        self._verify_prs_rules(child['id'])

        # Remove rule from parent
        self.update_policy_rule_set(parent['id'], expected_res_status=200,
                                    policy_rules=[])
        self._verify_prs_rules(child['id'])

        # Change rule classifier
        pr3 = self._create_tcp_allow_rule('443')
        self.update_policy_rule_set(parent['id'], expected_res_status=200,
                                    policy_rules=[pr1['id']])
        self.update_policy_rule(
            pr1['id'], expected_res_status=200,
            policy_classifier_id=pr3['policy_classifier_id'])
        self._verify_prs_rules(child['id'])

        # Swap parent
        self.update_policy_rule_set(parent['id'], expected_res_status=200,
                                    child_policy_rule_sets=[])
        self._verify_prs_rules(child['id'])

        self.create_policy_rule_set(
            expected_res_status=201, policy_rules=[pr1['id'], pr2['id']],
            child_policy_rule_sets=[child['id']])

        self._verify_prs_rules(child['id'])

        # TODO(ivar): Test that redirect is allowed too

    def test_update_policy_classifier(self):
        pr = self._create_http_allow_rule()
        prs = self.create_policy_rule_set(
            policy_rules=[pr['id']],
            expected_res_status=201)['policy_rule_set']

        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self._verify_prs_rules(prs['id'])

        self.update_policy_classifier(
            pr['policy_classifier_id'], expected_res_status=200,
            port_range=8080)
        self._verify_prs_rules(prs['id'])

    def _test_hierarchical_update_policy_classifier(self):
        pr = self._create_http_allow_rule()
        prs = self.create_policy_rule_set(
            policy_rules=[pr['id']],
            expected_res_status=201)['policy_rule_set']

        self.create_policy_rule_set(
            policy_rules=[pr['id']], child_policy_rule_sets=[prs['id']],
            expected_res_status=201)

        self._verify_prs_rules(prs['id'])

        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self._verify_prs_rules(prs['id'])

        self.update_policy_classifier(
            pr['policy_classifier_id'], expected_res_status=200,
            port_range=8080)
        self._verify_prs_rules(prs['id'])

    def _update_same_classifier_multiple_rules(self):
        action = self.create_policy_action(
            action_type='allow')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr1 = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action['id']])['policy_rule']
        pr2 = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action['id']])['policy_rule']

        prs = self.create_policy_rule_set(
            policy_rules=[pr1['id']],
            expected_res_status=201)['policy_rule_set']
        self.create_policy_rule_set(
            policy_rules=[pr2['id']], child_policy_rule_sets=[prs['id']],
            expected_res_status=201)
        self._verify_prs_rules(prs['id'])

        self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: None},
            expected_res_status=201)
        self._verify_prs_rules(prs['id'])

        self.update_policy_classifier(
            pr1['policy_classifier_id'], expected_res_status=200,
            port_range=8080)
        self._verify_prs_rules(prs['id'])

    def test_delete_policy_rule(self):
        pr = self._create_http_allow_rule()
        pr2 = self._create_ssh_allow_rule()
        prs = self.create_policy_rule_set(
            policy_rules=[pr['id'], pr2['id']],
            expected_res_status=201)['policy_rule_set']

        self._verify_prs_rules(prs['id'])

        provider_ptg = self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: None},
            expected_res_status=201)['policy_target_group']
        consumer_ptg = self.create_policy_target_group(
            consumed_policy_rule_sets={prs['id']: None},
            expected_res_status=201)['policy_target_group']
        self._verify_prs_rules(prs['id'])

        # Deleting a policy rule is allowed only when it is no longer in use
        self.delete_policy_target_group(
            provider_ptg['id'],
            expected_res_status=webob.exc.HTTPNoContent.code)
        self.delete_policy_target_group(
            consumer_ptg['id'],
            expected_res_status=webob.exc.HTTPNoContent.code)
        self.delete_policy_rule_set(
            prs['id'], expected_res_status=webob.exc.HTTPNoContent.code)
        self.delete_policy_rule(
            pr['id'], expected_res_status=webob.exc.HTTPNoContent.code)

    def test_shared_create_multiple_redirect_rules_ptg(self):
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        action2 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr1 = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr2 = self.create_policy_rule(
            policy_classifier_id=classifier['id'],
            policy_actions=[action2['id']])['policy_rule']

        res = self.create_policy_rule_set(
            policy_rules=[pr1['id'], pr2['id']],
            expected_res_status=400)
        self.assertEqual('MultipleRedirectActionsNotSupportedForPRS',
                         res['NeutronError']['type'])

    def test_ptg_deleted(self):
        pr1 = self._create_ssh_allow_rule()
        pr2 = self._create_http_allow_rule()

        prs = self.create_policy_rule_set(
            expected_res_status=201,
            policy_rules=[pr1['id'], pr2['id']])['policy_rule_set']
        ptg = self.create_policy_target_group(
            expected_res_status=201, provided_policy_rule_sets={prs['id']: ''},
            consumed_policy_rule_sets={prs['id']: ''})['policy_target_group']
        self.delete_policy_target_group(ptg['id'])
        self._verify_prs_rules(prs['id'])


class TestServiceChain(ResourceMappingTestCase):

    def _assert_proper_chain_instance(self, sc_instance, provider_ptg_id,
                                      consumer_ptg_id, scs_id_list,
                                      classifier_id=None):
        self.assertEqual(sc_instance['provider_ptg_id'], provider_ptg_id)
        self.assertEqual(sc_instance['consumer_ptg_id'], 'N/A')
        self.assertEqual(scs_id_list, sc_instance['servicechain_specs'])
        provider = self.show_policy_target_group(
            provider_ptg_id)['policy_target_group']
        self.assertEqual(sc_instance['tenant_id'], provider['tenant_id'])
        if classifier_id:
            self.assertEqual(sc_instance['classifier_id'], classifier_id)

    def _override_keystone_creds(self, usr, pwd, tenant, uri):
        config.cfg.CONF.set_override('admin_user', usr,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_password', pwd,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_tenant_name', tenant,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_uri', uri,
                                     group='keystone_authtoken')

    def test_get_keystone_creds(self):
        self._override_keystone_creds(
            'key_user', 'key_password', 'key_tenant_name',
            'http://127.0.0.1:35357/v2.0/')
        usr, pwd, tenant, uri = utils.get_keystone_creds()
        self.assertEqual('key_user', usr)
        self.assertEqual('key_password', pwd)
        self.assertEqual('key_tenant_name', tenant)
        self.assertEqual('http://127.0.0.1:35357/v2.0/', uri)

        # Now use old protocol/host/port
        config.cfg.CONF.set_override('auth_uri', '',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_protocol', 'http',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_host', '127.0.0.1',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_port', '35357',
                                     group='keystone_authtoken')
        usr, pwd, tenant, uri = utils.get_keystone_creds()
        # URI still correctly retrieved
        self.assertEqual('http://127.0.0.1:35357/v2.0/', uri)

    def test_chain_tenant_keystone_client(self):
        chain_mapping.k_client = mock.Mock()
        self._override_keystone_creds(
            'key_user', 'key_password', 'key_tenant_name',
            'http://127.0.0.1:35357/v2.0/')
        config.cfg.CONF.set_override(
            'chain_owner_tenant_name', 'chain_owner',
            group='chain_mapping')
        chain_mapping.ChainMappingDriver.chain_tenant_keystone_client()
        chain_mapping.k_client.Client.assert_called_once_with(
            username='key_user', password='key_password',
            auth_url='http://127.0.0.1:35357/v2.0/')

        # Use chain specific tenants
        chain_mapping.k_client.reset_mock()
        config.cfg.CONF.set_override(
            'chain_owner_user', 'chain_owner_user', group='chain_mapping')
        config.cfg.CONF.set_override(
            'chain_owner_password', 'chain_owner_p', group='chain_mapping')
        chain_mapping.ChainMappingDriver.chain_tenant_keystone_client()
        chain_mapping.k_client.Client.assert_called_once_with(
            username='chain_owner_user', password='chain_owner_p',
            auth_url='http://127.0.0.1:35357/v2.0/')

        # Not called if no tenant name
        chain_mapping.k_client.reset_mock()
        config.cfg.CONF.set_override(
            'chain_owner_tenant_name', '', group='chain_mapping')
        chain_mapping.ChainMappingDriver.chain_tenant_keystone_client()
        self.assertFalse(chain_mapping.k_client.Client.called)

    def test_chain_tenant_id(self):
        keyclient = mock.Mock()
        with mock.patch.object(
                chain_mapping.ChainMappingDriver,
                'chain_tenant_keystone_client') as key_client:

            key_client.return_value = keyclient

            # Test working case
            def ok(name=''):
                res = mock.Mock()
                res.id = CHAIN_TENANT_ID
                return res
            keyclient.tenants.find = ok

            res = chain_mapping.ChainMappingDriver.chain_tenant_id()
            self.assertEqual(CHAIN_TENANT_ID, res)

            # Test NotFound
            def not_found(name=''):
                raise chain_mapping.k_exceptions.NotFound()
            keyclient.tenants.find = not_found

            # Do not rerise
            res = chain_mapping.ChainMappingDriver.chain_tenant_id()
            self.assertIsNone(res)
            # Rerise
            self.assertRaises(
                chain_mapping.k_exceptions.NotFound,
                chain_mapping.ChainMappingDriver.chain_tenant_id, True)

            # Test Duplicated
            def duplicated(name=''):
                raise chain_mapping.k_exceptions.NoUniqueMatch()
            keyclient.tenants.find = duplicated

            # Do not rerise
            res = chain_mapping.ChainMappingDriver.chain_tenant_id()
            self.assertIsNone(res)

            # Rerise
            self.assertRaises(
                chain_mapping.k_exceptions.NoUniqueMatch,
                chain_mapping.ChainMappingDriver.chain_tenant_id, True)

    def test_update_ptg_with_redirect_prs(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self._verify_prs_rules(policy_rule_set_id)
        provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs()

        self._verify_prs_rules(policy_rule_set_id)
        # No service chain instances until we have provider and consumer prs
        sc_node_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_node_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

        # We should have one service chain instance created when PTGs are
        # updated with provided and consumed prs
        self.update_policy_target_group(
                            provider_ptg,
                            provided_policy_rule_sets={policy_rule_set_id: ''},
                            consumed_policy_rule_sets={},
                            expected_res_status=200)
        self.update_policy_target_group(
                            consumer_ptg,
                            provided_policy_rule_sets={},
                            consumed_policy_rule_sets={policy_rule_set_id: ''},
                            expected_res_status=200)

        self._verify_prs_rules(policy_rule_set_id)
        sc_node_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_node_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg,
                                           consumer_ptg, [scs_id])

        # Verify that PTG update removing prs cleansup the chain instances
        self.update_policy_target_group(
                            provider_ptg,
                            provided_policy_rule_sets={},
                            consumed_policy_rule_sets={},
                            expected_res_status=200)
        self._verify_prs_rules(policy_rule_set_id)
        sc_node_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_node_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    # REVISIT(Magesh): Enable this UT when we run the GBP UTs against NCP
    '''
    def test_classifier_update_to_chain(self):
        scs_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs_id)
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self._verify_prs_rules(policy_rule_set_id)
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            policy_rule_set_id)
        self._verify_prs_rules(policy_rule_set_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id, [scs_id])
        with mock.patch.object(
                ncp_plugin.NodeCompositionPlugin,
                'notify_chain_parameters_updated') as notify_chain_update:
            # Update classifier and verify instance is updated
            classifier = {'policy_classifier': {'port_range': "80"}}
            req = self.new_update_request('policy_classifiers',
                                          classifier, classifier_id)
            classifier = self.deserialize(self.fmt,
                                          req.get_response(self.ext_api))
            notify_chain_update.assert_called_once_with(
                mock.ANY, sc_instance['id'])
            self._verify_prs_rules(policy_rule_set_id)
            sc_instances = self._list(SERVICECHAIN_INSTANCES)
            self.assertEqual(len(sc_instances['servicechain_instances']), 1)
            sc_instance_updated = sc_instances['servicechain_instances'][0]
            self.assertEqual(sc_instance, sc_instance_updated)
        self._verify_ptg_delete_cleanup_chain(consumer_ptg_id)
    '''

    def test_redirect_to_chain(self):
        scs_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                        policy_rule_set['id'])

        self._verify_prs_rules(policy_rule_set['id'])
        sc_instance_list_req = self.new_list_request(SERVICECHAIN_INSTANCES)
        res = sc_instance_list_req.get_response(self.ext_api)
        sc_instances = self.deserialize(self.fmt, res)
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance, provider_ptg_id, consumer_ptg_id, [scs_id],
            classifier_id=classifier_id)
        # Verify that PTG delete cleans up the chain instances
        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_ptg_updates_affecting_chain(self):
        scs1_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs1_id)
        prs1 = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']
        self._verify_prs_rules(prs1['id'])
        provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs()
        self._verify_prs_rules(prs1['id'])

        # No service chain instances until we have provider and consumer prs
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual([], sc_instances['servicechain_instances'])

        # One service chain instance should be created when PTGs are
        # updated with provided and consumed prs
        self.update_policy_target_group(
            provider_ptg, provided_policy_rule_sets={prs1['id']: ''},
            consumed_policy_rule_sets={}, expected_res_status=200)
        self.update_policy_target_group(
            consumer_ptg, consumed_policy_rule_sets={prs1['id']: ''},
            provided_policy_rule_sets={}, expected_res_status=200)
        self._verify_prs_rules(prs1['id'])
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(1, len(sc_instances['servicechain_instances']))
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance, provider_ptg, consumer_ptg,
            [scs1_id], classifier_id=classifier_id)

        # Verify that adding a new PRS with just Allow rule does not affect
        # the chain
        with mock.patch.object(
                servicechain_db.ServiceChainDbPlugin,
                'update_servicechain_instance') as sc_instance_update:
            sc_instance_update.return_value = {'id': sc_instance['id']}
            pr = self._create_ssh_allow_rule()
            prs2 = self.create_policy_rule_set(
                policy_rules=[pr['id']])['policy_rule_set']
            self.update_policy_target_group(
                provider_ptg, consumed_policy_rule_sets={},
                provided_policy_rule_sets={prs1['id']: '', prs2['id']: ''},
                expected_res_status=200)
            self.update_policy_target_group(
                consumer_ptg, provided_policy_rule_sets={},
                consumed_policy_rule_sets={prs1['id']: '', prs2['id']: ''},
                expected_res_status=200)
            self._verify_prs_rules(prs2['id'])
            sc_instances_new = self._list(SERVICECHAIN_INSTANCES)
            self.assertEqual(sc_instances, sc_instances_new)
            self.assertEqual(sc_instance_update.call_args_list, [])

        # update with a new redirect ruleset and verify that the instance is
        # updated with the new classifier
        scs2_id = self._create_servicechain_spec()
        _, classifier3_id, policy_rule3_id = self._create_tcp_redirect_rule(
                                            "443", scs2_id)
        prs3 = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule3_id])['policy_rule_set']
        self._verify_prs_rules(prs3['id'])
        self.update_policy_target_group(
            provider_ptg, consumed_policy_rule_sets={},
            provided_policy_rule_sets={prs2['id']: '', prs3['id']: ''},
            expected_res_status=200)
        self.update_policy_target_group(
            consumer_ptg, provided_policy_rule_sets={},
            consumed_policy_rule_sets={prs2['id']: '', prs3['id']: ''},
            expected_res_status=200)
        self._verify_prs_rules(prs3['id'])
        sc_instances_new = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(1, len(sc_instances_new['servicechain_instances']))
        sc_instance_new = sc_instances_new['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance_new, provider_ptg, consumer_ptg,
            [scs2_id], classifier_id=classifier3_id)
        self.assertEqual(sc_instance['id'], sc_instance_new['id'])

        # Remove redirect and see if the instance got deleted
        self.update_policy_target_group(
            provider_ptg, provided_policy_rule_sets={prs2['id']: ''},
            consumed_policy_rule_sets={}, expected_res_status=200)
        self.update_policy_target_group(
            consumer_ptg, consumed_policy_rule_sets={prs2['id']: ''},
            provided_policy_rule_sets={}, expected_res_status=200)
        self._verify_prs_rules(prs2['id'])
        sc_instances_new = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual([], sc_instances_new['servicechain_instances'])
        self.assertEqual(sc_instance_update.call_args_list, [])

        # Verify that PTG update removing prs cleansup the chain instances
        self._verify_ptg_prs_unset_cleansup_chain(provider_ptg, [prs1['id']])

    def test_ptg_create_does_not_affect_other_chains(self):
        scs1_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", scs1_id)
        prs1 = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']
        self._verify_prs_rules(prs1['id'])
        provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs()
        self._verify_prs_rules(prs1['id'])

        # No service chain instances until we have provider and consumer prs
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual([], sc_instances['servicechain_instances'])

        # One service chain instance should be created when PTGs are
        # updated with provided and consumed prs
        self.update_policy_target_group(
            provider_ptg, provided_policy_rule_sets={prs1['id']: ''},
            consumed_policy_rule_sets={}, expected_res_status=200)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(1, len(sc_instances['servicechain_instances']))
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance, provider_ptg, consumer_ptg,
            [scs1_id], classifier_id=classifier_id)

        # Verify that creating a new PTG providing the same PRS does not affect
        # existing chains
        with mock.patch.object(
                servicechain_db.ServiceChainDbPlugin,
                'update_servicechain_instance') as sc_instance_update:
            provider_ptg_new = self.create_policy_target_group(
                provided_policy_rule_sets={prs1['id']: ''},
                expected_res_status=webob.exc.HTTPCreated.code)[
                    'policy_target_group']['id']
            self._verify_prs_rules(prs1['id'])
            sc_instances_new = self._list(SERVICECHAIN_INSTANCES)[
                'servicechain_instances']
            self.assertEqual(2, len(sc_instances_new))
            sc_instances_provider_ptg_ids = set()
            for sc_instance in sc_instances_new:
                sc_instances_provider_ptg_ids.add(
                    sc_instance['provider_ptg_id'])
            expected_provider_ptg_ids = set([provider_ptg, provider_ptg_new])
            self.assertEqual(expected_provider_ptg_ids,
                             sc_instances_provider_ptg_ids)
            self.assertEqual(sc_instance_update.call_args_list, [])

    def test_action_spec_value_update(self):
        scs1_id = self._create_servicechain_spec()
        action_id, classifier_id, policy_rule_id = (
                            self._create_tcp_redirect_rule("20:90", scs1_id))

        child_prs = self.create_policy_rule_set(
            name="prs", policy_rules=[policy_rule_id])
        child_prs_id = child_prs['policy_rule_set']['id']
        self._verify_prs_rules(child_prs_id)

        scs2_id = self._create_servicechain_spec()
        parent_action = self.create_policy_action(
            name="action2", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=scs2_id)
        parent_action_id = parent_action['policy_action']['id']
        parent_policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=[parent_action_id])
        parent_policy_rule_id = parent_policy_rule['policy_rule']['id']
        self.create_policy_rule_set(
            name="c1", policy_rules=[parent_policy_rule_id],
            child_policy_rule_sets=[child_prs_id])

        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                        child_prs_id)
        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        # We should have one service chain instance created now
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [scs2_id, scs1_id], classifier_id=classifier_id)

        # Update child spec and verify that SC instance is updated properly
        scs3_id = self._create_servicechain_spec()
        action = {'policy_action': {'action_value': scs3_id}}
        req = self.new_update_request('policy_actions', action, action_id)
        action = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [scs2_id, scs3_id], classifier_id=classifier_id)

        # Update parent spec and verify that SC instance is updated properly
        scs4_id = self._create_servicechain_spec()
        action = {'policy_action': {'action_value': scs4_id}}
        req = self.new_update_request(
                            'policy_actions', action, parent_action_id)
        action = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        # We should have one service chain instance created now
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [scs4_id, scs3_id], classifier_id=classifier_id)

        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_rule_update_updates_chain(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule("20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self._verify_prs_rules(policy_rule_set_id)
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            policy_rule_set_id)

        self._verify_prs_rules(policy_rule_set_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # One service chain instance should be created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id, [scs_id])

        # Update policy rule with new classifier and verify instance is updated
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="80",
            direction='bi')['policy_classifier']
        rule = {'policy_rule': {'policy_classifier_id': classifier['id']}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        self.deserialize(self.fmt, req.get_response(self.ext_api))

        self._verify_prs_rules(policy_rule_set_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # The service chain instance should be updated with new classifier
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance_updated = sc_instances['servicechain_instances'][0]
        sc_instance.update({'classifier_id': classifier['id']})
        self.assertEqual(sc_instance, sc_instance_updated)

        # Verify redirect action replacement in rule
        scs2_id = self._create_servicechain_spec()
        action2 = self.create_policy_action(
            action_type='redirect', action_value=scs2_id)['policy_action']
        rule2 = {'policy_rule': {'policy_actions': [action2['id']]}}
        req = self.new_update_request('policy_rules', rule2, policy_rule_id)
        rule2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                    'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        self.assertEqual(sc_instance['id'], sc_instances[0]['id'])
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [scs2_id], classifier_id=classifier['id'])

        # Verify Removing Redirect action deletes the chain
        action3 = self.create_policy_action(
                            action_type='allow')['policy_action']
        rule = {'policy_rule': {'policy_actions': [action3['id']]}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        rule = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(0, len(sc_instances))

        # Verify redirect action addition in rule
        rule = {'policy_rule': {'policy_actions': [action2['id']]}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        rule = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [scs2_id], classifier_id=classifier['id'])

        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_redirect_to_ep_update(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']

        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                self.create_external_segment(
                    shared=True, tenant_id='admin', name="default",
                    subnet_id=sub['subnet']['id'])

                ep = self.create_external_policy()
                provider = self.create_policy_target_group(
                    provided_policy_rule_sets={policy_rule_set_id: ''})

                self.update_external_policy(
                    ep['external_policy']['id'],
                    consumed_policy_rule_sets={policy_rule_set_id: ''})
                self._verify_prs_rules(policy_rule_set_id)
                sc_instance_list_req = self.new_list_request(
                    SERVICECHAIN_INSTANCES)
                res = sc_instance_list_req.get_response(self.ext_api)
                sc_instances = self.deserialize(self.fmt, res)
                # We should have one service chain instance created now
                self.assertEqual(
                    1, len(sc_instances['servicechain_instances']))
                sc_instance = sc_instances['servicechain_instances'][0]
                self._assert_proper_chain_instance(
                    sc_instance, provider['policy_target_group']['id'],
                    ep['external_policy']['id'], [scs_id])

                self.delete_policy_target_group(
                    provider['policy_target_group']['id'],
                    expected_res_status=webob.exc.HTTPNoContent.code)
                sc_instance_list_req = self.new_list_request(
                    SERVICECHAIN_INSTANCES)
                res = sc_instance_list_req.get_response(self.ext_api)
                sc_instances = self.deserialize(self.fmt, res)
                self.assertEqual(
                    0, len(sc_instances['servicechain_instances']))

    def test_redirect_to_ep(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']

        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                self.create_external_segment(
                    shared=True, tenant_id='admin', name="default",
                    subnet_id=sub['subnet']['id'])

                ep = self.create_external_policy(
                    consumed_policy_rule_sets={policy_rule_set_id: ''})
                provider = self.create_policy_target_group(
                    provided_policy_rule_sets={policy_rule_set_id: ''})

                self._verify_prs_rules(policy_rule_set_id)
                sc_instance_list_req = self.new_list_request(
                    SERVICECHAIN_INSTANCES)
                res = sc_instance_list_req.get_response(self.ext_api)
                sc_instances = self.deserialize(self.fmt, res)
                # We should have one service chain instance created now
                self.assertEqual(
                    1, len(sc_instances['servicechain_instances']))
                sc_instance = sc_instances['servicechain_instances'][0]
                self._assert_proper_chain_instance(
                    sc_instance, provider['policy_target_group']['id'],
                    ep['external_policy']['id'], [scs_id])

                # Verify that PTG delete cleans up the chain instances
                self.delete_policy_target_group(
                    provider['policy_target_group']['id'],
                    expected_res_status=webob.exc.HTTPNoContent.code)
                sc_instance_list_req = self.new_list_request(
                    SERVICECHAIN_INSTANCES)
                res = sc_instance_list_req.get_response(self.ext_api)
                sc_instances = self.deserialize(self.fmt, res)
                self.assertEqual(
                    0, len(sc_instances['servicechain_instances']))

    def test_parent_ruleset_update_for_redirect(self):
        scs_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs_id)

        child_prs = self.create_policy_rule_set(
            name="prs", policy_rules=[policy_rule_id])
        child_prs_id = child_prs['policy_rule_set']['id']

        self._verify_prs_rules(child_prs_id)

        parent_scs_id = self._create_servicechain_spec(node_types='FIREWALL')
        parent_action = self.create_policy_action(
            name="action2", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=parent_scs_id)
        parent_action_id = parent_action['policy_action']['id']
        parent_policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=[parent_action_id])
        parent_policy_rule_id = parent_policy_rule['policy_rule']['id']

        parent_prs = self.create_policy_rule_set(
            name="c1", policy_rules=[parent_policy_rule_id])
        parent_prs_id = parent_prs['policy_rule_set']['id']

        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                                child_prs_id)
        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id, [scs_id])

        self.update_policy_rule_set(parent_prs_id, expected_res_status=200,
                                    child_policy_rule_sets=[child_prs_id])

        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have a new service chain instance created now from both
        # parent and child specs
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id,
                                           [parent_scs_id, scs_id])

        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_enforce_parent_redirect_after_ptg_create(self):
        scs_id = self._create_servicechain_spec()
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs_id)

        child_prs = self.create_policy_rule_set(
            name="prs", policy_rules=[policy_rule_id])
        child_prs_id = child_prs['policy_rule_set']['id']
        self._verify_prs_rules(child_prs_id)

        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                                child_prs_id)
        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance, provider_ptg_id, consumer_ptg_id,
            [scs_id], classifier_id=classifier_id)

        parent_scs_id = self._create_servicechain_spec(node_types='FIREWALL')
        parent_action = self.create_policy_action(
            name="action2", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=parent_scs_id)
        parent_action_id = parent_action['policy_action']['id']
        parent_policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=[parent_action_id])
        parent_policy_rule_id = parent_policy_rule['policy_rule']['id']

        parent_prs = self.create_policy_rule_set(
            name="c1", policy_rules=[parent_policy_rule_id],
            child_policy_rule_sets=[child_prs_id])
        parent_prs_id = parent_prs['policy_rule_set']['id']

        self._verify_prs_rules(child_prs_id)

        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have a new service chain instance created now from both
        # parent and child specs
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id,
                                           [parent_scs_id, scs_id])

        # Delete parent ruleset and verify that the parent spec association
        # is removed from servicechain instance
        self.delete_policy_rule_set(
            parent_prs_id, expected_res_status=webob.exc.HTTPNoContent.code)
        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id, [scs_id])

        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_hierarchical_redirect(self):
        scs_id = self._create_servicechain_spec()
        action_id, classifier_id, policy_rule_id = (
            self._create_tcp_redirect_rule("20:90", scs_id))

        child_prs = self.create_policy_rule_set(
            name="prs", policy_rules=[policy_rule_id])
        child_prs_id = child_prs['policy_rule_set']['id']
        self._verify_prs_rules(child_prs_id)

        parent_scs_id = self._create_servicechain_spec()
        parent_action = self.create_policy_action(
            name="action2", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=parent_scs_id)
        parent_action_id = parent_action['policy_action']['id']
        parent_policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=[parent_action_id])
        parent_policy_rule_id = parent_policy_rule['policy_rule']['id']

        self.create_policy_rule_set(
            name="c1", policy_rules=[parent_policy_rule_id],
            child_policy_rule_sets=[child_prs_id])
        provider_ptg1_id, consumer_ptg1_id = (
                self._create_provider_consumer_ptgs(child_prs_id))
        provider_ptg2_id, consumer_ptg2_id = (
                self._create_provider_consumer_ptgs(child_prs_id))
        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have one service chain instance created now
        self.assertEqual(2, len(sc_instances['servicechain_instances']))
        sc_instances = sc_instances['servicechain_instances']
        sc_instances_provider_ptg_ids = set()
        for sc_instance in sc_instances:
            sc_instances_provider_ptg_ids.add(sc_instance['provider_ptg_id'])
            self.assertEqual(sc_instance['servicechain_specs'],
                             [parent_scs_id, scs_id])
        expected_provider_ptg_ids = set([provider_ptg1_id, provider_ptg2_id])
        self.assertEqual(expected_provider_ptg_ids,
                         sc_instances_provider_ptg_ids)

        with mock.patch.object(
                servicechain_db.ServiceChainDbPlugin,
                'update_servicechain_instance') as sc_instance_update:
            sc_instance_update.return_value = {'id': uuidutils.generate_uuid()}
            scs2_id = self._create_servicechain_spec()
            action = self.create_policy_action(
                                action_type='redirect',
                                action_value=scs2_id)['policy_action']
            policy_rule = self.create_policy_rule(
                                policy_classifier_id=classifier_id,
                                policy_actions=[action['id']])['policy_rule']
            policy_rule2_id = policy_rule['id']
            self.update_policy_rule_set(child_prs_id,
                                        expected_res_status=200,
                                        policy_rules=[policy_rule2_id])
            self._verify_prs_rules(child_prs_id)
            sc_instances_updated = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
            self.assertEqual(2, len(sc_instances_updated))
            self.assertEqual(sc_instances, sc_instances_updated)

            expected_update_calls = []
            instance_data = {'servicechain_instance': {
                                'classifier_id': classifier_id,
                                'servicechain_specs': [parent_scs_id,
                                                       scs2_id]}}
            for sc_instance in sc_instances:
                expected_update_calls.append(
                    mock.call(mock.ANY, sc_instance['id'], instance_data))
            self._check_call_list(expected_update_calls,
                                  sc_instance_update.call_args_list)

        # Deleting one group should end up deleting the two service chain
        # Instances associated to it
        req = self.new_delete_request(
            'policy_target_groups', provider_ptg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(1, len(sc_instances['servicechain_instances']))

        self._verify_ptg_delete_cleanup_chain(provider_ptg2_id)

    def test_rule_update_hierarchial_prs(self):
        scs_id = self._create_servicechain_spec()
        action_id, classifier_id, policy_rule_id = (
            self._create_tcp_redirect_rule("20:90", scs_id))

        child_prs = self.create_policy_rule_set(
            name="prs", policy_rules=[policy_rule_id])
        child_prs_id = child_prs['policy_rule_set']['id']
        self._verify_prs_rules(child_prs_id)
        parent_scs_id = self._create_servicechain_spec()
        parent_action = self.create_policy_action(
            name="action2", action_type=gconst.GP_ACTION_REDIRECT,
            action_value=parent_scs_id)
        parent_action_id = parent_action['policy_action']['id']
        parent_policy_rule = self.create_policy_rule(
            name='pr1', policy_classifier_id=classifier_id,
            policy_actions=[parent_action_id])
        parent_policy_rule_id = parent_policy_rule['policy_rule']['id']
        self.create_policy_rule_set(
            name="c1", policy_rules=[parent_policy_rule_id],
            child_policy_rule_sets=[child_prs_id])

        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            child_prs_id)

        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(
            sc_instance, provider_ptg_id, consumer_ptg_id,
            [parent_scs_id, scs_id])

        # Update policy rule with new classifier and verify instance is
        # deleted because of classifier mismatch
        classifier2 = self.create_policy_classifier(
            protocol='TCP', port_range="80",
            direction='bi')['policy_classifier']
        policy_rule = {'policy_rule': {
                                'policy_classifier_id': classifier2['id']}}
        req = self.new_update_request('policy_rules', policy_rule,
                                      policy_rule_id)
        policy_rule = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))

        self._verify_prs_rules(child_prs_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(0, len(sc_instances['servicechain_instances']))

        # Verify restoring classifier recreates chain
        rule = {'policy_rule': {'policy_classifier_id': classifier_id}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        rule = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        sc_instance = sc_instances[0]
        self.assertEqual(1, len(sc_instances))
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [parent_scs_id, scs_id], classifier_id=classifier_id)

        # Verify redirect action replacement in rule
        scs2_id = self._create_servicechain_spec()
        action2 = self.create_policy_action(
            action_type='redirect',
            action_value=scs2_id)['policy_action']
        rule2 = {'policy_rule': {'policy_actions': [action2['id']]}}
        req = self.new_update_request('policy_rules', rule2, policy_rule_id)
        rule2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        self.assertEqual(sc_instance['id'], sc_instances[0]['id'])
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [parent_scs_id, scs2_id], classifier_id=classifier_id)

        # Verify Removing child Redirect action deleted the chain
        action3 = self.create_policy_action(
            action_type='allow')['policy_action']
        rule = {'policy_rule': {'policy_actions': [action3['id']]}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        rule = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(0, len(sc_instances))

        # Verify redirect action adding in rule
        rule = {'policy_rule': {'policy_actions': [action2['id']]}}
        req = self.new_update_request('policy_rules', rule, policy_rule_id)
        rule = self.deserialize(self.fmt, req.get_response(self.ext_api))
        sc_instances = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
        self.assertEqual(1, len(sc_instances))
        self._assert_proper_chain_instance(
            sc_instances[0], provider_ptg_id, consumer_ptg_id,
            [parent_scs_id, scs2_id], classifier_id=classifier_id)
        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_redirect_multiple_ptgs_single_prs(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        self._verify_prs_rules(policy_rule_set_id)

        #Create 2 provider and 2 consumer PTGs
        provider_ptg1_id, consumer_ptg1_id = (
                self._create_provider_consumer_ptgs(policy_rule_set_id))
        provider_ptg2_id, consumer_ptg2_id = (
                self._create_provider_consumer_ptgs(policy_rule_set_id))
        self._verify_prs_rules(policy_rule_set_id)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        # We should have 4 service chain instances created now
        self.assertEqual(2, len(sc_instances['servicechain_instances']))
        sc_instances = sc_instances['servicechain_instances']
        sc_instances_provider_ptg_ids = set()
        for sc_instance in sc_instances:
            sc_instances_provider_ptg_ids.add(sc_instance['provider_ptg_id'])
        expected_provider_ptg_ids = set([provider_ptg1_id, provider_ptg2_id])
        self.assertEqual(expected_provider_ptg_ids,
                         sc_instances_provider_ptg_ids)

        with mock.patch.object(
                servicechain_db.ServiceChainDbPlugin,
                'update_servicechain_instance') as sc_instance_update:
            sc_instance_update.return_value = {'id': uuidutils.generate_uuid()}
            scs2_id = self._create_servicechain_spec()
            _, classifier_id, policy_rule2_id = self._create_tcp_redirect_rule(
                                                "80", scs2_id)
            self.update_policy_rule_set(policy_rule_set_id,
                                        expected_res_status=200,
                                        policy_rules=[policy_rule2_id])
            self._verify_prs_rules(policy_rule_set_id)
            sc_instances_updated = self._list(SERVICECHAIN_INSTANCES)[
                                                'servicechain_instances']
            self.assertEqual(2, len(sc_instances_updated))
            self.assertEqual(sc_instances, sc_instances_updated)

            expected_update_calls = []
            instance_data = {'servicechain_instance': {
                                        'classifier_id': classifier_id,
                                        'servicechain_specs': [scs2_id]}}
            for sc_instance in sc_instances:
                expected_update_calls.append(
                    mock.call(mock.ANY, sc_instance['id'], instance_data))
            self._check_call_list(expected_update_calls,
                                  sc_instance_update.call_args_list)

        # Deleting one group should end up deleting the two service chain
        # Instances associated to it
        req = self.new_delete_request(
            'policy_target_groups', consumer_ptg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(2, len(sc_instances['servicechain_instances']))

        req = self.new_delete_request('policy_target_groups', provider_ptg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        sc_instances = self._list(SERVICECHAIN_INSTANCES)
        self.assertEqual(1, len(sc_instances['servicechain_instances']))
        sc_instance = sc_instances['servicechain_instances'][0]
        self.assertNotEqual(sc_instance['provider_ptg_id'], provider_ptg1_id)

        self._verify_ptg_delete_cleanup_chain(provider_ptg2_id)


class TestServiceChainAdminOwner(TestServiceChain):

    def setUp(self, **kwargs):
        mock.patch('gbpservice.neutron.services.grouppolicy.drivers.'
                   'chain_mapping.ChainMappingDriver.'
                   'chain_tenant_keystone_client').start()
        res = mock.patch('gbpservice.neutron.services.grouppolicy.drivers.'
                         'chain_mapping.ChainMappingDriver.'
                         'chain_tenant_id').start()
        res.return_value = CHAIN_TENANT_ID
        super(TestServiceChainAdminOwner, self).setUp(**kwargs)

    def test_chain_tenant_id(self):
        pass

    def test_chain_tenant_keystone_client(self):
        pass

    def _assert_proper_chain_instance(self, sc_instance, provider_ptg_id,
                                      consumer_ptg_id, scs_id_list,
                                      classifier_id=None):
        self.assertEqual(sc_instance['provider_ptg_id'], provider_ptg_id)
        self.assertEqual(sc_instance['consumer_ptg_id'], 'N/A')
        self.assertEqual(sc_instance['tenant_id'], CHAIN_TENANT_ID)
        self.assertEqual(scs_id_list, sc_instance['servicechain_specs'])
        if classifier_id:
            self.assertEqual(sc_instance['classifier_id'], classifier_id)


class TestExternalSegment(ResourceMappingTestCase):

    def test_implicit_subnet_rejected(self):
        res = self.create_external_segment(expected_res_status=400)
        self.assertEqual('ImplicitSubnetNotSupported',
                         res['NeutronError']['type'])

    def test_explicit_subnet_lifecycle(self):

        with self.network(router__external=True) as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub:
                es = self.create_external_segment(
                    subnet_id=sub['subnet']['id'])['external_segment']
                subnet_id = es['subnet_id']
                self.assertIsNotNone(subnet_id)
                res = self.new_show_request('subnets', subnet_id)
                subnet = self.deserialize(self.fmt, res.get_response(self.api))

                self.assertEqual(subnet['subnet']['cidr'], es['cidr'])
                self.assertEqual(subnet['subnet']['ip_version'],
                                 es['ip_version'])

    def test_update(self, proxy_ip_pool1=None, proxy_ip_pool2=None):
        with self.network(router__external=True) as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub:
                changes = {'port_address_translation': True}
                es = self.create_external_segment(
                    subnet_id=sub['subnet']['id'])['external_segment']
                for k, v in changes.iteritems():
                    res = self.update_external_segment(
                        es['id'], expected_res_status=400, **{k: v})
                    self.assertEqual('InvalidAttributeUpdateForES',
                                     res['NeutronError']['type'])
                # Verify route updated correctly
                route = {'destination': '0.0.0.0/0', 'nexthop': None}
                self.update_external_segment(
                    es['id'], expected_res_status=200,
                    external_routes=[route])
                pr = self._create_ssh_allow_rule()
                prs = self.create_policy_rule_set(
                    policy_rules=[pr['id']])['policy_rule_set']
                l3p1 = self.create_l3_policy(
                    ip_pool='192.168.0.0/16')['l3_policy']
                if not proxy_ip_pool1:
                    l3p2 = self.create_l3_policy(
                        ip_pool='192.128.0.0/16',
                        external_segments={es['id']: []})['l3_policy']
                else:
                    l3p2 = self.create_l3_policy(
                        ip_pool='192.128.0.0/16', proxy_ip_pool=proxy_ip_pool1,
                        external_segments={es['id']: []})['l3_policy']
                self.create_external_policy(
                    external_segments=[es['id']],
                    provided_policy_rule_sets={prs['id']: ''})
                expected_cidrs = self._calculate_expected_external_cidrs(
                    es, [l3p1, l3p2])
                mapping = self._get_prs_mapping(prs['id'])

                # Not using _verify_prs_rules here because it's testing that
                # some specific delta rules are applied/removed instead of
                # the whole PRS state.
                attrs = {'security_group_id': [mapping.consumed_sg_id],
                         'direction': ['ingress'],
                         'protocol': ['tcp'],
                         'port_range_min': [22],
                         'port_range_max': [22],
                         'remote_ip_prefix': None}
                for cidr in expected_cidrs:
                    attrs['remote_ip_prefix'] = [cidr]
                    self.assertTrue(self._get_sg_rule(**attrs))
                self._verify_prs_rules(prs['id'])
                # Update the route and verify the SG rules changed
                route = {'destination': '172.0.0.0/8', 'nexthop': None}
                es = self.update_external_segment(
                    es['id'], expected_res_status=200,
                    external_routes=[route])['external_segment']

                # Verify the old rules have been deleted
                new_cidrs = self._calculate_expected_external_cidrs(
                    es, [l3p1, l3p2])
                removed = set(expected_cidrs) - set(new_cidrs)
                for cidr in removed:
                    attrs['remote_ip_prefix'] = [cidr]
                    self.assertFalse(self._get_sg_rule(**attrs))

                expected_cidrs = new_cidrs
                # Verify new rules exist
                for cidr in expected_cidrs:
                    attrs['remote_ip_prefix'] = [cidr]
                    self.assertTrue(self._get_sg_rule(**attrs))

                # Creating a new L3P changes the definition of what's external
                # and what is not
                if proxy_ip_pool2:
                    l3p3 = self.create_l3_policy(
                        ip_pool='192.64.0.0/16',
                        proxy_ip_pool=proxy_ip_pool2)['l3_policy']
                else:
                    l3p3 = self.create_l3_policy(
                        ip_pool='192.64.0.0/16')['l3_policy']
                new_cidrs = self._calculate_expected_external_cidrs(es,
                                                           [l3p1, l3p2, l3p3])

                # Verify removed rules
                removed = set(expected_cidrs) - set(new_cidrs)
                for cidr in removed:
                    attrs['remote_ip_prefix'] = [cidr]
                    self.assertFalse(self._get_sg_rule(**attrs))

                expected_cidrs = new_cidrs
                # Verify new rules exist
                for cidr in expected_cidrs:
                    attrs['remote_ip_prefix'] = [cidr]
                    self.assertTrue(self._get_sg_rule(**attrs))

    def test_update_different_tenant(self):
        with self.network(router__external=True, shared=True,
                          tenant_id='admin') as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub:
                es = self.create_external_segment(
                    subnet_id=sub['subnet']['id'],
                    shared=True, tenant_id='admin')['external_segment']
                l3p = self.create_l3_policy(
                    ip_pool='192.128.0.0/16',
                    external_segments={es['id']: []})['l3_policy']
                l2p = self.create_l2_policy(
                    l3_policy_id=l3p['id'])['l2_policy']
                rule = self._create_http_allow_rule()
                prs = self.create_policy_rule_set(
                    policy_rules=[rule['id']])['policy_rule_set']
                self.create_policy_target_group(
                    l2_policy_id=l2p['id'],
                    provided_policy_rule_sets={prs['id']: ''})
                self.create_external_policy(
                    external_segments=[es['id']],
                    provided_policy_rule_sets={prs['id']: ''})

                self._verify_prs_rules(prs['id'])
                route = {'destination': '0.0.0.0/0', 'nexthop': None}
                self.update_external_segment(
                    es['id'], expected_res_status=200,
                    external_routes=[route], is_admin_context=True)
                self._verify_prs_rules(prs['id'])

    def test_implicit_es(self):
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'])['external_segment']
                l3p = self.create_l3_policy()['l3_policy']
                self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
                self.assertEqual('192.168.0.2',
                                 l3p['external_segments'][es['id']][0])

                ep = self.create_external_policy()['external_policy']
                self.assertEqual(es['id'], ep['external_segments'][0])

                prs = self.create_policy_rule_set()['policy_rule_set']
                ep = self.update_external_policy(
                    ep['id'], provided_policy_rule_sets={prs['id']: ''},
                    expected_res_status=200)

    def test_implicit_es_shared(self):
        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    shared=True,
                    tenant_id='admin', name="default",
                    subnet_id=sub['subnet']['id'])['external_segment']
                l3p = self.create_l3_policy()['l3_policy']
                self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
                self.assertEqual('192.168.0.2',
                                 l3p['external_segments'][es['id']][0])

                ep = self.create_external_policy()['external_policy']
                self.assertEqual(es['id'], ep['external_segments'][0])

                prs = self.create_policy_rule_set()['policy_rule_set']
                ep = self.update_external_policy(
                    ep['id'], provided_policy_rule_sets={prs['id']: ''},
                    expected_res_status=200)

    def test_delete(self):
        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'])['external_segment']
                self.delete_external_segment(es['id'], expected_res_status=204)
                self.show_external_segment(es['id'], expected_res_status=404)

    def test_delete_in_use(self):
        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'])['external_segment']
                self.create_l3_policy()
                # ES is in use
                res = self.delete_external_segment(es['id'],
                                                   expected_res_status=409)
                self.assertEqual('ExternalSegmentInUse',
                                 res['NeutronError']['type'])
                self.show_external_segment(es['id'], expected_res_status=200)

    def test_update_l3p_remove_es(self):
        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                self.create_external_segment(
                    name="default", subnet_id=sub['subnet']['id'])
                l3p = self.create_l3_policy()['l3_policy']
                self.update_l3_policy(l3p['id'], external_segments={},
                                      expected_res_status=200)
                l3p = self.show_l3_policy(l3p['id'])['l3_policy']
                self.assertEqual({}, l3p['external_segments'])


class TestExternalPolicy(ResourceMappingTestCase):

    def test_create(self):
        with self.network(router__external=True) as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub1:
                with self.subnet(cidr='10.10.2.0/24', network=net) as sub2:
                    es1 = self.create_external_segment(
                        subnet_id=sub1['subnet']['id'],
                        shared=True)['external_segment']
                    es2 = self.create_external_segment(
                        subnet_id=sub2['subnet']['id'])['external_segment']
                    # Shared Rejected
                    res = self.create_external_policy(
                        expected_res_status=400, external_segments=[es1['id']],
                        shared=True)
                    self.assertEqual('InvalidSharedResource',
                                     res['NeutronError']['type'])
                    # Multiple ES reject
                    res = self.create_external_policy(
                        expected_res_status=400,
                        external_segments=[es1['id'], es2['id']])
                    self.assertEqual('MultipleESPerEPNotSupported',
                                     res['NeutronError']['type'])
                    # No ES reject
                    res = self.create_external_policy(
                        expected_res_status=400, external_segments=[])
                    self.assertEqual('ESIdRequiredWhenCreatingEP',
                                     res['NeutronError']['type'])

                    # Multiple EP per tenant rejected
                    self.create_external_policy(external_segments=[es1['id']],
                                                expected_res_status=201)
                    res = self.create_external_policy(
                        expected_res_status=400, external_segments=[es2['id']])
                    self.assertEqual('OnlyOneEPPerTenantAllowed',
                                     res['NeutronError']['type'])

    def test_update(self):
        with self.network(router__external=True) as net:
            with self.subnet(cidr='10.10.1.0/24', network=net) as sub1:
                with self.subnet(cidr='10.10.2.0/24', network=net) as sub2:
                    route = {'destination': '172.0.0.0/8', 'nexthop': None}
                    es1 = self.create_external_segment(
                        subnet_id=sub1['subnet']['id'],
                        external_routes=[route],
                        shared=True, is_admin_context=True)['external_segment']
                    es2 = self.create_external_segment(
                        subnet_id=sub2['subnet']['id'])['external_segment']
                    ep = self.create_external_policy(
                        external_segments=[es1['id']], expected_res_status=201)
                    ep = ep['external_policy']
                    # ES update rejectes
                    res = self.update_external_policy(
                        ep['id'], external_segments=[es2['id']],
                        expected_res_status=400)
                    self.assertEqual('ESUpdateNotSupportedForEP',
                                     res['NeutronError']['type'])
                    # Shared update rejected
                    res = self.update_external_policy(
                        ep['id'], shared=True, is_admin_context=True,
                        expected_res_status=400)
                    self.assertEqual('InvalidSharedResource',
                                     res['NeutronError']['type'])
                    # Rules changed when changing PRS
                    pr_ssh = self._create_ssh_allow_rule()
                    pr_http = self._create_http_allow_rule()

                    prs_ssh = self.create_policy_rule_set(
                        policy_rules=[pr_ssh['id']])['policy_rule_set']
                    prs_http = self.create_policy_rule_set(
                        policy_rules=[pr_http['id']])['policy_rule_set']

                    self.update_external_policy(
                        ep['id'], provided_policy_rule_sets={prs_ssh['id']:
                                                             ''},
                        consumed_policy_rule_sets={prs_ssh['id']: ''},
                        expected_res_status=200)

                    expected_cidrs = self._calculate_expected_external_cidrs(
                        es1, [])
                    self.assertTrue(len(expected_cidrs) > 0)
                    current_ssh_rules = self._verify_prs_rules(prs_ssh['id'])
                    self._verify_prs_rules(prs_http['id'])

                    # Now swap the contract
                    self.update_external_policy(
                        ep['id'], provided_policy_rule_sets={prs_http['id']:
                                                             ''},
                        consumed_policy_rule_sets={prs_http['id']: ''},
                        expected_res_status=200)

                    # SSH rules removed
                    for rule in current_ssh_rules:
                        if not (rule['direction'] == ['egress']
                                and rule['remote_ip_prefix'] == ['0.0.0.0/0']):
                            self.assertFalse(self._get_sg_rule(**rule))

                    # HTTP Added
                    current_http_rules = self._verify_prs_rules(prs_http['id'])

                    # All removed
                    self.update_external_policy(
                        ep['id'], provided_policy_rule_sets={},
                        consumed_policy_rule_sets={}, expected_res_status=200)
                    for rule in current_http_rules:
                        if not (rule['direction'] == ['egress']
                                and rule['remote_ip_prefix'] == ['0.0.0.0/0']):
                            self.assertFalse(self._get_sg_rule(**rule))


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


class TestPolicyRule(ResourceMappingTestCase):

    def test_shared_create_multiple_redirect_actions_rule(self):
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        action2 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        res = self.create_policy_rule(
            expected_res_status=400,
            policy_classifier_id=classifier['id'],
            policy_actions=[action1['id'], action2['id']])
        self.assertEqual('MultipleRedirectActionsNotSupportedForRule',
                         res['NeutronError']['type'])


class TestNetworkServicePolicy(ResourceMappingTestCase):

    def test_create_nsp_multiple_ptgs(self):
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
        # Create two PTGs that use this NSP
        ptg1 = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg2 = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        # Update the PTGs and unset the NSP used
        self.update_policy_target_group(
                    ptg1['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)
        self.update_policy_target_group(
                    ptg2['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)

    def test_unsupported_nsp_parameters_rejected(self):
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "self_subnet", "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "external_subnet",
                 "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_single", "value": "self_subnet", "name": "vip"},
                {"type": "ip_single", "value": "self_subnet", "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_nsp_cleanup_on_unset(self):
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg_subnet_id = ptg['subnets'][0]
        subnet = self._show_subnet(ptg_subnet_id)['subnet']
        initial_allocation_pool = subnet['allocation_pools']
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        # Update PTG, associating a NSP with it and verify that an IP is
        # reserved from the PTG subnet allocation pool
        self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)['subnet']
        allocation_pool_after_nsp = subnet['allocation_pools']
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('start')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('start')))
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('end')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('end')) + 1)

        # Update the PTGs and unset the NSP used and verify that the IP is
        # restored to the PTG subnet allocation pool
        self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)['subnet']
        allocation_pool_after_nsp_cleanup = subnet['allocation_pools']
        self.assertEqual(
                initial_allocation_pool, allocation_pool_after_nsp_cleanup)

    def test_create_nsp_ip_pool_multiple_ptgs(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4,
                    ip_pool='192.168.0.0/24',
                    expected_res_status=webob.exc.HTTPCreated.code)
                nsp = self.create_network_service_policy(
                        network_service_params=[
                                    {"type": "ip_pool", "value": "nat_pool",
                                     "name": "external_access"}],
                        expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
                # Create two PTGs that use this NSP
                ptg1 = self.create_policy_target_group(
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                ptg2 = self.create_policy_target_group(
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                pt = self.create_policy_target(
                        name="pt1", policy_target_group_id=ptg1['id'])
                port_id = pt['policy_target']['port_id']
                req = self.new_show_request('ports', port_id, fmt=self.fmt)
                port = self.deserialize(self.fmt,
                                        req.get_response(self.api))['port']

                res = self._list('floatingips')['floatingips']
                self.assertEqual(1, len(res))
                self.assertEqual(res[0]['fixed_ip_address'],
                                 port['fixed_ips'][0]['ip_address'])

                pt2 = self.create_policy_target(
                        name="pt2", policy_target_group_id=ptg1['id'])
                port2_id = pt2['policy_target']['port_id']
                req = self.new_show_request('ports', port2_id, fmt=self.fmt)
                port = self.deserialize(self.fmt,
                                        req.get_response(self.api))['port']

                res = self._list('floatingips')['floatingips']
                self.assertEqual(2, len(res))

                # Update the PTGs and unset the NSP used
                # TODO(Magesh): Remove the floating IPs here
                self.update_policy_target_group(
                            ptg1['id'],
                            network_service_policy_id=None,
                            expected_res_status=webob.exc.HTTPOk.code)
                self.update_policy_target_group(
                            ptg2['id'],
                            network_service_policy_id=None,
                            expected_res_status=webob.exc.HTTPOk.code)

    def test_nsp_fip_single(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4,
                    ip_pool='192.168.0.0/24',
                    expected_res_status=webob.exc.HTTPCreated.code)
                ptg = self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                nsp = self.create_network_service_policy(
                            network_service_params=[
                                    {"type": "ip_single", "value": "nat_pool",
                                     "name": "vip"}],
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

                # Update PTG, associating a NSP with it and verify that a FIP
                # is allocated
                self.update_policy_target_group(
                            ptg['id'],
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPOk.code)
                mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
                self.assertNotEqual([], mapping)
                self.assertEqual(mapping[0].service_policy_id, nsp['id'])
                self.assertIsNotNone(mapping[0].floatingip_id)

                # Update the PTGs and unset the NSP used and verify that the IP
                # is restored to the PTG subnet allocation pool
                self.update_policy_target_group(
                            ptg['id'],
                            network_service_policy_id=None,
                            expected_res_status=webob.exc.HTTPOk.code)
                mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
                self.assertEqual([], mapping)

    def test_nsp_fip_single_different_pool(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                # Create NAT Pool on a different subnet
                self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4,
                    ip_pool='192.168.1.0/24',
                    expected_res_status=webob.exc.HTTPCreated.code)
                ptg = self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                nsp = self.create_network_service_policy(
                            network_service_params=[
                                    {"type": "ip_single", "value": "nat_pool",
                                     "name": "vip"}],
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
                # Update PTG, associating a NSP with it and verify that a FIP
                # is allocated
                self.update_policy_target_group(
                            ptg['id'],
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPOk.code)
                mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
                self.assertNotEqual([], mapping)
                self.assertEqual(mapping[0].service_policy_id, nsp['id'])
                self.assertIsNotNone(mapping[0].floatingip_id)

                fip = self._get_object(
                    'floatingips', mapping[0].floatingip_id,
                    self.ext_api)['floatingip']

                # Verify FIP is in the new subnet
                self.assertTrue(
                    netaddr.IPAddress(fip['floating_ip_address']) in
                    netaddr.IPNetwork('192.168.1.0/24'),
                    "IP %s not in pool %s" % (fip['floating_ip_address'],
                                              '192.168.1.0/24'))
                # Update the PTGs and unset the NSP used and verify that the IP
                # is restored to the PTG subnet allocation pool
                self.update_policy_target_group(
                            ptg['id'],
                            network_service_policy_id=None,
                            expected_res_status=webob.exc.HTTPOk.code)
                mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
                self.assertEqual([], mapping)

    def test_nsp_rejected_without_nat_pool(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                ptg = self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                nsp = self.create_network_service_policy(
                            network_service_params=[
                                    {"type": "ip_single", "value": "nat_pool",
                                     "name": "vip"}],
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
                data = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
                self.assertEqual('NSPRequiresNatPool',
                                 data['NeutronError']['type'])
                self.update_policy_target_group(
                            ptg['id'],
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPBadRequest.code)
                self.assertEqual('NSPRequiresNatPool',
                                 data['NeutronError']['type'])

    def test_reject_nsp_without_es(self):
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_pool", "value": "nat_pool",
                             "name": "test"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
        # create PTG with NSP fails when ES is not present
        data = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NSPRequiresES',
                         data['NeutronError']['type'])
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        # update PTG with NSP fails when ES is not present
        data = self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NSPRequiresES',
                         data['NeutronError']['type'])

    def test_reject_l3p_update_with_es(self):
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_pool", "value": "nat_pool",
                             "name": "test"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
        with self.network(router__external=True) as net1:
            with self.network(router__external=True) as net2:
                with self.subnet(cidr='192.168.1.0/24', network=net1) as sub1:
                    with self.subnet(
                            cidr='192.168.2.0/24', network=net2) as sub2:
                        es1 = self.create_external_segment(
                            name="default",
                            subnet_id=sub1['subnet']['id'])['external_segment']
                        es2 = self.create_external_segment(
                            subnet_id=sub2['subnet']['id'])['external_segment']
                        self.create_nat_pool(
                            external_segment_id=es1['id'],
                            ip_version=4,
                            ip_pool='192.168.1.0/24',
                            expected_res_status=webob.exc.HTTPCreated.code)
                        self.create_policy_target_group(
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPCreated.code)
                        self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)
                        req = self.new_list_request('l3_policies',
                                                    fmt=self.fmt)
                        l3ps = self.deserialize(self.fmt,
                                        req.get_response(self.ext_api))[
                                                            'l3_policies']
                        res = self.update_l3_policy(
                            l3ps[0]['id'], expected_res_status=409,
                            external_segments={es2['id']: []})
                        self.assertEqual('L3PEsinUseByNSP',
                                         res['NeutronError']['type'])

    def test_nsp_delete_nat_pool_rejected(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                nat_pool = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4,
                    ip_pool='192.168.0.0/24',
                    expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
                self.create_network_service_policy(
                            network_service_params=[
                                    {"type": "ip_single", "value": "nat_pool",
                                     "name": "vip"}],
                            expected_res_status=webob.exc.HTTPCreated.code)
                self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)
                req = self.new_delete_request('nat_pools', nat_pool['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_update_nsp_nat_pool_after_pt_create(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4,
                    ip_pool='192.168.0.0/24',
                    expected_res_status=webob.exc.HTTPCreated.code)
                nsp = self.create_network_service_policy(
                        network_service_params=[
                                    {"type": "ip_pool", "value": "nat_pool",
                                     "name": "external_access"}],
                        expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
                # Create a PTG and PTs and then associate the NSP
                ptg1 = self.create_policy_target_group(
                            expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
                pt = self.create_policy_target(
                        name="pt1", policy_target_group_id=ptg1['id'])
                port_id = pt['policy_target']['port_id']

                pt2 = self.create_policy_target(
                        name="pt2", policy_target_group_id=ptg1['id'])
                port2_id = pt2['policy_target']['port_id']

                res = self._list('floatingips')['floatingips']
                self.assertEqual(0, len(res))

                self.update_policy_target_group(
                            ptg1['id'],
                            network_service_policy_id=nsp['id'],
                            expected_res_status=webob.exc.HTTPOk.code)
                res = self._list('floatingips')['floatingips']
                self.assertEqual(2, len(res))
                req = self.new_show_request('ports', port_id, fmt=self.fmt)
                port1 = self.deserialize(self.fmt,
                                         req.get_response(self.api))['port']
                req = self.new_show_request('ports', port2_id, fmt=self.fmt)
                port2 = self.deserialize(self.fmt,
                                         req.get_response(self.api))['port']
                port_fixed_ips = [port1['fixed_ips'][0]['ip_address'],
                                  port2['fixed_ips'][0]['ip_address']]
                fip_fixed_ips = [res[0]['fixed_ip_address'],
                                 res[1]['fixed_ip_address']]
                self.assertEqual(set(port_fixed_ips), set(fip_fixed_ips))
                self.update_policy_target_group(
                            ptg1['id'],
                            network_service_policy_id=None,
                            expected_res_status=webob.exc.HTTPOk.code)
                res = self._list('floatingips')['floatingips']
                self.assertEqual(0, len(res))

    def test_nsp_cleanup_multiple_on_unset(self):
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg_subnet_id = ptg['subnets'][0]
        subnet = self._show_subnet(ptg_subnet_id)['subnet']
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        nsp2 = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        # Update PTG, associating an NSP with it and verify that an IP is
        # reserved from the PTG subnet allocation pool. Also test updating
        # the PTG with a different NSP and then resetting it back to the
        # initially set NSP
        self._verify_update_ptg_with_nsp(ptg['id'], nsp['id'], subnet)
        self._verify_update_ptg_with_nsp(ptg['id'], nsp2['id'], subnet)
        self._verify_update_ptg_with_nsp(ptg['id'], nsp['id'], subnet)

    def _verify_update_ptg_with_nsp(self, ptg_id, nsp_id, ptg_subnet_no_nsp):
        ptg_subnet_id = ptg_subnet_no_nsp['id']
        initial_allocation_pool = ptg_subnet_no_nsp['allocation_pools']
        self.update_policy_target_group(
                    ptg_id,
                    network_service_policy_id=nsp_id,
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)['subnet']
        allocation_pool_after_nsp = subnet['allocation_pools']
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('start')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('start')))
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('end')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('end')) + 1)


class TestNatPool(ResourceMappingTestCase):

    def _test_overlapping_peer_rejected(self, shared1=False, shared2=False):
        shared_net = shared1 or shared2
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True, shared=shared_net) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes, shared=shared_net,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                # Allowed
                self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool='192.168.1.0/24', shared=shared1,
                    expected_res_status=webob.exc.HTTPCreated.code)

                # Fails
                res = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool='192.168.1.0/24', shared=shared2,
                    expected_res_status=webob.exc.HTTPBadRequest.code)
                self.assertEqual('OverlappingNATPoolInES',
                                 res['NeutronError']['type'])

    def test_overlapping_peer_rejected1(self):
        self._test_overlapping_peer_rejected(False, False)

    def test_overlapping_peer_rejected2(self):
        self._test_overlapping_peer_rejected(True, False)

    def test_overlapping_peer_rejected3(self):
        self._test_overlapping_peer_rejected(True, True)

    def test_overlapping_peer_rejected4(self):
        self._test_overlapping_peer_rejected(False, True)

    def _test_implicit_subnet_created(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True, shared=shared) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'],
                    external_routes=routes, shared=shared,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                nat_pool = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
                    expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
                self.assertIsNotNone(nat_pool['subnet_id'])
                subnet = self._get_object('subnets', nat_pool['subnet_id'],
                                          self.api)['subnet']
                self.assertEqual('192.168.1.0/24', subnet['cidr'])

    def test_implicit_subnet_created(self):
        self._test_implicit_subnet_created()

    def test_implicit_subnet_created_shared(self):
        self._test_implicit_subnet_created(True)

    def _test_partially_overlapping_subnets_rejected(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True, shared=shared) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                with self.subnet(cidr='192.168.1.0/28', network=net):
                    es = self.create_external_segment(
                        name="default",
                        subnet_id=sub['subnet']['id'],
                        external_routes=routes, shared=shared,
                        expected_res_status=webob.exc.HTTPCreated.code)
                    es = es['external_segment']
                    # Disallowed because they partially overlaps
                    res = self.create_nat_pool(
                        external_segment_id=es['id'],
                        ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
                        expected_res_status=webob.exc.HTTPBadRequest.code)
                    self.assertEqual('OverlappingSubnetForNATPoolInES',
                                     res['NeutronError']['type'])

    def test_partially_overlapping_subnets_rejected(self):
        self._test_partially_overlapping_subnets_rejected()

    def test_partially_overlapping_subnets_rejected_shared(self):
        self._test_partially_overlapping_subnets_rejected(True)

    def _test_overlapping_subnets(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True, shared=shared) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                with self.subnet(cidr='192.168.1.0/24', network=net) as sub2:
                    es = self.create_external_segment(
                        name="default",
                        subnet_id=sub['subnet']['id'],
                        external_routes=routes, shared=shared,
                        expected_res_status=webob.exc.HTTPCreated.code)
                    es = es['external_segment']
                    # Sub2 associated with the newly created NAT pool
                    nat_pool = self.create_nat_pool(
                        external_segment_id=es['id'],
                        ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
                        expected_res_status=webob.exc.HTTPCreated.code)[
                            'nat_pool']
                    self.assertEqual(sub2['subnet']['id'],
                                     nat_pool['subnet_id'])

    def test_overlapping_subnets(self):
        self._test_overlapping_subnets()

    def test_overlapping_subnets_shared(self):
        self._test_overlapping_subnets(True)

    def _test_subnet_swap(self, owned=True):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                es = self.create_external_segment(
                    name="default", subnet_id=sub['subnet']['id'],
                    external_routes=routes,
                    expected_res_status=webob.exc.HTTPCreated.code)
                es = es['external_segment']
                # Use same IP pool as ES sub_id if we don't have to own
                # the subnet.
                ip_pool = '192.168.1.0/24' if owned else '192.168.0.0/24'

                nat_pool = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool=ip_pool,
                    expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']

                # Subnet deleted on 'delete'
                sub_id = nat_pool['subnet_id']
                self.delete_nat_pool(
                    nat_pool['id'],
                    expected_res_status=webob.exc.HTTPNoContent.code)
                self._get_object(
                    'subnets', sub_id, self.api,
                    expected_res_status=404 if owned else 200)

                # Subnet deleted on 'update'
                nat_pool = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool=ip_pool,
                    expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
                sub_id = nat_pool['subnet_id']
                with self.network(router__external=True) as net2:
                    with self.subnet(cidr='192.167.0.0/24',
                                     network=net2) as sub2:
                        es2 = self.create_external_segment(
                            name="nondefault", subnet_id=sub2['subnet']['id'],
                            external_routes=routes,
                            expected_res_status=webob.exc.HTTPCreated.code)
                        es2 = es2['external_segment']

                        # Update External Segment
                        nat_pool = self.update_nat_pool(
                            nat_pool['id'],
                            external_segment_id=es2['id'])['nat_pool']
                        self.assertNotEqual(nat_pool['subnet_id'], sub_id)
                        self.assertIsNotNone(nat_pool['subnet_id'])

                        # Verify subnet deleted
                        self._get_object(
                            'subnets', sub_id, self.api,
                            expected_res_status=404 if owned else 200)

    def test_owned_subnet_deleted(self):
        self._test_subnet_swap(True)

    def test_not_owned_subnet_not_deleted(self):
        self._test_subnet_swap(False)

    def _test_create_rejected_for_es_without_subnet(self, shared=False):
        es = self.create_external_segment(
            name="default",
            expected_res_status=webob.exc.HTTPCreated.code)
        es = es['external_segment']
        result = self.create_nat_pool(
            external_segment_id=es['id'],
            ip_version=4,
            ip_pool='192.168.1.0/24',
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('ESSubnetRequiredForNatPool',
                         result['NeutronError']['type'])

    def test_delete_with_fip_allocated(self):
        with self.network(router__external=True) as net:
            with self.subnet(cidr='192.168.0.0/31', enable_dhcp=False,
                             network=net) as sub:
                es = self.create_external_segment(
                    name="default",
                    subnet_id=sub['subnet']['id'])['external_segment']
                nat_pool = self.create_nat_pool(
                    external_segment_id=es['id'],
                    ip_version=4, ip_pool='192.168.1.0/24')['nat_pool']
                fip_data = {'floatingip': {
                                'tenant_id': net['network']['tenant_id'],
                                'floating_network_id': net['network']['id']}}
                for i in range(2):
                    self._l3_plugin.create_floatingip(
                        nctx.get_admin_context(), fip_data)
                res = self.delete_nat_pool(nat_pool['id'],
                    expected_res_status=409)
                self.assertEqual('NatPoolInUseByPort',
                                 res['NeutronError']['type'])


class TestFloatingIpMonkeyPatch(ResourceMappingTestCase,
                                test_l3.L3NatTestCaseMixin):

    def test_create_fip_specify_router_id(self):
        with self.subnet() as sub:
            self._set_net_external(sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as router:
                    data = {
                        'tenant_id': 'test-tenant',
                        'floating_network_id': sub['subnet']['network_id'],
                        'port_id': private_port['port']['id'],
                        'router_id': router['router']['id']}
                    context = nctx.get_admin_context()
                    fip = self._l3_plugin.create_floatingip(
                        context, {'floatingip': data})
                    # Verify that the router was correctly set even if not
                    # directly connected
                    self.assertEqual(router['router']['id'],
                                     fip['router_id'])
