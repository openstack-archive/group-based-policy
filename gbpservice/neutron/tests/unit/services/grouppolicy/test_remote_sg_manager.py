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


import netaddr
from neutron import context as nctx
from neutron.extensions import securitygroup as ext_sg

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.drivers.sg_managers import (
    remote_group_manager as sg_manager)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_plugin)


class ResourceMappingTestCase(test_plugin.ResourceMappingTestCase):

    def setUp(self):
        super(ResourceMappingTestCase, self).setUp(
            sg_manager='remote_group_manager')

    def _get_prs_mappings(self, prs_id=None, l3p_id=None, tenant_id=None):
        ctx = nctx.get_admin_context()
        return (sg_manager.get_policy_rule_set_sg_mapping(ctx.session, prs_id,
                                                          l3p_id, tenant_id))

    def _calculate_expected_external_cidrs(self, es, l3p):
        routes = [x['destination'] for x in es['external_routes']]
        default = ['0.0.0.0/0', '::']
        result = []
        for route in routes:
            if route in default:
                result.extend([str(x) for x in
                               (netaddr.IPSet([route]) -
                                netaddr.IPSet([l3p['ip_pool']])).iter_cidrs()])
            else:
                result.append(route)
        return result

    def _get_cidrs_from_ep(self, eps, l3p):
        es_ids = []
        for ep in eps:
            es_ids += self.show_external_policy(
                ep)['external_policy']['external_segments']
        cidrs = set()
        for es_id in es_ids:
            cidrs |= set(self._calculate_expected_external_cidrs(
                self.show_external_segment(es_id)['external_segment'], l3p))
        return cidrs

    def _generate_expected_sg_rules(self, prs, l3_policy_id, tenant_id):
        """Returns a list of expected provider sg rules given a PTG."""
        # Get all the needed cidrs:
        prs = self._gbp_plugin.get_policy_rule_set(self._context, prs)
        l3p = self._gbp_plugin.get_l3_policy(self._context, l3_policy_id)

        providing_ep_cidrs = self._get_cidrs_from_ep(
            prs['providing_external_policies'], l3p)

        consuming_ep_cidrs = self._get_cidrs_from_ep(
            prs['consuming_external_policies'], l3p)

        consumers = consuming_ep_cidrs
        providers = providing_ep_cidrs

        mapping = self._get_prs_mappings(prs['id'], l3_policy_id, tenant_id)[0]
        provided_sg = mapping.provided_sg_id
        consumed_sg = mapping.consumed_sg_id
        # IN: from consumer to provider
        # OUT: from provider to consumer
        # Egress rules are filtered by subnet or remote group
        # Igress rules are filtered by subnet or remote group
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
                                 'port_range_min': [port_min],
                                 'port_range_max': [port_max],
                                 'remote_ip_prefix': [cidr]}
                        expected_rules.append(attrs)
                    for cidr in providers:
                        attrs = {'security_group_id': [consumed_sg],
                                 'direction': ['egress'],
                                 'protocol': [protocol],
                                 'port_range_min': [port_min],
                                 'port_range_max': [port_max],
                                 'remote_ip_prefix': [cidr]}
                        expected_rules.append(attrs)
                    # Remote SG rules
                    attrs = {'security_group_id': [provided_sg],
                             'direction': ['ingress'],
                             'protocol': [protocol],
                             'port_range_min': [port_min],
                             'port_range_max': [port_max],
                             'remote_group_id': [consumed_sg],
                             'ethertype': [str(l3p['ip_version'])]}
                    expected_rules.append(attrs)
                    attrs = {'security_group_id': [consumed_sg],
                             'direction': ['egress'],
                             'protocol': [protocol],
                             'port_range_min': [port_min],
                             'port_range_max': [port_max],
                             'remote_group_id': [provided_sg],
                             'ethertype': [str(l3p['ip_version'])]}
                    expected_rules.append(attrs)
                if classifier['direction'] in out_bi:
                    # If direction OUT/BI, provider CIDRs go into consumer SG
                    for cidr in providers:
                        attrs = {'security_group_id': [consumed_sg],
                                 'direction': ['ingress'],
                                 'protocol': [protocol],
                                 'port_range_min': [port_min],
                                 'port_range_max': [port_max],
                                 'remote_ip_prefix': [cidr]}
                        expected_rules.append(attrs)
                    for cidr in consumers:
                        attrs = {'security_group_id': [provided_sg],
                                 'direction': ['egress'],
                                 'protocol': [protocol],
                                 'port_range_min': [port_min],
                                 'port_range_max': [port_max],
                                 'remote_ip_prefix': [cidr]}
                        expected_rules.append(attrs)
                    # Remote SG rules
                    attrs = {'security_group_id': [consumed_sg],
                             'direction': ['ingress'],
                             'protocol': [protocol],
                             'port_range_min': [port_min],
                             'port_range_max': [port_max],
                             'remote_group_id': [provided_sg],
                             'ethertype': [str(l3p['ip_version'])]}
                    expected_rules.append(attrs)
                    # And provider SG have egress allowed
                    attrs = {'security_group_id': [provided_sg],
                             'direction': ['egress'],
                             'protocol': [protocol],
                             'port_range_min': [port_min],
                             'port_range_max': [port_max],
                             'remote_group_id': [consumed_sg],
                             'ethertype': [str(l3p['ip_version'])]}
                    expected_rules.append(attrs)
        return expected_rules

    def _verify_prs_rules(self, prs):
        """Verify the current PRS state in terms of SG rules.

        Make sure this is used in a context where at least a PT exists in the
        relationship! Otherwise the SGs will not exist as they are lazily
        created.
        """
        mappings = self._get_prs_mappings(prs)
        for mapping in mappings:
            existing = [
                x for x in self._get_sg_rule(
                    security_group_id=[mapping.provided_sg_id,
                                       mapping.consumed_sg_id])]
            expected = self._generate_expected_sg_rules(
                prs, mapping.l3_policy_id, mapping.tenant_id)
            for rule in expected:
                # Verify the rule exists
                r = self._get_sg_rule(**rule)
                self.assertTrue(len(r) == 1,
                                "Rule not found for l3p %s, "
                                "expected:\n%s\n\n\n\n\n\n\n\n "
                                "current:%s\n"
                                "provider_sg: %s\n"
                                "consumer_sg: %s\n" % (
                                    mapping.l3_policy_id, rule, existing,
                                    mapping.provided_sg_id,
                                    mapping.consumed_sg_id))
                existing.remove(r[0])
            self.assertTrue(len(existing) == 0,
                            "Some rules still exist:\n%s" % str(existing))


class TestPolicyTarget(ResourceMappingTestCase, test_plugin.TestPolicyTarget):
    pass


class TestPolicyTargetGroup(ResourceMappingTestCase,
                            test_plugin.TestPolicyTargetGroup):
    pass


class TestL2Policy(ResourceMappingTestCase, test_plugin.TestL2Policy):
    pass


class TestL3Policy(ResourceMappingTestCase, test_plugin.TestL3Policy):

    def test_overlapping_pools_per_tenant(self):
        pass


class NotificationTest(ResourceMappingTestCase, test_plugin.NotificationTest):
    pass


class TestPolicyRuleSet(ResourceMappingTestCase,
                        test_plugin.TestPolicyRuleSet):

    def test_shared_prs(self):
        prs = self._create_policy_rule_set_on_shared(
            shared=True, tenant_id='admin')
        ptg = self.create_policy_target_group(
            tenant_id='nonadmin',
            provided_policy_rule_sets={prs['id']: ''})['policy_target_group']
        pt = self.create_policy_target(
            tenant_id='nonadmin', policy_target_group_id=ptg['id'])
        mappings = self._get_prs_mappings(prs['id'])

        self.assertEqual(1, len(mappings))
        port_id = pt['policy_target']['port_id']
        res = self.new_show_request('ports', port_id)
        port = self.deserialize(self.fmt, res.get_response(self.api))
        security_groups = port['port'][ext_sg.SECURITYGROUPS]
        self.assertEqual(2, len(security_groups))
        self.assertTrue(mappings[0].provided_sg_id in
                        port['port'][ext_sg.SECURITYGROUPS])

    def test_shared_policy_rule_set_create(self):
        self.create_policy_rule_set(shared=True, expected_res_status=201)


class TestExternalSegment(ResourceMappingTestCase,
                          test_plugin.TestExternalSegment):

    def test_update(self):
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
                external_segments = {es['id']: []}
                l3p1 = self.create_l3_policy(
                    ip_pool='192.168.0.0/16',
                    external_segments=external_segments)['l3_policy']
                l3p2 = self.create_l3_policy(
                    ip_pool='192.128.0.0/16',
                    external_segments=external_segments)['l3_policy']
                self.create_external_policy(
                    external_segments=[es['id']],
                    provided_policy_rule_sets={prs['id']: ''},
                    consumed_policy_rule_sets={prs['id']: ''})

                self._create_pt_in_l3p(l3p1, consume=[prs['id']])
                self._create_pt_in_l3p(l3p2, consume=[prs['id']])

                for l3p in [l3p1, l3p2]:
                    expected_cidrs = self._calculate_expected_external_cidrs(
                        es, l3p)
                    mapping = self._get_prs_mappings(prs['id'], l3p['id'])[0]

                    # Not using _verify_prs_rules here because it's testing
                    # that some specific delta rules are applied/removed \
                    # instead of the whole PRS state.
                    attrs = {'security_group_id': [mapping.consumed_sg_id],
                             'direction': ['ingress'],
                             'protocol': ['tcp'],
                             'port_range_min': [22],
                             'port_range_max': [22],
                             'remote_ip_prefix': None}
                    for cidr in expected_cidrs:
                        attrs['remote_ip_prefix'] = [cidr]
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['egress']
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['ingress']

                    self._verify_prs_rules(prs['id'])
                    # Update the route and verify the SG rules changed
                    es = self.update_external_segment(
                        es['id'], expected_res_status=200,
                        external_routes=[])['external_segment']
                    self._verify_prs_rules(prs['id'])

                    route = {'destination': '172.0.0.0/8', 'nexthop': None}
                    es = self.update_external_segment(
                        es['id'], expected_res_status=200,
                        external_routes=[route])['external_segment']

                    self._verify_prs_rules(prs['id'])
                    # Verify the old rules have been deleted
                    new_cidrs = self._calculate_expected_external_cidrs(
                        es, l3p)
                    removed = set(expected_cidrs) - set(new_cidrs)
                    for cidr in removed:
                        attrs['remote_ip_prefix'] = [cidr]
                        self.assertFalse(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['egress']
                        self.assertFalse(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['ingress']

                    expected_cidrs = new_cidrs
                    # Verify new rules exist
                    for cidr in expected_cidrs:
                        attrs['remote_ip_prefix'] = [cidr]
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['egress']
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['ingress']

                    # Creating a new L3P *doesn't* change the definition of
                    # what's external and what is not
                    self.create_l3_policy(
                        ip_pool='192.64.0.0/16',
                        external_segments=external_segments)['l3_policy']

                    for cidr in expected_cidrs:
                        attrs['remote_ip_prefix'] = [cidr]
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['egress']
                        self.assertTrue(self._get_sg_rule(**attrs))
                        attrs['direction'] = ['ingress']


class TestExternalPolicy(ResourceMappingTestCase,
                         test_plugin.TestExternalPolicy):
    pass


class TestPolicyAction(ResourceMappingTestCase, test_plugin.TestPolicyAction):
    pass


class TestPolicyRule(ResourceMappingTestCase, test_plugin.TestPolicyRule):
    pass


class TestNetworkServicePolicy(ResourceMappingTestCase,
                               test_plugin.TestNetworkServicePolicy):
    pass