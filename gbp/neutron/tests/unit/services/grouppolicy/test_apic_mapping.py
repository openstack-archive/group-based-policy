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

import sys

import mock
from neutron.common import rpc as n_rpc
from neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)

sys.modules["apicapi"] = mock.Mock()

from gbp.neutron.services.grouppolicy import config
from gbp.neutron.services.grouppolicy.drivers.cisco.apic import apic_mapping
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin
from gbp.neutron.tests.unit.services.grouppolicy import test_resource_mapping

APIC_L2_POLICY = 'l2_policy'
APIC_L3_POLICY = 'l3_policy'
APIC_CONTRACT = 'contract'
APIC_ENDPOINT_GROUP = 'endpoint_group'
APIC_POLICY_RULE = 'policy_rule'


def echo(context, string):
    return string


class MockCallRecorder(mock.Mock):
    recorded_call_set = set()

    def __call__(self, *args, **kwargs):
        self.recorded_call_set.add((args, tuple(kwargs.items())))
        return mock.Mock()

    def call_happened_with(self, *args, **kwargs):
        return (args, tuple(kwargs.items())) in self.recorded_call_set


class ApicMappingTestCase(
        test_grouppolicy_plugin.GroupPolicyPluginTestCase,
        mocked.ControllerMixin, mocked.ConfigMixin):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'apic'],
                                     group='group_policy')
        n_rpc.create_connection = mock.Mock()
        apic_mapping.ApicMappingDriver.get_apic_manager = mock.Mock()
        super(ApicMappingTestCase, self).setUp(
            core_plugin=test_resource_mapping.CORE_PLUGIN)

        self.driver = apic_mapping.ApicMappingDriver.get_initialized_instance()
        apic_mapping.ApicMappingDriver.get_base_synchronizer = mock.Mock()
        self.driver.name_mapper = mock.Mock()
        self.driver.name_mapper.tenant = echo
        self.driver.name_mapper.l2_policy = echo
        self.driver.name_mapper.l3_policy = echo
        self.driver.name_mapper.contract = echo
        self.driver.name_mapper.policy_rule = echo
        self.driver.name_mapper.app_profile.return_value = mocked.APIC_AP
        self.driver.name_mapper.endpoint_group = echo
        self.driver.apic_manager = mock.Mock(name_mapper=mock.Mock())
        self.driver.apic_manager.apic.transaction = self.fake_transaction


class TestEndpointGroup(ApicMappingTestCase):

    def test_endpoint_group_created_on_apic(self):
        epg = self.create_endpoint_group(name="epg1")['endpoint_group']

        mgr = self.driver.apic_manager
        mgr.ensure_epg_created.assert_called_once_with(
            epg['tenant_id'], epg['id'], bd_name=epg['l2_policy_id'])

    def _test_epg_contract_created(self, provider=True):
        cntr = self.create_contract(name='c')['contract']

        if provider:
            epg = self.create_endpoint_group(
                provided_contracts={cntr['id']: 'scope'})['endpoint_group']
        else:
            epg = self.create_endpoint_group(
                consumed_contracts={cntr['id']: 'scope'})['endpoint_group']

        # Verify that the apic call is issued
        mgr = self.driver.apic_manager
        mgr.set_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], cntr['id'], transaction='transaction',
            provider=provider)

    def _test_epg_contract_updated(self, provider=True):
        p_or_c = {True: 'provided_contracts', False: 'consumed_contracts'}
        cntr = self.create_contract(name='c1')['contract']
        new_cntr = self.create_contract(name='c2')['contract']

        if provider:
            epg = self.create_endpoint_group(
                provided_contracts={cntr['id']: 'scope'})
        else:
            epg = self.create_endpoint_group(
                consumed_contracts={cntr['id']: 'scope'})

        data = {'endpoint_group': {p_or_c[provider]:
                {new_cntr['id']: 'scope'}}}
        req = self.new_update_request('endpoint_groups', data,
                                      epg['endpoint_group']['id'], self.fmt)
        epg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        epg = epg['endpoint_group']
        mgr = self.driver.apic_manager
        mgr.set_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], new_cntr['id'],
            transaction='transaction', provider=provider)
        mgr.unset_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], cntr['id'],
            transaction='transaction', provider=provider)

    def test_epg_contract_provider_created(self):
        self._test_epg_contract_created()

    def test_epg_contract_provider_updated(self):
        self._test_epg_contract_updated()

    def test_epg_contract_consumer_created(self):
        self._test_epg_contract_created(False)

    def test_epg_contract_consumer_updated(self):
        self._test_epg_contract_updated(False)

    def test_endpoint_group_deleted_on_apic(self):
        epg = self.create_endpoint_group(name="epg1")['endpoint_group']
        req = self.new_delete_request('endpoint_groups', epg['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        mgr.delete_epg_for_network.assert_called_once_with(
            epg['tenant_id'], epg['id'])


class TestL2Policy(ApicMappingTestCase):

    def test_l2_policy_created_on_apic(self):
        l2p = self.create_l2_policy(name="l2p")['l2_policy']

        mgr = self.driver.apic_manager
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            l2p['tenant_id'], l2p['id'], ctx_owner=l2p['tenant_id'],
            ctx_name=l2p['l3_policy_id'])

    def test_l2_policy_deleted_on_apic(self):
        l2p = self.create_l2_policy(name="l2p")['l2_policy']
        req = self.new_delete_request('l2_policies', l2p['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        mgr.delete_bd_on_apic.assert_called_once_with(
            l2p['tenant_id'], l2p['id'])


class TestL3Policy(ApicMappingTestCase):

    def test_l3_policy_created_on_apic(self):
        l3p = self.create_l3_policy(name="l3p")['l3_policy']

        mgr = self.driver.apic_manager
        mgr.ensure_context_enforced.assert_called_once_with(
            l3p['tenant_id'], l3p['id'])

    def test_l3_policy_deleted_on_apic(self):
        l3p = self.create_l3_policy(name="l3p")['l3_policy']
        req = self.new_delete_request('l3_policies', l3p['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        mgr.ensure_context_deleted.assert_called_once_with(
            l3p['tenant_id'], l3p['id'])


class TestContract(ApicMappingTestCase):

    # TODO(ivar): verify rule intersection with hierarchical contracts happens
    # on APIC
    def test_contract_created_on_apic(self):
        self.create_contract(name="ctr")

        mgr = self.driver.apic_manager
        self.assertEqual(1, mgr.create_contract.call_count)

    def test_contract_created_with_rules(self):
        bi, in_d, out = range(3)
        rules = self._create_3_direction_rules()
        # exclude BI rule for now
        ctr = self.create_contract(
            name="ctr", policy_rules=[x['id'] for x in rules[1:]])['contract']

        # Verify that the in-out rules are correctly enforced on the APIC
        mgr = self.driver.apic_manager
        mgr.manage_contract_subject_in_filter.assert_called_once_with(
            ctr['id'], ctr['id'], rules[in_d]['id'], owner=ctr['tenant_id'],
            transaction='transaction', unset=False)
        mgr.manage_contract_subject_out_filter.assert_called_once_with(
            ctr['id'], ctr['id'], rules[out]['id'], owner=ctr['tenant_id'],
            transaction='transaction', unset=False)

        # Create contract with BI rule
        ctr = self.create_contract(
            name="ctr", policy_rules=[rules[bi]['id']])['contract']

        mgr.manage_contract_subject_in_filter.assert_called_with(
            ctr['id'], ctr['id'], rules[bi]['id'], owner=ctr['tenant_id'],
            transaction='transaction', unset=False)
        mgr.manage_contract_subject_out_filter.assert_called_with(
            ctr['id'], ctr['id'], rules[bi]['id'], owner=ctr['tenant_id'],
            transaction='transaction', unset=False)

    def test_contract_updated_with_new_rules(self):
        bi, in_d, out = range(3)
        old_rules = self._create_3_direction_rules()
        new_rules = self._create_3_direction_rules()
        # exclude BI rule for now
        ctr = self.create_contract(
            name="ctr",
            policy_rules=[x['id'] for x in old_rules[1:]])['contract']
        data = {'contract': {'policy_rules': [x['id'] for x in new_rules[1:]]}}
        mgr = self.driver.apic_manager
        mgr.manage_contract_subject_in_filter = MockCallRecorder()
        mgr.manage_contract_subject_out_filter = MockCallRecorder()
        self.new_update_request(
            'contracts', data, ctr['id'], self.fmt).get_response(self.ext_api)
        # Verify old IN rule unset and new IN rule set
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[in_d]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True))
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[in_d]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[out]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[out]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False))

        ctr = self.create_contract(
            name="ctr",
            policy_rules=[old_rules[0]['id']])['contract']
        data = {'contract': {'policy_rules': [new_rules[0]['id']]}}
        self.new_update_request(
            'contracts', data, ctr['id'], self.fmt).get_response(self.ext_api)
        # Verify old BI rule unset and new Bu rule set
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True))
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False))

    def _create_3_direction_rules(self):
        a1 = self.create_policy_action(name='a1',
                                       action_type='allow')['policy_action']
        cl_attr = {'protocol': 'tcp', 'port_range': 80}
        cls = []
        for direction in ['bi', 'in', 'out']:
            cls.append(self.create_policy_classifier(
                direction=direction, **cl_attr)['policy_classifier'])
        rules = []
        for classifier in cls:
            rules.append(self.create_policy_rule(
                classifier['id'], policy_actions=[a1['id']])['policy_rule'])
        return rules


class TestPolicyRule(ApicMappingTestCase):

    def test_policy_rule_created_on_apic(self):
        pr = self._create_simple_policy_rule('in', 'udp', 88)

        mgr = self.driver.apic_manager
        mgr.create_tenant_filter.assert_called_once_with(
            pr['id'], owner=pr['tenant_id'], etherT='ip', prot='udp',
            dToPort=88, dFromPort=88)

    def test_policy_rule_many_actions_rejected(self):
        actions = [self.create_policy_action(
            action_type='allow')['policy_action']['id'] for x in range(2)]

        cls = self.create_policy_classifier(direction='in', protocol='udp',
                                            port_range=80)['policy_classifier']
        self.create_policy_rule(cls['id'], expected_res_status=400,
                                policy_actions=actions)

    def test_policy_rule_on_apic(self):
        pr = self._create_simple_policy_rule()
        req = self.new_delete_request('policy_rules', pr['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        mgr.delete_tenant_filter.assert_called_once_with(
            pr['id'], owner=pr['tenant_id'])

    def _create_simple_policy_rule(self, direction='bi', protocol='tcp',
                                   port_range=80):
        cls = self.create_policy_classifier(
            direction=direction, protocol=protocol,
            port_range=port_range)['policy_classifier']

        action = self.create_policy_action(
            action_type='allow')['policy_action']
        return self.create_policy_rule(
            cls['id'], policy_actions=[action['id']])['policy_rule']