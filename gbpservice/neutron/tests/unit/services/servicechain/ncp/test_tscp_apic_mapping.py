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

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db
import mock
import netaddr
from neutron.common import config  # noqa
from neutron import context
from neutron import manager
from oslo_config import cfg
import unittest2

from gbpservice.neutron.services.grouppolicy import (
    policy_driver_manager as pdm)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    plugin as ncp_plugin)
from gbpservice.neutron.services.servicechain.plugins.ncp import model
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_apic_mapping as test_apic)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as base)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_tscp_resource_mapping as test_tscp_rmd)


class ApicMappingStitchingPlumberGBPTestCase(
        test_apic.ApicMappingTestCase):

    def setUp(self, plumber='stitching_plumber'):
        cfg.CONF.set_override(
            'extension_drivers', ['apic_segmentation_label',
                                  'proxy_group'], group='group_policy')
        cfg.CONF.set_override('node_plumber', plumber,
                              group='node_composition_plugin')
        super(ApicMappingStitchingPlumberGBPTestCase, self).setUp(
            sc_plugin=base.SC_PLUGIN_KLASS)

        def get_plumbing_info(context):
            return test_tscp_rmd.info_mapping.get(
                context.current_profile['service_type'])

        self.node_driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.node_driver.get_plumbing_info = get_plumbing_info
        self.mgr = self.driver.apic_manager

        def get_plumbing_info(context):
            return test_tscp_rmd.info_mapping.get(
                context.current_profile['service_type'])

        self.node_driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.node_driver.get_plumbing_info = get_plumbing_info
        self.saved_get_policy_target_group_status = (
            pdm.PolicyDriverManager.get_policy_target_group_status)
        pdm.PolicyDriverManager.get_policy_target_group_status = (
                mock.MagicMock({}))

    def tearDown(self):
        pdm.PolicyDriverManager.get_policy_target_group_status = (
                self.saved_get_policy_target_group_status)
        super(ApicMappingStitchingPlumberGBPTestCase, self).tearDown()

    @property
    def sc_plugin(self):
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get('SERVICECHAIN')
        return servicechain_plugin


class TestPolicyRuleSet(ApicMappingStitchingPlumberGBPTestCase,
                        test_apic.TestPolicyRuleSet):
    pass


class TestPolicyRule(ApicMappingStitchingPlumberGBPTestCase,
                     test_apic.TestPolicyRule):
    pass


class TestExternalSegment(ApicMappingStitchingPlumberGBPTestCase,
                          test_apic.TestExternalSegment):
    pass


class TestExternalPolicy(ApicMappingStitchingPlumberGBPTestCase,
                         test_apic.TestExternalPolicy):
    pass


class TestApicChains(ApicMappingStitchingPlumberGBPTestCase,
                     base.NodeCompositionPluginTestMixin):

    def _assert_proper_chain_instance(self, sc_instance, provider_ptg_id,
                                      policy_rule_set_id, scs_id_list,
                                      classifier_id=None):
        self.assertEqual(sc_instance['provider_ptg_id'], provider_ptg_id)
        self.assertEqual(sc_instance['consumer_ptg_id'], 'N/A')
        self.assertEqual(scs_id_list, sc_instance['servicechain_specs'])
        provider = self.show_policy_target_group(
            provider_ptg_id)['policy_target_group']
        self.assertEqual(sc_instance['tenant_id'], provider['tenant_id'])
        if classifier_id:
            self.assertEqual(sc_instance['classifier_id'], classifier_id)

    def test_classifier_update_to_chain(self):
        scs_id = self._create_servicechain_spec(node_types=['FIREWALL'])
        _, classifier_id, policy_rule_id = self._create_tcp_redirect_rule(
                                                            "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            policy_rule_set_id)

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self._assert_proper_chain_instance(sc_instance, provider_ptg_id,
                                           consumer_ptg_id, [scs_id])
        with mock.patch.object(
                ncp_plugin.NodeCompositionPlugin,
                'notify_chain_parameters_updated') as notify_chain_update:

            # Update classifier and verify instance is updated
            self.update_policy_classifier(classifier_id, port_range=80)

            notify_chain_update.assert_called_once_with(
                mock.ANY, sc_instance['id'])
            sc_instances = self._list_service_chains()
            self.assertEqual(len(sc_instances['servicechain_instances']), 1)
            sc_instance_updated = sc_instances['servicechain_instances'][0]
            self.assertEqual(sc_instance, sc_instance_updated)

        self._verify_ptg_delete_cleanup_chain(provider_ptg_id)

    def test_redirect_multiple_ptgs_single_prs(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']

        #Create 2 provider and 2 consumer PTGs
        provider_ptg1 = self.create_policy_target_group(
            name="p_ptg1",
            provided_policy_rule_sets={policy_rule_set_id: None})
        provider_ptg1_id = provider_ptg1['policy_target_group']['id']
        self.create_policy_target_group(
            name="c_ptg1",
            consumed_policy_rule_sets={policy_rule_set_id: None})

        provider_ptg2 = self.create_policy_target_group(
            name="p_ptg2",
            provided_policy_rule_sets={policy_rule_set_id: None})
        provider_ptg2_id = provider_ptg2['policy_target_group']['id']
        self.create_policy_target_group(
            name="c_ptg2",
            consumed_policy_rule_sets={policy_rule_set_id: None})

        sc_instances = self._list_service_chains()
        # We should have 2 service chain instances (one per provider)
        self.assertEqual(len(sc_instances['servicechain_instances']), 2)
        sc_instances = sc_instances['servicechain_instances']
        sc_instances_provider_ptg_ids = set()
        sc_instances_consumer_ptg_ids = set()
        for sc_instance in sc_instances:
            sc_instances_provider_ptg_ids.add(sc_instance['provider_ptg_id'])
            sc_instances_consumer_ptg_ids.add(sc_instance['consumer_ptg_id'])
        expected_provider_ptg_ids = {provider_ptg1_id, provider_ptg2_id}
        self.assertEqual(expected_provider_ptg_ids,
                         sc_instances_provider_ptg_ids)

        # Deleting one provider should end up deleting the one service chain
        # Instance associated to it
        self.delete_policy_target_group(
            provider_ptg1_id, expected_res_status=204)

        sc_instances = self._list_service_chains()
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        self.assertNotEqual(sc_instance['provider_ptg_id'], provider_ptg1_id)

        self.delete_policy_target_group(
            provider_ptg2_id, expected_res_status=204)

        sc_instances = self._list_service_chains()
        # No more service chain instances when all the providers are deleted
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def test_redirect_to_chain(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            policy_rule_set_id)

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)

        # Verify that PTG delete cleans up the chain instances
        self.delete_policy_target_group(
            provider_ptg_id, expected_res_status=204)

        sc_instances = self._list_service_chains()
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def test_rule_update_updates_chain(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule("20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        provider_ptg_id, consumer_ptg_id = self._create_provider_consumer_ptgs(
                                                            policy_rule_set_id)
        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]

        # Update policy rule with new classifier and verify instance is
        # recreated
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="80",
            direction='bi')['policy_classifier']

        self.update_policy_rule(policy_rule_id,
                                policy_classifier_id=classifier['id'])
        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance_new = sc_instances['servicechain_instances'][0]
        self.assertNotEqual(sc_instance, sc_instance_new)

        scs_id2 = self._create_servicechain_spec()
        action = self.create_policy_action(
            action_type='redirect', action_value=scs_id2)['policy_action']
        self.update_policy_rule(policy_rule_id, policy_actions=[action['id']])

        # Verify SC instance changed
        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance_new = sc_instances['servicechain_instances'][0]
        self.assertNotEqual(sc_instance, sc_instance_new)

        self.delete_policy_target_group(
            provider_ptg_id, expected_res_status=204)

        sc_instances = self._list_service_chains()
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def test_update_ptg_with_redirect_prs(self):
        scs_id = self._create_servicechain_spec()
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
                                                "20:90", scs_id)

        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])
        policy_rule_set_id = policy_rule_set['policy_rule_set']['id']
        provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs()

        sc_instances = self._list_service_chains()
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

        sc_instances = self._list_service_chains()
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)

        # Verify that PTG update removing prs cleans up the chain instances
        self.update_policy_target_group(
            provider_ptg, provided_policy_rule_sets={},
            consumed_policy_rule_sets={}, expected_res_status=200)

        sc_instances = self._list_service_chains()
        self.assertEqual(len(sc_instances['servicechain_instances']), 0)

    def test_chain_on_apic_create(self):
        scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT'])
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", scs_id)
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']
        # Create PTGs on same L2P
        l2p = self.create_l2_policy()['l2_policy']
        provider = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        consumer = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        mgr = self.driver.apic_manager
        mgr.reset_mock()
        # Provide the redirect contract
        self.update_policy_target_group(
            consumer['id'],
            consumed_policy_rule_sets={policy_rule_set['id']: ''})
        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.ensure_epg_created.called)

        # Now form the chain
        self.update_policy_target_group(
            provider['id'],
            provided_policy_rule_sets={policy_rule_set['id']: ''})

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]

        expected = [
            # Provider EPG provided PRS
            mock.call(provider['tenant_id'], provider['id'],
                      policy_rule_set['id'], provider=True,
                      contract_owner=policy_rule_set['tenant_id'],
                      transaction=mock.ANY),
            # Consumer EPG consumed PRS
            mock.call(consumer['tenant_id'], consumer['id'],
                      policy_rule_set['id'], provider=False,
                      contract_owner=policy_rule_set['tenant_id'],
                      transaction=mock.ANY)]

        self._verify_chain_set(provider, l2p, policy_rule_set,
                               sc_instance, 1, pre_set_contract_calls=expected)

        # New consumer doesn't trigger anything
        new_consumer = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        mgr.reset_mock()
        self.update_policy_target_group(
            new_consumer['id'],
            consumed_policy_rule_sets={policy_rule_set['id']: ''})

        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.ensure_epg_created.called)

    def test_chain_on_apic_create_shared(self):
        scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT'], shared=True)
        policy_rule_id = self._create_simple_policy_rule(
            action_type='redirect', shared=True, action_value=scs_id)['id']
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id],
            shared=True)['policy_rule_set']
        # Create PTGs on same L2P
        l2p = self.create_l2_policy(shared=True,
                                    tenant_id='admin')['l2_policy']
        provider = self.create_policy_target_group(
            l2_policy_id=l2p['id'], shared=True)['policy_target_group']
        consumer = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        mgr = self.driver.apic_manager
        mgr.reset_mock()
        # Provide the redirect contract
        self.update_policy_target_group(
            consumer['id'],
            consumed_policy_rule_sets={policy_rule_set['id']: ''})
        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.ensure_epg_created.called)

        # Now form the chain
        self.update_policy_target_group(
            provider['id'],
            provided_policy_rule_sets={policy_rule_set['id']: ''})

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]

        expected = [
            # Provider EPG provided PRS
            mock.call('common', provider['id'],
                      policy_rule_set['id'], provider=True,
                      contract_owner='common',
                      transaction=mock.ANY),
            # Consumer EPG consumed PRS
            mock.call(consumer['tenant_id'], consumer['id'],
                      policy_rule_set['id'], provider=False,
                      contract_owner='common',
                      transaction=mock.ANY)]

        self._verify_chain_set(provider, l2p, policy_rule_set,
                               sc_instance, 1, pre_set_contract_calls=expected)

        # New consumer doesn't trigger anything
        new_consumer = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        mgr.reset_mock()
        self.update_policy_target_group(
            new_consumer['id'],
            consumed_policy_rule_sets={policy_rule_set['id']: ''})

        self.assertFalse(mgr.ensure_bd_created_on_apic.called)
        self.assertFalse(mgr.ensure_epg_created.called)
        mgr.reset_mock()
        self.update_policy_target_group(
            provider['id'], provided_policy_rule_sets={})
        # Provider EPG contract unset
        expected = mock.call('common', provider['id'],
                             policy_rule_set['id'], provider=True,
                             contract_owner='common',
                             transaction=mock.ANY)
        self._verify_chain_unset(
            provider, l2p, policy_rule_set,
            sc_instance, 1, pre_unset_contract_calls=[expected])

    def test_chain_on_apic_delete(self):
        scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT', 'FIREWALL_TRANSPARENT'])
        _, _, policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", scs_id)
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']
        # Create PTGs on same L2P
        l2p = self.create_l2_policy()['l2_policy']
        provider = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        consumer = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        # Provide the redirect contract
        self.update_policy_target_group(
            provider['id'],
            provided_policy_rule_sets={policy_rule_set['id']: ''})

        # Now form the chain
        self.update_policy_target_group(
            consumer['id'],
            consumed_policy_rule_sets={policy_rule_set['id']: ''})

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        sc_instance = sc_instances['servicechain_instances'][0]

        # Dissolve the chain by disassociation
        mgr = self.driver.apic_manager
        mgr.reset_mock()
        self.update_policy_target_group(
            provider['id'], provided_policy_rule_sets={})
        # Provider EPG contract unset
        expected = mock.call(provider['tenant_id'], provider['id'],
                             policy_rule_set['id'], provider=True,
                             contract_owner=policy_rule_set['tenant_id'],
                             transaction=mock.ANY)
        self._verify_chain_unset(
            provider, l2p, policy_rule_set,
            sc_instance, 2, pre_unset_contract_calls=[expected])

    def test_new_action_rejected_by_ptg(self):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        ptg2 = self.create_policy_target_group()['policy_target_group']
        ptg3 = self.create_policy_target_group()['policy_target_group']
        simple_rule = self._create_simple_policy_rule()
        simple_rule_2 = self._create_simple_policy_rule()
        prs = self.create_policy_rule_set()['policy_rule_set']
        prs2 = self.create_policy_rule_set(
            policy_rules=[simple_rule['id']])['policy_rule_set']
        prs3 = self.create_policy_rule_set(
            policy_rules=[simple_rule_2['id']])['policy_rule_set']
        self.update_policy_target_group(
            ptg1['id'], provided_policy_rule_sets={prs['id']: ''})
        self.update_policy_target_group(
            ptg2['id'], provided_policy_rule_sets={prs['id']: ''})
        # PTG 3 also consumes a contract
        self.update_policy_target_group(
            ptg3['id'], provided_policy_rule_sets={prs['id']: ''})
        self.update_policy_target_group(
            ptg3['id'], consumed_policy_rule_sets={prs2['id']: ''})

        # Adding a normal rule to PRS works normally
        self.update_policy_rule_set(prs['id'],
                                    policy_rules=[simple_rule['id']])
        redirect = self._create_simple_policy_rule(action_type='redirect')
        self.update_policy_rule_set(
            prs['id'], policy_rules=[simple_rule['id'], redirect['id']],
            expected_res_status=200)

        redirect = self._create_simple_policy_rule(action_type='redirect')
        self.update_policy_rule_set(
            prs3['id'], policy_rules=[simple_rule['id'], redirect['id']],
            expected_res_status=200)
        res = self.update_policy_target_group(
            ptg2['id'], provided_policy_rule_sets={prs['id']: '',
                                                   prs3['id']: ''},
            expected_res_status=400)
        self.assertEqual('PTGAlreadyProvidingRedirectPRS',
                         res['NeutronError']['type'])

        action = self.create_policy_action(
            action_type='redirect')['policy_action']

        self.update_policy_rule_set(
            prs['id'], policy_rules=[simple_rule['id']],
            expected_res_status=200)
        self.update_policy_rule_set(
            prs3['id'], policy_rules=[simple_rule['id']],
            expected_res_status=200)
        # Adding redirect action to the consumed PRS is fine
        self.update_policy_rule(
            simple_rule['id'], policy_actions=[action['id']],
            expected_res_status=200)

    def test_ptg_only_participate_one_prs_when_redirect(self):
        redirect_rule = self._create_simple_policy_rule(action_type='redirect')
        simple_rule = self._create_simple_policy_rule()
        prs_r = self.create_policy_rule_set(
            policy_rules=[redirect_rule['id']])['policy_rule_set']
        prs = self.create_policy_rule_set(
            policy_rules=[simple_rule['id']])['policy_rule_set']

        # Creating PTG with provided redirect and multiple PRS fails
        self.create_policy_target_group(
            provided_policy_rule_sets={prs_r['id']: '', prs['id']: ''},
            consumed_policy_rule_sets={prs['id']: ''},
            expected_res_status=201)

        action = self.create_policy_action(
            action_type='redirect')['policy_action']
        res = self.update_policy_rule(
            simple_rule['id'], policy_actions=[action['id']],
            expected_res_status=400)
        self.assertEqual('PTGAlreadyProvidingRedirectPRS',
                         res['NeutronError']['type'])

    def test_three_tier_sc(self):
        app_db_scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT', 'IDS'], shared=True)
        web_app_scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT', 'LOADBALANCER'])
        internet_web_scs_id = self._create_servicechain_spec(
            node_types=['LOADBALANCER'])
        _, _, app_db_policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", app_db_scs_id)
        _, _, web_app_policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", web_app_scs_id)
        _, _, internet_web_policy_rule_id = self._create_tcp_redirect_rule(
            "20:90", internet_web_scs_id)
        app_db_policy_rule_set = self.create_policy_rule_set(
            policy_rules=[app_db_policy_rule_id])['policy_rule_set']
        web_app_policy_rule_set = self.create_policy_rule_set(
            policy_rules=[web_app_policy_rule_id])['policy_rule_set']
        internet_web_policy_rule_set = self.create_policy_rule_set(
            policy_rules=[internet_web_policy_rule_id])['policy_rule_set']
        # Create DB and APP PTGs on same L2P
        l2p = self.create_l2_policy()['l2_policy']
        db = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        app = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        # Create WEB on a different L2P
        web_l2p = self.create_l2_policy()['l2_policy']
        web = self.create_policy_target_group(
            l2_policy_id=web_l2p['id'])['policy_target_group']

        mgr = self.driver.apic_manager
        mgr.reset_mock()
        self.update_policy_target_group(
            app['id'],
            consumed_policy_rule_sets={app_db_policy_rule_set['id']: ''})
        self.update_policy_target_group(
            db['id'],
            provided_policy_rule_sets={app_db_policy_rule_set['id']: ''})

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 1)
        sc_instance = sc_instances['servicechain_instances'][0]
        seen = {sc_instance['id']}

        expected = [
            # Provider EPG provided PRS
            mock.call(db['tenant_id'], db['id'],
                      app_db_policy_rule_set['id'], provider=True,
                      contract_owner=app_db_policy_rule_set['tenant_id'],
                      transaction=mock.ANY),
            # Consumer EPG consumed PRS
            mock.call(app['tenant_id'], app['id'],
                      app_db_policy_rule_set['id'], provider=False,
                      contract_owner=app_db_policy_rule_set['tenant_id'],
                      transaction=mock.ANY)]

        self._verify_chain_set(db, l2p, app_db_policy_rule_set,
                               sc_instance, 2, pre_set_contract_calls=expected)
        mgr.reset_mock()
        self.update_policy_target_group(
            app['id'],
            consumed_policy_rule_sets={app_db_policy_rule_set['id']: ''},
            provided_policy_rule_sets={web_app_policy_rule_set['id']: ''})
        self.update_policy_target_group(
            web['id'],
            consumed_policy_rule_sets={web_app_policy_rule_set['id']: ''})

        expected = [
            # Provider EPG provided PRS
            mock.call(app['tenant_id'], app['id'],
                      web_app_policy_rule_set['id'], provider=True,
                      contract_owner=web_app_policy_rule_set['tenant_id'],
                      transaction=mock.ANY),
            # Consumer EPG consumed PRS
            mock.call(web['tenant_id'], web['id'],
                      web_app_policy_rule_set['id'], provider=False,
                      contract_owner=web_app_policy_rule_set['tenant_id'],
                      transaction=mock.ANY)]

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 2)
        sc_instance = [x for x in sc_instances['servicechain_instances']
                       if x['id'] not in seen][0]
        seen.add(sc_instance['id'])

        self._verify_chain_set(app, l2p, web_app_policy_rule_set,
                               sc_instance, 1, pre_set_contract_calls=expected)

        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[], expected_res_status=201)['external_segment']

        ep = self.create_external_policy(
            external_segments=[es['id']],
            expected_res_status=201)['external_policy']
        mgr.reset_mock()
        self.update_policy_target_group(
            web['id'],
            consumed_policy_rule_sets={web_app_policy_rule_set['id']: ''},
            provided_policy_rule_sets={internet_web_policy_rule_set['id']: ''})
        self.update_external_policy(
            ep['id'],
            consumed_policy_rule_sets={internet_web_policy_rule_set['id']: ''})
        expected = [
            # Provider EPG provided PRS
            mock.call(web['tenant_id'], web['id'],
                      internet_web_policy_rule_set['id'], provider=True,
                      contract_owner=internet_web_policy_rule_set['tenant_id'],
                      transaction=mock.ANY)]

        sc_instances = self._list_service_chains()
        # We should have one service chain instance created now
        self.assertEqual(len(sc_instances['servicechain_instances']), 3)
        sc_instance = [x for x in sc_instances['servicechain_instances']
                       if x['id'] not in seen][0]
        seen.add(sc_instance['id'])

        self._verify_chain_set(app, web_l2p, internet_web_policy_rule_set,
                               sc_instance, 0, pre_set_contract_calls=expected)

    def test_rule_removed_by_shared(self):
        scs_id = self._create_servicechain_spec(
            node_types=['FIREWALL_TRANSPARENT'], shared=True)
        policy_rule_id = self._create_simple_policy_rule(
            action_type='redirect', shared=True, action_value=scs_id)['id']
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id],
            shared=True)['policy_rule_set']
        # Create PTGs on same L2P
        l2p = self.create_l2_policy(tenant_id='noadmin')['l2_policy']
        provider = self.create_policy_target_group(
            l2_policy_id=l2p['id'], tenant_id='noadmin')['policy_target_group']

        mgr = self.driver.apic_manager
        # form the chain
        self.update_policy_target_group(
            provider['id'], tenant_id=provider['tenant_id'],
            provided_policy_rule_sets={policy_rule_set['id']: ''})

        mgr.reset_mock()
        self.update_policy_rule_set(policy_rule_set['id'], policy_rules=[],
                                    expected_res_status=200)

    def _verify_chain_set(self, *args, **kwargs):
        pass

    def _verify_chain_unset(self, *args, **kwargs):
        pass

    def _list_service_chains(self):
        sc_instance_list_req = self.new_list_request(
            'servicechain/servicechain_instances')
        res = sc_instance_list_req.get_response(self.ext_api)
        return self.deserialize(self.fmt, res)

    # REVISIT: The following test is being temporarily disabled since the
    # logic in the chain_mapping driver needs to be revisited.
    @unittest2.skip('skipping')
    def test_ha_chain_same_subnet(self):
        session = context.get_admin_context().session
        # Create 2 L3Ps with same pools
        l3p1 = self.create_l3_policy()['l3_policy']
        l3p2 = self.create_l3_policy()['l3_policy']

        # Attach proper L2Ps
        l2p1 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        l2p2 = self.create_l2_policy(l3_policy_id=l3p2['id'])['l2_policy']

        # Set providers PTGs
        ptg_prov_1 = self.create_policy_target_group(
            l2_policy_id=l2p1['id'])['policy_target_group']
        ptg_prov_2 = self.create_policy_target_group(
            l2_policy_id=l2p2['id'])['policy_target_group']

        # At this point, they  have the same subnet CIDR associated, same will
        # be for Proxy Groups
        ha_spec_id = self._create_servicechain_spec(node_types=['FIREWALL_HA'])

        # Create proper PRS
        policy_rule_id = self._create_simple_policy_rule(
            action_type='redirect', action_value=ha_spec_id)['id']
        policy_rule_set = self.create_policy_rule_set(
            name="c1", policy_rules=[policy_rule_id])['policy_rule_set']

        # Form first and second chain
        ptg_prov_1 = self.update_policy_target_group(
            ptg_prov_1['id'], provided_policy_rule_sets={
                policy_rule_set['id']: ''})['policy_target_group']
        ptg_prov_2 = self.update_policy_target_group(
            ptg_prov_2['id'], provided_policy_rule_sets={
                policy_rule_set['id']: ''})['policy_target_group']

        # One proxy group exists for both, each with 2 service PTs. Put them in
        # HA
        scis = self._list_service_chains()['servicechain_instances']
        self.assertEqual(2, len(scis))
        # Chain 1 targets
        targets_1 = model.get_service_targets(
            session, servicechain_instance_id=scis[0]['id'])
        # Chain 2 targets
        targets_2 = model.get_service_targets(
            session, servicechain_instance_id=scis[1]['id'])

        def _assert_service_targets_and_cluster_them(targets):
            result = {}
            for pt in targets:
                pt = self.show_policy_target(
                    pt.policy_target_id,
                    is_admin_context=True)['policy_target']
                result.setdefault(
                    pt['policy_target_group_id'], []).append(pt)

            # There are 2 PTGs, and 3 PTs each
            self.assertEqual(2, len(result))
            for key in result:
                # Sort by IP address
                result[key].sort(key=lambda x: self._get_object(
                    'ports', x['port_id'],
                    self.api)['port']['fixed_ips'][0]['ip_address'])
                value = result[key]
                self.assertEqual(3, len(value))
                # Set first PT as master of the other twos
                self.update_policy_target(value[1]['id'],
                                          cluster_id=value[0]['id'],
                                          is_admin_context=True)
                self.update_policy_target(value[2]['id'],
                                          cluster_id=value[0]['id'],
                                          is_admin_context=True)
            return result
        # Group chain 1 targets by PTG:
        chain_targets_1 = _assert_service_targets_and_cluster_them(targets_1)
        # Group chain 2 targets by PTG:
        chain_targets_2 = _assert_service_targets_and_cluster_them(targets_2)

        # Verify IPs overlap on provider side
        main_ip = None
        for x in range(3):
            port_1 = self._get_object(
                'ports', chain_targets_1[ptg_prov_1['id']][x]['port_id'],
                self.api)['port']
            port_2 = self._get_object(
                'ports', chain_targets_2[ptg_prov_2['id']][x]['port_id'],
                self.api)['port']
            self.assertEqual(port_1['fixed_ips'][0]['ip_address'],
                             port_2['fixed_ips'][0]['ip_address'])
            if x == 0:
                main_ip = port_1['fixed_ips'][0]['ip_address']

        # Update address ownership on second port
        self.driver.update_ip_owner(
            {'port': chain_targets_1[ptg_prov_1['id']][1]['port_id'],
             'ip_address_v4': main_ip})
        # Same address owned by another port in a different subnet
        self.driver.update_ip_owner(
            {'port': chain_targets_2[ptg_prov_2['id']][1]['port_id'],
             'ip_address_v4': main_ip})

        # There are 2 ownership entries for the same address
        entries = self.driver.ha_ip_handler.session.query(
                    ha_ip_db.HAIPAddressToPortAssocation).all()
        self.assertEqual(2, len(entries))
        self.assertEqual(main_ip, entries[0].ha_ip_address)
        self.assertEqual(main_ip, entries[1].ha_ip_address)


class TestProxyGroup(ApicMappingStitchingPlumberGBPTestCase):

    def _proxy_tenant(self, ptg, admin_proxy):
        return 'admin' if admin_proxy else ptg['tenant_id']

    def _test_proxy_group_same_l2p(self, admin_proxy=False):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        l2p = self.create_l2_policy()['l2_policy']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'],
            l2_policy_id=l2p['id'],
            tenant_id=self._proxy_tenant(ptg1, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        # The used L2P will be ignored, and the proxy will be put on the
        # proxied group's L2P
        self.assertEqual(ptg1['l2_policy_id'], proxy['l2_policy_id'])

    def test_proxy_group_same_l2p(self):
        self._test_proxy_group_same_l2p()

    def test_proxy_group_same_l2p_admin(self):
        self._test_proxy_group_same_l2p(True)

    def _test_l2_proxy_group_subnets(self, admin_proxy=False):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            proxy_type='l2', tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg['subnets'], proxy['subnets'])
        self.assertEqual(1, len(proxy['subnets']))

    def test_l2_proxy_group_subnets(self):
        self._test_l2_proxy_group_subnets()

    def test_l2_proxy_group_subnets_admin(self):
        self._test_l2_proxy_group_subnets(True)

    def _test_l3_proxy_group_subnets(self, admin_proxy=False):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        original_subnet = ptg1['subnets'][0]
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'],
            proxy_type='l3', tenant_id=self._proxy_tenant(ptg1, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']

        ptg1 = self.show_policy_target_group(ptg1['id'])['policy_target_group']
        self.assertEqual(set(ptg1['subnets']), set(proxy['subnets']))
        self.assertEqual(2, len(proxy['subnets']))
        proxy['subnets'].remove(original_subnet)
        new_subnet = proxy['subnets'][0]

        # Verify subnet from proxy pool
        l2p = self.show_l2_policy(ptg1['l2_policy_id'])['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        subnet = self._get_object('subnets', new_subnet, self.api)['subnet']
        self.assertTrue(netaddr.IPNetwork(subnet['cidr']) in
                        netaddr.IPNetwork(l3p['proxy_ip_pool']))

        # Attach external segment to create a router interface
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']
        self.update_l3_policy(l2p['l3_policy_id'],
                              external_segments={es['id']: []},
                              expected_res_status=200)

        # the proxy subnets should have no router
        ports = self._list(
            'ports',
            query_params='device_owner=network:router_interface')['ports']
        self.assertEqual(1, len(ports))

        # this router port is only connected to the original PTG
        self.assertEqual(original_subnet,
                         ports[0]['fixed_ips'][0]['subnet_id'])

        # Verify port address comes from that subnet
        pt = self.create_policy_target(
            policy_target_group_id=proxy['id'],
            tenant_id=proxy['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']
        port = self._get_object('ports', pt['port_id'], self.api)['port']
        self.assertTrue(
            netaddr.IPNetwork(port['fixed_ips'][0]['ip_address']) in
            netaddr.IPNetwork(subnet['cidr']),
            "IP address %s is not part of subnet %s" % (
                port['fixed_ips'][0]['ip_address'], subnet['cidr']))

    def test_l3_proxy_group_subnets(self):
        self._test_l3_proxy_group_subnets()

    def test_l3_proxy_group_subnets_admin(self):
        self._test_l3_proxy_group_subnets(True)

    def test_proxy_shadow_created(self):
        l2p = self.create_l2_policy()['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.mgr.reset_mock()
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'])['policy_target_group']
        l2p = self.show_l2_policy(ptg['l2_policy_id'])['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'])['l3_policy']
        # Shadow BD created
        self.mgr.ensure_bd_created_on_apic.assert_called_once_with(
            ptg['tenant_id'], 'Shd-' + ptg['id'], ctx_owner=l3p['tenant_id'],
            ctx_name=l3p['id'], allow_broadcast=True, unicast_route=False,
            transaction=mock.ANY, enforce_subnet_check=False)
        # Proxied PTG moved
        expected_calls = [
            # Proxy created on L2P
            mock.call(
                ptg['tenant_id'], proxy['id'], bd_owner=l2p['tenant_id'],
                bd_name=l2p['id']),
            # Proxied moved on shadow BD
            mock.call(
                ptg['tenant_id'], ptg['id'], bd_owner=ptg['tenant_id'],
                bd_name='Shd-' + ptg['id'], transaction=mock.ANY)]
        self._check_call_list(expected_calls,
                              self.mgr.ensure_epg_created.call_args_list)

    def _test_proxy_any_contract(self, admin_proxy=False):
        ptg = self.create_policy_target_group()['policy_target_group']
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']

        self.mgr.create_contract('any-' + ptg['id'], owner='COMMON',
                                 transaction=mock.ANY)
        expected_calls = [
            mock.call(
                ptg['tenant_id'], ptg['id'], 'any-' + ptg['id'], provider=True,
                contract_owner='common'),
            mock.call(
                ptg['tenant_id'], proxy['id'], 'any-' + ptg['id'],
                provider=False, contract_owner='common')]
        self._check_call_list(expected_calls,
                              self.mgr.set_contract_for_epg.call_args_list,
                              check_all=False)

    def test_proxy_any_contract(self):
        self._test_proxy_any_contract()

    def test_proxy_any_contract_admin(self):
        self._test_proxy_any_contract(True)

    def _test_proxy_shadow_deleted(self, admin_proxy=False):
        ptg1 = self.create_policy_target_group()['policy_target_group']
        original_subnet = ptg1['subnets'][0]
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg1['id'],
            tenant_id=self._proxy_tenant(ptg1, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']

        self.mgr.reset_mock()
        self.delete_policy_target_group(proxy['id'], expected_res_status=204)
        proxy['subnets'].remove(original_subnet)
        # Proxied PTG moved back
        self.mgr.ensure_epg_created.assert_called_once_with(
            ptg1['tenant_id'], ptg1['id'], bd_owner=ptg1['tenant_id'],
            bd_name=ptg1['l2_policy_id'])
        # Shadow BD deleted
        self.mgr.delete_bd_on_apic.assert_called_once_with(
            ptg1['tenant_id'], 'Shd-' + ptg1['id'])
        # Verify Jump subnet deleted
        self.assertEqual(1, len(proxy['subnets']))
        self._get_object('subnets', proxy['subnets'][0], self.api,
                         expected_res_status=404)

    def _test_get_gbp_details(self, admin_proxy=False, async=False):
        def request_wrapper(*args, **kwargs):
            kwargs['timestamp'] = 0
            kwargs['request_id'] = 'some_id'
            result = self.driver.request_endpoint_details(*args,
                                                          request=kwargs)
            if result:
                return result.get('gbp_details')

        gbp_details = {False: self.driver.get_gbp_details,
                       True: request_wrapper}
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        data = {'allowed_address_pairs':
                [{'ip_address': '170.166.0.1'},
                 {'ip_address': '170.166.0.2'}]}
        # Create EP with bound port
        port = self.driver._update_port(context.get_admin_context(),
                                        pt1['port_id'], data)
        self.assertEqual(['170.166.0.1', '170.166.0.2'],
                         [x['ip_address'] for x in
                          port['allowed_address_pairs']])
        self._bind_port_to_host(pt1['port_id'], 'h1')
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h2')

        # Create proxy group
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        proxy_gw = self.create_policy_target(
            policy_target_group_id=proxy['id'],
            proxy_gateway=True,
            tenant_id=proxy['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']
        self._bind_port_to_host(proxy_gw['port_id'], 'h2')
        # Create a PT in the same cluster
        proxy_gw_failover = self.create_policy_target(
            policy_target_group_id=proxy['id'],
            cluster_id=proxy_gw['id'],
            tenant_id=proxy['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']
        self._bind_port_to_host(proxy_gw_failover['port_id'], 'h2')
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[], expected_res_status=201)['external_segment']
        self.create_external_policy(external_segments=[es['id']],
                                    expected_res_status=201)

        l2p = self.show_l2_policy(ptg['l2_policy_id'])['l2_policy']
        self.update_l3_policy(l2p['l3_policy_id'],
                              external_segments={es['id']: []},
                              expected_res_status=200)

        self._bind_port_to_host(pt2['port_id'], 'h2')
        master_port = self._get_object('ports', proxy_gw['port_id'],
                                       self.api)['port']

        def echo(name):
            return name
        self.mgr.apic.fvTenant.name = echo
        mapping = gbp_details[async](
            context.get_admin_context(),
            device='tap%s' % proxy_gw['port_id'], host='h2')

        # Verify extra addresses
        ips = self._get_pts_addresses([pt1, pt2])
        self.assertEqual(set(ips + ['170.166.0.1', '170.166.0.2']),
                         set(mapping['extra_ips']))
        self.assertEqual(ptg['tenant_id'], mapping['ptg_tenant'])
        self.assertEqual(1, len(mapping['ip_mapping']))
        # No SNAT subnet
        self.assertEqual(0, len(mapping['host_snat_ips']))

        group_default_gw = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            group_default_gateway=True,
            tenant_id=ptg['tenant_id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h2')
        mapping = gbp_details[async](
            context.get_admin_context(),
            device='tap%s' % group_default_gw['port_id'], host='h2')
        self.assertTrue(mapping['promiscuous_mode'])

        # No extra IPs for the failover since it doesn't own the master IP
        mapping = gbp_details[async](
            context.get_admin_context(),
            device='tap%s' % proxy_gw_failover['port_id'], host='h2')
        self.assertEqual(0, len(mapping['extra_ips'] or []))
        self.assertEqual(
            [{'mac_address': master_port['mac_address'],
             'ip_address': master_port['fixed_ips'][0]['ip_address']}],
            mapping['allowed_address_pairs'])
        # Set the port ownership and verify that extra_ips is correctly set
        ips = self._get_pts_addresses([pt1, pt2, group_default_gw])
        for x in master_port['fixed_ips']:
            self.driver.ha_ip_handler.set_port_id_for_ha_ipaddress(
                proxy_gw_failover['port_id'], x['ip_address'])

        mapping = gbp_details[async](
            context.get_admin_context(),
            device='tap%s' % proxy_gw_failover['port_id'], host='h2')
        self.assertEqual(
            set(ips + ['170.166.0.1', '170.166.0.2']),
            set(mapping['extra_details'][master_port['mac_address']][
                    'extra_ips']))
        self.assertEqual(
            [{'mac_address': master_port['mac_address'],
             'ip_address': master_port['fixed_ips'][0]['ip_address'],
             'active': True}],
            mapping['allowed_address_pairs'])

    def test_get_gbp_details(self):
        self._test_get_gbp_details()

    def test_get_gbp_details_admin(self):
        self._test_get_gbp_details(True)

    def test_get_gbp_details_async(self):
        self._test_get_gbp_details(False, True)

    def test_get_gbp_details_admin_async(self):
        self._test_get_gbp_details(True, True)

    def test_cluster_promiscuous_mode(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        # Create proxy group
        self.create_policy_target_group(proxied_group_id=ptg['id'])
        group_gw = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            group_default_gateway=True)['policy_target']
        # Create a PT in the same cluster
        group_gw_failover = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            cluster_id=group_gw['id'])['policy_target']
        mapping = self.driver.get_gbp_details(
            context.get_admin_context(),
            device='tap%s' % group_gw_failover['port_id'], host='h2')
        self.assertTrue(mapping['promiscuous_mode'])

    def _test_end_chain_notified(self, admin_proxy=False):
        self.driver.notifier = mock.Mock()
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        proxy1 = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy1['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        proxy_gw = self.create_policy_target(
            policy_target_group_id=proxy2['id'],
            proxy_gateway=True, tenant_id=proxy2['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']
        self._bind_port_to_host(proxy_gw['port_id'], 'h2')
        self.driver.notifier.reset_mock()

        # Create a PT on the starting PTG, and verify that proxy_gw is
        # notified
        self.create_policy_target(policy_target_group_id=ptg['id'])
        self.assertEqual(1, self.driver.notifier.port_update.call_count)
        self.assertEqual(
            proxy_gw['port_id'],
            self.driver.notifier.port_update.call_args[0][1]['id'])

    def _test_end_chain_notified_cluster_id(self, admin_proxy=False):
        self.driver.notifier = mock.Mock()
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        proxy1 = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy1['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        proxy_gw_master = self.create_policy_target(
            policy_target_group_id=proxy2['id'],
            proxy_gateway=True, tenant_id=proxy2['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']
        # The following is not proxy gateway, but is part of a proxy_gw cluster
        proxy_gw = self.create_policy_target(
            policy_target_group_id=proxy2['id'],
            cluster_id=proxy_gw_master['id'], tenant_id=proxy2['tenant_id'],
            is_admin_context=admin_proxy)['policy_target']

        self._bind_port_to_host(proxy_gw['port_id'], 'h2')
        self.driver.notifier.reset_mock()

        # Create a PT on the starting PTG, and verify that proxy_gw is
        # notified
        self.create_policy_target(policy_target_group_id=ptg['id'])
        self.assertEqual(1, self.driver.notifier.port_update.call_count)
        self.assertEqual(
            proxy_gw['port_id'],
            self.driver.notifier.port_update.call_args[0][1]['id'])

    def test_end_chain_notified(self):
        self._test_end_chain_notified()

    def test_end_chain_notified_admin(self):
        self._test_end_chain_notified(True)

    def test_proxy_group_right_tenant(self):
        l2p = self.create_l2_policy(tenant_id='non-admin')['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            tenant_id='non-admin')['policy_target_group']
        self.mgr.reset_mock()
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'], is_admin_context=True,
            tenant_id='admin-tenant')['policy_target_group']
        l3p = self.show_l3_policy(l2p['l3_policy_id'],
                                  tenant_id='non-admin')['l3_policy']

        # Shadow BD created in non-admin tenant
        self.mgr.ensure_bd_created_on_apic.assert_called_once_with(
            'non-admin', 'Shd-' + ptg['id'], ctx_owner=l3p['tenant_id'],
            ctx_name=l3p['id'], allow_broadcast=True, unicast_route=False,
            transaction=mock.ANY, enforce_subnet_check=False)
        # Proxied PTG moved
        expected_calls = [
            # Proxy created on L2P
            mock.call(
                'non-admin', proxy['id'], bd_owner=l2p['tenant_id'],
                bd_name=l2p['id']),
            # Proxied moved on shadow BD
            mock.call(
                'non-admin', ptg['id'], bd_owner=ptg['tenant_id'],
                bd_name='Shd-' + ptg['id'], transaction=mock.ANY)]
        self._check_call_list(expected_calls,
                              self.mgr.ensure_epg_created.call_args_list)

    def test_prs_sync_with_proxy(self, admin_proxy=False):
        rule = self._create_ssh_allow_rule()
        policy_rule_set_1 = self.create_policy_rule_set(
            name="c1", policy_rules=[rule['id']])['policy_rule_set']
        policy_rule_set_2 = self.create_policy_rule_set(
            name="c2", policy_rules=[rule['id']])['policy_rule_set']
        ptg = self.create_policy_target_group(
            provided_policy_rule_sets={policy_rule_set_1['id']: ''},
            consumed_policy_rule_sets={policy_rule_set_2['id']: ''})[
                'policy_target_group']
        # Sync on proxy creation
        proxy1 = self.create_policy_target_group(
            proxied_group_id=ptg['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']

        self.assertEqual([policy_rule_set_1['id']],
                         proxy1['provided_policy_rule_sets'])
        self.assertEqual([policy_rule_set_2['id']],
                         proxy1['consumed_policy_rule_sets'])
        proxy2 = self.create_policy_target_group(
            proxied_group_id=proxy1['id'],
            tenant_id=self._proxy_tenant(ptg, admin_proxy),
            is_admin_context=admin_proxy)['policy_target_group']
        self.assertEqual([policy_rule_set_1['id']],
                         proxy2['provided_policy_rule_sets'])
        self.assertEqual([policy_rule_set_2['id']],
                         proxy2['consumed_policy_rule_sets'])

        # Sync on original update
        self.update_policy_target_group(
            ptg['id'], provided_policy_rule_sets={})
        proxy1 = self.show_policy_target_group(
            proxy1['id'])['policy_target_group']
        self.assertEqual([],
                         proxy1['provided_policy_rule_sets'])
        self.assertEqual([policy_rule_set_2['id']],
                         proxy1['consumed_policy_rule_sets'])
        proxy2 = self.show_policy_target_group(
            proxy2['id'])['policy_target_group']
        self.assertEqual([],
                         proxy1['provided_policy_rule_sets'])
        self.assertEqual([policy_rule_set_2['id']],
                         proxy2['consumed_policy_rule_sets'])

    def test_l3_proxy_subnets_delete(self):
        l2p = self.create_l2_policy(tenant_id='non-admin')['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            tenant_id='non-admin')['policy_target_group']
        main_subnet = set(ptg['subnets'])
        self.mgr.reset_mock()
        proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'], is_admin_context=True,
            tenant_id='admin-tenant')['policy_target_group']
        subnets = set(proxy['subnets'])
        added = subnets - main_subnet
        self.delete_policy_target_group(proxy['id'], is_admin_context=True,
                                        expected_res_status=204)
        # Subnet doesn't exist anymore
        self._get_object('subnets', list(added)[0], self.api,
                         expected_res_status=404)


class TestApicChainsAdminOwner(TestApicChains):

    def setUp(self, **kwargs):
        mock.patch('gbpservice.neutron.services.grouppolicy.drivers.'
                   'chain_mapping.ChainMappingDriver.'
                   'chain_tenant_keystone_client').start()
        res = mock.patch('gbpservice.neutron.services.grouppolicy.drivers.'
                         'chain_mapping.ChainMappingDriver.'
                         'chain_tenant_id').start()
        res.return_value = test_rmd.CHAIN_TENANT_ID
        super(TestApicChainsAdminOwner, self).setUp(**kwargs)

    def _assert_proper_chain_instance(self, sc_instance, provider_ptg_id,
                                      consumer_ptg_id, scs_id_list,
                                      classifier_id=None):
        self.assertEqual(sc_instance['provider_ptg_id'], provider_ptg_id)
        self.assertEqual(sc_instance['consumer_ptg_id'], 'N/A')
        self.assertEqual(sc_instance['tenant_id'], test_rmd.CHAIN_TENANT_ID)
        self.assertEqual(scs_id_list, sc_instance['servicechain_specs'])
        if classifier_id:
            self.assertEqual(sc_instance['classifier_id'], classifier_id)
