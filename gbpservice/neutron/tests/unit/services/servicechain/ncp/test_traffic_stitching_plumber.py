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

import mock
from neutron.common import config  # noqa
from neutron import context as n_context
from oslo_config import cfg

from gbpservice.neutron.services.servicechain.plugins.ncp import model
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as base)


class TrafficStitchingPlumberTestCase(base.NodeCompositionPluginTestCase):

    def setUp(self):
        cfg.CONF.set_override('policy_drivers', ['implicit_policy',
                                                 'resource_mapping'],
                              group='group_policy')
        cfg.CONF.set_override('allow_overlapping_ips', True)
        cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        super(TrafficStitchingPlumberTestCase, self).setUp(
            node_drivers=['node_dummy'], node_plumber='stitching_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)
        res = mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                         '_check_router_needs_rescheduling').start()
        res.return_value = None
        self.driver = self.sc_plugin.driver_manager.ordered_drivers[0].obj
        self.driver.get_plumbing_info = mock.Mock()
        self.driver.get_plumbing_info.return_value = {}

    def test_one_gateway_pt_prov_cons(self):
        context = n_context.get_admin_context()
        self.driver.get_plumbing_info.return_value = {
            'provider': [{}], 'consumer': [{}], 'plumbing_type': 'gateway'}
        provider, consumer, node = self._create_simple_chain()
        provider = self.show_policy_target_group(
            provider['id'])['policy_target_group']
        # Verify Service PT created and correctly placed
        targets = model.get_service_targets(context.session)
        self.assertEqual(2, len(targets))
        old_relationship = None
        for target in targets:
            self.assertEqual(node['id'], target.servicechain_node_id)
            pt = self.show_policy_target(
                target.policy_target_id)['policy_target']
            if target.relationship == 'provider':
                self.assertEqual(provider['id'],
                                 pt['policy_target_group_id'])
                self.assertTrue(pt['group_default_gateway'])
                self.assertFalse(pt['proxy_gateway'])
            else:
                # Consumer side a proxy group exists
                self.assertEqual(provider['proxy_group_id'],
                                 pt['policy_target_group_id'])
                self.assertFalse(pt['group_default_gateway'])
                self.assertTrue(pt['proxy_gateway'])

            self.assertNotEqual(old_relationship, target.relationship)
            old_relationship = target.relationship
            port = self._get_object('ports', pt['port_id'], self.api)['port']
            self.assertTrue(port['name'].startswith('pt_service_target_'),
                            "Port name doesn't start with 'pt_service_target_"
                            "'.\nport:\n%s\n" % port)

        self.update_policy_target_group(
            provider['id'], provided_policy_rule_sets={})
        # With chain deletion, also the Service PTs are deleted
        new_targets = model.get_service_targets(context.session)
        self.assertEqual(0, len(new_targets))
        for target in targets:
            self.show_policy_target(
                target.policy_target_id, expected_res_status=404)
        provider = self.show_policy_target_group(
            provider['id'])['policy_target_group']
        self.assertIsNone(provider['proxy_group_id'])

    def test_ptg_delete(self):
        self.driver.get_plumbing_info.return_value = {
            'provider': [{}], 'consumer': [{}],
            'plumbing_type': 'transparent'}
        provider, _, _ = self._create_simple_service_chain()
        # Deleting a PTG will fail because of existing PTs
        self.delete_policy_target_group(provider['id'],
                                        expected_res_status=204)
