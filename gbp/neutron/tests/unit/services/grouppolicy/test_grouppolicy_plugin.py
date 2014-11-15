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

import mock
from neutron import context
from oslo.config import cfg

import gbp.neutron.tests.unit.db.grouppolicy.test_group_policy_db as tgpdb
import gbp.neutron.tests.unit.db.grouppolicy.test_group_policy_mapping_db as \
    tgpmdb


cfg.CONF.import_opt('policy_drivers',
                    'gbp.neutron.services.grouppolicy.config',
                    group='group_policy')
GP_PLUGIN_KLASS = (
    "gbp.neutron.services.grouppolicy.plugin.GroupPolicyPlugin"
)


class FakeDriver(object):

    def _fill_order(self, context):
        context.call_order.append(self)

    def __getattr__(self, item):
        return self._fill_order


class GroupPolicyPluginTestCase(tgpmdb.GroupPolicyMappingDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None):
        if not gp_plugin:
            gp_plugin = GP_PLUGIN_KLASS
        super(GroupPolicyPluginTestCase, self).setUp(core_plugin=core_plugin,
                                                     gp_plugin=gp_plugin)

    def test_reverse_on_delete(self):
        manager = self.plugin.policy_driver_manager
        ctx = context.get_admin_context()
        drivers = manager.ordered_policy_drivers
        first, second = mock.Mock(), mock.Mock()
        first.obj, second.obj = FakeDriver(), FakeDriver()
        try:
            manager.ordered_policy_drivers = [first, second]
            manager.reverse_ordered_policy_drivers = [second, first]
            ordered_obj = [first.obj, second.obj]
            ctx.call_order = []
            manager._call_on_drivers('nodelete', ctx)
            self.assertEqual(ordered_obj, ctx.call_order)
            ctx.call_order = []
            manager._call_on_drivers('delete', ctx)
            self.assertEqual(ordered_obj[::-1], ctx.call_order)
        finally:
            manager.ordered_policy_drivers = drivers

    def test_delete_fails_on_used_epg(self):
        epg = self.create_endpoint_group()['endpoint_group']
        self.create_endpoint(endpoint_group_id=epg['id'])
        req = self.new_delete_request('endpoint_groups', epg['id'], self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def _create_l2_policy_on_shared(self, **kwargs):
        l3p = self.create_l3_policy(shared=True)['l3_policy']
        return self.create_l2_policy(l3_policy_id=l3p['id'],
                                     **kwargs)['l2_policy']

    def _create_epg_on_shared(self, **kwargs):
        l2p = self._create_l2_policy_on_shared(shared=True)
        return self.create_endpoint_group(l2_policy_id=l2p['id'], **kwargs)

    def _create_rule_on_shared(self, **kwargs):
        pa = self.create_policy_action(action_type='allow',
                                       shared=True)['policy_action']
        cl_attr = {'protocol': 'tcp', 'port_range': 80}
        pc = self.create_policy_classifier(direction='in',
                                           shared=True,
                                           **cl_attr)['policy_classifier']
        return self.create_policy_rule(
            pc['id'], policy_actions=[pa['id']], **kwargs)['policy_rule']

    def _create_contract_on_shared(self, **kwargs):
        pr = self._create_rule_on_shared(shared=True)
        return self.create_contract(policy_rules=[pr['id']],
                                    **kwargs)['contract']

    def test_shared_l3_policy_create(self):
        # Verify default is False
        l3p = self.create_l3_policy()
        self.assertEqual(False, l3p['l3_policy']['shared'])
        # Verify shared True created without errors
        l3p = self.create_l3_policy(shared=True)
        self.assertEqual(True, l3p['l3_policy']['shared'])

    def test_shared_l2_policy_create(self):
        l3p = self.create_l3_policy(shared=True)['l3_policy']
        # Verify Default False
        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])
        self.assertEqual(False, l2p['l2_policy']['shared'])
        # Verify shared True created without errors
        l2p = self.create_l2_policy(l3_policy_id=l3p['id'], shared=True)
        self.assertEqual(True, l2p['l2_policy']['shared'])

    def test_shared_l2_policy_create_negative(self):
        l3p = self.create_l3_policy()['l3_policy']
        self.create_l2_policy(l3_policy_id=l3p['id'], shared=True,
                              expected_res_status=400)

    def test_shared_epg_create(self):
        l2p = self._create_l2_policy_on_shared(shared=True)
        l2pns = self._create_l2_policy_on_shared()

        ct = self._create_contract_on_shared(shared=True)
        ctns = self._create_contract_on_shared()

        nsp = self.create_network_service_policy(
            shared=True)['network_service_policy']
        nspns = self.create_network_service_policy()['network_service_policy']
        # Verify non-shared epg providing and consuming shared and non shared
        # contracts
        epg = self.create_endpoint_group(
            l2_policy_id=l2p['id'], expected_res_status=201)
        self.assertEqual(False, epg['endpoint_group']['shared'])
        epg = self.create_endpoint_group(
            l2_policy_id=l2p['id'],
            provided_contracts={ct['id']: '', ctns['id']: ''},
            consumed_contracts={ct['id']: '', ctns['id']: ''},
            expected_res_status=201)
        self.assertEqual(False, epg['endpoint_group']['shared'])
        epg = self.create_endpoint_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=201)
        self.assertEqual(False, epg['endpoint_group']['shared'])
        epg = self.create_endpoint_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nspns['id'],
            expected_res_status=201)
        self.assertEqual(False, epg['endpoint_group']['shared'])

        # Verify shared True created without errors by providing/consuming
        # shared contracts
        epg = self.create_endpoint_group(l2_policy_id=l2p['id'], shared=True,
                                         expected_res_status=201)
        self.assertEqual(True, epg['endpoint_group']['shared'])
        epg = self.create_endpoint_group(
            l2_policy_id=l2p['id'], provided_contracts={ct['id']: ''},
            consumed_contracts={ct['id']: ''}, shared=True,
            expected_res_status=201)
        self.assertEqual(True, epg['endpoint_group']['shared'])

        # Verify not shared created without error on not shared l2p
        self.create_endpoint_group(l2_policy_id=l2pns['id'],
                                   expected_res_status=201)

    def test_shared_epg_create_negative(self):
        l2pns = self._create_l2_policy_on_shared()
        ctns = self._create_contract_on_shared()
        # Verify shared EPG fails on non-shared l2p
        self.create_endpoint_group(l2_policy_id=l2pns['id'], shared=True,
                                   expected_res_status=400)
        # Verify shared EPG fails to provide/consume non shared contracts
        self._create_epg_on_shared(
            shared=True, provided_contracts={ctns['id']: ''},
            consumed_contracts={ctns['id']: ''}, expected_res_status=400)

    def test_shared_contract_create(self):
        # Verify shared contract created with shared rules
        ct = self._create_contract_on_shared(shared=True,
                                             expected_res_status=201)
        self.assertEqual(True, ct['shared'])

        # Verify non shared contract created with shared rules
        ct = self._create_contract_on_shared(expected_res_status=201)
        self.assertEqual(False, ct['shared'])

    def test_shared_contract_create_negative(self):
        # Verify shared contract fails with non shared rules
        prns = self._create_rule_on_shared()
        pr = self._create_rule_on_shared(shared=True)
        self.create_contract(expected_res_status=400,
                             shared=True,
                             policy_rules=[pr['id'], prns['id']])

    def test_shared_rule_create(self):
        # Verify shared rule created with shared actions and classifier
        pr = self._create_rule_on_shared(shared=True,
                                         expected_res_status=201)
        self.assertEqual(True, pr['shared'])

        # Verify non shared rule create with shared actions and classifier
        pr = self._create_rule_on_shared(expected_res_status=201)
        self.assertEqual(False, pr['shared'])

    def test_shared_rule_create_negative(self):
        # Verify shared rule fails with non shared classifier
        pans = self.create_policy_action(action_type='allow')['policy_action']
        pcns = self.create_policy_classifier(
            direction='in')['policy_classifier']
        pc = self.create_policy_classifier(direction='in',
                                           shared=True)['policy_classifier']
        self.create_policy_rule(
            pcns['id'], expected_res_status=400, shared=True)

        #Verify shared rule fails with non shared action
        self.create_policy_rule(
            pc['id'], policy_actions=[pans['id']],
            expected_res_status=400, shared=True)

    def test_l2p_create_among_tenants(self):
        # L2P on shared L3P:
        self._create_l2_policy_on_shared(
            tenant_id='other', expected_res_status=201)

    def test_epg_create_among_tenants(self):
        self._create_epg_on_shared(tenant_id='other',
                                   expected_res_status=201)

    def test_contract_create_among_tenants(self):
        self._create_contract_on_shared(tenant_id='other',
                                        expected_res_status=201)

    def test_rule_create_among_tenants(self):
        self._create_rule_on_shared(tenant_id='other',
                                    expected_res_status=201)

    def test_complex_epg_create_among_tenant(self):
        ctp = self._create_contract_on_shared(shared=True)
        ctc = self._create_contract_on_shared(shared=True)
        nsp = self.create_network_service_policy(
            shared=True)['network_service_policy']
        self._create_epg_on_shared(
            tenant_id='other', provided_contracts={ctp['id']: ''},
            consumed_contracts={ctc['id']: ''},
            network_service_policy_id=nsp['id'], expected_res_status=201)


class TestGroupPolicyPluginGroupResources(
    GroupPolicyPluginTestCase, tgpdb.TestGroupResources):

    pass


class TestGroupPolicyPluginMappedGroupResourceAttrs(
    GroupPolicyPluginTestCase, tgpmdb.TestMappedGroupResourceAttrs):

    pass
