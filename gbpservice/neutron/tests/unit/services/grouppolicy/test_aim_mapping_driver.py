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

from aim.api import resource as aim_resource
from aim.api import status as aim_status
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from keystoneclient.v3 import client as ksc_client
from neutron import context as nctx
from neutron.db import api as db_api
import webob.exc

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as aim_md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.tests.unit.plugins.ml2plus import (
    test_apic_aim as test_aim_md)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_neutron_resources_driver as test_nr_base)


ML2PLUS_PLUGIN = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'


class AIMBaseTestCase(test_nr_base.CommonNeutronBaseTestCase,
                      test_ext_base.ExtensionDriverTestBase):
    _extension_drivers = ['aim_extension']
    _extension_path = None

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              sc_plugin=None, **kwargs):
        core_plugin = core_plugin or ML2PLUS_PLUGIN
        # The dummy driver configured here is meant to be the second driver
        # invoked and helps in rollback testing. We mock the dummy driver
        # methods to raise an exception and validate that DB operations
        # performed up until that point (including those in the aim_mapping)
        # driver are rolled back.
        policy_drivers = policy_drivers or ['aim_mapping', 'dummy']
        ml2_opts = ml2_options or {'mechanism_drivers': ['logger', 'apic_aim'],
                                   'extension_drivers': ['apic_aim'],
                                   'type_drivers': ['opflex', 'local', 'vlan'],
                                   'tenant_network_types': ['opflex']}
        super(AIMBaseTestCase, self).setUp(
            policy_drivers=policy_drivers, core_plugin=core_plugin,
            ml2_options=ml2_opts, sc_plugin=sc_plugin)
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = test_aim_md.FakeKeystoneClient

        self._tenant_id = 'test-tenant'
        self._neutron_context = nctx.Context(
            '', kwargs.get('tenant_id', self._tenant_id),
            is_admin_context=False)
        self._neutron_admin_context = nctx.get_admin_context()

        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)
        self._aim_mgr = None
        self._aim_context = aim_context.AimContext(
            self._neutron_context.session)
        self._db = model.DbModel()
        self._name_mapper = None

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        super(AIMBaseTestCase, self).tearDown()

    @property
    def aim_mgr(self):
        if not self._aim_mgr:
            self._aim_mgr = (
                self._gbp_plugin.policy_driver_manager.policy_drivers[
                    'aim_mapping'].obj.aim)
        return self._aim_mgr

    @property
    def name_mapper(self):
        if not self._name_mapper:
            self._name_mapper = (
                self._gbp_plugin.policy_driver_manager.policy_drivers[
                    'aim_mapping'].obj.name_mapper)
        return self._name_mapper

    def _test_aim_resource_status(self, aim_resource_obj, gbp_resource):
        aim_status = self.aim_mgr.get_status(self._aim_context,
                                             aim_resource_obj)
        if aim_status.is_error():
            self.assertEqual(gp_const.STATUS_ERROR, gbp_resource['status'])
        elif aim_status.is_build():
            self.assertEqual(gp_const.STATUS_BUILD, gbp_resource['status'])
        else:
            self.assertEqual(gp_const.STATUS_ACTIVE, gbp_resource['status'])


class TestL2Policy(test_nr_base.TestL2Policy, AIMBaseTestCase):

    pass


class TestPolicyTargetGroup(AIMBaseTestCase):

    def test_policy_target_group_lifecycle_implicit_l2p(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        ptg_show = self.show_policy_target_group(
            ptg_id, expected_res_status=200)['policy_target_group']

        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['subnet']['id'])
        ptg_name = ptg['name']
        aim_epg_name = str(self.name_mapper.policy_target_group(
            self._neutron_context.session, ptg_id, ptg_name))
        aim_tenant_name = str(self.name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        aim_app_profile_name = aim_md.AP_NAME
        aim_app_profiles = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self.assertEqual(aim_epgs[0].dn,
                         ptg['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg)
        self.assertEqual(aim_epgs[0].dn,
                         ptg_show['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg_show)

        # TODO(Sumit): Test update

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Implicitly created L2P should be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=404)

        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(0, len(aim_epgs))

    def test_policy_target_group_lifecycle_explicit_l2p(self):
        # TODO(Sumit): Refactor the common parts of this and the implicit test
        l2p = self.create_l2_policy(name="l2p1")['l2_policy']
        l2p_id = l2p['id']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_id)['policy_target_group']
        ptg_id = ptg['id']
        ptg_show = self.show_policy_target_group(
            ptg_id, expected_res_status=200)['policy_target_group']
        self.assertEqual(l2p_id, ptg['l2_policy_id'])
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['subnet']['id'])
        ptg_name = ptg['name']
        aim_epg_name = str(self.name_mapper.policy_target_group(
            self._neutron_context.session, ptg_id, ptg_name))
        aim_tenant_name = str(self.name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        aim_app_profile_name = aim_md.AP_NAME
        aim_app_profiles = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self.assertEqual(aim_epgs[0].dn,
                         ptg['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg)
        self.assertEqual(aim_epgs[0].dn,
                         ptg_show['apic:distinguished_names']['EndpointGroup'])

        # TODO(Sumit): Test update

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Explicitly created L2P should not be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)

        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(0, len(aim_epgs))

    def test_ptg_delete_no_subnet_delete(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        ptg2 = self.create_policy_target_group(
            name="ptg2", l2_policy_id=ptg['l2_policy_id'])[
                'policy_target_group']
        self.assertEqual(ptg['subnets'], ptg2['subnets'])
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['subnet']['id'])

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should not be deleted
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['subnet']['id'])


class TestPolicyTargetGroupRollback(AIMBaseTestCase):

    def test_policy_target_group_create_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_group_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_group_precommit = (
                mock.Mock(side_effect=Exception))
        self.create_policy_target_group(name="ptg1", expected_res_status=500)
        self.assertEqual([], self._plugin.get_subnets(self._context))
        self.assertEqual([], self._plugin.get_networks(self._context))
        self.assertEqual([], self._gbp_plugin.get_policy_target_groups(
            self._context))
        self.assertEqual([], self._gbp_plugin.get_l2_policies(self._context))
        self.assertEqual([], self._gbp_plugin.get_l3_policies(self._context))
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_group_precommit = orig_func

    def test_policy_target_group_update_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_group_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_group_precommit = (
                mock.Mock(side_effect=Exception))
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        self.update_policy_target_group(ptg_id, expected_res_status=500,
                                        name="new name")
        new_ptg = self.show_policy_target_group(ptg_id,
                                                expected_res_status=200)
        self.assertEqual(ptg['policy_target_group']['name'],
                         new_ptg['policy_target_group']['name'])
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_group_precommit = orig_func

    def test_policy_target_group_delete_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_l3_policy_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_l3_policy_precommit = mock.Mock(
                side_effect=Exception)
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        l2p_id = ptg['policy_target_group']['l2_policy_id']
        subnet_id = ptg['policy_target_group']['subnets'][0]
        l2p = self.show_l2_policy(l2p_id, expected_res_status=200)
        l3p_id = l2p['l2_policy']['l3_policy_id']
        self.delete_policy_target_group(ptg_id, expected_res_status=500)
        req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['subnet']['id'])
        self.show_policy_target_group(ptg_id, expected_res_status=200)
        self.show_l2_policy(l2p_id, expected_res_status=200)
        self.show_l3_policy(l3p_id, expected_res_status=200)
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_l3_policy_precommit = orig_func


class TestPolicyTarget(AIMBaseTestCase):

    def test_policy_target_lifecycle_implicit_port(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)['policy_target']
        pt_id = pt['id']
        self.show_policy_target(pt_id, expected_res_status=200)

        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['port']['id'])

        self.update_policy_target(pt_id, expected_res_status=200,
                                  name="new name")
        new_pt = self.show_policy_target(pt_id, expected_res_status=200)
        self.assertEqual('new name', new_pt['policy_target']['name'])

        self.delete_policy_target(pt_id, expected_res_status=204)
        self.show_policy_target(pt_id, expected_res_status=404)
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)


class TestPolicyTargetRollback(AIMBaseTestCase):

    def test_policy_target_create_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_precommit = mock.Mock(
                side_effect=Exception)
        ptg_id = self.create_policy_target_group(
            name="ptg1")['policy_target_group']['id']
        self.create_policy_target(name="pt1",
                                  policy_target_group_id=ptg_id,
                                  expected_res_status=500)
        self.assertEqual([],
                         self._gbp_plugin.get_policy_targets(self._context))
        self.assertEqual([], self._plugin.get_ports(self._context))
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_target_precommit = orig_func

    def test_policy_target_update_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_precommit = mock.Mock(
                side_effect=Exception)
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)['policy_target']
        pt_id = pt['id']
        self.update_policy_target(pt_id, expected_res_status=500,
                                  name="new name")
        new_pt = self.show_policy_target(pt_id, expected_res_status=200)
        self.assertEqual(pt['name'], new_pt['policy_target']['name'])
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_precommit = orig_func

    def test_policy_target_delete_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_policy_target_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_policy_target_precommit = mock.Mock(
                side_effect=Exception)
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj._delete_port = mock.Mock(
                side_effect=Exception)
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg_id)['policy_target']
        pt_id = pt['id']
        port_id = pt['port_id']

        self.delete_policy_target(pt_id, expected_res_status=500)
        self.show_policy_target(pt_id, expected_res_status=200)

        req = self.new_show_request('ports', port_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['port']['id'])
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_target_precommit = orig_func


class TestAIMStatus(AIMBaseTestCase):

    def test_status_merging(self):
        aim_driver = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj

        def mock_get_aim_status(aim_context, aim_resource):
            astatus = aim_status.AciStatus()
            if aim_resource['status'] == '':
                return
            elif aim_resource['status'] == 'build':
                astatus.sync_status = aim_status.AciStatus.SYNC_PENDING
            elif aim_resource['status'] == 'error':
                astatus.sync_status = aim_status.AciStatus.SYNC_FAILED
            else:
                astatus.sync_status = aim_status.AciStatus.SYNCED
            return astatus

        orig_get_status = self.aim_mgr.get_status
        self.aim_mgr.get_status = mock_get_aim_status

        aim_active = {'status': 'active'}
        aim_objs_active = [aim_active, aim_active, aim_active]
        mstatus = aim_driver._merge_aim_status(self._neutron_context.session,
                                               aim_objs_active)
        self.assertEqual(gp_const.STATUS_ACTIVE, mstatus)

        aim_build = {'status': 'build'}
        aim_none = {'status': ''}
        aim_objs_build = [aim_active, aim_active, aim_build]
        mstatus = aim_driver._merge_aim_status(self._neutron_context.session,
                                               aim_objs_build)
        self.assertEqual(gp_const.STATUS_BUILD, mstatus)
        aim_objs_build = [aim_active, aim_active, aim_none]
        mstatus = aim_driver._merge_aim_status(self._neutron_context.session,
                                               aim_objs_build)
        self.assertEqual(gp_const.STATUS_BUILD, mstatus)

        aim_error = {'status': 'error'}
        aim_objs_error = [aim_active, aim_build, aim_error]
        mstatus = aim_driver._merge_aim_status(self._neutron_context.session,
                                               aim_objs_error)
        self.assertEqual(gp_const.STATUS_ERROR, mstatus)

        self.aim_mgr.get_status = orig_get_status


class TestPolicyRuleBase(AIMBaseTestCase):

    def _test_policy_rule_create_update_result(self, aim_tenant_name,
                                               aim_filter_name,
                                               aim_reverse_filter_name,
                                               policy_rule):
        filter_entries = []
        aim_obj_list = []
        for filter_name in [aim_filter_name, aim_reverse_filter_name]:
            aim_filters = self.aim_mgr.find(
                self._aim_context, aim_resource.Filter, name=filter_name)
            aim_obj_list.append(aim_filters[0])
            self.assertEqual(1, len(aim_filters))
            self.assertEqual(filter_name, aim_filters[0].name)
            self.assertEqual(aim_tenant_name, aim_filters[0].tenant_name)
            aim_filter_entries = self.aim_mgr.find(
                self._aim_context, aim_resource.FilterEntry,
                tenant_name=aim_filters[0].tenant_name,
                filter_name=aim_filters[0].name)
            self.assertEqual(1, len(aim_filter_entries))
            self.assertEqual('os-entry-0', aim_filter_entries[0].name)
            filter_entries.append(aim_filter_entries[0])
        aim_obj_list.append(filter_entries)
        prule = policy_rule
        self.assertEqual(
            filter_entries[0].dn,
            prule['apic:distinguished_names']['Forward-FilterEntries'][0])
        self.assertEqual(
            filter_entries[1].dn,
            prule['apic:distinguished_names']['Reverse-FilterEntries'][0])
        merged_status = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj._merge_aim_status(self._neutron_context.session,
                                                 aim_obj_list)
        self.assertEqual(merged_status, prule['status'])


class TestPolicyRule(TestPolicyRuleBase):

    def test_policy_rule_lifecycle(self):
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']
        pr_name = pr['name']
        self.show_policy_rule(pr_id, expected_res_status=200)

        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name))
        aim_reverse_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name,
            prefix=alib.REVERSE_PREFIX))
        aim_tenant_name = str(self.name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        self._test_policy_rule_create_update_result(
            aim_tenant_name, aim_filter_name, aim_reverse_filter_name, pr)

        pr_name = 'new name'
        new_pr = self.update_policy_rule(pr_id, expected_res_status=200,
                                         name=pr_name)['policy_rule']
        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name))
        aim_reverse_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name,
            prefix=alib.REVERSE_PREFIX))
        self._test_policy_rule_create_update_result(
            aim_tenant_name, aim_filter_name, aim_reverse_filter_name, new_pr)

        self.delete_policy_rule(pr_id, expected_res_status=204)
        self.show_policy_rule(pr_id, expected_res_status=404)

        for filter_name in [aim_filter_name, aim_reverse_filter_name]:
            aim_filters = self.aim_mgr.find(
                self._aim_context, aim_resource.Filter, name=filter_name)
            self.assertEqual(0, len(aim_filters))


class TestPolicyRuleRollback(TestPolicyRuleBase):

    def test_policy_rule_create_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_rule_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_rule_precommit = mock.Mock(
                side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']], expected_res_status=500)

        self.assertEqual([],
                         self._gbp_plugin.get_policy_rules(self._context))
        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter)
        self.assertEqual(0, len(aim_filters))
        aim_filter_entries = self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry)
        self.assertEqual(0, len(aim_filter_entries))
        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_rule_precommit = orig_func

    def test_policy_rule_update_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_rule_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.update_policy_rule_precommit = mock.Mock(
                side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']

        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr['id'], pr['name']))
        aim_reverse_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr['id'], pr['name'],
            prefix=alib.REVERSE_PREFIX))

        self.update_policy_rule(pr['id'], expected_res_status=500,
                                name='new name')
        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter, name=aim_filter_name)
        self.assertEqual(1, len(aim_filters))
        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter,
            name=aim_reverse_filter_name)
        self.assertEqual(1, len(aim_filters))

        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.create_policy_rule_precommit = orig_func

    def test_policy_rule_delete_fail(self):
        orig_func = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_policy_rule_precommit
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_policy_rule_precommit = mock.Mock(
                side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']
        pr_name = pr['name']

        self.delete_policy_rule(pr_id, expected_res_status=500)
        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name))
        aim_reverse_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, pr_id, pr_name,
            prefix=alib.REVERSE_PREFIX))
        aim_tenant_name = str(self.name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        self._test_policy_rule_create_update_result(
            aim_tenant_name, aim_filter_name, aim_reverse_filter_name, pr)

        # restore mock
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'dummy'].obj.delete_policy_rule_precommit = orig_func
