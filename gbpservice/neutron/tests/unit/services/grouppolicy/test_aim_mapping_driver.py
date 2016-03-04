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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from keystonemiddleware import auth_token  # noqa
from keystoneclient.v2_0 import client as keyclient
from neutron import context as nctx
from neutron.db import api as db_api
from oslo_log import log as logging

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.plugins.ml2plus import (
    test_apic_aim as test_aim_md)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_neutron_resources_driver as test_nr_base)


ML2PLUS_PLUGIN = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'


class AIMBaseTestCase(test_nr_base.CommonNeutronBaseTestCase):

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              sc_plugin=None, **kwargs):
        core_plugin = core_plugin or ML2PLUS_PLUGIN
        policy_drivers = policy_drivers or ['aim_driver']
        ml2_opts = ml2_options or {'mechanism_drivers': ['logger', 'apic_aim']}
        config.cfg.CONF.set_override('admin_user', 'user',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_password', 'password',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_tenant_name', 'tenant_name',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override(
            'auth_uri', 'http://127.0.0.1:35357/v2.0/',
            group='keystone_authtoken')
        super(AIMBaseTestCase, self).setUp(
            policy_drivers=policy_drivers, core_plugin=core_plugin,
            ml2_options=ml2_opts, sc_plugin=sc_plugin)

        self.saved_keystone_client = keyclient.Client
        keyclient.Client = test_aim_md.FakeKeystoneClient

        self._tenant_id = 'test-tenant'
        self._neutron_context = nctx.Context(
            '', kwargs.get('tenant_id', self._tenant_id),
            is_admin_context=False)
        self._neutron_admin_context = nctx.get_admin_context()

        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)
        self._aim = aim_manager.AimManager()
        self._aim_context = aim_context.AimContext(
            self._neutron_context.session)
        self._db = model.DbModel()
        self._name_mapper = apic_mapper.APICNameMapper(
            self._db, logging, keyclient, config.cfg.CONF.keystone_authtoken)

    def tearDown(self):
        keyclient.Client = self.saved_keystone_client
        super(AIMBaseTestCase, self).tearDown()


class TestL2Policy(test_nr_base.TestL2Policy, AIMBaseTestCase):

    pass


class TestPolicyTargetGroup(AIMBaseTestCase):

    def test_policy_target_group_lifecycle_implicit_l2p(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        self.show_policy_target_group(ptg_id, expected_res_status=200)

        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        ptg_name = ptg['name']
        aim_epg_name = str(self._name_mapper.policy_target_group(
            self._neutron_context.session, ptg_id, ptg_name))
        aim_tenant_name = str(self._name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        aim_app_profile_name = aim_tenant_name
        aim_app_profiles = self._aim.find(
            self._aim_context, aim_resource.ApplicationProfile,
            name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self._aim.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created L2P should be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=404)

        aim_epgs = self._aim.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(0, len(aim_epgs))

    def test_policy_target_group_lifecycle_explicit_l2p(self):
        # TODO(Sumit): Refactor the common parts of this and the implicit test
        l2p = self.create_l2_policy(name="l2p1")['l2_policy']
        l2p_id = l2p['id']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_id)['policy_target_group']
        ptg_id = ptg['id']
        self.show_policy_target_group(ptg_id, expected_res_status=200)

        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        ptg_name = ptg['name']
        aim_epg_name = str(self._name_mapper.policy_target_group(
            self._neutron_context.session, ptg_id, ptg_name))
        aim_tenant_name = str(self._name_mapper.tenant(
            self._neutron_context.session, self._tenant_id))
        aim_app_profile_name = aim_tenant_name
        aim_app_profiles = self._aim.find(
            self._aim_context, aim_resource.ApplicationProfile,
            name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self._aim.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Explicitly created L2P should not be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)

        aim_epgs = self._aim.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(0, len(aim_epgs))


# TODO(Sumit): Add test class for PTG Rollback


class TestPolicyRule(AIMBaseTestCase):

    def _test_policy_rule_lifecycle(self):
        # TODO(Sumit): Enable this test when the AIM driver is ready
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']
        self.show_policy_rule(pr_id, expected_res_status=200)

        tenant = pr['tenant_id']
        pr_id = pr['id']
        pr_name = pr['name']
        rn = self._aim_mapper.tenant_filter(tenant, pr_id, name=pr_name)
        aim_pr = self._aim.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(1, len(aim_pr))
        self.assertEqual(rn, aim_pr[0].rn)
        self.assertEqual(tenant, aim_pr[0].tenant_rn)

        self.delete_policy_rule(pr_id, expected_res_status=204)
        self.show_policy_rule(pr_id, expected_res_status=404)

        aim_pr = self._aim.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(0, len(aim_pr))
