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
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from keystoneclient.v3 import client as ksc_client
from neutron import context as nctx
from neutron.db import api as db_api
from opflexagent import constants as ocst
import webob.exc

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as aim_md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.plugins.ml2plus import (
    test_apic_aim as test_aim_md)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_neutron_resources_driver as test_nr_base)


ML2PLUS_PLUGIN = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'
AGENT_TYPE = ocst.AGENT_TYPE_OPFLEX_OVS
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'opflex_networks': None,
                                 'bridge_mappings': {'physnet1': 'br-eth1'}}}


class AIMBaseTestCase(test_nr_base.CommonNeutronBaseTestCase,
                      test_ext_base.ExtensionDriverTestBase):
    _extension_drivers = ['aim_extension']
    _extension_path = None

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              sc_plugin=None, **kwargs):
        core_plugin = core_plugin or ML2PLUS_PLUGIN
        self.agent_conf = AGENT_CONF
        policy_drivers = policy_drivers or ['aim_mapping']
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
        self._driver = None
        nova_client = mock.patch(
            'gbpservice.neutron.services.grouppolicy.drivers.cisco.'
            'apic.nova_client.NovaClient.get_server').start()
        vm = mock.Mock()
        vm.name = 'someid'
        nova_client.return_value = vm

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        super(AIMBaseTestCase, self).tearDown()

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'compute:',
                         'device_id': 'someid'}}
        return super(AIMBaseTestCase, self)._bind_port_to_host(
            port_id, host, data=data)

    @property
    def driver(self):
        if not self._driver:
            self._driver = (
                self._gbp_plugin.policy_driver_manager.policy_drivers[
                    'aim_mapping'].obj)
        return self._driver

    @property
    def aim_mgr(self):
        if not self._aim_mgr:
            self._aim_mgr = self.driver.aim
        return self._aim_mgr

    @property
    def name_mapper(self):
        if not self._name_mapper:
            self._name_mapper = self.driver.name_mapper
        return self._name_mapper


class TestL2Policy(test_nr_base.TestL2Policy, AIMBaseTestCase):

    pass


class TestPolicyTargetGroup(AIMBaseTestCase):

    def _test_aim_resource_status(self, aim_resource_obj, gbp_resource):
        aim_status = self.driver.get_status(self._aim_context,
                                            aim_resource_obj)
        if aim_status.is_error():
            self.assertEqual(gp_const.STATUS_ERROR, gbp_resource['status'])
        elif aim_status.is_build():
            self.assertEqual(gp_const.STATUS_BUILD, gbp_resource['status'])
        else:
            self.assertEqual(gp_const.STATUS_ACTIVE, gbp_resource['status'])

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
        aim_app_profiles = self.driver.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self.driver.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self._test_aim_resource_status(aim_epgs[0], ptg)
        self.assertEqual(aim_epgs[0].dn,
                         ptg_show['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg_show)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Implicitly created L2P should be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=404)

        aim_epgs = self.driver.find(
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
        aim_app_profiles = self.driver.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epgs = self.driver.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)

        self._test_aim_resource_status(aim_epgs[0], ptg)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Explicitly created L2P should not be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)

        aim_epgs = self.driver.find(
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
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj._validate_and_add_subnet = mock.Mock(
                side_effect=Exception)
        self.create_policy_target_group(name="ptg1", expected_res_status=500)
        self.assertEqual([], self._plugin.get_subnets(self._context))
        self.assertEqual([], self._plugin.get_networks(self._context))
        self.assertEqual([], self._gbp_plugin.get_policy_target_groups(
            self._context))
        self.assertEqual([], self._gbp_plugin.get_l2_policies(self._context))
        self.assertEqual([], self._gbp_plugin.get_l3_policies(self._context))

    def test_policy_target_group_update_fail(self):
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj.update_policy_target_group_precommit = (
                mock.Mock(side_effect=Exception))
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        self.update_policy_target_group(ptg_id, expected_res_status=500,
                                        name="new name")
        new_ptg = self.show_policy_target_group(ptg_id,
                                                expected_res_status=200)
        self.assertEqual(ptg['policy_target_group']['name'],
                         new_ptg['policy_target_group']['name'])

    def test_policy_target_group_delete_fail(self):
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj.delete_l3_policy_precommit = mock.Mock(
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

    def _do_test_get_gbp_details(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')

        mapping = self.driver.get_gbp_details(self._neutron_admin_context,
            device='tap%s' % pt1['port_id'], host='h1')
        req_mapping = self.driver.request_endpoint_details(
            nctx.get_admin_context(),
            request={'device': 'tap%s' % pt1['port_id'], 'host': 'h1',
                     'timestamp': 0, 'request_id': 'request_id'})
        self.assertEqual(mapping, req_mapping['gbp_details'])

        self.assertEqual(pt1['port_id'], mapping['port_id'])
        epg_name = self.name_mapper.policy_target_group(
            self._neutron_context.session, ptg['id'], ptg['name'])
        epg_tenant = self.name_mapper.tenant(self._neutron_context.session,
                                             ptg['tenant_id'])
        self.assertEqual(epg_name, mapping['endpoint_group_name'])
        self.assertEqual(epg_tenant, mapping['ptg_tenant'])
        self.assertEqual('someid', mapping['vm-name'])
        self.assertTrue(mapping['enable_dhcp_optimization'])
        self.assertTrue(mapping['enable_metadata_optimization'])
        self.assertEqual(1, len(mapping['subnets']))
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        self.assertEqual(subnet['subnet']['cidr'],
                         mapping['subnets'][0]['cidr'])

        # Verify Neutron details
        self.assertEqual(pt1['port_id'],
                         req_mapping['neutron_details']['port_id'])

        # Create event on a second host to verify that the SNAT
        # port gets created for this second host
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h1')

        mapping = self.driver.get_gbp_details(self._neutron_admin_context,
            device='tap%s' % pt2['port_id'], host='h2')
        self.assertEqual(pt2['port_id'], mapping['port_id'])

    def test_get_gbp_details(self):
        self._do_test_get_gbp_details()


class TestPolicyTargetRollback(AIMBaseTestCase):

    def test_policy_target_create_fail(self):
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj._mark_port_owned = mock.Mock(
                side_effect=Exception)
        ptg_id = self.create_policy_target_group(
            name="ptg1")['policy_target_group']['id']
        self.create_policy_target(name="pt1",
                                  policy_target_group_id=ptg_id,
                                  expected_res_status=500)
        self.assertEqual([],
                         self._gbp_plugin.get_policy_targets(self._context))
        self.assertEqual([], self._plugin.get_ports(self._context))

    def test_policy_target_update_fail(self):
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
        self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj.update_policy_target_precommit = mock.Mock(
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

    def test_policy_target_delete_fail(self):
        # REVISIT(Sumit): This exception should be raised from the deepest
        # point. Currently this is the deepest point.
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
        aim_pr = self.driver.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(1, len(aim_pr))
        self.assertEqual(rn, aim_pr[0].rn)
        self.assertEqual(tenant, aim_pr[0].tenant_rn)

        self.delete_policy_rule(pr_id, expected_res_status=204)
        self.show_policy_rule(pr_id, expected_res_status=404)

        aim_pr = self.driver.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(0, len(aim_pr))
