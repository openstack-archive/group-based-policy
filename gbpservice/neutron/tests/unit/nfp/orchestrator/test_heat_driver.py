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

import copy
from keystoneclient.v2_0 import client as identity_client
import mock
from oslo_config import cfg
from oslo_utils import uuidutils
import unittest

from gbpclient.v2_0 import client as gbp_client
from gbpservice.neutron.tests.unit.nfp.orchestrator import mock_dicts
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.orchestrator.config_drivers import (
    heat_client as heat_client)
from gbpservice.nfp.orchestrator.config_drivers import heat_driver
from neutronclient.v2_0 import client as neutron_client


class MockStackObject(object):

    def __init__(self, status):
        self.stack_status = status


class MockHeatClientFunctionsDeleteNotFound(object):

    def delete(self, stack_id):
        raise heat_client.exc.HTTPNotFound()

    def create(self, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}

    def get(self, stack_id):
        return MockStackObject('DELETE_COMPLETE')


class MockHeatClientFunctions(object):

    def delete(self, stack_id):
        pass

    def create(self, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}

    def get(self, stack_id):
        return MockStackObject('DELETE_COMPLETE')

    def update(self, *args, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}


class MockHeatClient(object):

    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctions()

cfg.CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')
IS_SERVICE_ADMIN_OWNED = True
SVC_MGMT_PTG_NAME = 'svc_management_ptg'
RESOURCE_OWNER_TENANT_ID = '8ae6701128994ab281dde6b92207bb19'


class TestHeatDriver(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestHeatDriver, self).__init__(*args, **kwargs)
        with mock.patch.object(identity_client, "Client"):
            self.heat_driver_obj = heat_driver.HeatDriver(cfg.CONF)
        self.mock_dict = mock_dicts.DummyDictionaries()

    def setUp(self):
        cfg.CONF.set_override('is_service_admin_owned',
                              IS_SERVICE_ADMIN_OWNED,
                              group='heat_driver')
        cfg.CONF.set_override('svc_management_ptg_name',
                              SVC_MGMT_PTG_NAME,
                              group='heat_driver')
        cfg.CONF.set_override('admin_user',
                              'neutron',
                              group='keystone_authtoken')
        cfg.CONF.set_override('admin_password',
                              'admin_pass',
                              group='keystone_authtoken')
        cfg.CONF.set_override('admin_tenant_name',
                              'admin',
                              group='keystone_authtoken')
        # cfg.CONF.set_override('resource_owner_tenant_id',
        #                      RESOURCE_OWNER_TENANT_ID,
        #                      group='heat_driver')
        mock.patch(heat_client.__name__ + ".HeatClient",
                   new=MockHeatClient).start()

    @mock.patch.object(identity_client, "Client")
    def test_keystone(self, mock_obj):
        keystone_client = mock_obj.return_value
        keystone_client.auth_token = 'abcd123'
        password = 'neutron_pass'
        tenant_name = 'services'
        username = 'neutron'
        expected_token = 'abcd123'
        token = self.heat_driver_obj.keystone(
            username, password, tenant_name, tenant_id=None)
        self.assertEqual(token, expected_token)

    @mock.patch.object(identity_client, "Client")
    def test_get_heat_client(self, mock_obj):
        keystone_client = mock_obj.return_value
        keystone_client.auth_token = True
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        heat_client_obj = self.heat_driver_obj._get_heat_client(
            tenant_id)
        self.assertIsNotNone(heat_client_obj)

    @mock.patch.object(identity_client, "Client")
    def test_resource_owner_tenant_id(self, mock_obj):
        keystone_client = mock_obj.return_value
        keystone_client.auth_token = True
        keystone_client.tenants.find().id = '8ae6701128994ab281dde6b92207bb19'
        expected_resource_owner_tenant_id = '8ae6701128994ab281dde6b92207bb19'
        resource_owner_tenant_id = (
            self.heat_driver_obj._resource_owner_tenant_id())
        self.assertEqual(resource_owner_tenant_id,
                         expected_resource_owner_tenant_id)

    def mock_objects(self):
        with mock.patch.object(identity_client, "Client"):
            self.heat_driver_obj = heat_driver.HeatDriver(cfg.CONF)
            self.heat_driver_obj.keystoneclient.get_scoped_keystone_token = (
                mock.MagicMock(return_value='token'))
            self.heat_driver_obj.keystoneclient.get_tenant_id = mock.MagicMock(
                return_value='8ae6701128994ab281dde6b92207bb19')
            self.heat_driver_obj.neutron_client.get_port = mock.MagicMock(
                return_value=self.mock_dict.port_info)
            self.heat_driver_obj.neutron_client.get_floating_ips = (
                mock.MagicMock(return_value=self.mock_dict.fip))
            self.heat_driver_obj.neutron_client.get_subnets = mock.MagicMock(
                return_value=self.mock_dict.subnets_info['subnets'])
            self.heat_driver_obj.neutron_client.get_subnet = mock.MagicMock(
                return_value=self.mock_dict.subnet_info)
            self.heat_driver_obj.gbp_client.get_external_policies = (
                mock.MagicMock(
                    return_value=self.mock_dict.external_policies[
                        'external_policies']))
            self.heat_driver_obj.gbp_client.get_network_service_policies = (
                mock.MagicMock(return_value=self.mock_dict.services_nsp))
            self.heat_driver_obj.gbp_client.get_l3_policies = mock.MagicMock(
                return_value=self.mock_dict.l3_policies['l3_policies'])
            self.heat_driver_obj.gbp_client.get_policy_targets = (
                mock.MagicMock(
                    return_value=self.mock_dict.policy_targets[
                        'policy_targets']))
            self.heat_driver_obj.gbp_client.get_policy_target_groups = (
                mock.MagicMock(
                    return_value=self.mock_dict.policy_target_groups[
                        'policy_target_groups']))
            self.heat_driver_obj.gbp_client.get_policy_rule_sets = (
                mock.MagicMock(
                    return_value=self.mock_dict.policy_rule_sets[
                        'policy_rule_sets']))
            self.heat_driver_obj.gbp_client.get_policy_rules = mock.MagicMock(
                return_value=self.mock_dict.policy_rules['policy_rules'])
            self.heat_driver_obj.gbp_client.get_policy_actions = (
                mock.MagicMock(
                    return_value=self.mock_dict.policy_actions[
                        'policy_actions']))
            self.heat_driver_obj.gbp_client.get_l3_policy = mock.MagicMock(
                return_value=self.mock_dict.l3p)
            self.heat_driver_obj.gbp_client.get_l2_policy = mock.MagicMock(
                return_value=self.mock_dict.l2p)
            self.heat_driver_obj.gbp_client.update_policy_target_group = (
                mock.MagicMock(return_value={}))
            self.heat_driver_obj.gbp_client.create_policy_target_group = (
                mock.MagicMock(return_value={}))
            self.heat_driver_obj.gbp_client.create_policy_target = (
                mock.MagicMock(return_value=self.mock_dict.policy_target))
            self.heat_driver_obj.gbp_client.create_network_service_policy = (
                mock.MagicMock(return_value={}))

    def test_get_resource_owner_context(self):
        self.mock_objects()
        expected_resource_owner_context = (
            'token', '8ae6701128994ab281dde6b92207bb19')
        resource_owner_context = (
            self.heat_driver_obj._get_resource_owner_context())
        self.assertEqual(resource_owner_context,
                         expected_resource_owner_context)

    @mock.patch.object(identity_client, "Client")
    def test_get_tenant_context(self, mock_obj):
        keystone_client = mock_obj.return_value
        keystone_client.auth_token = True
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        expected_tenant_context = (True, tenant_id)
        tenant_context = self.heat_driver_obj._get_tenant_context(tenant_id)
        self.assertEqual(tenant_context, expected_tenant_context)

    def test_is_service_target(self):
        policy_target = {'name': 'service_target_provider_0132c_00b93'}
        retval = self.heat_driver_obj._is_service_target(policy_target)
        self.assertTrue(retval)
        policy_target = {'name': 'mem1_gbpui'}
        expected_result = False
        result = self.heat_driver_obj._is_service_target(policy_target)
        self.assertEqual(result, expected_result)

    @mock.patch.object(neutron_client.Client, "show_port")
    @mock.patch.object(gbp_client.Client, "list_policy_targets")
    def test_get_member_ips(self, list_pt_mock_obj, show_port_mock_obj):
        list_pt_mock_obj.return_value = self.mock_dict.policy_targets
        show_port_mock_obj.return_value = self.mock_dict.port_info
        auth_token = "81273djs138"
        expected_member_ips = ['42.0.0.13']
        member_ips = self.heat_driver_obj._get_member_ips(
            auth_token, self.mock_dict.provider_ptg)
        self.assertEqual(member_ips, expected_member_ips)

    def test_generate_lb_member_template(self):
        is_template_aws_version = False
        member_ip = '11.0.0.4'
        pool_res_name = 'HaproxyPool'
        stack_template = self.mock_dict.DEFAULT_LB_CONFIG
        expected_member_template = {
            'type': 'OS::Neutron::PoolMember',
            'properties': {
                'protocol_port': 101, 'admin_state_up': True,
                'pool_id': {'get_resource': 'HaproxyPool'},
                'weight': 1, 'address': '11.0.0.4'
            }
        }
        member_template = self.heat_driver_obj._generate_lb_member_template(
            is_template_aws_version,
            pool_res_name, member_ip, stack_template)
        self.assertEqual(member_template, expected_member_template)

    def test_modify_fw_resources_name(self):
        is_template_aws_version = False
        stack_template = copy.deepcopy(self.mock_dict.DEFAULT_FW_CONFIG)
        expected_fw_resources_name = 'serviceVM_infra_FW-fw_redirect'
        self.heat_driver_obj._modify_fw_resources_name(
            stack_template, self.mock_dict.provider_ptg,
            is_template_aws_version)
        modified_fw_resources_name = (
            stack_template['resources']['sc_firewall']['properties']['name'])
        self.assertEqual(modified_fw_resources_name,
                         expected_fw_resources_name)

    def test_get_heat_resource_key(self):
        is_template_aws_version = False
        resource_name = 'OS::Neutron::Pool'
        template_resource_dict = self.mock_dict.DEFAULT_LB_CONFIG['resources']
        expected_heat_resource_key = 'LoadBalancerPool'
        heat_resource_key = self.heat_driver_obj._get_heat_resource_key(
            template_resource_dict, is_template_aws_version, resource_name)
        self.assertEqual(heat_resource_key, expected_heat_resource_key)

    def test_get_all_heat_resource_keys(self):
        is_template_aws_version = False
        resource_name = 'OS::Neutron::Pool'
        template_resource_dict = self.mock_dict.DEFAULT_LB_CONFIG['resources']
        expected_heat_resource_keys = ['LoadBalancerPool']
        all_heat_resource_keys = (
            self.heat_driver_obj._get_all_heat_resource_keys(
                template_resource_dict, is_template_aws_version,
                resource_name))
        self.assertEqual(all_heat_resource_keys, expected_heat_resource_keys)

    @mock.patch.object(neutron_client.Client, "show_port")
    @mock.patch.object(gbp_client.Client, "list_policy_targets")
    def test_generate_pool_members(self, list_pt_mock_obj, show_port_mock_obj):
        list_pt_mock_obj.return_value = self.mock_dict.policy_targets
        show_port_mock_obj.return_value = self.mock_dict.port_info
        is_template_aws_version = False
        stack_template = self.mock_dict.DEFAULT_LB_CONFIG
        auth_token = "81273djs138"
        config_param_values = {}
        expected_pool_members = self.mock_dict.pool_members
        self.heat_driver_obj._generate_pool_members(
            auth_token,
            stack_template,
            config_param_values,
            self.mock_dict.provider_ptg,
            is_template_aws_version)
        generated_pool_members = stack_template['resources']['mem-42.0.0.13']
        self.assertEqual(generated_pool_members, expected_pool_members)

    def test_append_firewall_rule(self):
        stack_template = copy.deepcopy(self.mock_dict.DEFAULT_FW_CONFIG)
        provider_cidr = '192.169.0.0/29'
        consumer_cidr = '11.0.2.0/24'
        consumer_id = '2b86019a-45f7-4441-8e2c-1fbded4432c1'
        self.heat_driver_obj._append_firewall_rule(
            stack_template,
            provider_cidr, consumer_cidr,
            self.mock_dict.fw_template_properties,
            consumer_id)
        self.assertEqual(stack_template['resources']['sc_firewall_policy'],
                         self.mock_dict.appended_sc_firewall_policy)

    @mock.patch.object(heat_client.HeatClient, 'delete')
    @mock.patch.object(heat_client.HeatClient, 'get')
    @mock.patch.object(identity_client, "Client")
    def test_delete_config(self, mock_obj, heat_get_mock_obj,
                           heat_delete_mock_obj):
        heat_get_mock_obj.return_value = MockStackObject('DELETE_COMPLETE')
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})

        instance = mock_obj.return_value
        instance.auth_token = True
        stack_id = '70754fdd-0325-4856-8a39-f171b65617d6'
        self.heat_driver_obj.delete_config(stack_id, '1627')
        heat_delete_mock_obj.assert_called_once_with(stack_id)

    @mock.patch.object(heat_client.HeatClient, 'get')
    @mock.patch.object(identity_client, "Client")
    def test_is_config_complete(self, mock_obj, heat_get_mock_obj):
        stack_id = '70754fdd-0325-4856-8a39-f171b65617d6'
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})
        self.heat_driver_obj.loadbalancer_post_stack_create = mock.Mock(
            return_value=None)
        heat_get_mock_obj.return_value = MockStackObject(
            'CREATE_COMPLETE')
        instance = mock_obj.return_value
        instance.auth_token = True
        expected_status = 'COMPLETED'
        status = self.heat_driver_obj.is_config_complete(
            stack_id, tenant_id, self.mock_dict.network_function_details)
        self.assertEqual(status, expected_status)

    @mock.patch.object(heat_client.HeatClient, 'get')
    @mock.patch.object(identity_client, "Client")
    def test_is_config_delete_complete(self, identity_mock_obj,
                                       heat_get_mock_obj):
        stack_id = '70754fdd-0325-4856-8a39-f171b65617d6'
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})
        heat_get_mock_obj.return_value = MockStackObject(
            'DELETE_COMPLETE')
        identity_mock_obj.return_value.auth_token = "1234"
        identity_mock_obj.return_value.tenants.find(
        ).id = "8ae6701128994ab281dde6b92207bb19"
        expected_status = 'COMPLETED'
        status = self.heat_driver_obj.is_config_delete_complete(stack_id,
                                                                tenant_id)
        self.assertEqual(status, expected_status)

    def test_get_site_conn_keys(self):
        is_template_aws_version = False
        resource_name = 'OS::Neutron::IPsecSiteConnection'
        template_resource_dict = (
            self.mock_dict.DEFAULT_VPN_CONFIG['resources'])
        expected_site_conn_keys = ['site_to_site_connection1']
        site_conn_keys = self.heat_driver_obj._get_site_conn_keys(
            template_resource_dict,
            is_template_aws_version, resource_name)
        self.assertEqual(site_conn_keys, expected_site_conn_keys)

    @mock.patch.object(neutron_client.Client, "show_subnet")
    @mock.patch.object(gbp_client.Client, "list_policy_target_groups")
    def test_get_management_gw_ip(self, list_ptg_mock_obj,
                                  show_subnet_mock_obj):
        list_ptg_mock_obj.return_value = self.mock_dict.policy_target_groups
        show_subnet_mock_obj.return_value = self.mock_dict.subnet_info
        auth_token = 'jkijqe18381'
        expected_management_gw_ip = '42.0.0.1'
        management_gw_ip = self.heat_driver_obj._get_management_gw_ip(
            auth_token)
        self.assertEqual(management_gw_ip, expected_management_gw_ip)

    @mock.patch.object(gbp_client.Client, "list_policy_actions")
    @mock.patch.object(gbp_client.Client, "list_policy_rules")
    @mock.patch.object(gbp_client.Client, "list_policy_rule_sets")
    def test_get_consumers_for_chain(self, list_policy_rule_sets_mock_obj,
                                     list_policy_rules_mock_obj,
                                     list_policy_actions_mock_obj):
        list_policy_rule_sets_mock_obj.return_value = (
            self.mock_dict.policy_rule_sets)
        list_policy_rules_mock_obj.return_value = self.mock_dict.policy_rules
        list_policy_actions_mock_obj.return_value = (
            self.mock_dict.policy_actions)
        auth_token = 'jkijqe18381'
        expected_consumers_for_chain = (
            (['af6a8a58-1e25-49c4-97a3-d5f50b3aa04b'], None))
        consumers_for_chain = self.heat_driver_obj._get_consumers_for_chain(
            auth_token,
            self.mock_dict.provider_ptg)
        self.assertEqual(consumers_for_chain, expected_consumers_for_chain)

    def test_update_firewall_template(self):
        self.mock_objects()
        stack_template = copy.deepcopy(self.mock_dict.DEFAULT_FW_CONFIG)
        auth_token = 'adakjiq'
        stack_template = self.heat_driver_obj._update_firewall_template(
            auth_token,
            self.mock_dict.provider_ptg, stack_template)
        self.assertEqual(
            stack_template['resources']['sc_firewall_policy'],
            copy.deepcopy(self.mock_dict.updated_template_sc_firewall_policy))

    @mock.patch.object(gbp_client.Client, "list_l3_policies")
    def test_get_rvpn_l3_policy(self, mock_obj):
        mock_obj.return_value = self.mock_dict.l3_policies
        auth_token = 'asdaddasd'
        node_update = True
        expected_rvpn_l3_policy = {
            u'tenant_id': '8ae6701128994ab281dde6b92207bb19',
            u'name': u'remote-vpn-client-pool-cidr-l3policy'
        }
        rvpn_l3_policy = self.heat_driver_obj._get_rvpn_l3_policy(
            auth_token,
            self.mock_dict.provider_ptg, node_update)
        self.assertEqual(rvpn_l3_policy, expected_rvpn_l3_policy)

    @mock.patch.object(gbp_client.Client, "create_policy_target")
    @mock.patch.object(gbp_client.Client, "update_policy_target")
    @mock.patch.object(neutron_client.Client, "list_subnets")
    @mock.patch.object(neutron_client.Client, "list_pools")
    @mock.patch.object(neutron_client.Client, "show_vip")
    def test_create_policy_target_for_vip(self, vip, pools, subnets,
            pt, pt_update):
        pt.return_value = {
            'policy_target': {
                'name': 'service_target_provider_0132c_00b93'
            }
        }
        subnets.return_value = self.mock_dict.subnets_info
        pools.return_value = {
            'pools': [{
                'vip_id': '1234'
            }]
        }
        vip.return_value = {
            'vip': {
                'port_id': '1234'
            }
        }
        auth_token = 'adsdsdd'
        provider_tenant_id = '8ae6701128994ab281dde6b92207bb19'
        provider = self.mock_dict.provider_ptg
        self.heat_driver_obj.gbp_client.get_policy_targets = (
                mock.MagicMock(
                    return_value=self.mock_dict.policy_targets[
                        'policy_targets']))
        self.heat_driver_obj.keystoneclient.get_admin_token = (
                mock.MagicMock(return_value='token'))
        self.heat_driver_obj._create_policy_target_for_vip(
            auth_token, provider_tenant_id, provider)
        pools.assert_called_once_with(
            subnet_id=[subnets.return_value['subnets'][0]['id']])

    def test_create_node_config_data_vpn(self):
        self.mock_objects()
        auth_token = 'asdasasd'
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        provider = self.mock_dict.provider_ptg
        consumer = self.mock_dict.provider_ptg
        provider_port = self.mock_dict.port_info['port']
        mgmt_ip = self.mock_dict.mgmt_ip
        stack_template, stack_params = (
            self.heat_driver_obj._create_node_config_data(
                auth_token, tenant_id,
                self.mock_dict.vpn_service_chain_node,
                self.mock_dict.service_chain_instance,
                provider, provider_port, consumer,
                self.mock_dict.consumer_port,
                self.mock_dict.network_function_details['network_function'],
                mgmt_ip,
                self.mock_dict.service_details))
        self.assertEqual(stack_template['resources']['VPNService'][
                            'properties']['name'], 'VPNService')
        self.assertEqual(stack_params['RouterId'],
                         self.mock_dict.l3p['routers'][0])

    def test_update_node_config(self):
        self.mock_objects()
        auth_token = 'asdasasd'
        tenant_id = '8ae6701128994ab281dde6b92207bb19'
        provider = self.mock_dict.provider_ptg
        provider_port = self.mock_dict.port_info['port']
        mgmt_ip = self.mock_dict.mgmt_ip
        stack_template, stack_params = (
            self.heat_driver_obj._update_node_config(
                auth_token, tenant_id,
                self.mock_dict.service_profile,
                self.mock_dict.fw_service_chain_node,
                self.mock_dict.service_chain_instance,
                provider, self.mock_dict.consumer_port,
                self.mock_dict.network_function_details['network_function'],
                provider_port, mgmt_ip))
        self.assertEqual(stack_template['resources']['sc_firewall_policy'],
                         self.mock_dict.updated_sc_firewall_policy)

    @mock.patch.object(heat_client.HeatClient, "delete")
    @mock.patch.object(heat_client.HeatClient, "update")
    @mock.patch.object(heat_client.HeatClient, "get")
    @mock.patch.object(heat_client.HeatClient, "create")
    def test_update(
            self, heat_create, heat_get, heat_update,
            heat_delete):
        self.mock_objects()
        heat_create.return_value = {'stack': {
            'id': uuidutils.generate_uuid()}}
        heat_delete.return_value = MockStackObject(
            'CREATE_COMPLETE')
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})
        auth_token = 'dasddasda'
        resource_owner_tenant_id = '8ae6701128994ab281dde6b92207bb19'
        provider = self.mock_dict.provider_ptg
        provider_port = self.mock_dict.port_info['port']
        stack_id = '70754fdd-0325-4856-8a39-f171b65617d6'
        mgmt_ip = self.mock_dict.mgmt_ip

        service_details = {}
        service_details['service_profile'] = self.mock_dict.service_profile
        service_details['servicechain_node'] = (
            self.mock_dict.fw_service_chain_node)
        service_details['servicechain_instance'] = (
            self.mock_dict.service_chain_instance)
        service_details['policy_target_group'] = self.mock_dict.provider_ptg
        service_details['provider_ptg'] = self.mock_dict.provider_ptg
        service_details['consumer_ptg'] = self.mock_dict.consumer_ptg
        service_details['consumer_port'] = self.mock_dict.consumer_port
        service_details['provider_port'] = self.mock_dict.port_info['port']
        service_details['mgmt_ip'] = '11.3.4.5'
        service_details['heat_stack_id'] = (
            '70754fdd-0325-4856-8a39-f171b65617d6')
        self.heat_driver_obj.get_service_details = mock.Mock(
            return_value=service_details)

        stack_id = self.heat_driver_obj._update(
            auth_token, resource_owner_tenant_id,
            self.mock_dict.service_profile,
            self.mock_dict.fw_service_chain_node,
            self.mock_dict.service_chain_instance, provider,
            self.mock_dict.consumer_port,
            self.mock_dict.network_function_details['network_function'],
            provider_port, stack_id, mgmt_ip=mgmt_ip,
            pt_added_or_removed=False)
        self.assertIsNotNone(stack_id)

    @mock.patch.object(heat_client.HeatClient, "delete")
    @mock.patch.object(heat_client.HeatClient, "update")
    @mock.patch.object(heat_client.HeatClient, "get")
    @mock.patch.object(heat_client.HeatClient, "create")
    def test_handle_consumer_ptg_operations(
            self, heat_create,
            heat_get, heat_update, heat_delete):

        self.mock_objects()
        heat_create.return_value = {'stack': {
            'id': uuidutils.generate_uuid()}}
        heat_delete.return_value = MockStackObject(
            'CREATE_COMPLETE')
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})

        service_details = {}
        service_details['service_profile'] = self.mock_dict.service_profile
        service_details['servicechain_node'] = (
            self.mock_dict.fw_service_chain_node)
        service_details['servicechain_instance'] = (
            self.mock_dict.service_chain_instance)
        service_details['policy_target_group'] = self.mock_dict.provider_ptg
        service_details['provider_ptg'] = self.mock_dict.provider_ptg
        service_details['consumer_ptg'] = self.mock_dict.consumer_ptg
        service_details['consumer_port'] = self.mock_dict.consumer_port
        service_details['provider_port'] = self.mock_dict.port_info['port']
        service_details['mgmt_ip'] = '11.3.4.5'
        service_details['heat_stack_id'] = (
            '70754fdd-0325-4856-8a39-f171b65617d6')
        self.heat_driver_obj.get_service_details = mock.Mock(
            return_value=service_details)

        policy_target_group = self.mock_dict.provider_ptg
        stack_id = self.heat_driver_obj.handle_consumer_ptg_operations(
            self.mock_dict.network_function_details,
            policy_target_group, "add")
        self.assertIsNotNone(stack_id)

    @mock.patch.object(heat_client.HeatClient, "delete")
    @mock.patch.object(heat_client.HeatClient, "update")
    @mock.patch.object(heat_client.HeatClient, "get")
    @mock.patch.object(heat_client.HeatClient, "create")
    def test_handle_policy_target_operations(
            self, heat_create,
            heat_get, heat_update, heat_delete):

        self.mock_objects()
        heat_create.return_value = {'stack': {
            'id': uuidutils.generate_uuid()}}
        heat_delete.return_value = MockStackObject(
            'CREATE_COMPLETE')
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})

        service_details = {}
        service_details['service_profile'] = self.mock_dict.lb_service_profile
        service_details['servicechain_node'] = (
            self.mock_dict.lb_service_chain_node)
        service_details['servicechain_instance'] = (
            self.mock_dict.service_chain_instance)
        service_details['policy_target_group'] = self.mock_dict.provider_ptg
        service_details['provider_ptg'] = self.mock_dict.provider_ptg
        service_details['consumer_ptg'] = self.mock_dict.consumer_ptg
        service_details['consumer_port'] = self.mock_dict.consumer_port
        service_details['provider_port'] = self.mock_dict.port_info['port']
        service_details['mgmt_ip'] = '11.3.4.5'
        service_details['heat_stack_id'] = (
            '70754fdd-0325-4856-8a39-f171b65617d6')
        self.heat_driver_obj.get_service_details = mock.Mock(
            return_value=service_details)
        policy_target = {
            'name': 'policy_target_0132c_00b93'
        }
        stack_id = self.heat_driver_obj.handle_policy_target_operations(
            self.mock_dict.network_function_details,
            policy_target, "add")
        self.assertIsNotNone(stack_id)

    @mock.patch.object(heat_client.HeatClient, "delete")
    @mock.patch.object(heat_client.HeatClient, "update")
    @mock.patch.object(heat_client.HeatClient, "get")
    @mock.patch.object(heat_client.HeatClient, "create")
    def test_apply_config(
            self, heat_create,
            heat_get, heat_update, heat_delete):

        self.mock_objects()
        heat_create.return_value = {'stack': {
            'id': uuidutils.generate_uuid()}}
        heat_delete.return_value = MockStackObject(
            'CREATE_COMPLETE')
        self.heat_driver_obj._assign_admin_user_to_project = mock.Mock(
            return_value=None)
        nfp_logging.get_logging_context = mock.Mock(
            return_value={'auth_token': '7fd6701128994ab281ccb6b92207bb15'})

        service_details = {}
        service_details['service_profile'] = self.mock_dict.service_profile
        service_details['servicechain_node'] = (
            self.mock_dict.fw_service_chain_node)
        service_details['servicechain_instance'] = (
            self.mock_dict.service_chain_instance)
        service_details['policy_target_group'] = self.mock_dict.provider_ptg
        service_details['provider_ptg'] = self.mock_dict.provider_ptg
        service_details['consumer_ptg'] = self.mock_dict.consumer_ptg
        service_details['consumer_port'] = self.mock_dict.consumer_port
        service_details['provider_port'] = self.mock_dict.port_info['port']
        service_details['mgmt_ip'] = '11.3.4.5'
        service_details['heat_stack_id'] = (
            '70754fdd-0325-4856-8a39-f171b65617d6')
        self.heat_driver_obj.get_service_details = mock.Mock(
            return_value=service_details)
        stack_id = self.heat_driver_obj.apply_config(
            self.mock_dict.network_function_details)
        self.assertIsNotNone(stack_id)
