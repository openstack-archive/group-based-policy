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

import heatclient
import mock
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from oslo_serialization import jsonutils
import webob

from gbpservice.neutron.services.servicechain.plugins.ncp import config
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    openstack_heat_api_client as heatClient)
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    template_node_driver as template_node_driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as test_ncp_plugin)


STACK_ACTION_WAIT_TIME = 15


class MockStackObject(object):
    def __init__(self, status):
        self.stack_status = status


class MockHeatClientFunctionsDeleteNotFound(object):
    def delete(self, stack_id):
        raise heatclient.exc.HTTPNotFound()

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


class MockHeatClientDeleteNotFound(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctionsDeleteNotFound()


class MockHeatClient(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctions()


class TemplateNodeDriverTestCase(
        test_ncp_plugin.NodeCompositionPluginTestCase):

    DEFAULT_LB_CONFIG_DICT = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "test_pool": {
                    "Type": "OS::Neutron::Pool",
                    "Properties": {
                        "admin_state_up": True,
                        "description": "Haproxy pool from teplate",
                        "lb_method": "ROUND_ROBIN",
                        "monitors": [{"Ref": "HttpHM"}],
                        "name": "Haproxy pool",
                        "protocol": "HTTP",
                        "subnet_id": {"Ref": "Subnet"},
                        "vip": {
                            "subnet": {"Ref": "Subnet"},
                            "address": {"Ref": "vip_ip"},
                            "name": "Haproxy vip",
                            "protocol_port": 80,
                            "connection_limit": -1,
                            "admin_state_up": True,
                            "description": "Haproxy vip from template"
                        }
                    }
                },
                "test_lb": {
                    "Type": "OS::Neutron::LoadBalancer",
                    "Properties": {
                        "pool_id": {"Ref": "HaproxyPool"},
                        "protocol_port": 80
                    }
                }
            }
    }
    DEFAULT_LB_CONFIG = jsonutils.dumps(DEFAULT_LB_CONFIG_DICT)
    DEFAULT_FW_CONFIG_DICT = {
            "heat_template_version": "2013-05-23",
            "resources": {
                'test_fw': {
                    "type": "OS::Neutron::Firewall",
                    "properties": {
                        "admin_state_up": True,
                        "firewall_policy_id": {
                            "get_resource": "Firewall_policy"},
                        "name": "testFirewall",
                        "description": "test Firewall"
                    }
                },
                'test_fw_policy': {
                    "type": "OS::Neutron::FirewallPolicy",
                    "properties": {
                        "shared": False,
                        "description": "test firewall policy",
                        "name": "testFWPolicy",
                        "firewall_rules": [{
                                "get_resource": "Rule_1"}],
                        "audited": True
                    }
                }
            }
    }
    DEFAULT_FW_CONFIG = jsonutils.dumps(DEFAULT_FW_CONFIG_DICT)
    SERVICE_PROFILE_VENDOR = 'gbp_reference'

    def setUp(self):
        config.cfg.CONF.set_override('stack_action_wait_time',
                                     STACK_ACTION_WAIT_TIME,
                                     group='servicechain')
        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClient).start()
        super(TemplateNodeDriverTestCase, self).setUp(
            node_drivers=['template_node_driver'],
            node_plumber='agnostic_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              template_node_driver.TemplateNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)

    def _create_simple_service_chain(self, number_of_nodes=1):
        prof = self.create_service_profile(
            service_type=constants.LOADBALANCER,
            vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

        node_ids = []
        for x in xrange(number_of_nodes):
            node_ids.append(self.create_servicechain_node(
                service_profile_id=prof['id'],
                config=self.DEFAULT_LB_CONFIG,
                expected_res_status=201)['servicechain_node']['id'])

        return self._create_chain_with_nodes(node_ids)

    def _create_profiled_servicechain_node(
            self, service_type=constants.LOADBALANCER, shared_profile=False,
            profile_tenant_id=None, profile_id=None, **kwargs):
        if not profile_id:
            prof = self.create_service_profile(
                service_type=service_type,
                shared=shared_profile,
                vendor='gbp_reference',
                tenant_id=profile_tenant_id or self._tenant_id)[
                                                    'service_profile']
        else:
            prof = self.get_service_profile(profile_id)

        service_config = kwargs.get('config')
        if not service_config or service_config == '{}':
            if service_type == constants.FIREWALL:
                kwargs['config'] = self.DEFAULT_FW_CONFIG
            else:
                kwargs['config'] = self.DEFAULT_LB_CONFIG
        return self.create_servicechain_node(
            service_profile_id=prof['id'], **kwargs)


class TestServiceChainInstance(TemplateNodeDriverTestCase):

    def test_invalid_service_type_rejected(self):
        node_used = self._create_profiled_servicechain_node(
            service_type="test")['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        res = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
            classifier_id=classifier['id'],
            servicechain_specs=[spec_used['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NoDriverAvailableForAction',
                         res['NeutronError']['type'])

    def test_node_create(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            self._create_simple_service_chain()
            expected_stack_name = mock.ANY
            expected_stack_params = mock.ANY
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    self.DEFAULT_LB_CONFIG_DICT,
                    expected_stack_params)

    def test_node_create_add_lb_member(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prof = self.create_service_profile(
                service_type=constants.LOADBALANCER,
                vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
            node_id = self.create_servicechain_node(
                    service_profile_id=prof['id'],
                    config=self.DEFAULT_LB_CONFIG,
                    expected_res_status=201)['servicechain_node']['id']
            spec = self.create_servicechain_spec(
                nodes=[node_id],
                expected_res_status=201)['servicechain_spec']
            prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
            provider = self.create_policy_target_group(
                provided_policy_rule_sets={prs['id']: ''})[
                                                'policy_target_group']
            pt1 = self.create_policy_target(
                    policy_target_group_id=provider['id'])['policy_target']
            req = self.new_show_request('ports', pt1['port_id'], fmt=self.fmt)
            port1 = self.deserialize(self.fmt,
                                     req.get_response(self.api))['port']
            pt2 = self.create_policy_target(
                    policy_target_group_id=provider['id'])['policy_target']
            req = self.new_show_request('ports', pt2['port_id'], fmt=self.fmt)
            port2 = self.deserialize(self.fmt,
                                     req.get_response(self.api))['port']
            self.create_policy_target_group(
                consumed_policy_rule_sets={prs['id']: ''})[
                                            'policy_target_group']

            member1_ip = port1['fixed_ips'][0]['ip_address']
            member2_ip = port2['fixed_ips'][0]['ip_address']
            member1_name = 'mem-' + member1_ip
            member2_name = 'mem-' + member2_ip
            pool_member1 = {member1_name: {
                                'Type': 'OS::Neutron::PoolMember',
                                'Properties': {
                                    'protocol_port': '80',
                                    'admin_state_up': True,
                                    'pool_id': {'Ref': u'test_pool'},
                                    'weight': 1,
                                    'address': member1_ip
                                }
                            }
                            }
            pool_member2 = {member2_name: {
                                'Type': 'OS::Neutron::PoolMember',
                                'Properties': {
                                    'protocol_port': '80',
                                    'admin_state_up': True,
                                    'pool_id': {'Ref': u'test_pool'},
                                    'weight': 1,
                                    'address': member2_ip
                                }
                            }
                            }
            expected_stack_template = self.DEFAULT_LB_CONFIG_DICT
            expected_stack_template['Resources'].update(pool_member1)
            expected_stack_template['Resources'].update(pool_member2)
            expected_stack_name = mock.ANY
            # TODO(Magesh): Verify expected_stack_params with IP address from
            # Network Service Policy
            expected_stack_params = mock.ANY
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    expected_stack_template,
                    expected_stack_params)

    def test_node_create_add_fw_rule(self):
        classifier_port = '66'
        classifier_protocol = 'udp'
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prof = self.create_service_profile(
                service_type=constants.FIREWALL,
                vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']
            node_id = self.create_servicechain_node(
                    service_profile_id=prof['id'],
                    config=self.DEFAULT_FW_CONFIG,
                    expected_res_status=201)['servicechain_node']['id']
            spec = self.create_servicechain_spec(
                nodes=[node_id],
                expected_res_status=201)['servicechain_spec']
            action = self.create_policy_action(action_type='REDIRECT',
                                               action_value=spec['id'])
            classifier = self.create_policy_classifier(
                port_range=classifier_port, protocol=classifier_protocol,
                direction='bi')
            rule = self.create_policy_rule(
                policy_actions=[action['policy_action']['id']],
                policy_classifier_id=classifier['policy_classifier']['id'])
            rule = rule['policy_rule']
            prs = self.create_policy_rule_set(policy_rules=[rule['id']])
            prs = prs['policy_rule_set']
            provider = self.create_policy_target_group(
                provided_policy_rule_sets={prs['id']: ''})[
                                                'policy_target_group']
            consumer = self.create_policy_target_group(
                consumed_policy_rule_sets={prs['id']: ''})[
                                                'policy_target_group']

            req = self.new_show_request(
                'subnets', provider['subnets'][0], fmt=self.fmt)
            provider_subnet = self.deserialize(
                    self.fmt, req.get_response(self.api))['subnet']
            req = self.new_show_request(
                    'subnets', consumer['subnets'][0], fmt=self.fmt)
            consumer_subnet = self.deserialize(
                    self.fmt, req.get_response(self.api))['subnet']

            fw_rule = {'Rule_1': {
                            'type': "OS::Neutron::FirewallRule",
                            'properties': {
                                "protocol": classifier_protocol,
                                "enabled": True,
                                "destination_port": classifier_port,
                                "action": "allow",
                                "destination_ip_address": provider_subnet[
                                                                    'cidr'],
                                "source_ip_address": consumer_subnet['cidr']
                            }
                       }
                       }

            expected_stack_template = self.DEFAULT_FW_CONFIG_DICT
            expected_stack_template['resources'].update(fw_rule)
            expected_stack_name = mock.ANY
            expected_stack_params = mock.ANY
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    expected_stack_template,
                    expected_stack_params)

            with mock.patch.object(heatClient.HeatClient,
                                   'delete'):
                self.update_policy_target_group(
                                        consumer['id'],
                                        consumed_policy_rule_sets={},
                                        expected_res_status=200)
                self.delete_policy_target_group(consumer['id'],
                                                expected_res_status=204)

            # FIXME(Magesh): router:external is not set with the below code
            '''
            with self.network(router__external=True, shared=True) as net:
                with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                    routes = [{'destination': '172.0.0.0/22', 'nexthop': None}]
                    self.assertEqual(net, "test")
                    req = self.new_show_request(
                        'networks', net, fmt=self.fmt)
                    network = self.deserialize(
                        self.fmt, req.get_response(self.api))['network']
                    self.assertEqual(network, "test")
                    self.create_external_segment(
                        shared=True,
                        tenant_id='admin',
                        name="default",
                        external_routes=routes,
                        subnet_id=sub['subnet']['id'])['external_segment']
                    self.create_external_policy(
                        consumed_policy_rule_sets={prs['id']: ''})
                    fw_rule['Rule_1']['properties']['source_ip_address'] = (
                                                                '172.0.0.0/22')
                    expected_stack_template['resources'].update(fw_rule)
                    expected_stack_name = mock.ANY
                    expected_stack_params = mock.ANY
                    stack_create.assert_called_once_with(
                            expected_stack_name,
                            expected_stack_template,
                            expected_stack_params)
            '''

    def test_node_update(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prof = self.create_service_profile(
                        service_type=constants.LOADBALANCER,
                        vendor=self.SERVICE_PROFILE_VENDOR)['service_profile']

            node = self.create_servicechain_node(
                        service_profile_id=prof['id'],
                        config=self.DEFAULT_LB_CONFIG,
                        expected_res_status=201)['servicechain_node']

            self._create_chain_with_nodes(node_ids=[node['id']])
            with mock.patch.object(heatClient.HeatClient,
                                   'update') as stack_update:
                self.update_servicechain_node(
                                        node['id'],
                                        name='newname',
                                        expected_res_status=200)
                stack_update.assert_called_once_with(
                                    mock.ANY, mock.ANY, mock.ANY)

    def test_node_delete(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            provider, _, _ = self._create_simple_service_chain()
            with mock.patch.object(heatClient.HeatClient,
                                   'delete'):
                self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)

    def test_wait_stack_delete_for_instance_delete(self):

        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            provider, _, _ = self._create_simple_service_chain()

            # Verify that as part of delete service chain instance we call
            # get method for heat stack 5 times before giving up if the state
            # does not become DELETE_COMPLETE
            with mock.patch.object(heatClient.HeatClient,
                                   'delete') as stack_delete:
                with mock.patch.object(heatClient.HeatClient,
                                       'get') as stack_get:
                    stack_get.return_value = MockStackObject('PENDING_DELETE')
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)
                    stack_delete.assert_called_once_with(mock.ANY)
                    self.assertEqual(STACK_ACTION_WAIT_TIME / 5,
                                     stack_get.call_count)

            # Create and delete another service chain instance and verify that
            # we call get method for heat stack only once if the stack state
            # is DELETE_COMPLETE
            provider, _, _ = self._create_simple_service_chain()
            with mock.patch.object(heatClient.HeatClient,
                                   'delete') as stack_delete:
                with mock.patch.object(heatClient.HeatClient,
                                       'get') as stack_get:
                    stack_get.return_value = MockStackObject(
                        'DELETE_COMPLETE')
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)
                    stack_delete.assert_called_once_with(mock.ANY)
                    self.assertEqual(1, stack_get.call_count)

    def test_stack_not_found_ignored(self):
        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClientDeleteNotFound).start()

        provider, _, _ = self._create_simple_service_chain()

        # Removing the PRSs will make the PTG deletable again
        self.update_policy_target_group(provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
        self.delete_policy_target_group(provider['id'],
                                        expected_res_status=204)
