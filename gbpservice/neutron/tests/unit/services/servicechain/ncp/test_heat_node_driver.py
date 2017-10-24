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

import itertools

import copy
import heatclient
import mock
from neutron.extensions import external_net as external_net
from neutron.plugins.common import constants
from neutron_lib import context as neutron_context
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import webob

from gbpservice.neutron.services.servicechain.plugins.ncp import config
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    heat_node_driver as heat_node_driver)
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    openstack_heat_api_client as heatClient)
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

    def update(self, *args, **fields):
        return {'stack': {'id': uuidutils.generate_uuid()}}


class MockHeatClientDeleteNotFound(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctionsDeleteNotFound()


class MockHeatClient(object):
    def __init__(self, api_version, endpoint, **kwargs):
        self.stacks = MockHeatClientFunctions()
        self.resources = mock.MagicMock()


class HeatNodeDriverTestCase(
        test_ncp_plugin.NodeCompositionPluginTestCase):

    DEFAULT_LB_CONFIG_DICT = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "test_pool": {
                    "Type": "OS::Neutron::LBaaS::Pool",
                    "Properties": {
                        "description": "Haproxy pool from template",
                        "lb_algorithm": "ROUND_ROBIN",
                        "protocol": "HTTP",
                        'listener': {u'get_resource': u'listener'},
                    }
                },
                "test_listener": {
                    "Type": "OS::Neutron::LBaaS::Listener",
                    "Properties": {
                        "protocol": "HTTP",
                        "protocol_port": 80,
                    }
                },
                "test_lb": {
                    "Type": "OS::Neutron::LBaaS::LoadBalancer",
                    "Properties": {
                        "provider": 'haproxy',
                        'vip_address': '1.1.1.1',
                        'vip_subnet': '1.1.1.0/24',
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
    SERVICE_PROFILE_VENDOR = 'heat_based_node_driver'

    def setUp(self):
        config.cfg.CONF.set_override('stack_action_wait_time',
                                     STACK_ACTION_WAIT_TIME,
                                     group='heat_node_driver')
        mock.patch(heatclient.__name__ + ".client.Client",
                   new=MockHeatClient).start()
        super(HeatNodeDriverTestCase, self).setUp(
            node_drivers=['heat_node_driver'],
            node_plumber='stitching_plumber',
            core_plugin=test_gp_driver.CORE_PLUGIN)

    def _create_network(self, fmt, name, admin_state_up, **kwargs):
        """Override the routine for allowing the router:external attribute."""
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = new_args.pop('arg_list', ()) + (external_net.EXTERNAL,)
        return super(HeatNodeDriverTestCase, self)._create_network(
            fmt, name, admin_state_up, arg_list=arg_list, **new_args)

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              heat_node_driver.HeatNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)

    def _create_profiled_servicechain_node(
            self, service_type=constants.LOADBALANCERV2, shared_profile=False,
            profile_tenant_id=None, profile_id=None, **kwargs):
        if not profile_id:
            prof = self.create_service_profile(
                service_type=service_type,
                shared=shared_profile,
                vendor=self.SERVICE_PROFILE_VENDOR,
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


class TestServiceChainInstance(HeatNodeDriverTestCase):

    def _get_node_instance_stacks(self, sc_node_id):
        context = neutron_context.get_admin_context()
        with context.session.begin(subtransactions=True):
            return (context.session.query(
                        heat_node_driver.ServiceNodeInstanceStack).
                    filter_by(sc_node_id=sc_node_id).
                    all())

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

    def _get_pool_member_resource_dict(self, port):
        member_ip = port['fixed_ips'][0]['ip_address']
        member_name = 'mem-' + member_ip
        member = {member_name: {
                        'Type': 'OS::Neutron::LBaaS::PoolMember',
                        'Properties': {
                            'subnet': {'get_param': 'Subnet'},
                            'weight': 1,
                            'admin_state_up': True,
                            'address': member_ip,
                            'protocol_port': {'get_param': 'app_port'},
                            'pool': {'Ref': u'test_pool'}
                        }
                    }
                  }
        return member

    def _create_policy_target_port(self, policy_target_group_id):
        pt = self.create_policy_target(
                policy_target_group_id=policy_target_group_id)['policy_target']
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        port = self.deserialize(self.fmt,
                                req.get_response(self.api))['port']
        return (pt, port)

    def _create_external_policy(self, consumed_prs, routes=None):
        with self.network(router__external=True, shared=True) as net:
            with self.subnet(cidr='192.168.0.0/24', network=net) as sub:
                if not routes:
                    routes = [{'destination': '172.0.0.0/22', 'nexthop': None}]
                self.create_external_segment(
                    shared=True,
                    name="default",
                    external_routes=routes,
                    subnet_id=sub['subnet']['id'])
                return self.create_external_policy(
                    consumed_policy_rule_sets={consumed_prs: ''})

    def _test_lb_node_create(self, consumer_external=False):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}

            node_id = self._create_profiled_servicechain_node(
                service_type=constants.LOADBALANCERV2)[
                        'servicechain_node']['id']
            spec = self.create_servicechain_spec(
                nodes=[node_id],
                expected_res_status=201)['servicechain_spec']

            prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
            provider = self.create_policy_target_group()['policy_target_group']

            _, port1 = self._create_policy_target_port(provider['id'])
            _, port2 = self._create_policy_target_port(provider['id'])

            if consumer_external:
                self._create_external_policy(prs['id'])
            else:
                self.create_policy_target_group(
                    consumed_policy_rule_sets={prs['id']: ''})

            self.update_policy_target_group(
                provider['id'], provided_policy_rule_sets={prs['id']: ''})
            created_stacks_map = self._get_node_instance_stacks(node_id)
            self.assertEqual(1, len(created_stacks_map))

            pool_member1 = self._get_pool_member_resource_dict(port1)
            pool_member2 = self._get_pool_member_resource_dict(port2)

            # Instantiating the chain invokes stack create
            expected_stack_template = copy.deepcopy(
                                    self.DEFAULT_LB_CONFIG_DICT)
            expected_stack_template['Resources'].update(pool_member1)
            expected_stack_template['Resources'].update(pool_member2)
            expected_stack_name = mock.ANY
            # TODO(Magesh): Verify expected_stack_params with IP address from
            # Network Service Policy
            expected_stack_params = {}
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    expected_stack_template,
                    expected_stack_params)
            return (expected_stack_template, provider,
                    created_stacks_map[0].stack_id)

    def _test_lb_dynamic_pool_member_add(self, expected_stack_template,
                                         provider, stack_id):
        with mock.patch.object(heatClient.HeatClient,
                           'update') as stack_update:
            stack_update.return_value = {'stack': {
                                        'id': stack_id}}

            # Creating PT will update the node, thereby adding the PT as an
            # LB Pool Member using heat stack
            pt, port = self._create_policy_target_port(provider['id'])

            pool_member = self._get_pool_member_resource_dict(port)
            expected_stack_template['Resources'].update(pool_member)
            expected_stack_id = stack_id
            expected_stack_params = {}
            stack_update.assert_called_once_with(
                    expected_stack_id,
                    expected_stack_template,
                    expected_stack_params)
            return (pt, pool_member)

    def _test_dynamic_lb_pool_member_delete(self, pt, pool_member,
                                            expected_stack_template,
                                            stack_id):
        # Deleting PT will update the node, thereby removing the Pool
        # Member from heat stack
        with mock.patch.object(heatClient.HeatClient,
                           'update') as stack_update:
            self.delete_policy_target(pt['id'])

            template_on_delete_pt = copy.deepcopy(expected_stack_template)
            template_on_delete_pt['Resources'].pop(pool_member.keys()[0])
            expected_stack_id = stack_id
            expected_stack_params = {}
            stack_update.assert_called_once_with(
                    expected_stack_id,
                    template_on_delete_pt,
                    expected_stack_params)

    def _test_node_cleanup(self, ptg, stack_id):
        with mock.patch.object(heatClient.HeatClient,
                               'delete') as stack_delete:
            self.update_policy_target_group(
                    ptg['id'], consumed_policy_rule_sets={},
                    expected_res_status=200)
            self.delete_policy_target_group(ptg['id'], expected_res_status=204)
            stack_delete.assert_called_once_with(stack_id)

    def test_lb_node_operations(self):
        expected_stack_template, provider, stack_id = (
                                self._test_lb_node_create())
        pt, pool_member = self._test_lb_dynamic_pool_member_add(
                expected_stack_template, provider, stack_id)
        self._test_dynamic_lb_pool_member_delete(
                pt, pool_member, expected_stack_template, stack_id)
        self._test_node_cleanup(provider, stack_id)

    def test_lb_redirect_from_external(self):
        expected_stack_template, provider, stack_id = (
                self._test_lb_node_create(consumer_external=True))
        pt, pool_member = self._test_lb_dynamic_pool_member_add(
                expected_stack_template, provider, stack_id)
        self._test_dynamic_lb_pool_member_delete(
                pt, pool_member, expected_stack_template, stack_id)
        self._test_node_cleanup(provider, stack_id)

    def _create_fwredirect_ruleset(self, classifier_port, classifier_protocol):
        node_id = self._create_profiled_servicechain_node(
                service_type=constants.FIREWALL)['servicechain_node']['id']
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
        return (prs['policy_rule_set'], node_id)

    def _get_ptg_cidr(self, ptg):
        req = self.new_show_request(
                'subnets', ptg['subnets'][0], fmt=self.fmt)
        ptg_subnet = self.deserialize(
                self.fmt, req.get_response(self.api))['subnet']
        return ptg_subnet['cidr']

    def _get_firewall_rule_dict(self, rule_name, protocol, port, provider_cidr,
                                consumer_cidr):
        if provider_cidr and consumer_cidr:
            fw_rule = {rule_name: {'type': "OS::Neutron::FirewallRule",
                                   'properties': {
                                       "protocol": protocol,
                                       "enabled": True,
                                       "destination_port": port,
                                       "action": "allow",
                                       "destination_ip_address": provider_cidr,
                                       "source_ip_address": consumer_cidr
                                   }
                                   }
                       }
            return fw_rule
        return {}

    def test_fw_node_east_west(self):
        classifier_port = '66'
        classifier_protocol = 'udp'
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prs, node_id = self._create_fwredirect_ruleset(
                                    classifier_port, classifier_protocol)
            provider = self.create_policy_target_group(
                provided_policy_rule_sets={prs['id']: ''})[
                                                'policy_target_group']
            self.create_policy_target_group(
                consumed_policy_rule_sets={prs['id']: ''})

            created_stacks_map = self._get_node_instance_stacks(node_id)
            self.assertEqual(1, len(created_stacks_map))
            stack_id = created_stacks_map[0].stack_id

            provider_cidr = self._get_ptg_cidr(provider)
            # TODO(ivar): This has to be removed once support to consumer list
            # is implemented
            #consumer_cidr = self._get_ptg_cidr(consumer)
            consumer_cidr = []
            fw_rule = self._get_firewall_rule_dict(
                'Rule_1', classifier_protocol, classifier_port,
                provider_cidr, consumer_cidr)

            expected_stack_template = copy.deepcopy(
                                        self.DEFAULT_FW_CONFIG_DICT)
            expected_stack_template['resources'][
                'test_fw_policy']['properties']['firewall_rules'] = []
            expected_stack_template['resources'].update(fw_rule)
            expected_stack_name = mock.ANY
            expected_stack_params = {}
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    expected_stack_template,
                    expected_stack_params)

            self._test_node_cleanup(provider, stack_id)

    def _test_fw_node_north_south(self, consumer_cidrs):
        classifier_port = '66'
        classifier_protocol = 'udp'
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prs, node_id = self._create_fwredirect_ruleset(
                                    classifier_port, classifier_protocol)
            provider = self.create_policy_target_group(
                provided_policy_rule_sets={prs['id']: ''})[
                                                'policy_target_group']

            routes = []
            for consumer_cidr in consumer_cidrs:
                routes.append({'destination': consumer_cidr, 'nexthop': None})
            self._create_external_policy(prs['id'], routes=routes)

            # TODO(ivar): This has to be removed once support to consumer list
            # is implemented
            consumer_cidrs = []

            created_stacks_map = self._get_node_instance_stacks(node_id)
            self.assertEqual(1, len(created_stacks_map))
            stack_id = created_stacks_map[0].stack_id

            expected_stack_template = copy.deepcopy(
                                        self.DEFAULT_FW_CONFIG_DICT)
            expected_stack_template['resources']['test_fw_policy'][
                                        'properties']['firewall_rules'] = []
            provider_cidr = self._get_ptg_cidr(provider)

            rule_num = 1
            for consumer_cidr in consumer_cidrs:
                rule_name = 'Rule_' + str(rule_num)
                fw_rule = self._get_firewall_rule_dict(
                    rule_name, classifier_protocol, classifier_port,
                    provider_cidr, consumer_cidr)
                rule_num = rule_num + 1
                expected_stack_template['resources'].update(fw_rule)
                expected_stack_template['resources']['test_fw_policy'][
                    'properties']['firewall_rules'].append(
                                                {'get_resource': rule_name})

            expected_stack_name = mock.ANY
            expected_stack_params = {}
            stack_create.assert_called_once_with(
                    expected_stack_name,
                    expected_stack_template,
                    expected_stack_params)

            self._test_node_cleanup(provider, stack_id)

    def test_fw_node_north_south_single_external_cidr(self):
        self._test_fw_node_north_south(['172.0.0.0/22'])

    def test_fw_node_north_south_multiple_external_cidr(self):
        self._test_fw_node_north_south(['172.0.0.0/22', '20.0.0.0/16'])

    def test_node_update(self):
        with mock.patch.object(heatClient.HeatClient,
                               'create') as stack_create:
            stack_create.return_value = {'stack': {
                                        'id': uuidutils.generate_uuid()}}
            prof = self.create_service_profile(
                        service_type=constants.LOADBALANCERV2,
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
                # Name update should not update stack ??
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
                    stack_get.return_value = MockStackObject(
                        'DELETE_IN_PROGRESS')
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                        provider['id'],
                                        provided_policy_rule_sets={},
                                        expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                                expected_res_status=204)
                    stack_delete.assert_called_once_with(mock.ANY)

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
