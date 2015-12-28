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

import copy
import sys

import mock
import netaddr
import webob.exc

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db
from apic_ml2.neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)
from neutron.agent import securitygroups_rpc as sg_cfg
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2 as n_db
from neutron.db import model_base
from neutron import manager
from opflexagent import constants as ocst
from oslo_config import cfg

sys.modules["apicapi"] = mock.Mock()

from gbpservice.neutron.services.grouppolicy import (
    group_policy_context as p_context)
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)

APIC_L2_POLICY = 'l2_policy'
APIC_L3_POLICY = 'l3_policy'
APIC_POLICY_RULE_SET = 'policy_rule_set'
APIC_POLICY_TARGET_GROUP = 'policy_target_group'
APIC_POLICY_RULE = 'policy_rule'

APIC_EXTERNAL_RID = '1.0.0.1'
APIC_EXTERNAL_EPG = 'ext-epg'
APIC_PRE_L3OUT_TENANT = 'common'
APIC_PRE_VRF_TENANT = APIC_PRE_L3OUT_TENANT
APIC_PRE_VRF = 'pre-vrf'

AGENT_TYPE = ocst.AGENT_TYPE_OPFLEX_OVS
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'opflex_networks': None,
                                 'bridge_mappings': {'physnet1': 'br-eth1'}}}


def echo(context, string, prefix=''):
    return prefix + string


class MockCallRecorder(mock.Mock):
    recorded_call_set = set()

    def __call__(self, *args, **kwargs):
        self.recorded_call_set.add(self.generate_entry(*args, **kwargs))
        return mock.Mock()

    def call_happened_with(self, *args, **kwargs):
        return self.generate_entry(*args, **kwargs) in self.recorded_call_set

    def generate_entry(self, *args, **kwargs):
        return args, tuple((x, kwargs[x]) for x in sorted(kwargs.keys()))


class ApicMappingTestCase(
        test_rmd.ResourceMappingTestCase,
        mocked.ControllerMixin, mocked.ConfigMixin):

    def setUp(self, sc_plugin=None, nat_enabled=True,
              pre_existing_l3out=False):
        self.agent_conf = AGENT_CONF
        cfg.CONF.register_opts(sg_cfg.security_group_opts, 'SECURITYGROUP')
        config.cfg.CONF.set_override('enable_security_group', False,
                                     group='SECURITYGROUP')
        n_rpc.create_connection = mock.Mock()
        amap.ApicMappingDriver.get_apic_manager = mock.Mock()
        self.set_up_mocks()
        ml2_opts = {
            'mechanism_drivers': ['apic_gbp'],
            'type_drivers': ['opflex'],
            'tenant_network_types': ['opflex']
        }
        mock.patch('gbpservice.neutron.services.grouppolicy.drivers.cisco.'
                   'apic.apic_mapping.ApicMappingDriver._setup_rpc').start()
        host_agents = mock.patch('neutron.plugins.ml2.driver_context.'
                                 'PortContext.host_agents').start()
        host_agents.return_value = [self.agent_conf]
        nova_client = mock.patch(
            'gbpservice.neutron.services.grouppolicy.drivers.cisco.'
            'apic.nova_client.NovaClient.get_server').start()
        vm = mock.Mock()
        vm.name = 'someid'
        nova_client.return_value = vm
        super(ApicMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'apic', 'chain_mapping'],
            ml2_options=ml2_opts, sc_plugin=sc_plugin)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)
        plugin = manager.NeutronManager.get_plugin()
        plugin.remove_networks_from_down_agents = mock.Mock()
        plugin.is_agent_down = mock.Mock(return_value=False)
        self.driver = manager.NeutronManager.get_service_plugins()[
            'GROUP_POLICY'].policy_driver_manager.policy_drivers['apic'].obj
        amap.ApicMappingDriver.get_base_synchronizer = mock.Mock()
        self.driver.name_mapper.name_mapper = mock.Mock()
        self.driver.name_mapper.name_mapper.tenant = echo
        self.driver.name_mapper.name_mapper.l2_policy = echo
        self.driver.name_mapper.name_mapper.l3_policy = echo
        self.driver.name_mapper.name_mapper.policy_rule_set = echo
        self.driver.name_mapper.name_mapper.policy_rule = echo
        self.driver.name_mapper.name_mapper.app_profile.return_value = (
            mocked.APIC_AP)
        self.driver.name_mapper.name_mapper.policy_target_group = echo
        self.driver.name_mapper.name_mapper.external_policy = echo
        self.driver.name_mapper.name_mapper.external_segment = echo
        self.driver.name_mapper.name_mapper.pre_existing = echo
        self.driver.apic_manager = mock.Mock(name_mapper=mock.Mock(),
                                             ext_net_dict={})
        self.driver.apic_manager.apic.transaction = self.fake_transaction
        self.driver.notifier = mock.Mock()
        self.driver.apic_manager.ext_net_dict = {}
        amap.apic_manager.TENANT_COMMON = 'common'
        amap.apic_manager.CP_ENTRY = 'os-entry'
        self.common_tenant = amap.apic_manager.TENANT_COMMON
        self.nat_enabled = nat_enabled
        self.pre_l3out = pre_existing_l3out
        if self.pre_l3out:
            self.orig_query_l3out_info = self.driver._query_l3out_info
            self.driver._query_l3out_info = mock.Mock()
            self.driver._query_l3out_info.return_value = {
                'l3out_tenant': APIC_PRE_L3OUT_TENANT,
                'vrf_name': APIC_PRE_VRF,
                'vrf_tenant': APIC_PRE_VRF_TENANT}

        def echo2(string):
            return string
        self.driver.apic_manager.apic.fvTenant.name = echo2
        self.driver.apic_manager.apic.fvCtx.name = echo2
        self._db_plugin = n_db.NeutronDbPluginV2()

    def _build_external_dict(self, name, cidr_exposed):
        ext_info = {
            'enable_nat': 'True' if self.nat_enabled else 'False'
        }
        if self.pre_l3out:
            ext_info['preexisting'] = 'True'
            ext_info['external_epg'] = APIC_EXTERNAL_EPG
        else:
            ext_info.update({
                'switch': mocked.APIC_EXT_SWITCH,
                'port': mocked.APIC_EXT_MODULE + '/' + mocked.APIC_EXT_PORT,
                'encap': mocked.APIC_EXT_ENCAP,
                'router_id': APIC_EXTERNAL_RID,
                'gateway_ip': str(netaddr.IPNetwork(cidr_exposed)[1]),
                'cidr_exposed': cidr_exposed})
        return {name: ext_info}

    def _mock_external_dict(self, data):
        self.driver.apic_manager.ext_net_dict = {}
        for x in data:
            self.driver.apic_manager.ext_net_dict.update(
                self._build_external_dict(x[0], x[1]))

    def _create_simple_policy_rule(self, direction='bi', protocol='tcp',
                                   port_range=80, shared=False,
                                   action_type='allow', action_value=None):
        cls = self.create_policy_classifier(
            direction=direction, protocol=protocol,
            port_range=port_range, shared=shared)['policy_classifier']

        action = self.create_policy_action(
            action_type=action_type, shared=shared,
            action_value=action_value)['policy_action']
        return self.create_policy_rule(
            policy_classifier_id=cls['id'], policy_actions=[action['id']],
            shared=shared)['policy_rule']

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host, 'device_owner': 'compute:',
                         'device_id': 'someid'}}
        return super(ApicMappingTestCase, self)._bind_port_to_host(
            port_id, host, data=data)

    def _update_pre_l3out_info(self, l3p):
        rv = self.driver._query_l3out_info.return_value
        rv['vrf_name'] = l3p['id']
        rv['vrf_tenant'] = (self.common_tenant if l3p['shared']
                            else l3p['tenant_id'])


class TestPolicyTarget(ApicMappingTestCase):

    def test_policy_target_port_deleted_on_apic(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        with self.port(subnet=subnet) as port:
            self._bind_port_to_host(port['port']['id'], 'h1')
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'], port_id=port['port']['id'])
            self.new_delete_request(
                'policy_targets', pt['policy_target']['id'],
                self.fmt).get_response(self.ext_api)
            self.assertTrue(self.driver.notifier.port_update.called)

    def test_policy_target_delete_no_port(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        with self.port(subnet=subnet) as port:
            self._bind_port_to_host(port['port']['id'], 'h1')
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'], port_id=port['port']['id'])
            res = self.new_delete_request('ports', port['port']['id'],
                                          self.fmt).get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
            self.delete_policy_target(pt['policy_target']['id'],
                                      expected_res_status=404)

    def test_delete_policy_target_notification_no_apic_network(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        # Implicit port will be deleted with the PT
        self.delete_policy_target(pt1['id'], expected_res_status=204)
        # No notification needed
        self.assertFalse(self.driver.notifier.port_update.called)
        self.driver.notifier.port_update.reset_mock()
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        with self.port(subnet=subnet) as port:
            # Create EP with bound port
            port = self._bind_port_to_host(port['port']['id'], 'h1')
            pt1 = self.create_policy_target(
                policy_target_group_id=ptg['id'], port_id=port['port']['id'])
            # Explicit port won't be deleted with PT
            self.delete_policy_target(pt1['policy_target']['id'],
                                      expected_res_status=204)
            # Issue notification for the agent
            self.assertTrue(self.driver.notifier.port_update.called)

    def test_get_vrf_details(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        details = self.driver.get_vrf_details(
            context.get_admin_context(),
            vrf_id=l3p['id'], host='h1')
        self.assertEqual(l3p['id'], details['l3_policy_id'])
        pool = set([l3p['ip_pool']])
        if 'proxy_ip_pool' in l3p:
            pool.add(l3p['proxy_ip_pool'])
        self.assertEqual(pool, set(details['vrf_subnets']))
        self.assertEqual(l3p['tenant_id'], details['vrf_tenant'])
        self.assertEqual(l3p['id'], details['vrf_name'])

    def test_get_gbp_details(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        self.driver.apic_manager.ext_net_dict[
                'supported']['host_pool_cidr'] = '192.168.200.1/24'
        es = self.create_external_segment(name='supported',
            cidr='192.168.0.2/24',
            expected_res_status=201, shared=False)['external_segment']
        self.create_nat_pool(external_segment_id=es['id'],
                             ip_pool='20.20.20.0/24')
        l3p = self.create_l3_policy(name='myl3',
            external_segments={es['id']: ['']})['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "nat_pool", "name": "test"}])[
            'network_service_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'],
            network_service_policy_id=nsp['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')

        mapping = self.driver.get_gbp_details(context.get_admin_context(),
            device='tap%s' % pt1['port_id'], host='h1')
        self.assertEqual(pt1['port_id'], mapping['port_id'])
        self.assertEqual(ptg['id'], mapping['endpoint_group_name'])
        self.assertEqual('someid', mapping['vm-name'])
        self.assertTrue(mapping['enable_dhcp_optimization'])
        self.assertEqual(1, len(mapping['subnets']))
        self.assertEqual(ptg['subnets'][0], mapping['subnets'][0]['id'])
        self.assertEqual(1, len(mapping['floating_ip']))
        fip = mapping['floating_ip'][0]
        self.assertEqual(pt1['port_id'], fip['port_id'])
        self.assertEqual("NAT-epg-%s" % es['id'], fip['nat_epg_name'])
        self.assertEqual(es['tenant_id'], fip['nat_epg_tenant'])

        self.assertEqual(l3p['tenant_id'], mapping['vrf_tenant'])
        self.assertEqual(l3p['id'], mapping['vrf_name'])
        if 'proxy_ip_pool' in l3p:
            self.assertEqual([l3p['ip_pool'], l3p['proxy_ip_pool']],
                             mapping['vrf_subnets'])
        else:
            self.assertEqual([l3p['ip_pool']], mapping['vrf_subnets'])
        self.assertEqual(1, len(mapping['host_snat_ips']))
        self.assertEqual(es['name'],
            mapping['host_snat_ips'][0]['external_segment_name'])
        self.assertEqual("192.168.200.1",
            mapping['host_snat_ips'][0]['gateway_ip'])
        self.assertEqual("192.168.200.2",
            mapping['host_snat_ips'][0]['host_snat_ip'])
        self.assertEqual(24, mapping['host_snat_ips'][0]['prefixlen'])

        # Create event on a second host to verify that the SNAT
        # port gets created for this second host
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h1')

        mapping = self.driver.get_gbp_details(context.get_admin_context(),
            device='tap%s' % pt2['port_id'], host='h2')
        self.assertEqual(pt2['port_id'], mapping['port_id'])
        self.assertEqual(1, len(mapping['host_snat_ips']))
        self.assertEqual(es['name'],
            mapping['host_snat_ips'][0]['external_segment_name'])
        self.assertEqual("192.168.200.1",
            mapping['host_snat_ips'][0]['gateway_ip'])
        self.assertEqual("192.168.200.3",
            mapping['host_snat_ips'][0]['host_snat_ip'])
        self.assertEqual(24, mapping['host_snat_ips'][0]['prefixlen'])

    def test_snat_pool_subnet_deletion(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        self.driver.apic_manager.ext_net_dict[
                'supported']['host_pool_cidr'] = '192.168.200.1/24'
        es = self.create_external_segment(name='supported',
            cidr='192.168.0.2/24',
            expected_res_status=201, shared=False)['external_segment']
        admin_ctx = context.get_admin_context()
        ext_net_id = self._db_plugin.get_subnet(
                admin_ctx, es['subnet_id'])['network_id']

        l3p = self.create_l3_policy(name='myl3',
            external_segments={es['id']: ['']})['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')

        mapping = self.driver.get_gbp_details(context.get_admin_context(),
            device='tap%s' % pt1['port_id'], host='h1')
        self.assertEqual(pt1['port_id'], mapping['port_id'])
        self.assertEqual(1, len(mapping['host_snat_ips']))
        self.assertEqual(es['name'],
            mapping['host_snat_ips'][0]['external_segment_name'])
        self.assertEqual("192.168.200.1",
            mapping['host_snat_ips'][0]['gateway_ip'])
        self.assertEqual("192.168.200.2",
            mapping['host_snat_ips'][0]['host_snat_ip'])
        self.assertEqual(24, mapping['host_snat_ips'][0]['prefixlen'])
        self.update_l3_policy(l3p['id'], external_segments={},
                expected_res_status=200)
        subnet_filter = {'name': [amap.HOST_SNAT_POOL],
                         'network_id': [ext_net_id]}
        internal_subnets = self._db_plugin.get_subnets(
                admin_ctx, filters=subnet_filter)
        self.assertEqual(1, len(internal_subnets))
        self.delete_external_segment(es['id'],
            expected_res_status=webob.exc.HTTPNoContent.code)
        internal_subnets = self._db_plugin.get_subnets(
                admin_ctx, filters=subnet_filter)
        self.assertEqual(0, len(internal_subnets))

    def test_ip_address_owner_update(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        self._bind_port_to_host(pt2['port_id'], 'h2')

        ip_owner_info = {'port': pt1['port_id'], 'ip_address_v4': '1.2.3.4'}
        self.driver._notify_port_update = mock.Mock()

        # set new owner
        self.driver.ip_address_owner_update(context.get_admin_context(),
            ip_owner_info=ip_owner_info, host='h1')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', l2p['network_id'])
        self.assertEqual(pt1['port_id'], obj['port_id'])
        self.driver._notify_port_update.assert_called_with(mock.ANY,
            pt1['port_id'])

        # update existing owner
        self.driver._notify_port_update.reset_mock()
        ip_owner_info['port'] = pt2['port_id']
        self.driver.ip_address_owner_update(context.get_admin_context(),
            ip_owner_info=ip_owner_info, host='h2')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', l2p['network_id'])
        self.assertEqual(pt2['port_id'], obj['port_id'])
        exp_calls = [
            mock.call(mock.ANY, pt1['port_id']),
            mock.call(mock.ANY, pt2['port_id'])]
        self._check_call_list(exp_calls,
            self.driver._notify_port_update.call_args_list)

    def test_enhanced_subnet_options(self):
        self.driver.enable_metadata_opt = False
        l3p = self.create_l3_policy(name='myl3',
                                    ip_pool='192.168.0.0/16')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        sub = self._get_object('subnets', ptg['subnets'][0],
                               self.api)
        with self.port(subnet=sub, device_owner='network:dhcp',
                       tenant_id='onetenant') as dhcp:
            dhcp = dhcp['port']
            details = self.driver.get_gbp_details(
                context.get_admin_context(),
                device='tap%s' % pt1['port_id'], host='h1')

            self.assertEqual(1, len(details['subnets']))
            # Verify that DNS nameservers are correctly set
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dns_nameservers'])
            # Verify Default route via GW
            self.assertTrue({'destination': '0.0.0.0/0',
                             'nexthop': '192.168.0.1'} in
                            details['subnets'][0]['host_routes'])

            # Verify Metadata route via DHCP
            self.assertTrue(
                {'destination': '169.254.169.254/16',
                 'nexthop': dhcp['fixed_ips'][0]['ip_address']} in
                details['subnets'][0]['host_routes'])

            # Verify no extra routes are leaking inside
            self.assertEqual(2, len(details['subnets'][0]['host_routes']))
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dhcp_server_ips'])

    def test_update_l2p_inject_default_route_false(self):
        self.driver.enable_metadata_opt = False
        l3p = self.create_l3_policy(name='myl3',
                                    ip_pool='192.168.0.0/16')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        sub = self._get_object('subnets', ptg['subnets'][0],
                               self.api)

        # Add one more host_route to the subnet
        more_host_routes = [{'destination': '172.16.0.0/24',
                             'nexthop': '10.0.2.2'}]
        data = {'subnet': {'host_routes': more_host_routes}}
        req = self.new_update_request('subnets', data, sub['subnet']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(sorted(res['subnet']['host_routes']),
                         sorted(more_host_routes))

        with self.port(subnet=sub, device_owner='network:dhcp',
                       tenant_id='onetenant') as dhcp:
            dhcp = dhcp['port']
            details = self.driver.get_gbp_details(
                context.get_admin_context(),
                device='tap%s' % pt1['port_id'], host='h1')

            self.assertEqual(1, len(details['subnets']))
            # Verify that DNS nameservers are correctly set
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dns_nameservers'])
            # Verify Default route via GW
            self.assertTrue({'destination': '0.0.0.0/0',
                             'nexthop': '192.168.0.1'} in
                            details['subnets'][0]['host_routes'])

            # Verify Metadata route via DHCP
            self.assertTrue(
                {'destination': '169.254.169.254/16',
                 'nexthop': dhcp['fixed_ips'][0]['ip_address']} in
                details['subnets'][0]['host_routes'])

            # Verify additional host_routes are also added:
            # GW + Metadata + 1 additional route = 3
            self.assertEqual(3, len(details['subnets'][0]['host_routes']))
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dhcp_server_ips'])

            # Verify gateway_ip is set
            self.assertTrue('gateway_ip' in details['subnets'][0])

        data = {'l2_policy': {'inject_default_route': False}}
        res = self.new_update_request('l2_policies', data, l2p['id'],
                                    self.fmt).get_response(self.ext_api)
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h1')
        with self.port(subnet=sub, tenant_id='onetenant'):
            details = self.driver.get_gbp_details(
                context.get_admin_context(),
                device='tap%s' % pt2['port_id'], host='h1')

            self.assertEqual(1, len(details['subnets']))
            # Verify Default route via GW is not present
            self.assertFalse({'destination': '0.0.0.0/0',
                             'nexthop': '192.168.0.1'} in
                            details['subnets'][0]['host_routes'])

            # Verify Metadata route via DHCP is not present
            self.assertFalse(
                {'destination': '169.254.169.254/16',
                 'nexthop': dhcp['fixed_ips'][0]['ip_address']} in
                details['subnets'][0]['host_routes'])

            # Verify only extra route is present
            self.assertEqual(1, len(details['subnets'][0]['host_routes']))
            self.assertTrue(
                {'destination': '172.16.0.0/24',
                 'nexthop': '10.0.2.2'} in
                details['subnets'][0]['host_routes'])
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dhcp_server_ips'])
            # Verify gateway_ip is not set
            self.assertFalse('gateway_ip' in details['subnets'][0])

    def test_create_l2p_inject_default_route_false(self):
        self.driver.enable_metadata_opt = False
        l3p = self.create_l3_policy(name='myl3',
                                    ip_pool='192.168.0.0/16')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'],
                                    inject_default_route=False)['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        sub = self._get_object('subnets', ptg['subnets'][0],
                               self.api)

        # Add one more host_route to the subnet
        more_host_routes = [{'destination': '172.16.0.0/24',
                             'nexthop': '10.0.2.2'}]
        data = {'subnet': {'host_routes': more_host_routes}}
        req = self.new_update_request('subnets', data, sub['subnet']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(sorted(res['subnet']['host_routes']),
                         sorted(more_host_routes))

        with self.port(subnet=sub, device_owner='network:dhcp',
                       tenant_id='onetenant') as dhcp:
            dhcp = dhcp['port']
            details = self.driver.get_gbp_details(
                context.get_admin_context(),
                device='tap%s' % pt1['port_id'], host='h1')

            self.assertEqual(1, len(details['subnets']))
            # Verify that DNS nameservers are correctly set
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dns_nameservers'])
            # Verify Default route via GW is not present
            self.assertFalse({'destination': '0.0.0.0/0',
                             'nexthop': '192.168.0.1'} in
                            details['subnets'][0]['host_routes'])

            # Verify Metadata route via DHCP is not present
            self.assertFalse(
                {'destination': '169.254.169.254/16',
                 'nexthop': dhcp['fixed_ips'][0]['ip_address']} in
                details['subnets'][0]['host_routes'])

            # Verify only extra route is present
            self.assertEqual(1, len(details['subnets'][0]['host_routes']))
            self.assertTrue(
                {'destination': '172.16.0.0/24',
                 'nexthop': '10.0.2.2'} in
                details['subnets'][0]['host_routes'])
            self.assertEqual([dhcp['fixed_ips'][0]['ip_address']],
                             details['subnets'][0]['dhcp_server_ips'])
            # Verify gateway_ip is not set
            self.assertFalse('gateway_ip' in details['subnets'][0])

    def test_get_gbp_details_error(self):
        details = self.driver.get_gbp_details(
            context.get_admin_context(), device='tap%s' % 'randomid',
            host='h1')
        # device was not found
        self.assertEqual(None, details)
        ptg = self.create_policy_target_group()['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        self.driver._get_owned_addresses = mock.Mock(side_effect=Exception)
        details = self.driver.get_gbp_details(
            context.get_admin_context(), device='tap%s' % pt1['port_id'],
            host='h1')
        # device was not found
        self.assertEqual({'device': 'tap%s' % pt1['port_id']}, details)

    def test_get_gbp_proxy_details(self):
        l3p_fake = self.create_l3_policy(name='myl3')['l3_policy']
        l2p_fake = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p_fake['id'])['l2_policy']
        ptg_fake = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_fake['id'])['policy_target_group']
        # The PT below will be actually bound for a VM
        pt_bound = self.create_policy_target(
            policy_target_group_id=ptg_fake['id'])['policy_target']

        l3p_real = self.create_l3_policy(name='myl3')['l3_policy']
        l2p_real = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p_real['id'])['l2_policy']
        ptg_real = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_real['id'])['policy_target_group']
        # The PT below will never be bound
        pt_unbound = self.create_policy_target(
            policy_target_group_id=ptg_real['id'])['policy_target']

        # Change description to link the ports. The bound on will point
        # to the unbound one to get its info overridden
        self.update_policy_target(
            pt_bound['id'],
            description=amap.PROXY_PORT_PREFIX + pt_unbound['port_id'])

        port_unbound = self._get_object('ports', pt_unbound['port_id'],
                                        self.api)['port']
        # Bind the first port
        self._bind_port_to_host(pt_bound['port_id'], 'h1')
        # Get info on bound port
        mapping = self.driver.get_gbp_details(context.get_admin_context(),
            device='tap%s' % pt_bound['port_id'], host='h1')
        # Bound port info
        self.assertEqual(pt_bound['port_id'], mapping['port_id'])
        self.assertEqual('tap%s' % pt_bound['port_id'], mapping['device'])
        # APIC info are from the unbound port
        self.assertEqual(ptg_real['id'], mapping['endpoint_group_name'])
        self.assertEqual(l3p_real['tenant_id'], mapping['vrf_tenant'])
        self.assertEqual(l3p_real['id'], mapping['vrf_name'])
        self.assertEqual(port_unbound['fixed_ips'], mapping['fixed_ips'])

    def test_get_gbp_details_shadow(self):
        l2p = self.create_l2_policy()['l2_policy']
        network = self._get_object('networks', l2p['network_id'], self.api)
        with self.subnet(network=network) as sub:
            with self.port(subnet=sub) as port:
                self._bind_port_to_host(port['port']['id'], 'h1')
                mapping = self.driver.get_gbp_details(
                    context.get_admin_context(),
                    device='tap%s' % port['port']['id'], host='h1')
                self.assertEqual(port['port']['id'], mapping['port_id'])
                self.assertEqual(amap.SHADOW_PREFIX + l2p['id'],
                                 mapping['endpoint_group_name'])

    def test_explicit_port(self):
        with self.network() as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub) as port:
                    self._bind_port_to_host(port['port']['id'], 'h1')
                    l2p = self.create_l2_policy(
                        network_id=net['network']['id'])['l2_policy']
                    ptg = self.create_policy_target_group(
                        l2_policy_id=l2p['id'])['policy_target_group']
                    self.create_policy_target(
                        port_id=port['port']['id'],
                        policy_target_group_id=ptg['id'])
                    self.assertTrue(self.driver.notifier.port_update.called)

    def test_port_notified_on_changed_ptg(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        ptg2 = self.create_policy_target_group(
            l2_policy_id=ptg['l2_policy_id'])['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt['port_id'], 'h1')

        self.driver.notifier.port_update.reset_mock()
        self.update_policy_target(pt['id'], policy_target_group_id=ptg2['id'])
        self.assertTrue(self.driver.notifier.port_update.called)

    def test_update_ptg_failed(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        ptg2 = self.create_policy_target_group()['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']

        res = self.update_policy_target(
            pt['id'], policy_target_group_id=ptg2['id'],
            expected_res_status=400)
        self.assertEqual('InvalidPortForPTG', res['NeutronError']['type'])

    def test_port_notified_on_subnet_change(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt['port_id'], 'h1')

        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        subnet2 = copy.deepcopy(subnet)
        subnet2['subnet']['gateway_ip'] = '10.0.0.254'

        self.driver.apic_manager.reset_mock()
        self.driver.notifier.port_update.reset_mock()
        self.driver.process_subnet_changed(context.get_admin_context(),
                                           subnet['subnet'], subnet2['subnet'])
        self.assertTrue(self.driver.notifier.port_update.called)

    def test_get_gbp_proxy_address_ownership(self):
        l3p_fake = self.create_l3_policy(name='myl3')['l3_policy']
        l2p_fake = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p_fake['id'])['l2_policy']
        ptg_fake = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_fake['id'])['policy_target_group']
        # The PT below will be actually bound for a VM. They are in the same
        # Network
        pt_bound_1 = self.create_policy_target(
            policy_target_group_id=ptg_fake['id'])['policy_target']
        pt_bound_2 = self.create_policy_target(
            policy_target_group_id=ptg_fake['id'])['policy_target']
        pt_bound_3 = self.create_policy_target(
            policy_target_group_id=ptg_fake['id'])['policy_target']

        l3p_real = self.create_l3_policy(name='myl3')['l3_policy']
        # Build 2 L2Ps in order to get 2 networks.
        l2p_real_1 = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p_real['id'])['l2_policy']
        l2p_real_2 = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p_real['id'])['l2_policy']

        ptg_real_1 = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_real_1['id'])['policy_target_group']
        ptg_real_2 = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_real_2['id'])['policy_target_group']

        # The PTs below will never be bound. They are on different networks
        pt_unbound_1 = self.create_policy_target(
            policy_target_group_id=ptg_real_1['id'])['policy_target']
        pt_unbound_2 = self.create_policy_target(
            policy_target_group_id=ptg_real_2['id'])['policy_target']
        pt_unbound_2_1 = self.create_policy_target(
            policy_target_group_id=ptg_real_2['id'])['policy_target']

        # Change description to link the ports. The bound one will point
        # to the unbound one to get its info overridden
        self.update_policy_target(
            pt_bound_1['id'],
            description=amap.PROXY_PORT_PREFIX + pt_unbound_1['port_id'])
        self.update_policy_target(
            pt_bound_2['id'],
            description=amap.PROXY_PORT_PREFIX + pt_unbound_2['port_id'])
        self.update_policy_target(
            pt_bound_3['id'],
            description=amap.PROXY_PORT_PREFIX + pt_unbound_2_1['port_id'])

        # Set up address ownership on the bound ports, and verify that  both
        # entries exists
        # Update address ownership on second port
        self.driver.update_ip_owner({'port': pt_bound_1['port_id'],
                                     'ip_address_v4': '1.1.1.1'})
        # Same address owned by another port in a different subnet
        self.driver.update_ip_owner({'port': pt_bound_2['port_id'],
                                     'ip_address_v4': '1.1.1.1'})

        # There are 2 ownership entries for the same address
        entries = self.driver.ha_ip_handler.session.query(
                    ha_ip_db.HAIPAddressToPortAssocation).all()
        self.assertEqual(2, len(entries))
        self.assertEqual('1.1.1.1', entries[0].ha_ip_address)
        self.assertEqual('1.1.1.1', entries[1].ha_ip_address)
        self.driver.update_ip_owner({'port': pt_bound_3['port_id'],
                                     'ip_address_v4': '1.1.1.1'})

        entries = self.driver.ha_ip_handler.session.query(
                    ha_ip_db.HAIPAddressToPortAssocation).all()
        self.assertEqual(2, len(entries))
        self.assertEqual('1.1.1.1', entries[0].ha_ip_address)
        self.assertEqual('1.1.1.1', entries[1].ha_ip_address)


class TestPolicyTargetGroup(ApicMappingTestCase):

    def _test_policy_target_group_created_on_apic(self, shared=False):
        ptg = self.create_policy_target_group(
            name="ptg1", shared=shared)['policy_target_group']
        tenant = self.common_tenant if shared else ptg['tenant_id']
        mgr = self.driver.apic_manager
        expected_calls = [
            mock.call(tenant, ptg['id'], bd_name=ptg['l2_policy_id'],
                      bd_owner=tenant),
            mock.call(tenant, amap.SHADOW_PREFIX + ptg['l2_policy_id'],
                      bd_name=ptg['l2_policy_id'], bd_owner=tenant,
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.ensure_epg_created.call_args_list)

    def test_policy_target_group_created_on_apic(self):
        self._test_policy_target_group_created_on_apic()

    def test_policy_target_group_created_on_apic_shared(self):
        self._test_policy_target_group_created_on_apic(shared=True)

    def _test_ptg_policy_rule_set_created(self, provider=True, shared=False):
        cntr = self.create_policy_rule_set(name='c',
                                           shared=shared)['policy_rule_set']
        l2p = self.create_l2_policy()['l2_policy']
        mgr = self.driver.apic_manager
        mgr.set_contract_for_epg.reset_mock()
        if provider:
            ptg = self.create_policy_target_group(
                l2_policy_id=l2p['id'],
                provided_policy_rule_sets={cntr['id']: 'scope'})[
                    'policy_target_group']
        else:
            ptg = self.create_policy_target_group(
                l2_policy_id=l2p['id'],
                consumed_policy_rule_sets={cntr['id']: 'scope'})[
                    'policy_target_group']

        # Verify that the apic call is issued
        ct_owner = self.common_tenant if shared else cntr['tenant_id']
        expected_calls = [
            mock.call(
                ptg['tenant_id'], ptg['id'], cntr['id'],
                transaction=mock.ANY, contract_owner=ct_owner,
                provider=provider),
            mock.call(
                ptg['tenant_id'], ptg['id'],
                amap.SERVICE_PREFIX + ptg['l2_policy_id'],
                transaction=mock.ANY, contract_owner=ptg['tenant_id'],
                provider=False),
            mock.call(
                ptg['tenant_id'], ptg['id'],
                amap.IMPLICIT_PREFIX + ptg['l2_policy_id'],
                transaction=mock.ANY, contract_owner=ptg['tenant_id'],
                provider=True),
            mock.call(
                ptg['tenant_id'], ptg['id'],
                amap.IMPLICIT_PREFIX + ptg['l2_policy_id'],
                transaction=mock.ANY, contract_owner=ptg['tenant_id'],
                provider=False)]
        self._check_call_list(expected_calls,
                              mgr.set_contract_for_epg.call_args_list)

    def _test_ptg_policy_rule_set_updated(self, provider=True, shared=False):
        p_or_c = {True: 'provided_policy_rule_sets',
                  False: 'consumed_policy_rule_sets'}
        cntr = self.create_policy_rule_set(
            name='c1', shared=shared)['policy_rule_set']
        new_cntr = self.create_policy_rule_set(
            name='c2', shared=shared)['policy_rule_set']

        if provider:
            ptg = self.create_policy_target_group(
                provided_policy_rule_sets={cntr['id']: 'scope'})
        else:
            ptg = self.create_policy_target_group(
                consumed_policy_rule_sets={cntr['id']: 'scope'})

        data = {'policy_target_group': {p_or_c[provider]:
                {new_cntr['id']: 'scope'}}}
        req = self.new_update_request('policy_target_groups', data,
                                      ptg['policy_target_group']['id'],
                                      self.fmt)
        ptg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        ptg = ptg['policy_target_group']
        mgr = self.driver.apic_manager
        ct_owner = self.common_tenant if shared else cntr['tenant_id']
        mgr.set_contract_for_epg.assert_called_with(
            ptg['tenant_id'], ptg['id'], new_cntr['id'],
            contract_owner=ct_owner, transaction=mock.ANY,
            provider=provider)
        mgr.unset_contract_for_epg.assert_called_with(
            ptg['tenant_id'], ptg['id'], cntr['id'],
            contract_owner=ct_owner,
            transaction=mock.ANY, provider=provider)

    def test_ptg_policy_rule_set_provider_created(self):
        self._test_ptg_policy_rule_set_created()

    def test_ptg_policy_rule_set_provider_updated(self):
        self._test_ptg_policy_rule_set_updated()

    def test_ptg_policy_rule_set_consumer_created(self):
        self._test_ptg_policy_rule_set_created(False)

    def test_ptg_policy_rule_set_consumer_updated(self):
        self._test_ptg_policy_rule_set_updated(False)

    def test_ptg_policy_rule_set_provider_created_shared(self):
        self._test_ptg_policy_rule_set_created(shared=True)

    def test_ptg_policy_rule_set_provider_updated_shared(self):
        self._test_ptg_policy_rule_set_updated(shared=True)

    def test_ptg_policy_rule_set_consumer_created_shared(self):
        self._test_ptg_policy_rule_set_created(False, shared=True)

    def test_ptg_policy_rule_set_consumer_updated_shared(self):
        self._test_ptg_policy_rule_set_updated(False, shared=True)

    def _test_policy_target_group_deleted_on_apic(self, shared=False):
        ptg = self.create_policy_target_group(
            name="ptg1", shared=shared)['policy_target_group']
        req = self.new_delete_request('policy_target_groups',
                                      ptg['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        tenant = self.common_tenant if shared else ptg['tenant_id']

        expected_calls = [
            mock.call(tenant, ptg['id']),
            mock.call(tenant, amap.SHADOW_PREFIX + ptg['l2_policy_id'],
                      transaction=mock.ANY)]
        self._check_call_list(expected_calls,
                              mgr.delete_epg_for_network.call_args_list)

    def test_policy_target_group_deleted_on_apic(self):
        self._test_policy_target_group_deleted_on_apic()

    def test_policy_target_group_deleted_on_apic_shared(self):
        self._test_policy_target_group_deleted_on_apic(shared=True)

    def _test_policy_target_group_subnet_created_on_apic(self, shared=False):

        ptg = self._create_explicit_subnet_ptg('10.0.0.0/24', shared=shared)

        mgr = self.driver.apic_manager
        tenant = self.common_tenant if shared else ptg['tenant_id']
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            tenant, ptg['l2_policy_id'], '10.0.0.1/24',
            transaction=mock.ANY)

    def test_policy_target_group_subnet_created_on_apic(self):
        self._test_policy_target_group_subnet_created_on_apic()

    def test_policy_target_group_subnet_created_on_apic_shared(self):
        self._test_policy_target_group_subnet_created_on_apic(shared=True)

    def _test_policy_target_group_subnet_added(self, shared=False):
        ptg = self._create_explicit_subnet_ptg('10.0.0.0/24', shared=shared)
        l2p = self._get_object('l2_policies', ptg['l2_policy_id'],
                               self.ext_api)
        network = self._get_object('networks', l2p['l2_policy']['network_id'],
                                   self.api)

        with self.subnet(network=network, cidr='10.0.1.0/24') as subnet:
            data = {'policy_target_group':
                    {'subnets': ptg['subnets'] + [subnet['subnet']['id']]}}
            mgr = self.driver.apic_manager
            self.new_update_request('policy_target_groups', data, ptg['id'],
                                    self.fmt).get_response(self.ext_api)
            tenant = self.common_tenant if shared else ptg['tenant_id']
            mgr.ensure_subnet_created_on_apic.assert_called_with(
                tenant, ptg['l2_policy_id'], '10.0.1.1/24',
                transaction=mock.ANY)

    def test_policy_target_group_subnet_added(self):
        self._test_policy_target_group_subnet_added()

    def test_policy_target_group_subnet_added_shared(self):
        self._test_policy_target_group_subnet_added(shared=True)

    def _test_process_subnet_update(self, shared=False):
        ptg = self._create_explicit_subnet_ptg('10.0.0.0/24', shared=shared)
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)
        subnet2 = copy.deepcopy(subnet)
        subnet2['subnet']['gateway_ip'] = '10.0.0.254'
        mgr = self.driver.apic_manager
        mgr.reset_mock()
        self.driver.process_subnet_changed(context.get_admin_context(),
                                           subnet['subnet'], subnet2['subnet'])

        tenant = self.common_tenant if shared else ptg['tenant_id']
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            tenant, ptg['l2_policy_id'], '10.0.0.254/24',
            transaction=mock.ANY)
        mgr.ensure_subnet_deleted_on_apic.assert_called_with(
            tenant, ptg['l2_policy_id'], '10.0.0.1/24',
            transaction=mock.ANY)

    def test_process_subnet_update(self):
        self._test_process_subnet_update()

    def test_process_subnet_update_shared(self):
        self._test_process_subnet_update(shared=True)

    def test_multiple_ptg_per_l2p(self):
        l2p = self.create_l2_policy()['l2_policy']
        # Create first PTG
        ptg1 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        ptg2 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.assertEqual(ptg1['subnets'], ptg2['subnets'])

    def test_force_add_subnet(self):
        l2p = self.create_l2_policy()['l2_policy']
        # Create first PTG
        ptg1 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        ptg2 = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        ctx = p_context.PolicyTargetGroupContext(
            self.driver.gbp_plugin, context.get_admin_context(), ptg2)
        # Emulate force add
        self.driver._use_implicit_subnet(ctx, force_add=True)
        # There now a new subnet, and it's added to both the PTGs
        self.assertEqual(2, len(ctx.current['subnets']))
        ptg1 = self.show_policy_target_group(ptg1['id'])['policy_target_group']
        self.assertEqual(2, len(ptg1['subnets']))
        ptg2 = self.show_policy_target_group(ptg2['id'])['policy_target_group']
        self.assertEqual(2, len(ptg2['subnets']))
        self.assertEqual(set(ptg1['subnets']), set(ptg2['subnets']))
        self.assertNotEqual(ptg2['subnets'][0], ptg2['subnets'][1])

    def test_subnets_unique_per_l3p(self):
        l3p = self.create_l3_policy(shared=True, tenant_id='admin',
                                    is_admin_context=True)['l3_policy']
        l2p1 = self.create_l2_policy(
            tenant_id='hr', l3_policy_id=l3p['id'])['l2_policy']
        l2p2 = self.create_l2_policy(
            tenant_id='eng', l3_policy_id=l3p['id'])['l2_policy']
        ptg1 = self.create_policy_target_group(
            tenant_id='hr', l2_policy_id=l2p1['id'])['policy_target_group']
        ptg2 = self.create_policy_target_group(
            tenant_id='eng', l2_policy_id=l2p2['id'])['policy_target_group']
        sub_ptg_1 = set(self._get_object('subnets',
                                         x, self.api)['subnet']['cidr']
                        for x in ptg1['subnets'])
        sub_ptg_2 = set(self._get_object('subnets',
                                         x, self.api)['subnet']['cidr']
                        for x in ptg2['subnets'])
        self.assertNotEqual(sub_ptg_1, sub_ptg_2)
        self.assertFalse(sub_ptg_1 & sub_ptg_2)

    def _create_explicit_subnet_ptg(self, cidr, shared=False):
        l2p = self.create_l2_policy(name="l2p", shared=shared)
        l2p_id = l2p['l2_policy']['id']
        network_id = l2p['l2_policy']['network_id']
        network = self._get_object('networks', network_id, self.api)
        with self.subnet(network=network, cidr=cidr):
            # The subnet creation in the proper network causes the subnet ID
            # to be added to the PTG
            return self.create_policy_target_group(
                name="ptg1", l2_policy_id=l2p_id,
                shared=shared)['policy_target_group']


class TestL2Policy(ApicMappingTestCase):

    def _test_l2_policy_created_on_apic(self, shared=False):
        l2p = self.create_l2_policy(name="l2p", shared=shared)['l2_policy']

        tenant = self.common_tenant if shared else l2p['tenant_id']
        mgr = self.driver.apic_manager
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            tenant, l2p['id'], ctx_owner=tenant, ctx_name=l2p['l3_policy_id'],
            transaction=mock.ANY)
        mgr.ensure_epg_created.assert_called_once_with(
            tenant, amap.SHADOW_PREFIX + l2p['id'], bd_owner=tenant,
            bd_name=l2p['id'], transaction=mock.ANY)

    def test_l2_policy_created_on_apic(self):
        self._test_l2_policy_created_on_apic()

    def test_l2_policy_created_on_apic_shared(self):
        self._test_l2_policy_created_on_apic(shared=True)

    def _test_l2_policy_deleted_on_apic(self, shared=False):
        l2p = self.create_l2_policy(name="l2p", shared=shared)['l2_policy']
        req = self.new_delete_request('l2_policies', l2p['id'], self.fmt)
        req.get_response(self.ext_api)
        tenant = self.common_tenant if shared else l2p['tenant_id']
        mgr = self.driver.apic_manager
        mgr.delete_bd_on_apic.assert_called_once_with(
            tenant, l2p['id'], transaction=mock.ANY)
        mgr.delete_epg_for_network.assert_called_once_with(
            tenant, amap.SHADOW_PREFIX + l2p['id'],
            transaction=mock.ANY)
        expected_calls = [
            mock.call(amap.IMPLICIT_PREFIX + l2p['id'], owner=tenant,
                      transaction=mock.ANY),
            mock.call(amap.SERVICE_PREFIX + l2p['id'], owner=tenant,
                      transaction=mock.ANY)]
        self._check_call_list(expected_calls,
                              mgr.delete_contract.call_args_list)

    def test_l2_policy_deleted_on_apic(self):
        self._test_l2_policy_deleted_on_apic()

    def test_l2_policy_deleted_on_apic_shared(self):
        self._test_l2_policy_deleted_on_apic(shared=True)

    def test_pre_existing_subnets_added(self):
        with self.network() as net:
            with self.subnet(network=net) as sub:
                sub = sub['subnet']
                l2p = self.create_l2_policy(
                    network_id=net['network']['id'])['l2_policy']
                mgr = self.driver.apic_manager
                mgr.ensure_subnet_created_on_apic.assert_called_with(
                    l2p['tenant_id'], l2p['id'],
                    sub['gateway_ip'] + '/' + sub['cidr'].split('/')[1],
                    transaction=mock.ANY)
                ptg = self.create_policy_target_group(
                    l2_policy_id=l2p['id'])['policy_target_group']
                self.assertEqual(ptg['subnets'], [sub['id']])


class TestL3Policy(ApicMappingTestCase):

    def _test_l3_policy_created_on_apic(self, shared=False):
        l3p = self.create_l3_policy(name="l3p", shared=shared)['l3_policy']

        tenant = self.common_tenant if shared else l3p['tenant_id']
        mgr = self.driver.apic_manager
        mgr.ensure_context_enforced.assert_called_once_with(
            tenant, l3p['id'])

    def test_l3_policy_created_on_apic(self):
        self._test_l3_policy_created_on_apic()

    def test_l3_policy_created_on_apic_shared(self):
        self._test_l3_policy_created_on_apic(shared=True)

    def _test_l3_policy_deleted_on_apic(self, shared=False):
        l3p = self.create_l3_policy(name="l3p", shared=shared)['l3_policy']
        req = self.new_delete_request('l3_policies', l3p['id'], self.fmt)
        req.get_response(self.ext_api)

        tenant = self.common_tenant if shared else l3p['tenant_id']
        mgr = self.driver.apic_manager
        mgr.ensure_context_deleted.assert_called_once_with(
            tenant, l3p['id'])

    def test_l3_policy_deleted_on_apic(self):
        self._test_l3_policy_deleted_on_apic()

    def test_l3_policy_deleted_on_apic_shared(self):
        self._test_l3_policy_deleted_on_apic(shared=True)

    def _test_multiple_l3_policy_per_es(self, shared_es=False):
        # Verify 2 L3P can be created on same ES if NAT is enabled
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(name='supported',
            cidr='192.168.0.0/24', shared=shared_es)['external_segment']
        l3p = self.create_l3_policy(expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es['id']: ['']},
            expected_res_status=200)['l3_policy']
        res = self.create_l3_policy(
            external_segments={es['id']: ['']},
            expected_res_status=201 if self.nat_enabled else 400)
        if self.nat_enabled:
            es = self.show_external_segment(es['id'])['external_segment']
            self.assertEqual(2, len(es['l3_policies']))
        else:
            self.assertEqual('OnlyOneL3PolicyIsAllowedPerExternalSegment',
                             res['NeutronError']['type'])

        # Verify existing L3P updated to use used ES works if NAT is enabled
        sneaky_l3p = self.create_l3_policy()['l3_policy']
        self.update_l3_policy(
            sneaky_l3p['id'],
            expected_res_status=200 if self.nat_enabled else 400,
            external_segments={es['id']: ['']})
        if self.nat_enabled:
            es = self.show_external_segment(es['id'])['external_segment']
            self.assertEqual(3, len(es['l3_policies']))
        else:
            self.assertEqual('OnlyOneL3PolicyIsAllowedPerExternalSegment',
                             res['NeutronError']['type'])

    def test_multiple_l3_policy_per_es(self):
        self._test_multiple_l3_policy_per_es(shared_es=False)

    def test_multiple_l3_policy_per_es_shared(self):
        self._test_multiple_l3_policy_per_es(shared_es=True)

    def test_one_l3_policy_ip_on_es(self):
        # Verify L3P created with more than 1 IP on ES fails
        es = self.create_external_segment(
            cidr='192.168.0.0/24')['external_segment']
        res = self.create_l3_policy(
            external_segments={es['id']: ['192.168.0.2', '192.168.0.3']},
            expected_res_status=400)
        self.assertEqual('OnlyOneAddressIsAllowedPerExternalSegment',
                         res['NeutronError']['type'])
        # Verify L3P updated to more than 1 IP on ES fails
        sneaky_l3p = self.create_l3_policy(
            external_segments={es['id']: ['192.168.0.2']},
            expected_res_status=201)['l3_policy']
        res = self.update_l3_policy(
            sneaky_l3p['id'], expected_res_status=400,
            external_segments={es['id']: ['192.168.0.2', '192.168.0.3']})
        self.assertEqual('OnlyOneAddressIsAllowedPerExternalSegment',
                         res['NeutronError']['type'])

    def test_router_interface_no_gateway(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24')['external_segment']
        if self.pre_l3out and not self.nat_enabled:
            l3p = self.create_l3_policy(expected_res_status=201)['l3_policy']
            self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es['id']: ['169.254.0.42']},
                expected_res_status=200)['l3_policy']
        else:
            l3p = self.create_l3_policy(
                external_segments={es['id']: ['169.254.0.42']},
                expected_res_status=201)['l3_policy']
        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']

        l3p = self.show_l3_policy(l3p['id'])['l3_policy']
        self.assertEqual(1, len(l3p['routers']))

        subnet = self._show_subnet(ptg['subnets'][0])['subnet']
        router_ports = self._list(
            'ports',
            query_params='device_id=%s' % l3p['routers'][0])['ports']
        self.assertEqual(2, len(router_ports))

        for port in router_ports:
            self.assertEqual(1, len(port['fixed_ips']))
            self.assertNotEqual(subnet['gateway_ip'],
                                port['fixed_ips'][0]['ip_address'])

        # One of the two ports is in subnet
        self.assertNotEqual(router_ports[0]['fixed_ips'][0]['subnet_id'],
                            router_ports[1]['fixed_ips'][0]['subnet_id'])
        self.assertTrue(
            router_ports[0]['fixed_ips'][0]['subnet_id'] == subnet['id'] or
            router_ports[1]['fixed_ips'][0]['subnet_id'] == subnet['id'])

    def _test_l3p_plugged_to_es_at_creation(self, shared_es, shared_l3p):
        # Verify L3P is correctly plugged to ES on APIC during create
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            shared=shared_es,
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']

        exp_err = self.pre_l3out and not self.nat_enabled
        # Create with explicit address
        res = self.create_l3_policy(
            shared=shared_l3p,
            tenant_id=es['tenant_id'] if not shared_es else 'another_tenant',
            external_segments={es['id']: []},
            expected_res_status=400 if exp_err else 201)
        if exp_err:
            self.assertEqual('PreExistingL3OutHasIncorrectVrf',
                             res['NeutronError']['type'])
            return
        else:
            l3p = res['l3_policy']

        self.assertEqual(1, len(l3p['external_segments'][es['id']]))
        self.assertEqual('169.254.0.2', l3p['external_segments'][es['id']][0])

        owner = self.common_tenant if shared_es else es['tenant_id']
        l3p_owner = self.common_tenant if shared_l3p else l3p['tenant_id']
        mgr = self.driver.apic_manager
        if self.nat_enabled:
            expected_l3out_calls = [
                mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                          owner=l3p_owner, context=l3p['id'],
                          transaction=mock.ANY)]
            if not self.pre_l3out:
                expected_l3out_calls.append(
                    mock.call(es['id'], owner=owner,
                              context="NAT-vrf-%s" % es['id'],
                              transaction=mock.ANY))
        elif not self.pre_l3out:
            expected_l3out_calls = [
                mock.call(es['id'], owner=owner, context=l3p['id'],
                          transaction=mock.ANY)]
        self._check_call_list(expected_l3out_calls,
                mgr.ensure_external_routed_network_created.call_args_list)
        expected_route_calls = [
            mock.call(es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.254',
                      owner=owner, subnet='0.0.0.0/0',
                      transaction=mock.ANY),
            mock.call(es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.1',
                      owner=owner, subnet='128.0.0.0/16',
                      transaction=mock.ANY)]
        if not self.pre_l3out:
            mgr.set_domain_for_external_routed_network.assert_called_once_with(
                es['id'], owner=owner, transaction=mock.ANY)
            mgr.ensure_logical_node_profile_created.assert_called_once_with(
                es['id'], mocked.APIC_EXT_SWITCH, mocked.APIC_EXT_MODULE,
                mocked.APIC_EXT_PORT, mocked.APIC_EXT_ENCAP, '192.168.0.2/24',
                owner=owner, router_id=APIC_EXTERNAL_RID,
                transaction=mock.ANY)
            self._check_call_list(expected_route_calls,
                mgr.ensure_static_route_created.call_args_list)
        else:
            self.assertFalse(mgr.set_domain_for_external_routed_network.called)
            self.assertFalse(mgr.ensure_logical_node_profile_created.called)
            self.assertFalse(mgr.ensure_static_route_created.called)

        if self.nat_enabled:
            mgr.set_l3out_for_bd.assert_called_once_with(owner,
                "NAT-bd-%s" % es['id'],
                es['name' if self.pre_l3out else 'id'], transaction=mock.ANY)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_l3p_plugged_to_es_at_creation_1(self):
        self._test_l3p_plugged_to_es_at_creation(shared_es=True,
                                                 shared_l3p=False)

    def test_l3p_plugged_to_es_at_creation_2(self):
        self._test_l3p_plugged_to_es_at_creation(shared_es=True,
                                                 shared_l3p=True)

    def test_l3p_plugged_to_es_at_creation_3(self):
        self._test_l3p_plugged_to_es_at_creation(shared_es=False,
                                                 shared_l3p=False)

    def _test_l3p_plugged_to_es_at_update(self, shared_es, shared_l3p):
        # Verify L3P is correctly plugged to ES on APIC during update
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            shared=shared_es,
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']

        # Create with explicit address
        l3p = self.create_l3_policy(
            expected_res_status=201,
            tenant_id=es['tenant_id'] if not shared_es else 'another_tenant',
            shared=shared_l3p)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(
            l3p['id'], tenant_id=l3p['tenant_id'], expected_res_status=200,
            external_segments={es['id']: []})['l3_policy']
        self.assertEqual(1, len(l3p['external_segments'][es['id']]))
        self.assertEqual('169.254.0.2', l3p['external_segments'][es['id']][0])

        mgr = self.driver.apic_manager
        owner = self.common_tenant if shared_es else es['tenant_id']
        l3p_owner = self.common_tenant if shared_l3p else l3p['tenant_id']
        expected_l3out_calls = []
        if self.nat_enabled:
            expected_l3out_calls = [
                mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                          owner=l3p_owner, context=l3p['id'],
                          transaction=mock.ANY)]
            if not self.pre_l3out:
                expected_l3out_calls.append(
                    mock.call(es['id'], owner=owner,
                              context="NAT-vrf-%s" % es['id'],
                              transaction=mock.ANY))

        elif not self.pre_l3out:
            expected_l3out_calls = [
                mock.call(es['id'], owner=owner, context=l3p['id'],
                          transaction=mock.ANY)]
        self._check_call_list(expected_l3out_calls,
            mgr.ensure_external_routed_network_created.call_args_list)

        if not self.pre_l3out:
            mgr.set_domain_for_external_routed_network.assert_called_once_with(
                es['id'], owner=owner, transaction=mock.ANY)
            mgr.ensure_logical_node_profile_created.assert_called_once_with(
                es['id'], mocked.APIC_EXT_SWITCH, mocked.APIC_EXT_MODULE,
                mocked.APIC_EXT_PORT, mocked.APIC_EXT_ENCAP, '192.168.0.2/24',
                owner=owner, router_id=APIC_EXTERNAL_RID,
                transaction=mock.ANY)

            expected_route_calls = [
                mock.call(es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.254',
                          owner=owner, subnet='0.0.0.0/0',
                          transaction=mock.ANY),
                mock.call(es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.1',
                          owner=owner, subnet='128.0.0.0/16',
                          transaction=mock.ANY)]
            self._check_call_list(expected_route_calls,
                mgr.ensure_static_route_created.call_args_list)
        if self.nat_enabled:
            mgr.set_l3out_for_bd.assert_called_once_with(owner,
                "NAT-bd-%s" % es['id'],
                es['name' if self.pre_l3out else 'id'], transaction=mock.ANY)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_l3p_plugged_to_es_at_update_1(self):
        self._test_l3p_plugged_to_es_at_update(shared_es=True,
                                               shared_l3p=False)

    def test_l3p_plugged_to_es_at_update_2(self):
        self._test_l3p_plugged_to_es_at_update(shared_es=True,
                                               shared_l3p=True)

    def test_l3p_plugged_to_es_at_update_3(self):
        self._test_l3p_plugged_to_es_at_update(shared_es=False,
                                               shared_l3p=False)

    def _test_l3p_unplugged_from_es_on_delete(self, shared_es, shared_l3p):
        self._mock_external_dict([('supported1', '192.168.0.2/24'),
                                 ('supported2', '192.168.1.2/24')])
        es1 = self.create_external_segment(
            name='supported1', cidr='192.168.0.0/24', shared=shared_es,
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']
        es2 = self.create_external_segment(
            shared=shared_es, name='supported2',
            cidr='192.168.1.0/24')['external_segment']

        l3p = self.create_l3_policy(shared=shared_l3p,
            tenant_id=es1['tenant_id'] if not shared_es else 'another_tenant',
            expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es1['id']: ['169.254.0.3']},
            tenant_id=l3p['tenant_id'],
            expected_res_status=200)['l3_policy']
        req = self.new_delete_request('l3_policies', l3p['id'], self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

        mgr = self.driver.apic_manager
        owner = self.common_tenant if shared_es else es1['tenant_id']
        l3p_owner = self.common_tenant if shared_l3p else l3p['tenant_id']
        expected_delete_calls = []
        if not self.pre_l3out:
            expected_delete_calls.append(
                mock.call(es1['id'], owner=owner, transaction=mock.ANY))
        if self.nat_enabled:
            expected_delete_calls.append(
                mock.call("Shd-%s-%s" % (l3p['id'], es1['id']),
                    owner=l3p_owner, transaction=mock.ANY))
        self._check_call_list(
            expected_delete_calls,
            mgr.delete_external_routed_network.call_args_list)
        if self.nat_enabled:
            mgr.unset_l3out_for_bd.assert_called_once_with(owner,
                "NAT-bd-%s" % es1['id'],
                es1['name' if self.pre_l3out else 'id'], transaction=mock.ANY)

        mgr.delete_external_routed_network.reset_mock()
        mgr.unset_l3out_for_bd.reset_mock()

        # Verify correct deletion for 2 ESs
        l3p = self.create_l3_policy(
            shared=shared_l3p,
            tenant_id=es1['tenant_id'] if not shared_es else 'another_tenant',
            expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es1['id']: ['169.254.0.3'],
                               es2['id']: ['169.254.0.3']},
            tenant_id=l3p['tenant_id'],
            expected_res_status=200)['l3_policy']
        req = self.new_delete_request('l3_policies', l3p['id'], self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

        expected_delete_calls = []
        if not self.pre_l3out:
            expected_delete_calls.extend([
                mock.call(es1['id'], owner=owner, transaction=mock.ANY),
                mock.call(es2['id'], owner=owner, transaction=mock.ANY)])
        if self.nat_enabled:
            expected_delete_calls.extend([
                mock.call("Shd-%s-%s" % (l3p['id'], es1['id']),
                     owner=l3p_owner, transaction=mock.ANY),
                mock.call("Shd-%s-%s" % (l3p['id'], es2['id']),
                     owner=l3p_owner, transaction=mock.ANY)])
        self._check_call_list(
            expected_delete_calls,
            mgr.delete_external_routed_network.call_args_list)
        if self.nat_enabled:
            expected_unset_calls = [
                mock.call(owner, "NAT-bd-%s" % es1['id'],
                    es1['name' if self.pre_l3out else 'id'],
                    transaction=mock.ANY),
                mock.call(owner, "NAT-bd-%s" % es2['id'],
                    es2['name' if self.pre_l3out else 'id'],
                    transaction=mock.ANY)]
            self._check_call_list(
                expected_unset_calls, mgr.unset_l3out_for_bd.call_args_list)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_l3p_unplugged_from_es_on_delete_1(self):
        self._test_l3p_unplugged_from_es_on_delete(shared_es=True,
                                                   shared_l3p=False)

    def test_l3p_unplugged_from_es_on_delete_2(self):
        self._test_l3p_unplugged_from_es_on_delete(shared_es=True,
                                                   shared_l3p=True)

    def test_l3p_unplugged_from_es_on_delete_3(self):
        self._test_l3p_unplugged_from_es_on_delete(shared_es=False,
                                                   shared_l3p=False)

    def _test_l3p_unplugged_from_es_on_update(self, shared_es, shared_l3p):
        self._mock_external_dict([('supported1', '192.168.0.2/24'),
                                 ('supported2', '192.168.1.2/24')])
        es1 = self.create_external_segment(
            name='supported1', cidr='192.168.0.0/24', shared=shared_es,
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']
        es2 = self.create_external_segment(
            shared=shared_es,
            name='supported2', cidr='192.168.1.0/24')['external_segment']
        l3p = self.create_l3_policy(
            tenant_id=es1['tenant_id'] if not shared_es else 'another_tenant',
            shared=shared_l3p,
            expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es1['id']: ['169.254.0.3']},
            tenant_id=l3p['tenant_id'],
            expected_res_status=200)['l3_policy']

        mgr = self.driver.apic_manager
        owner = self.common_tenant if shared_es else es1['tenant_id']
        l3p_owner = self.common_tenant if shared_l3p else l3p['tenant_id']
        mgr.ensure_external_routed_network_created.reset_mock()
        mgr.set_domain_for_external_routed_network.reset_mock()
        mgr.ensure_logical_node_profile_created.reset_mock()
        mgr.ensure_static_route_created.reset_mock()

        l3p = self.update_l3_policy(
            l3p['id'], tenant_id=l3p['tenant_id'], expected_res_status=200,
            external_segments={es2['id']: ['169.254.0.4']})['l3_policy']

        expected_delete_calls = []
        if not self.pre_l3out:
            expected_delete_calls.append(
                mock.call(es1['id'], owner=owner, transaction=mock.ANY))
        if self.nat_enabled:
            expected_delete_calls.append(
                mock.call("Shd-%s-%s" % (l3p['id'], es1['id']),
                    owner=l3p_owner, transaction=mock.ANY))
        self._check_call_list(
            expected_delete_calls,
            mgr.delete_external_routed_network.call_args_list)
        expected_l3out_calls = []
        if self.nat_enabled:
            expected_l3out_calls = [
                mock.call("Shd-%s-%s" % (l3p['id'], es2['id']),
                          owner=l3p_owner, context=l3p['id'],
                          transaction=mock.ANY)]
            if not self.pre_l3out:
                expected_l3out_calls.append(
                    mock.call(es2['id'], owner=owner,
                              context="NAT-vrf-%s" % es2['id'],
                              transaction=mock.ANY))
        elif not self.pre_l3out:
            expected_l3out_calls = [
                mock.call(es2['id'], owner=owner, context=l3p['id'],
                          transaction=mock.ANY)]
        self._check_call_list(expected_l3out_calls,
            mgr.ensure_external_routed_network_created.call_args_list)
        if not self.pre_l3out:
            mgr.set_domain_for_external_routed_network.assert_called_once_with(
                es2['id'], owner=owner, transaction=mock.ANY)
            mgr.ensure_logical_node_profile_created.assert_called_once_with(
                es2['id'], mocked.APIC_EXT_SWITCH, mocked.APIC_EXT_MODULE,
                mocked.APIC_EXT_PORT, mocked.APIC_EXT_ENCAP, '192.168.1.2/24',
                owner=owner, router_id=APIC_EXTERNAL_RID,
                transaction=mock.ANY)
        else:
            self.assertFalse(mgr.set_domain_for_external_routed_network.called)
            self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        if self.nat_enabled:
            mgr.unset_l3out_for_bd.assert_called_once_with(owner,
                "NAT-bd-%s" % es1['id'],
                es1['name' if self.pre_l3out else 'id'], transaction=mock.ANY)

        mgr.delete_external_routed_network.reset_mock()
        mgr.unset_l3out_for_bd.reset_mock()
        self.update_l3_policy(
            l3p['id'], expected_res_status=200, tenant_id=l3p['tenant_id'],
            external_segments={es1['id']: ['169.254.0.5'],
                               es2['id']: ['169.254.0.6']})
        self.update_l3_policy(
            l3p['id'], tenant_id=l3p['tenant_id'],
            expected_res_status=200, external_segments={})
        expected_delete_calls = []
        if not self.pre_l3out:
            expected_delete_calls.extend([
                mock.call(es1['id'], owner=owner, transaction=mock.ANY),
                mock.call(es2['id'], owner=owner, transaction=mock.ANY)])
        if self.nat_enabled:
            expected_delete_calls.extend([
                mock.call("Shd-%s-%s" % (l3p['id'], es1['id']),
                     owner=l3p_owner, transaction=mock.ANY),
                mock.call("Shd-%s-%s" % (l3p['id'], es2['id']),
                     owner=l3p_owner, transaction=mock.ANY)])
        self._check_call_list(
            expected_delete_calls,
            mgr.delete_external_routed_network.call_args_list)
        if self.nat_enabled:
            expected_unset_calls = [
                mock.call(owner, "NAT-bd-%s" % es1['id'],
                    es1['name' if self.pre_l3out else 'id'],
                    transaction=mock.ANY),
                mock.call(owner, "NAT-bd-%s" % es2['id'],
                    es2['name' if self.pre_l3out else 'id'],
                    transaction=mock.ANY)]
            self._check_call_list(
                expected_unset_calls, mgr.unset_l3out_for_bd.call_args_list)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_l3p_unplugged_from_es_on_update_1(self):
        self._test_l3p_unplugged_from_es_on_update(shared_es=True,
                                                   shared_l3p=False)

    def test_l3p_unplugged_from_es_on_update_2(self):
        self._test_l3p_unplugged_from_es_on_update(shared_es=True,
                                                   shared_l3p=True)

    def test_l3p_unplugged_from_es_on_update_3(self):
        self._test_l3p_unplugged_from_es_on_update(shared_es=False,
                                                   shared_l3p=False)

    def test_verify_unsupported_es_noop(self):
        # Verify L3P is correctly plugged to ES on APIC during update
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='unsupported', cidr='192.168.0.0/24')['external_segment']
        self.create_l3_policy(
            external_segments={es['id']: ['192.168.0.3']},
            expected_res_status=201)

        mgr = self.driver.apic_manager
        self.assertFalse(mgr.ensure_external_routed_network_created.called)
        self.assertFalse(mgr.set_domain_for_external_routed_network.called)
        self.assertFalse(mgr.ensure_logical_node_profile_created.called)
        self.assertFalse(mgr.ensure_static_route_created.called)

    def test_l3p_external_address(self):
        # Verify auto allocated IP address is assigned to L3P when no
        # explicit address is configured
        self._mock_external_dict([('supported1', '192.168.0.2/24'),
                                  ('supported2', '192.168.1.2/24')])
        es1 = self.create_external_segment(
            name='supported1', cidr='192.168.0.0/24')['external_segment']
        es2 = self.create_external_segment(
            name='supported2', cidr='192.168.1.0/24')['external_segment']
        l3p = self.create_l3_policy(expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es1['id']: []},
            expected_res_status=200)['l3_policy']

        self.assertEqual(['169.254.0.2'], l3p['external_segments'][es1['id']])

        l3p = self.update_l3_policy(
            l3p['id'], expected_res_status=200,
            external_segments={es1['id']: [], es2['id']: []})['l3_policy']
        self.assertEqual(['169.254.0.2'], l3p['external_segments'][es1['id']])
        self.assertEqual(['169.254.0.2'], l3p['external_segments'][es2['id']])

        # Address IP changed
        l3p = self.update_l3_policy(
            l3p['id'], expected_res_status=200,
            external_segments={es1['id']: ['169.254.0.3'],
                               es2['id']: []})['l3_policy']
        self.assertEqual(['169.254.0.3'], l3p['external_segments'][es1['id']])
        self.assertEqual(['169.254.0.2'], l3p['external_segments'][es2['id']])

    def _test_multi_es_with_ptg(self, shared_es):
        self._mock_external_dict([('supported1', '192.168.0.2/24'),
                                 ('supported2', '192.168.1.2/24')])
        es1 = self.create_external_segment(shared=shared_es,
            name='supported1', cidr='192.168.0.0/24')['external_segment']
        es2 = self.create_external_segment(shared=shared_es,
            name='supported2', cidr='192.168.1.0/24')['external_segment']
        l3p = self.create_l3_policy(expected_res_status=201)['l3_policy']
        if self.pre_l3out and not self.nat_enabled:
            self._update_pre_l3out_info(l3p)
        l3p = self.update_l3_policy(l3p['id'],
            external_segments={es1['id']: [], es2['id']: []},
            expected_res_status=200)['l3_policy']
        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(name="ptg",
            l2_policy_id=l2p['id'],
            expected_res_status=201)['policy_target_group']

        res = self.new_delete_request('policy_target_groups', ptg['id'],
                                      self.fmt).get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_multi_es_with_ptg_1(self):
        self._test_multi_es_with_ptg(False)

    def test_multi_es_with_ptg_2(self):
        self._test_multi_es_with_ptg(True)


class TestL3PolicyNoNat(TestL3Policy):
    def setUp(self):
        super(TestL3PolicyNoNat, self).setUp(nat_enabled=False)


class TestL3PolicyPreL3Out(TestL3Policy):
    def setUp(self):
        super(TestL3PolicyPreL3Out, self).setUp(pre_existing_l3out=True)


class TestL3PolicyNoNatPreL3Out(TestL3Policy):
    def setUp(self):
        super(TestL3PolicyNoNatPreL3Out, self).setUp(
            nat_enabled=False, pre_existing_l3out=True)


class TestPolicyRuleSet(ApicMappingTestCase):

    # TODO(ivar): verify rule intersection with hierarchical PRS happens
    # on APIC
    def _test_policy_rule_set_created_on_apic(self, shared=False):
        ct = self.create_policy_rule_set(name="ctr",
                                         shared=shared)['policy_rule_set']

        tenant = self.common_tenant if shared else ct['tenant_id']
        mgr = self.driver.apic_manager
        mgr.create_contract.assert_called_once_with(
            ct['id'], owner=tenant, transaction=mock.ANY)

    def test_policy_rule_set_created_on_apic(self):
        self._test_policy_rule_set_created_on_apic()

    def test_policy_rule_set_created_on_apic_shared(self):
        self._test_policy_rule_set_created_on_apic(shared=True)

    def _test_policy_rule_set_created_with_rules(self, shared=False):
        bi, in_d, out = range(3)
        rules = self._create_3_direction_rules(shared=shared)
        # exclude BI rule for now
        ctr = self.create_policy_rule_set(
            name="ctr", policy_rules=[x['id'] for x in rules[1:]])[
                'policy_rule_set']

        rule_owner = self.common_tenant if shared else rules[0]['tenant_id']
        # Verify that the in-out rules are correctly enforced on the APIC
        mgr = self.driver.apic_manager
        expected_calls = [
            mock.call(ctr['id'], ctr['id'], rules[in_d]['id'],
                      owner=ctr['tenant_id'], transaction=mock.ANY,
                      unset=False, rule_owner=rule_owner),
            mock.call(ctr['id'], ctr['id'],
                      amap.REVERSE_PREFIX + rules[out]['id'],
                      owner=ctr['tenant_id'], transaction=mock.ANY,
                      unset=False, rule_owner=rule_owner)]
        self._check_call_list(
            expected_calls,
            mgr.manage_contract_subject_in_filter.call_args_list)

        expected_calls = [
            mock.call(ctr['id'], ctr['id'], rules[out]['id'],
                      owner=ctr['tenant_id'], transaction=mock.ANY,
                      unset=False, rule_owner=rule_owner),
            mock.call(ctr['id'], ctr['id'],
                      amap.REVERSE_PREFIX + rules[in_d]['id'],
                      owner=ctr['tenant_id'], transaction=mock.ANY,
                      unset=False, rule_owner=rule_owner)]
        self._check_call_list(
            expected_calls,
            mgr.manage_contract_subject_out_filter.call_args_list)

        # Create policy_rule_set with BI rule
        ctr = self.create_policy_rule_set(
            name="ctr", policy_rules=[rules[bi]['id']])['policy_rule_set']

        mgr.manage_contract_subject_in_filter.call_happened_with(
            ctr['id'], ctr['id'], rules[bi]['id'], owner=ctr['tenant_id'],
            transaction=mock.ANY, unset=False,
            rule_owner=rule_owner)
        mgr.manage_contract_subject_out_filter.call_happened_with(
            ctr['id'], ctr['id'], rules[bi]['id'], owner=ctr['tenant_id'],
            transaction=mock.ANY, unset=False,
            rule_owner=rule_owner)
        mgr.manage_contract_subject_in_filter.call_happened_with(
            ctr['id'], ctr['id'], amap.REVERSE_PREFIX + rules[bi]['id'],
            owner=ctr['tenant_id'], transaction=mock.ANY, unset=False,
            rule_owner=rule_owner)
        mgr.manage_contract_subject_out_filter.call_happened_with(
            ctr['id'], ctr['id'], amap.REVERSE_PREFIX + rules[bi]['id'],
            owner=ctr['tenant_id'], transaction=mock.ANY, unset=False,
            rule_owner=rule_owner)

    def test_policy_rule_set_created_with_rules(self):
        self._test_policy_rule_set_created_with_rules()

    def test_policy_rule_set_created_with_rules_shared(self):
        self._test_policy_rule_set_created_with_rules(shared=True)

    def _test_policy_rule_set_updated_with_new_rules(self, shared=False):
        bi, in_d, out = range(3)
        old_rules = self._create_3_direction_rules(shared=shared)
        new_rules = self._create_3_direction_rules(shared=shared)
        # exclude BI rule for now
        ctr = self.create_policy_rule_set(
            name="ctr",
            policy_rules=[x['id'] for x in old_rules[1:]])['policy_rule_set']
        data = {'policy_rule_set': {
            'policy_rules': [x['id'] for x in new_rules[1:]]}}
        rule_owner = (self.common_tenant if shared else
                      old_rules[in_d]['tenant_id'])
        mgr = self.driver.apic_manager
        mgr.manage_contract_subject_in_filter = MockCallRecorder()
        mgr.manage_contract_subject_out_filter = MockCallRecorder()
        self.new_update_request(
            'policy_rule_sets', data, ctr['id'], self.fmt).get_response(
                self.ext_api)
        # Verify old IN rule unset and new IN rule set
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[in_d]['id'],
                rule_owner=rule_owner,
                owner=ctr['tenant_id'], transaction='transaction', unset=True))
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[in_d]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False, rule_owner=rule_owner))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[out]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True,
                rule_owner=rule_owner))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[out]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False, rule_owner=rule_owner))

        ctr = self.create_policy_rule_set(
            name="ctr",
            policy_rules=[old_rules[0]['id']])['policy_rule_set']
        data = {'policy_rule_set': {'policy_rules': [new_rules[0]['id']]}}
        self.new_update_request(
            'policy_rule_sets', data, ctr['id'], self.fmt).get_response(
                self.ext_api)
        # Verify old BI rule unset and new Bu rule set
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True,
                rule_owner=rule_owner))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], old_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction', unset=True,
                rule_owner=rule_owner))
        self.assertTrue(
            mgr.manage_contract_subject_in_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False, rule_owner=rule_owner))
        self.assertTrue(
            mgr.manage_contract_subject_out_filter.call_happened_with(
                ctr['id'], ctr['id'], new_rules[bi]['id'],
                owner=ctr['tenant_id'], transaction='transaction',
                unset=False, rule_owner=rule_owner))

    def test_policy_rule_set_updated_with_new_rules(self):
        self._test_policy_rule_set_updated_with_new_rules()

    def test_policy_rule_set_updated_with_new_rules_shared(self):
        self._test_policy_rule_set_updated_with_new_rules(shared=True)

    def _create_3_direction_rules(self, shared=False):
        a1 = self.create_policy_action(name='a1',
                                       action_type='allow',
                                       shared=shared)['policy_action']
        cl_attr = {'protocol': 'tcp', 'port_range': 80}
        cls = []
        for direction in ['bi', 'in', 'out']:
            if direction == 'out':
                cl_attr['protocol'] = 'udp'
            cls.append(self.create_policy_classifier(
                direction=direction, shared=shared,
                **cl_attr)['policy_classifier'])
        rules = []
        for classifier in cls:
            rules.append(self.create_policy_rule(
                policy_classifier_id=classifier['id'],
                policy_actions=[a1['id']],
                shared=shared)['policy_rule'])
        return rules


class TestPolicyRule(ApicMappingTestCase):

    def _test_policy_rule_created_on_apic(self, shared=False):
        pr = self._create_simple_policy_rule('in', 'tcp', 88, shared=shared)
        pr1 = self._create_simple_policy_rule('in', 'udp', 53, shared=shared)
        pr2 = self._create_simple_policy_rule('in', None, 88, shared=shared)

        tenant = self.common_tenant if shared else pr['tenant_id']
        mgr = self.driver.apic_manager
        expected_calls = [
            mock.call(pr['id'], owner=tenant, entry='os-entry-0', etherT='ip',
                      prot='tcp', dToPort=88, dFromPort=88,
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      entry='os-entry-0', etherT='ip', prot='tcp', sToPort=88,
                      sFromPort=88, tcpRules='est', transaction=mock.ANY),
            mock.call(pr1['id'], owner=tenant, entry='os-entry-0',
                      etherT='ip', prot='udp', dToPort=53, dFromPort=53,
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner=tenant,
                      entry='os-entry-0', etherT='ip', prot='udp', sToPort=53,
                      sFromPort=53, transaction=mock.ANY),
            mock.call(pr2['id'], owner=tenant, entry='os-entry-0',
                      etherT='unspecified', dToPort=88, dFromPort=88,
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)
        mgr.reset_mock()
        pr = self._create_simple_policy_rule('bi', None, None, shared=shared)
        expected_calls = [
            mock.call(pr['id'], owner=tenant, entry='os-entry-0',
                      etherT='unspecified', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)

    def test_policy_rule_created_on_apic(self):
        self._test_policy_rule_created_on_apic()

    def test_policy_rule_created_on_apic_shared(self):
        self._test_policy_rule_created_on_apic(shared=True)

    def _test_policy_rule_deleted_on_apic(self, shared=False):
        pr = self._create_simple_policy_rule(shared=shared)
        pr1 = self._create_simple_policy_rule('in', 'udp', 53, shared=shared)
        self.delete_policy_rule(pr['id'], expected_res_status=204)

        tenant = self.common_tenant if shared else pr['tenant_id']
        mgr = self.driver.apic_manager
        expected_calls = [
            mock.call(pr['id'], owner=tenant, transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.delete_tenant_filter.call_args_list)

        mgr.delete_tenant_filter.reset_mock()
        self.delete_policy_rule(pr1['id'], expected_res_status=204)
        expected_calls = [
            mock.call(pr1['id'], owner=tenant, transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner=tenant,
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.delete_tenant_filter.call_args_list)

    def test_policy_rule_deleted_on_apic(self):
        self._test_policy_rule_deleted_on_apic()

    def test_policy_rule_deleted_on_apic_shared(self):
        self._test_policy_rule_deleted_on_apic(shared=True)

    def test_policy_classifier_updated(self):
        pa = self.create_policy_action(
            action_type='allow', is_admin_context=True,
            tenant_id='admin', shared=True)['policy_action']
        pc = self.create_policy_classifier(
            direction='in', protocol='udp', port_range=80,
            shared=True, is_admin_context=True,
            tenant_id='admin')['policy_classifier']
        pr1 = self.create_policy_rule(
            policy_classifier_id=pc['id'], policy_actions=[pa['id']],
            shared=True, is_admin_context=True,
            tenant_id='admin')['policy_rule']
        pr2 = self.create_policy_rule(policy_classifier_id=pc['id'],
                                      policy_actions=[pa['id']])['policy_rule']
        prs1 = self.create_policy_rule_set(
            policy_rules=[pr1['id']])['policy_rule_set']
        prs2 = self.create_policy_rule_set(
            policy_rules=[pr2['id'], pr1['id']])['policy_rule_set']

        mgr = self.driver.apic_manager
        mgr.reset_mock()

        # Remove Classifier port, should just delete and create the filter
        self.update_policy_classifier(pc['id'], port_range=None,
                                      is_admin_context=True)
        expected_calls = [
            mock.call(pr1['id'], owner='common', etherT='ip', prot='udp',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', etherT='ip', prot='udp',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner='common',
                      etherT='ip', prot='udp', entry='os-entry-0',
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr2['id'], owner='test-tenant',
                      etherT='ip', prot='udp', entry='os-entry-0',
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)
        expected_calls = [
            mock.call(pr1['id'], owner='common', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner='common',
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr2['id'], owner='test-tenant',
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.delete_tenant_filter.call_args_list)
        self.assertFalse(mgr.manage_contract_subject_in_filter.called)
        self.assertFalse(mgr.manage_contract_subject_out_filter.called)
        mgr.reset_mock()

        # Change Classifier protocol, to not revertible
        self.update_policy_classifier(pc['id'], protocol=None,
                                      is_admin_context=True)
        expected_calls = [
            mock.call(pr1['id'], owner='common', etherT='unspecified',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', etherT='unspecified',
                      entry='os-entry-0', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)
        expected_calls = [
            mock.call(pr1['id'], owner='common', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner='common',
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr2['id'], owner='test-tenant',
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.delete_tenant_filter.call_args_list)

        # Protocol went from revertible to non-revertible
        self.assertTrue(mgr.manage_contract_subject_in_filter.called)
        self.assertTrue(mgr.manage_contract_subject_out_filter.called)
        mgr.reset_mock()

        # Change Classifier protocol to revertible
        self.update_policy_classifier(pc['id'], protocol='tcp',
                                      is_admin_context=True)
        expected_calls = [
            mock.call(pr1['id'], owner='common', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner='common',
                      transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr2['id'], owner='test-tenant',
                      transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.delete_tenant_filter.call_args_list)
        expected_calls = [
            mock.call(pr1['id'], owner='common', etherT='ip', prot='tcp',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(pr2['id'], owner='test-tenant', etherT='ip', prot='tcp',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr1['id'], owner='common',
                      etherT='ip', prot='tcp', tcpRules='est',
                      entry='os-entry-0', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr2['id'], owner='test-tenant',
                      etherT='ip', prot='tcp', tcpRules='est',
                      entry='os-entry-0', transaction=mock.ANY)]
        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)

        expected_calls = [
            # Unset PR1 and PR2 IN
            mock.call(prs1['id'], prs1['id'], pr1['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=True, rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], pr1['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=True, rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], pr2['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=True,
                      rule_owner='test-tenant'),
            # SET PR1 and PR2 IN
            mock.call(prs1['id'], prs1['id'], pr1['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=False, rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], pr1['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=False, rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], pr2['id'], owner='test-tenant',
                      transaction=mock.ANY, unset=False,
                      rule_owner='test-tenant')
        ]
        self._check_call_list(
            expected_calls,
            mgr.manage_contract_subject_in_filter.call_args_list)
        # SET Reverse PR1 and PR2 OUT
        expected_calls = [
            mock.call(prs1['id'], prs1['id'], amap.REVERSE_PREFIX + pr1['id'],
                      owner='test-tenant', transaction=mock.ANY, unset=False,
                      rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], amap.REVERSE_PREFIX + pr1['id'],
                      owner='test-tenant', transaction=mock.ANY, unset=False,
                      rule_owner='common'),
            mock.call(prs2['id'], prs2['id'], amap.REVERSE_PREFIX + pr2['id'],
                      owner='test-tenant', transaction=mock.ANY, unset=False,
                      rule_owner='test-tenant')
        ]
        self._check_call_list(
            expected_calls,
            mgr.manage_contract_subject_out_filter.call_args_list)

    def test_icmp_rule_created_on_apic(self):
        pr = self._create_simple_policy_rule('in', 'icmp', None)
        tenant = pr['tenant_id']

        mgr = self.driver.apic_manager
        expected_calls = [
            mock.call(pr['id'], owner=tenant, entry='os-entry-0', etherT='ip',
                      prot='icmp', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      entry=mock.ANY, etherT='ip', icmpv4T='echo-rep',
                      prot='icmp', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      entry=mock.ANY, etherT='ip', icmpv4T='dst-unreach',
                      prot='icmp', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      entry=mock.ANY, etherT='ip', icmpv4T='src-quench',
                      prot='icmp', transaction=mock.ANY),
            mock.call(amap.REVERSE_PREFIX + pr['id'], owner=tenant,
                      entry=mock.ANY, etherT='ip', icmpv4T='time-exceeded',
                      prot='icmp', transaction=mock.ANY)]
        # verify that entry is always different
        found = set()
        for call in mgr.create_tenant_filter.call_args_list:
            # Only for reverse filters
            if call[0][0].startswith(amap.REVERSE_PREFIX):
                self.assertFalse(call[1]['entry'] in found)
                found.add(call[1]['entry'])

        self._check_call_list(
            expected_calls, mgr.create_tenant_filter.call_args_list)


class TestExternalSegment(ApicMappingTestCase):

    def test_pat_rejected(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        # Verify Rejected on create
        res = self.create_external_segment(
            name='supported', port_address_translation=True,
            expected_res_status=400)
        self.assertEqual('PATNotSupportedByApicDriver',
                         res['NeutronError']['type'])

        # Verify Rejected on Update
        es = self.create_external_segment(
            name='supported', expected_res_status=201,
            port_address_translation=False)['external_segment']
        res = self.update_external_segment(
            es['id'], expected_res_status=400, port_address_translation=True)
        self.assertEqual('PATNotSupportedByApicDriver',
                         res['NeutronError']['type'])

    def _test_create_delete(self, shared=False):
        mgr = self.driver.apic_manager
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        mgr.ext_net_dict['supported']['host_pool_cidr'] = '192.168.200.1/24'
        es = self.create_external_segment(name='supported',
            cidr='192.168.0.2/24',
            expected_res_status=201, shared=shared)['external_segment']
        self.create_external_segment(name='unsupport', expected_res_status=201,
                                     shared=shared)
        self.assertEqual('192.168.0.2/24', es['cidr'])
        self.assertIsNotNone(es['subnet_id'])
        subnet = self._get_object('subnets', es['subnet_id'],
            self.api)['subnet']
        self.assertEqual('169.254.0.0/25', subnet['cidr'])
        owner = es['tenant_id'] if not shared else self.common_tenant
        prs = "NAT-allow-%s" % es['id']
        if self.nat_enabled:
            ctx = "NAT-vrf-%s" % es['id']
            ctx_owner = owner
            contract_owner = owner
            if self.pre_l3out:
                ctx = APIC_PRE_VRF
                ctx_owner = APIC_PRE_VRF_TENANT
                contract_owner = APIC_PRE_L3OUT_TENANT
                self.assertFalse(mgr.ensure_context_enforced.called)
            else:
                mgr.ensure_context_enforced.assert_called_with(
                    owner=owner, ctx_id=ctx,
                    transaction=mock.ANY)
            mgr.ensure_bd_created_on_apic(
                owner, "NAT-bd-%s" % es['id'], ctx_owner=ctx_owner,
                ctx_name=ctx, transaction=mock.ANY)
            mgr.ensure_epg_created.assert_called_with(
                owner, "NAT-epg-%s" % es['id'], bd_name="NAT-bd-%s" % es['id'],
                transaction=mock.ANY)
            mgr.create_tenant_filter.assert_called_with(
                prs, owner=contract_owner,
                entry="allow-all", transaction=mock.ANY)
            mgr.manage_contract_subject_bi_filter.assert_called_with(
                prs, prs, prs, owner=contract_owner, transaction=mock.ANY)
            expected_calls = [
                mock.call(owner, "NAT-epg-%s" % es['id'], prs,
                          transaction=mock.ANY),
                mock.call(owner, "NAT-epg-%s" % es['id'], prs,
                          provider=True, transaction=mock.ANY)]
            self._check_call_list(expected_calls,
                mgr.set_contract_for_epg.call_args_list)
            ctx = context.get_admin_context()
            internal_subnets = self._db_plugin.get_subnets(
                    ctx, filters={'name': [amap.HOST_SNAT_POOL]})
            self.assertEqual(1, len(internal_subnets))
        else:
            self.assertFalse(mgr.ensure_bd_created_on_apic.called)
            self.assertFalse(mgr.ensure_epg_created.called)
            self.assertFalse(mgr.create_tenant_filter.called)
            self.assertFalse(mgr.manage_contract_subject_bi_filter.called)
            self.assertFalse(mgr.set_contract_for_epg.called)

        subnet_id = es['subnet_id']
        self.delete_external_segment(es['id'],
            expected_res_status=webob.exc.HTTPNoContent.code)
        self._get_object('subnets', subnet_id, self.api,
                         expected_res_status=404)
        if self.nat_enabled:
            ctx = "NAT-vrf-%s" % es['id']
            ctx_owner = owner
            contract_owner = owner
            if self.pre_l3out:
                ctx = APIC_PRE_VRF
                ctx_owner = APIC_PRE_VRF_TENANT
                contract_owner = APIC_PRE_L3OUT_TENANT
                self.assertFalse(mgr.ensure_context_enforced.called)
            else:
                mgr.ensure_context_deleted.assert_called_with(
                    ctx_owner, ctx, transaction=mock.ANY)
            mgr.delete_bd_on_apic.assert_called_with(
                owner, "NAT-bd-%s" % es['id'], transaction=mock.ANY)
            mgr.delete_epg_for_network.assert_called_with(
                owner, "NAT-epg-%s" % es['id'], transaction=mock.ANY)
            mgr.delete_contract.assert_called_with(
                prs, owner=contract_owner, transaction=mock.ANY)
            mgr.delete_tenant_filter.assert_called_with(
                prs, owner=contract_owner, transaction=mock.ANY)
        else:
            self.assertFalse(mgr.delete_bd_on_apic.called)
            self.assertFalse(mgr.delete_epg_for_network.called)
            self.assertFalse(mgr.delete_contract.called)
            self.assertFalse(mgr.delete_tenant_filter.called)

    def test_create_delete_unshared(self):
        self._test_create_delete(False)

    def test_create_delete_shared(self):
        self._test_create_delete(True)

    def test_update_unsupported_noop(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='unsupport', cidr='192.168.0.0/24',
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}],
            expected_res_status=201)['external_segment']

        self.update_external_segment(es['id'], expected_res_status=200,
                                     external_routes=[])

        mgr = self.driver.apic_manager
        self.assertFalse(mgr.ensure_static_route_deleted.called)
        self.assertFalse(mgr.ensure_external_epg_routes_deleted.called)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)
        self.assertFalse(mgr.ensure_next_hop_deleted.called)

    def _test_route_update_remove(self, shared_es):
        # Verify routes are updated correctly
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24', shared=shared_es,
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': '192.168.0.254'},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}],
            expected_res_status=201)['external_segment']

        # create L3-policies
        if self.pre_l3out and not self.nat_enabled:
            tenants = [es['tenant_id']]
        else:
            tenants = (['tenant_a', 'tenant_b', 'tenant_c']
                       if self.nat_enabled and shared_es
                       else [es['tenant_id']])
        l3p_list = []
        for x in xrange(len(tenants)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=tenants[x],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es['id']: []},
                tenant_id=tenants[x],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)

        # Attach external policy
        f = self.create_external_policy
        eps = [f(external_segments=[es['id']],
                 tenant_id=tenants[x],
                 expected_res_status=201)['external_policy']
               for x in xrange(len(tenants))]
        mgr = self.driver.apic_manager
        owner = es['tenant_id'] if not shared_es else self.common_tenant
        mgr.ensure_external_epg_created.reset_mock()
        mgr.ensure_static_route_created.reset_mock()
        # Remove route completely
        self.update_external_segment(es['id'], expected_res_status=200,
                                     external_routes=[
                                         {'destination': '0.0.0.0/0',
                                          'nexthop': '192.168.0.254'}])
        mgr = self.driver.apic_manager
        if not self.pre_l3out:
            mgr.ensure_static_route_deleted.assert_called_with(
                es['id'], mocked.APIC_EXT_SWITCH, '128.0.0.0/16',
                owner=owner, transaction=mock.ANY)
        else:
            self.assertFalse(mgr.ensure_static_route_deleted.called)
        expected_delete_calls = []
        for x in range(len(tenants)):
            ep = eps[x]
            l3p = l3p_list[x]
            l3out = es['name' if self.pre_l3out else 'id']
            ext_epg = ep['id']
            tenant = APIC_PRE_L3OUT_TENANT if self.pre_l3out else owner
            if self.nat_enabled:
                l3out = "Shd-%s-%s" % (l3p['id'], es['id'])
                ext_epg = "Shd-%s-%s" % (l3p['id'], ext_epg)
                tenant = tenants[x]
            expected_delete_calls.append(
                mock.call(l3out, subnets=['128.0.0.0/16'],
                          external_epg=ext_epg, owner=tenant,
                          transaction=mock.ANY))
        self._check_call_list(
            expected_delete_calls,
            mgr.ensure_external_epg_routes_deleted.call_args_list)
        self.assertFalse(mgr.ensure_static_route_created.called)
        self.assertFalse(mgr.ensure_external_epg_created.called)
        self.assertFalse(mgr.ensure_next_hop_deleted.called)

        # Remove nexthop only
        mgr.ensure_static_route_deleted.reset_mock()
        mgr.ensure_external_epg_routes_deleted.reset_mock()

        self.update_external_segment(es['id'], expected_res_status=200,
                                     external_routes=[
                                         {'destination': '0.0.0.0/0',
                                          'nexthop': None}])
        if not self.pre_l3out:
            mgr.ensure_next_hop_deleted.assert_called_with(
                es['id'], mocked.APIC_EXT_SWITCH, '0.0.0.0/0', '192.168.0.254',
                owner=owner, transaction=mock.ANY)
            # Being the new nexthop 'None', the default one is used
            mgr.ensure_static_route_created.assert_called_with(
                es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.1',
                subnet='0.0.0.0/0', owner=owner, transaction=mock.ANY)
        else:
            self.assertFalse(mgr.ensure_static_route_created.called)
            self.assertFalse(mgr.ensure_next_hop_deleted.called)

        expected_delete_calls = []
        for x in range(len(tenants)):
            ep = eps[x]
            l3p = l3p_list[x]
            l3out = es['name' if self.pre_l3out else 'id']
            ext_epg = ep['id']
            tenant = APIC_PRE_L3OUT_TENANT if self.pre_l3out else owner
            if self.nat_enabled:
                l3out = "Shd-%s-%s" % (l3p['id'], es['id'])
                ext_epg = "Shd-%s-%s" % (l3p['id'], ext_epg)
                tenant = tenants[x]
            expected_delete_calls.append(
                mock.call(l3out, subnet='0.0.0.0/0',
                          external_epg=ext_epg, owner=tenant,
                          transaction=mock.ANY))
        self._check_call_list(expected_delete_calls,
                              mgr.ensure_external_epg_created.call_args_list)

        self.assertFalse(mgr.ensure_static_route_deleted.called)
        self.assertFalse(mgr.ensure_external_epg_routes_deleted.called)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_route_update_remove_1(self):
        self._test_route_update_remove(shared_es=True)

    def test_route_update_remove_2(self):
        self._test_route_update_remove(shared_es=False)

    def _test_route_update_add(self, shared_es):
        # Verify routes are updated correctly
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24', shared=shared_es,
            external_routes=[], expected_res_status=201)['external_segment']

        if self.pre_l3out and not self.nat_enabled:
            tenants = [es['tenant_id']]
        else:
            tenants = (['tenant_a', 'tenant_b', 'tenant_c']
                       if self.nat_enabled and shared_es
                       else [es['tenant_id']])
        # create L3-policies
        l3p_list = []
        for x in xrange(len(tenants)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=tenants[x],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es['id']: []},
                tenant_id=tenants[x],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)

        # Attach external policies
        f = self.create_external_policy
        eps = [f(external_segments=[es['id']],
                 tenant_id=tenants[x],
                 expected_res_status=201)['external_policy']
               for x in xrange(len(tenants))]
        mgr = self.driver.apic_manager
        mgr.ensure_external_epg_created.reset_mock()
        owner = es['tenant_id'] if not shared_es else self.common_tenant
        self.update_external_segment(es['id'], expected_res_status=200,
                                     external_routes=[
                                         {'destination': '128.0.0.0/16',
                                          'nexthop': '192.168.0.254'}])

        if not self.pre_l3out:
            mgr.ensure_static_route_created.assert_called_with(
                es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.254',
                subnet='128.0.0.0/16', owner=owner, transaction=mock.ANY)
        else:
            self.assertFalse(mgr.ensure_static_route_created.called)

        expected_create_calls = []
        for x in range(len(tenants)):
            ep = eps[x]
            l3p = l3p_list[x]
            l3out = es['name' if self.pre_l3out else 'id']
            ext_epg = ep['id']
            tenant = APIC_PRE_L3OUT_TENANT if self.pre_l3out else owner
            if self.nat_enabled:
                l3out = "Shd-%s-%s" % (l3p['id'], es['id'])
                ext_epg = "Shd-%s-%s" % (l3p['id'], ext_epg)
                tenant = tenants[x]
            expected_create_calls.append(
                mock.call(l3out, subnet='128.0.0.0/16',
                          external_epg=ext_epg, owner=tenant,
                          transaction=mock.ANY))
        self._check_call_list(expected_create_calls,
                              mgr.ensure_external_epg_created.call_args_list)
        self.assertFalse(mgr.ensure_static_route_deleted.called)
        self.assertFalse(mgr.ensure_external_epg_routes_deleted.called)
        self.assertFalse(mgr.ensure_next_hop_deleted.called)

        mgr.ensure_static_route_created.reset_mock()
        mgr.ensure_external_epg_created.reset_mock()

        # Verify Route added with default gateway
        self.update_external_segment(es['id'], expected_res_status=200,
                                     external_routes=[
                                         {'destination': '128.0.0.0/16',
                                          'nexthop': '192.168.0.254'},
                                         {'destination': '0.0.0.0/0',
                                          'nexthop': None}])

        if not self.pre_l3out:
            mgr.ensure_static_route_created.assert_called_with(
                es['id'], mocked.APIC_EXT_SWITCH, '192.168.0.1',
                subnet='0.0.0.0/0', owner=owner, transaction=mock.ANY)
        else:
            self.assertFalse(mgr.ensure_static_route_created.called)
        expected_create_calls = []
        for x in range(len(tenants)):
            ep = eps[x]
            l3p = l3p_list[x]
            l3out = es['name' if self.pre_l3out else 'id']
            ext_epg = ep['id']
            tenant = APIC_PRE_L3OUT_TENANT if self.pre_l3out else owner
            if self.nat_enabled:
                l3out = "Shd-%s-%s" % (l3p['id'], es['id'])
                ext_epg = "Shd-%s-%s" % (l3p['id'], ext_epg)
                tenant = tenants[x]
            expected_create_calls.append(
                mock.call(l3out, subnet='0.0.0.0/0',
                          external_epg=ext_epg, owner=tenant,
                          transaction=mock.ANY))
        self._check_call_list(expected_create_calls,
                              mgr.ensure_external_epg_created.call_args_list)
        self.assertFalse(mgr.ensure_static_route_deleted.called)
        self.assertFalse(mgr.ensure_external_epg_routes_deleted.called)
        self.assertFalse(mgr.ensure_next_hop_deleted.called)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_route_update_add_1(self):
        self._test_route_update_add(shared_es=True)

    def test_route_update_add_2(self):
        self._test_route_update_add(shared_es=False)

    def test_es_create_no_cidr_with_routes(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        nh = '172.16.0.1' if self.pre_l3out else '192.168.0.254'
        self.create_external_segment(
            name='supported',
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': nh}],
            expected_res_status=201)

    def test_implicit_es_router_gw_ip(self):
        self._mock_external_dict([('default', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='default',
            external_routes=[{'destination': '0.0.0.0/0',
                              'nexthop': None}])['external_segment']
        l3p = self.create_l3_policy()['l3_policy']
        self.assertEqual(es['id'],
                         l3p['external_segments'].keys()[0])
        self.assertEqual('169.254.0.2',
                         l3p['external_segments'][es['id']][0])


class TestExternalSegmentNoNat(TestExternalSegment):
    def setUp(self):
        super(TestExternalSegmentNoNat, self).setUp(nat_enabled=False)


class TestExternalSegmentPreL3Out(TestExternalSegment):
    def setUp(self):
        super(TestExternalSegmentPreL3Out, self).setUp(
            pre_existing_l3out=True)

    def test_query_l3out_info(self):
        self.driver._query_l3out_info = self.orig_query_l3out_info
        ctx1 = [{
            'l3extRsEctx': {'attributes': {'tDn': 'uni/tn-foo/ctx-foobar'}}}]
        mgr = self.driver.apic_manager
        mgr.apic.l3extOut.get_subtree.return_value = ctx1
        info = self.driver._query_l3out_info('l3out', 'bar_tenant')
        self.assertEqual('bar_tenant', info['l3out_tenant'])
        self.assertEqual('foobar', info['vrf_name'])
        self.assertEqual('foo', info['vrf_tenant'])

        mgr.apic.l3extOut.get_subtree.reset_mock()
        mgr.apic.l3extOut.get_subtree.return_value = []
        info = self.driver._query_l3out_info('l3out', 'bar_tenant')
        self.assertEqual(None, info)
        expected_calls = [
            mock.call('bar_tenant', 'l3out'),
            mock.call('common', 'l3out')]
        self._check_call_list(
            expected_calls, mgr.apic.l3extOut.get_subtree.call_args_list)


class TestExternalSegmentNoNatPreL3Out(TestExternalSegment):
    def setUp(self):
        super(TestExternalSegmentNoNatPreL3Out, self).setUp(
            nat_enabled=False, pre_existing_l3out=True)


class TestExternalPolicy(ApicMappingTestCase):

    def test_creation_noop(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[], expected_res_status=201)['external_segment']

        self.create_external_policy(
            name=APIC_EXTERNAL_EPG,
            external_segments=[es['id']], expected_res_status=201)
        # Verify called with default route always
        mgr = self.driver.apic_manager
        if self.nat_enabled and not self.pre_l3out:
            mgr.ensure_external_epg_created.assert_called_once_with(
                es['id'], subnet='0.0.0.0/0',
                external_epg=("default-%s" % es['id']), owner=es['tenant_id'],
                transaction=mock.ANY)
        else:
            self.assertFalse(mgr.ensure_external_epg_created.called)

        mgr.ensure_external_epg_created.reset_mock()
        es = self.create_external_segment(
            name='unsupported', cidr='192.168.0.0/24', expected_res_status=201,
            external_routes=[{'destination': '128.0.0.0/16',
                              'nexthop': '192.168.0.254'}])['external_segment']

        self.create_external_policy(
            external_segments=[es['id']], expected_res_status=201)
        # Verify noop on unsupported
        self.assertFalse(mgr.ensure_external_epg_created.called)

    def test_create_shared(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[], shared=True,
            expected_res_status=201)['external_segment']

        res = self.create_external_policy(
            external_segments=[es['id']], shared=True,
            expected_res_status=400)
        self.assertEqual('SharedExternalPolicyUnsupported',
                         res['NeutronError']['type'])

    def test_update_shared(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            external_routes=[], shared=True,
            expected_res_status=201)['external_segment']

        ep = self.create_external_policy(
            external_segments=[es['id']],
            expected_res_status=201)['external_policy']
        res = self.update_external_policy(
            ep['id'], shared=True, expected_res_status=400)
        self.assertEqual('SharedExternalPolicyUnsupported',
                         res['NeutronError']['type'])

    def _test_creation_no_prs(self, shared_es):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es_list = [
            self.create_external_segment(
                name='supported', cidr='192.168.0.0/24', shared=shared_es,
                expected_res_status=201,
                external_routes=[{
                    'destination': '128.0.0.0/16',
                    'nexthop': '192.168.0.254'}])['external_segment']
            for x in range(3)]
        l3p_list = []
        for x in xrange(len(es_list)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=shared_es and 'another' or es_list[x]['tenant_id'],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es_list[x]['id']: []},
                tenant_id=l3p['tenant_id'],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)

        ep = self.create_external_policy(
            name=APIC_EXTERNAL_EPG,
            external_segments=[x['id'] for x in es_list],
            tenant_id=es_list[0]['tenant_id'] if not shared_es else 'another',
            expected_res_status=201)['external_policy']

        mgr = self.driver.apic_manager
        owner = (es_list[0]['tenant_id'] if not shared_es
                 else self.common_tenant)
        l3p_owner = l3p_list[0]['tenant_id']
        expected_create_calls = []
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            if self.nat_enabled:
                if not self.pre_l3out:
                    expected_create_calls.append(
                        mock.call(es['id'], subnet='0.0.0.0/0',
                        external_epg="default-%s" % es['id'], owner=owner,
                        transaction=mock.ANY))
                expected_create_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                    subnet='128.0.0.0/16',
                    external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                    owner=l3p_owner,
                    transaction=mock.ANY))
            elif not self.pre_l3out:
                expected_create_calls.append(
                    mock.call(es['id'], subnet='128.0.0.0/16',
                    external_epg=ep['id'], owner=owner,
                    transaction=mock.ANY))
        self._check_call_list(expected_create_calls,
                              mgr.ensure_external_epg_created.call_args_list)
        if self.nat_enabled:
            expected_contract_calls = []
            ext_epg_tenant = (APIC_PRE_L3OUT_TENANT if self.pre_l3out
                              else owner)
            for x in range(len(es_list)):
                es = es_list[x]
                ext_epg = (APIC_EXTERNAL_EPG if self.pre_l3out
                           else "default-%s" % es['id'])
                es_name = es['name' if self.pre_l3out else 'id']
                nat_contract = "NAT-allow-%s" % es['id']
                expected_contract_calls.extend([
                    mock.call(es_name, nat_contract,
                        external_epg=ext_epg, owner=ext_epg_tenant,
                        provided=True, transaction=mock.ANY),
                    mock.call(es_name, nat_contract,
                        external_epg=ext_epg, owner=ext_epg_tenant,
                        provided=False, transaction=mock.ANY)])
            self._check_call_list(expected_contract_calls,
                  mgr.set_contract_for_external_epg.call_args_list)
        else:
            self.assertFalse(mgr.set_contract_for_external_epg.called)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_creation_no_prs_1(self):
        self._test_creation_no_prs(shared_es=True)

    def test_creation_no_prs_2(self):
        self._test_creation_no_prs(shared_es=False)

    def _test_update_no_prs(self, shared_es):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es_list = [
            self.create_external_segment(
                name='supported', cidr='192.168.0.0/24', shared=shared_es,
                expected_res_status=201,
                external_routes=[{
                    'destination': '128.0.0.0/16',
                    'nexthop': '192.168.0.254'}])['external_segment']
            for x in range(3)]
        l3p_list = []
        for x in xrange(len(es_list)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=shared_es and 'another' or es_list[x]['tenant_id'],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es_list[x]['id']: []},
                tenant_id=l3p['tenant_id'],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)

        ep = self.create_external_policy(
            name=APIC_EXTERNAL_EPG,
            tenant_id=es_list[0]['tenant_id'] if not shared_es else 'another',
            expected_res_status=201)['external_policy']
        ep = self.update_external_policy(
            ep['id'], expected_res_status=200, tenant_id=ep['tenant_id'],
            external_segments=[x['id'] for x in es_list])['external_policy']
        mgr = self.driver.apic_manager
        owner = (es_list[0]['tenant_id'] if not shared_es
                 else self.common_tenant)
        l3p_owner = l3p_list[0]['tenant_id']
        expected_create_calls = []
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            if self.nat_enabled:
                if not self.pre_l3out:
                    expected_create_calls.append(
                        mock.call(es['id'], subnet='0.0.0.0/0',
                            external_epg="default-%s" % es['id'],
                            owner=owner, transaction=mock.ANY))
                expected_create_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                         subnet='128.0.0.0/16',
                         external_epg="Shd-%s-%s" % (l3p['id'], ep['id']),
                         owner=l3p_owner, transaction=mock.ANY))
            elif not self.pre_l3out:
                expected_create_calls.append(
                    mock.call(es['id'], subnet='128.0.0.0/16',
                        external_epg=ep['id'],
                        owner=owner, transaction=mock.ANY))
        self._check_call_list(expected_create_calls,
                              mgr.ensure_external_epg_created.call_args_list)
        if self.nat_enabled:
            expected_contract_calls = []
            ext_epg_tenant = (APIC_PRE_L3OUT_TENANT if self.pre_l3out
                              else owner)
            for x in range(len(es_list)):
                es = es_list[x]
                ext_epg = (APIC_EXTERNAL_EPG if self.pre_l3out
                           else "default-%s" % es['id'])
                es_name = es['name' if self.pre_l3out else 'id']
                nat_contract = "NAT-allow-%s" % es['id']
                expected_contract_calls.extend([
                    mock.call(es_name, nat_contract,
                        external_epg=ext_epg, owner=ext_epg_tenant,
                        provided=True, transaction=mock.ANY),
                    mock.call(es_name, nat_contract,
                        external_epg=ext_epg, owner=ext_epg_tenant,
                        provided=False, transaction=mock.ANY)])
            self._check_call_list(expected_contract_calls,
                  mgr.set_contract_for_external_epg.call_args_list)
        else:
            self.assertFalse(mgr.set_contract_for_external_epg.called)

        ep = self.update_external_policy(
            ep['id'], expected_res_status=200, tenant_id=ep['tenant_id'],
            external_segments=[])['external_policy']
        mgr = self.driver.apic_manager
        expected_create_calls = []
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            if self.nat_enabled:
                if not self.pre_l3out:
                    expected_create_calls.append(
                        mock.call(es['id'], owner=owner,
                        external_epg="default-%s" % es['id']))
                expected_create_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                         owner=l3p_owner,
                         external_epg="Shd-%s-%s" % (l3p['id'], ep['id'])))
            elif not self.pre_l3out:
                expected_create_calls.append(
                    mock.call(es['id'], owner=owner, external_epg=ep['id']))
        self._check_call_list(expected_create_calls,
                              mgr.ensure_external_epg_deleted.call_args_list)
        if self.nat_enabled and self.pre_l3out:
            expected_contract_calls = []
            ext_epg_tenant = APIC_PRE_L3OUT_TENANT
            for x in range(len(es_list)):
                es = es_list[x]
                nat_contract = "NAT-allow-%s" % es['id']
                expected_contract_calls.extend([
                    mock.call(es['name'], nat_contract,
                        external_epg=APIC_EXTERNAL_EPG, owner=ext_epg_tenant,
                        provided=True, transaction=mock.ANY),
                    mock.call(es['name'], nat_contract,
                        external_epg=APIC_EXTERNAL_EPG, owner=ext_epg_tenant,
                        provided=False, transaction=mock.ANY)])
            self._check_call_list(expected_contract_calls,
                  mgr.unset_contract_for_external_epg.call_args_list)
        else:
            self.assertFalse(mgr.unset_contract_for_external_epg.called)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_update_no_prs_1(self):
        self._test_update_no_prs(shared_es=True)

    def test_update_no_prs_2(self):
        self._test_update_no_prs(shared_es=False)

    def _test_create_with_prs(self, shared_es, shared_prs):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es_list = [
            self.create_external_segment(
                name='supported', cidr='192.168.0.0/24', shared=shared_es,
                expected_res_status=201,
                external_routes=[{
                    'destination': '128.0.0.0/16',
                    'nexthop': '192.168.0.254'}])['external_segment']
            for x in range(3)]
        l3p_list = []
        for x in xrange(len(es_list)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=shared_es and 'another' or es_list[x]['tenant_id'],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es_list[x]['id']: []},
                tenant_id=l3p['tenant_id'],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)
        prov = self._create_policy_rule_set_on_shared(
            shared=shared_prs,
            tenant_id=es_list[0]['tenant_id'] if not (
                shared_es | shared_prs) else 'another')
        cons = self._create_policy_rule_set_on_shared(
            shared=shared_prs,
            tenant_id=es_list[0]['tenant_id'] if not (
                shared_es | shared_prs) else 'another')
        ep = self.create_external_policy(
            name=APIC_EXTERNAL_EPG,
            provided_policy_rule_sets={prov['id']: ''},
            consumed_policy_rule_sets={cons['id']: ''},
            tenant_id=es_list[0]['tenant_id'] if not shared_es else 'another',
            external_segments=[x['id'] for x in es_list],
            expected_res_status=201)['external_policy']
        mgr = self.driver.apic_manager
        owner = (es_list[0]['tenant_id'] if not shared_es
                 else self.common_tenant)
        l3p_owner = l3p_list[0]['tenant_id']
        expected_calls = []
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            nat = self.nat_enabled
            external_epg = APIC_EXTERNAL_EPG if self.pre_l3out else (
                ("default-%s" % es['id']) if nat else ep['id'])
            ext_epg_tenant = (APIC_PRE_L3OUT_TENANT if self.pre_l3out else
                              owner)
            es_name = es['name' if self.pre_l3out else 'id']
            expected_calls.append(
                mock.call(es_name,
                    ("NAT-allow-%s" % es['id']) if nat else prov['id'],
                    external_epg=external_epg,
                    provided=True, owner=ext_epg_tenant,
                    transaction=mock.ANY))
            expected_calls.append(
                mock.call(es_name,
                    ("NAT-allow-%s" % es['id']) if nat else cons['id'],
                    external_epg=external_epg,
                    provided=False, owner=ext_epg_tenant,
                    transaction=mock.ANY))
            if nat:
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), prov['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=True, owner=l3p_owner,
                        transaction=mock.ANY))
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), cons['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=False, owner=l3p_owner,
                        transaction=mock.ANY))
        self._check_call_list(expected_calls,
                              mgr.set_contract_for_external_epg.call_args_list)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_create_with_prs_1(self):
        self._test_create_with_prs(shared_es=True, shared_prs=True)

    def test_create_with_prs_2(self):
        self._test_create_with_prs(shared_es=True, shared_prs=False)

    def test_create_with_prs_3(self):
        self._test_create_with_prs(shared_es=False, shared_prs=False)

    def test_create_with_prs_4(self):
        self._test_create_with_prs(shared_es=False, shared_prs=True)

    def _test_update_add_prs(self, shared_es, shared_prs):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es_list = [
            self.create_external_segment(
                name='supported', cidr='192.168.0.0/24', shared=shared_es,
                expected_res_status=201,
                external_routes=[{
                    'destination': '128.0.0.0/16',
                    'nexthop': '192.168.0.254'}])['external_segment']
            for x in range(3)]
        l3p_list = []
        for x in xrange(len(es_list)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=shared_es and 'another' or es_list[x]['tenant_id'],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={es_list[x]['id']: []},
                tenant_id=l3p['tenant_id'],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)
        prov = self._create_policy_rule_set_on_shared(
            shared=shared_prs, tenant_id=es_list[0]['tenant_id'] if not (
                shared_es | shared_prs) else 'another')
        cons = self._create_policy_rule_set_on_shared(
            shared=shared_prs, tenant_id=es_list[0]['tenant_id'] if not (
                shared_es | shared_prs) else 'another')
        ep = self.create_external_policy(
            name=APIC_EXTERNAL_EPG,
            external_segments=[x['id'] for x in es_list],
            tenant_id=es_list[0]['tenant_id'] if not shared_es else 'another',
            expected_res_status=201)['external_policy']
        ep = self.update_external_policy(
            ep['id'], expected_res_status=200, tenant_id=ep['tenant_id'],
            provided_policy_rule_sets={prov['id']: ''},
            consumed_policy_rule_sets={cons['id']: ''})['external_policy']
        mgr = self.driver.apic_manager
        owner = (es_list[0]['tenant_id'] if not shared_es
                 else self.common_tenant)
        l3p_owner = l3p_list[0]['tenant_id']
        expected_calls = []
        nat = self.nat_enabled
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            external_epg = APIC_EXTERNAL_EPG if self.pre_l3out else (
                ("default-%s" % es['id']) if nat else ep['id'])
            ext_epg_tenant = (APIC_PRE_L3OUT_TENANT if self.pre_l3out else
                              owner)
            es_name = es['name' if self.pre_l3out else 'id']
            expected_calls.append(
                mock.call(es_name,
                    ("NAT-allow-%s" % es['id']) if nat else prov['id'],
                    external_epg=external_epg,
                    provided=True, owner=ext_epg_tenant,
                    transaction=mock.ANY))
            expected_calls.append(
                mock.call(es_name,
                    ("NAT-allow-%s" % es['id']) if nat else cons['id'],
                    external_epg=external_epg,
                    provided=False, owner=ext_epg_tenant,
                    transaction=mock.ANY))
            if nat:
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), prov['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=True, owner=l3p_owner,
                        transaction=mock.ANY))
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), cons['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=False, owner=l3p_owner,
                        transaction=mock.ANY))
        self._check_call_list(expected_calls,
                              mgr.set_contract_for_external_epg.call_args_list)

        ep = self.update_external_policy(
            ep['id'], expected_res_status=200, provided_policy_rule_sets={},
            consumed_policy_rule_sets={},
            tenant_id=ep['tenant_id'])['external_policy']
        expected_calls = []
        for x in range(len(es_list)):
            es = es_list[x]
            l3p = l3p_list[x]
            if nat:
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), prov['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=True, owner=l3p_owner,
                        transaction=mock.ANY))
                expected_calls.append(
                    mock.call("Shd-%s-%s" % (l3p['id'], es['id']), cons['id'],
                        external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                        provided=False, owner=l3p_owner,
                        transaction=mock.ANY))
            else:
                external_epg = (APIC_EXTERNAL_EPG if self.pre_l3out
                                else ep['id'])
                ext_epg_tenant = (APIC_PRE_L3OUT_TENANT if self.pre_l3out else
                                  owner)
                es_name = es['name' if self.pre_l3out else 'id']
                expected_calls.append(
                    mock.call(es_name, prov['id'],
                        external_epg=external_epg,
                        provided=True, owner=ext_epg_tenant,
                        transaction=mock.ANY))
                expected_calls.append(
                    mock.call(es_name, cons['id'],
                        external_epg=external_epg,
                        provided=False, owner=ext_epg_tenant,
                        transaction=mock.ANY))
        self._check_call_list(
            expected_calls, mgr.unset_contract_for_external_epg.call_args_list)

    # Although the naming convention used here has been chosen poorly,
    # I'm separating the tests in order to get the mock re-set.
    def test_update_add_prs_1(self):
        self._test_update_add_prs(shared_es=True, shared_prs=True)

    def test_update_add_prs_2(self):
        self._test_update_add_prs(shared_es=True, shared_prs=False)

    def test_update_add_prs_3(self):
        self._test_update_add_prs(shared_es=False, shared_prs=False)

    def test_update_add_prs_4(self):
        self._test_update_add_prs(shared_es=False, shared_prs=True)

    def test_update_add_prs_unsupported(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='unsupported', cidr='192.168.0.0/24', expected_res_status=201,
            external_routes=[{'destination': '128.0.0.0/16',
                              'nexthop': '192.168.0.254'}])['external_segment']
        prov = self._create_policy_rule_set_on_shared()
        cons = self._create_policy_rule_set_on_shared()
        ep = self.create_external_policy(
            external_segments=[es['id']],
            expected_res_status=201)['external_policy']
        self.update_external_policy(
            ep['id'], expected_res_status=200, tenant_id=ep['tenant_id'],
            provided_policy_rule_sets={prov['id']: ''},
            consumed_policy_rule_sets={cons['id']: ''})['external_policy']
        mgr = self.driver.apic_manager
        self.assertFalse(mgr.set_contract_for_external_epg.called)

    def _test_multi_policy_single_tenant(self, shared_es):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24',
            expected_res_status=201, shared=shared_es,
            external_routes=[{
                'destination': '128.0.0.0/16',
                'nexthop': '192.168.0.254'}])['external_segment']

        owner = 'another' if shared_es else es['tenant_id']
        self.create_external_policy(
            external_segments=[es['id']],
            tenant_id=owner,
            expected_res_status=201)
        res = self.create_external_policy(
            external_segments=[es['id']],
            tenant_id=owner,
            expected_res_status=400)
        self.assertEqual('MultipleExternalPoliciesForL3Policy',
                         res['NeutronError']['type'])

        # create another external policy and update it to use external-segment
        ep2 = self.create_external_policy(
            tenant_id=owner,
            expected_res_status=201)['external_policy']
        res = self.update_external_policy(
            ep2['id'], external_segments=[es['id']],
            tenant_id=owner,
            expected_res_status=400)
        self.assertEqual('MultipleExternalPoliciesForL3Policy',
                         res['NeutronError']['type'])

    def test_multi_policy_single_tenant_1(self):
        self._test_multi_policy_single_tenant(True)

    def test_multi_policy_single_tenant_2(self):
        self._test_multi_policy_single_tenant(False)

    def test_multi_policy_multi_tenant(self):
        tenants = (['tenant_a', 'tenant_b', 'tenant_c']
                   if self.nat_enabled else ['tenant_a'])

        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es_list = [
            self.create_external_segment(
                name='supported', cidr='192.168.0.0/24', shared=True,
                expected_res_status=201,
                external_routes=[{
                    'destination': '128.0.0.0/16',
                    'nexthop': '192.168.0.254'}])['external_segment']
            for x in range(2)]

        l3p_list = []
        for x in xrange(len(tenants)):
            l3p = self.create_l3_policy(
                shared=False,
                tenant_id=tenants[x],
                expected_res_status=201)['l3_policy']
            if self.pre_l3out and not self.nat_enabled:
                self._update_pre_l3out_info(l3p)
            l3p = self.update_l3_policy(l3p['id'],
                external_segments={x['id']: [] for x in es_list},
                tenant_id=l3p['tenant_id'],
                expected_res_status=200)['l3_policy']
            l3p_list.append(l3p)

        # create external-policy
        ep_list = []
        mgr = self.driver.apic_manager
        for x in range(len(tenants)):
            ep = self.create_external_policy(
                name=APIC_EXTERNAL_EPG,
                external_segments=[e['id'] for e in es_list],
                tenant_id=tenants[x],
                expected_res_status=201)['external_policy']
            ep_list.append(ep)
            l3p = l3p_list[x]
            expected_calls = []
            for es in es_list:
                if self.nat_enabled:
                    if not self.pre_l3out:
                        expected_calls.append(
                            mock.call(es['id'], subnet='0.0.0.0/0',
                                external_epg="default-%s" % es['id'],
                                owner=self.common_tenant,
                                transaction=mock.ANY))
                    expected_calls.append(
                        mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                            subnet='128.0.0.0/16',
                            external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                            owner=tenants[x],
                            transaction=mock.ANY))
                elif not self.pre_l3out:
                    expected_calls.append(
                        mock.call(es['id'], subnet='128.0.0.0/16',
                            external_epg=ep['id'], owner=self.common_tenant,
                            transaction=mock.ANY))
            self._check_call_list(expected_calls,
                mgr.ensure_external_epg_created.call_args_list)
            mgr.ensure_external_epg_created.reset_mock()

        # delete external-policy
        expected_calls = []
        for x in range(len(tenants)):
            ep = ep_list[x]
            self.delete_external_policy(
                ep['id'], tenant_id=ep['tenant_id'],
                expected_res_status=webob.exc.HTTPNoContent.code)
            l3p = l3p_list[x]

            for es in es_list:
                if self.nat_enabled:
                    expected_calls.append(
                        mock.call("Shd-%s-%s" % (l3p['id'], es['id']),
                            external_epg=("Shd-%s-%s" % (l3p['id'], ep['id'])),
                            owner=tenants[x]))
                elif not self.pre_l3out:
                    expected_calls.append(
                        mock.call(es['id'], external_epg=ep['id'],
                            owner=self.common_tenant))
        if self.nat_enabled and not self.pre_l3out:
            for es in es_list:
                expected_calls.append(
                    mock.call(es['id'], external_epg="default-%s" % es['id'],
                              owner=self.common_tenant))
        self._check_call_list(expected_calls,
            mgr.ensure_external_epg_deleted.call_args_list)


class TestExternalPolicyNoNat(TestExternalPolicy):
    def setUp(self):
        super(TestExternalPolicyNoNat, self).setUp(nat_enabled=False)


class TestExternalPolicyPreL3Out(TestExternalPolicy):
    def setUp(self):
        super(TestExternalPolicyPreL3Out, self).setUp(
            pre_existing_l3out=True)

    def test_multi_tenant_delete(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24', shared=True,
            expected_res_status=201)['external_segment']

        ep_list = [
            self.create_external_policy(
                name=APIC_EXTERNAL_EPG,
                external_segments=[es['id']],
                tenant_id=tnnt,
                expected_res_status=201)['external_policy']
            for tnnt in ['tenant_a', 'tenant_b', 'tenant_c']]
        for ep in ep_list:
            self.delete_external_policy(
                ep['id'], tenant_id=ep['tenant_id'],
                expected_res_status=webob.exc.HTTPNoContent.code)
        nat_contract = "NAT-allow-%s" % es['id']
        expected_calls = [
            mock.call(es['name'], nat_contract,
                      external_epg=APIC_EXTERNAL_EPG,
                      provided=True, owner=APIC_PRE_L3OUT_TENANT,
                      transaction=mock.ANY),
            mock.call(es['name'], nat_contract,
                      external_epg=APIC_EXTERNAL_EPG,
                      provided=False, owner=APIC_PRE_L3OUT_TENANT,
                      transaction=mock.ANY)
        ]
        mgr = self.driver.apic_manager
        self._check_call_list(expected_calls,
            mgr.unset_contract_for_external_epg.call_args_list)

    def test_multi_tenant_update_dissociate(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(
            name='supported', cidr='192.168.0.0/24', shared=True,
            expected_res_status=201)['external_segment']

        ep_list = [
            self.create_external_policy(
                name=APIC_EXTERNAL_EPG,
                external_segments=[es['id']],
                tenant_id=tnnt,
                expected_res_status=201)['external_policy']
            for tnnt in ['tenant_a', 'tenant_b', 'tenant_c']]
        for ep in ep_list:
            self.update_external_policy(
                ep['id'], tenant_id=ep['tenant_id'],
                external_segments=[],
                expected_res_status=200)
        nat_contract = "NAT-allow-%s" % es['id']
        expected_calls = [
            mock.call(es['name'], nat_contract,
                      external_epg=APIC_EXTERNAL_EPG,
                      provided=True, owner=APIC_PRE_L3OUT_TENANT,
                      transaction=mock.ANY),
            mock.call(es['name'], nat_contract,
                      external_epg=APIC_EXTERNAL_EPG,
                      provided=False, owner=APIC_PRE_L3OUT_TENANT,
                      transaction=mock.ANY)
        ]
        mgr = self.driver.apic_manager
        self._check_call_list(expected_calls,
            mgr.unset_contract_for_external_epg.call_args_list)


class TestExternalPolicyNoNatPreL3Out(TestExternalPolicy):
    def setUp(self):
        super(TestExternalPolicyNoNatPreL3Out, self).setUp(
            nat_enabled=False, pre_existing_l3out=True)


class TestNatPool(ApicMappingTestCase):

    def test_overlap_nat_pool_create(self):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        mgr = self.driver.apic_manager
        mgr.ext_net_dict['supported']['host_pool_cidr'] = '192.168.200.1/24'
        es = self.create_external_segment(name='supported',
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        # cidr_exposed overlap
        res = self.create_nat_pool(
            external_segment_id=es['id'],
            ip_version=4, ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NatPoolOverlapsApicSubnet',
                         res['NeutronError']['type'])
        # host-pool overlap
        res = self.create_nat_pool(
            external_segment_id=es['id'],
            ip_version=4, ip_pool='192.168.200.0/24',
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NatPoolOverlapsApicSubnet',
                         res['NeutronError']['type'])

    def test_overlap_nat_pool_update(self):
        self._mock_external_dict([('supported', '192.168.0.2/24'),
                                  ('supported1', '192.168.1.2/24')])
        es1 = self.create_external_segment(name='supported',
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        es2 = self.create_external_segment(name='supported1',
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es1['id'],
            ip_version=4, ip_pool='192.168.1.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        res = self.update_nat_pool(nat_pool['id'],
            external_segment_id=es2['id'],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NatPoolOverlapsApicSubnet',
                         res['NeutronError']['type'])

    def _test_nat_bd_subnet_created_deleted(self, shared):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(name='supported',
            expected_res_status=webob.exc.HTTPCreated.code,
            shared=shared)['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'],
            ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        owner = es['tenant_id'] if not shared else self.common_tenant
        mgr = self.driver.apic_manager

        if self.nat_enabled:
            mgr.ensure_subnet_created_on_apic.assert_called_with(
                owner, "NAT-bd-%s" % es['id'], '192.168.1.1/24')
        else:
            self.assertFalse(mgr.ensure_subnet_created_on_apic.called)

        self.delete_nat_pool(nat_pool['id'],
            expected_res_status=webob.exc.HTTPNoContent.code)
        if self.nat_enabled:
            mgr.ensure_subnet_deleted_on_apic.assert_called_with(
                owner, "NAT-bd-%s" % es['id'], '192.168.1.1/24')
        else:
            self.assertFalse(mgr.ensure_subnet_deleted_on_apic.called)

    def test_nat_bd_subnet_create_delete_1(self):
        self._test_nat_bd_subnet_created_deleted(False)

    def test_nat_bd_subnet_create_delete_2(self):
        self._test_nat_bd_subnet_created_deleted(True)

    def _test_nat_bd_subnet_updated(self, shared):
        self._mock_external_dict([('supported', '192.168.0.2/24'),
                                  ('supported1', '192.168.10.2/24')])
        es1 = self.create_external_segment(name='supported',
            expected_res_status=webob.exc.HTTPCreated.code,
            shared=shared)['external_segment']
        es2 = self.create_external_segment(name='supported1',
            expected_res_status=webob.exc.HTTPCreated.code,
            shared=shared)['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es1['id'],
            ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        owner = es1['tenant_id'] if not shared else self.common_tenant
        mgr = self.driver.apic_manager

        mgr.ensure_subnet_created_on_apic.reset_mock()
        nat_pool = self.update_nat_pool(nat_pool['id'],
            external_segment_id=es2['id'],
            expected_res_status=webob.exc.HTTPOk.code)['nat_pool']
        if self.nat_enabled:
            mgr.ensure_subnet_deleted_on_apic.assert_called_with(
                owner, "NAT-bd-%s" % es1['id'], '192.168.1.1/24')
            mgr.ensure_subnet_created_on_apic.assert_called_with(
                owner, "NAT-bd-%s" % es2['id'], '192.168.1.1/24')
        else:
            self.assertFalse(mgr.ensure_subnet_created_on_apic.called)
            self.assertFalse(mgr.ensure_subnet_deleted_on_apic.called)

    def test_nat_bd_subnet_update_1(self):
        self._test_nat_bd_subnet_updated(False)

    def test_nat_bd_subnet_update_2(self):
        self._test_nat_bd_subnet_updated(True)

    def _test_create_fip(self, shared):
        self._mock_external_dict([('supported', '192.168.0.2/24')])
        es = self.create_external_segment(name='supported',
            expected_res_status=webob.exc.HTTPCreated.code,
            shared=shared)['external_segment']
        self.create_nat_pool(external_segment_id=es['id'],
            ip_version=4, ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)
        subnet = self._get_object('subnets', es['subnet_id'],
            self.api)['subnet']

        fip_dict = {'floating_network_id': subnet['network_id']}
        fip_id = self.driver.create_floatingip_in_nat_pool(
            context.get_admin_context(),
            es['tenant_id'], {'floatingip': fip_dict})
        self.assertIsNotNone(fip_id)
        fip = self._get_object(
            'floatingips', fip_id, self.ext_api)['floatingip']
        self.assertTrue(
            netaddr.IPAddress(fip['floating_ip_address']) in
            netaddr.IPNetwork('192.168.1.0/24'))

    def test_create_fip(self):
        self._test_create_fip(False)

    def test_create_fip_shared(self):
        self._test_create_fip(True)


class TestNatPoolNoNat(TestNatPool):
    def setUp(self):
        super(TestNatPoolNoNat, self).setUp(nat_enabled=False)
