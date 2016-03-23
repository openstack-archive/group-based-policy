# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
#
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

from aim.db import model_base as aim_model_base
from keystoneclient.v3 import client as ksc_client
from neutron import context
from neutron.db import api as db_api
from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from opflexagent import constants as ofcst

PLUGIN_NAME = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'

AGENT_CONF_OPFLEX = {'alive': True, 'binary': 'somebinary',
                     'topic': 'sometopic',
                     'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
                     'configurations': {
                         'opflex_networks': None,
                         'bridge_mappings': {'physnet1': 'br-eth1'}}}


# REVISIT(rkukura): Use mock for this instead?
class FakeTenant(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name


class FakeProjectManager(object):
    def list(self):
        return [FakeTenant('test-tenant', 'TestTenantName'),
                FakeTenant('bad_tenant_id', 'BadTenantName')]


class FakeKeystoneClient(object):
    def __init__(self, **kwargs):
        self.projects = FakeProjectManager()


class ApicAimTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'apic_aim'],
                                     'ml2')
        config.cfg.CONF.set_override('extension_drivers',
                                     ['apic_aim'],
                                     'ml2')
        config.cfg.CONF.set_override('type_drivers',
                                     ['opflex', 'local', 'vlan'],
                                     'ml2')
        config.cfg.CONF.set_override('tenant_network_types',
                                     ['opflex'],
                                     'ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')

        super(ApicAimTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = FakeKeystoneClient

        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)

        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        super(ApicAimTestCase, self).tearDown()


class TestApicExtension(ApicAimTestCase):
    def _verify_dn(self, dist_names, key, mo_types, id):
        dn = dist_names.get(key)
        self.assertIsInstance(dn, basestring)
        self.assertEqual('uni/', dn[:4])
        for mo_type in mo_types:
            self.assertIn('/' + mo_type + '-', dn)
        self.assertIn(id, dn)

    def _verify_no_dn(self, dist_names, key):
        self.assertIn(key, dist_names)
        self.assertIsNone(dist_names.get(key))

    def _verify_network_dist_names(self, net):
        id = net['id']
        dist_names = net.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        self._verify_dn(dist_names, 'BridgeDomain', ['tn', 'BD'], id[:5])
        self._verify_dn(dist_names, 'EndpointGroup', ['tn', 'ap', 'epg'],
                        id[:5])

    def test_network(self):
        # Test create.
        net = self._make_network(self.fmt, 'net1', True)['network']
        net_id = net['id']
        self._verify_network_dist_names(net)

        # Test show.
        res = self._show('networks', net_id)['network']
        self._verify_network_dist_names(res)

        # Test update.
        data = {'network': {'name': 'newnamefornet'}}
        res = self._update('networks', net_id, data)['network']
        self._verify_network_dist_names(res)

    def _verify_subnet_dist_names(self, subnet):
        dist_names = subnet.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        if subnet['gateway_ip']:
            id = subnet['gateway_ip'] + '/' + subnet['cidr'].split('/')[1]
            self._verify_dn(dist_names, 'Subnet', ['tn', 'BD', 'subnet'], id)
        else:
            self._verify_no_dn(dist_names, 'Subnet')

    def test_subnet_without_gw(self):
        # Test create without gateway.
        net = self._make_network(self.fmt, 'net', True)
        pools = [{'start': '10.0.0.2', 'end': '10.0.0.254'}]
        subnet = self._make_subnet(self.fmt, net, None,
                                   '10.0.0.0/24',
                                   allocation_pools=pools)['subnet']
        subnet_id = subnet['id']
        self._verify_subnet_dist_names(subnet)

        # Test show.
        res = self._show('subnets', subnet_id)['subnet']
        self._verify_subnet_dist_names(res)

        # Test update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        res = self._update('subnets', subnet_id, data)['subnet']
        self._verify_subnet_dist_names(res)

        # Test update adding gateay.
        data = {'subnet': {'gateway_ip': '10.0.0.1'}}
        res = self._update('subnets', subnet_id, data)['subnet']
        self._verify_subnet_dist_names(res)

        # Test show after adding gateway.
        res = self._show('subnets', subnet_id)['subnet']
        self._verify_subnet_dist_names(res)

    def test_subnet_with_gw(self):
        # Test create.
        net = self._make_network(self.fmt, 'net', True)
        subnet = self._make_subnet(self.fmt, net, '10.0.1.1',
                                   '10.0.1.0/24')['subnet']
        subnet_id = subnet['id']
        self._verify_subnet_dist_names(subnet)

        # Test show.
        res = self._show('subnets', subnet_id)['subnet']
        self._verify_subnet_dist_names(res)

        # Test update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        res = self._update('subnets', subnet_id, data)['subnet']
        self._verify_subnet_dist_names(res)

        # Test update removing gateway.
        data = {'subnet': {'gateway_ip': None}}
        res = self._update('subnets', subnet_id, data)['subnet']
        self._verify_subnet_dist_names(res)

        # Test show after removing gateway.
        res = self._show('subnets', subnet_id)['subnet']
        self._verify_subnet_dist_names(res)


class TestPortBinding(ApicAimTestCase):
    def _register_agent(self, host, agent_conf):
        agent = {'host': host}
        agent.update(agent_conf)
        self.plugin.create_or_update_agent(context.get_admin_context(), agent)

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'compute:',
                         'device_id': 'someid'}}
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def test_bind_opflex_agent(self):
        self._register_agent('host1', AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        port = self._bind_port_to_host(port_id, 'host1')['port']
        self.assertEqual('ovs', port['binding:vif_type'])
        self.assertEqual({'port_filter': False, 'ovs_hybrid_plug': False},
                         port['binding:vif_details'])

        # Verify get_gbp_details.
        device = 'tap%s' % port_id
        details = self.driver.get_gbp_details(context.get_admin_context(),
            device=device, host='host1')
        self.assertEqual(port['allowed_address_pairs'],
                         details['allowed_address_pairs'])
        self.assertEqual('NeutronAP', details['app_profile_name'])
        self.assertEqual(device, details['device'])
        self.assertTrue(details['enable_dhcp_optimization'])
        self.assertTrue(details['enable_metadata_optimization'])
        self.assertIn('net1', details['endpoint_group_name'])
        self.assertEqual('host1', details['host'])
        self.assertEqual('test-tenant', details['l3_policy_id'])
        self.assertEqual(port['mac_address'], details['mac_address'])
        self.assertEqual(port_id, details['port_id'])
        self.assertFalse(details['promiscuous_mode'])
        self.assertIn('TestTenantName', details['ptg_tenant'])
        self.assertEqual(1, len(details['subnets']))
        self.assertEqual('someid', details['vm-name'])

        # TODO(rkukura): Verify subnet details. Also, test with
        # variations of DHCP IPs on subnet, dns_nameservers and
        # host_routes values, etc..

    # TODO(rkukura): Add tests for promiscuous_mode cases.

    def test_bind_unsupported_vnic_type(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        vnic_arg = {'binding:vnic_type': 'macvtap'}
        port = self._make_port(self.fmt, net['network']['id'],
                               arg_list=('binding:vnic_type',),
                               **vnic_arg)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']
        self.assertEqual('binding_failed', port['binding:vif_type'])

    # TODO(rkukura): Add tests for opflex, local and unsupported
    # network_type values.


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      ApicAimTestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            ApicAimTestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2,
                     ApicAimTestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        ApicAimTestCase):
    pass


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       ApicAimTestCase):
    pass


class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           ApicAimTestCase):
    pass
