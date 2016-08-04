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

import mock

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import config as aim_cfg
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from keystoneclient.v3 import client as ksc_client
from neutron.api import extensions
from neutron import context
from neutron.db import api as db_api
from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
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


class ApicAimTestMixin(object):

    def initialize_db_config(self, session):
        aim_cfg._get_option_subscriber_manager = mock.Mock()
        self.aim_cfg_manager = aim_cfg.ConfigManager(
            aim_context.AimContext(db_session=session), '')
        self.aim_cfg_manager.replace_all(aim_cfg.CONF)

    def set_override(self, item, value, group=None, host=''):
        # Override DB config as well
        if group:
            aim_cfg.CONF.set_override(item, value, group)
        else:
            aim_cfg.CONF.set_override(item, value)
        self.aim_cfg_manager.to_db(aim_cfg.CONF, host=host)


class ApicAimTestCase(test_address_scope.AddressScopeTestCase,
                      ApicAimTestMixin):

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

        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)
        self.db_session = db_api.get_session()

        self.initialize_db_config(self.db_session)

        super(ApicAimTestCase, self).setUp(PLUGIN_NAME)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.port_create_status = 'DOWN'

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = FakeKeystoneClient
        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj
        self.aim_mgr = aim_manager.AimManager()
        self._app_profile_name = 'NeutronAP'
        self._tenant_name = self._map_name({'id': 'test-tenant',
                                            'name': 'TestTenantName'})

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        super(ApicAimTestCase, self).tearDown()

    def _map_name(self, resource):
        # Assumes no conflicts and no substition needed.
        return resource['name'][:40] + '_' + resource['id'][:5]

    def _find_by_dn(self, dn, cls):
        aim_ctx = aim_context.AimContext(self.db_session)
        resource = cls.from_dn(dn)
        return self.aim_mgr.get(aim_ctx, resource)


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

        # Verify AIM resources.
        aim_bd = self._find_by_dn(
            net['apic:distinguished_names']['BridgeDomain'],
            aim_resource.BridgeDomain)
        aim_epg = self._find_by_dn(
            net['apic:distinguished_names']['EndpointGroup'],
            aim_resource.EndpointGroup)
        self.assertEqual(aim_bd.name, aim_epg.name)
        self.assertEqual(aim_bd.name, aim_epg.bd_name)

        # Test show.
        res = self._show('networks', net_id)['network']
        self._verify_network_dist_names(res)

        # Test update.
        data = {'network': {'name': 'newnamefornet'}}
        res = self._update('networks', net_id, data)['network']
        self._verify_network_dist_names(res)

    # def _verify_subnet_dist_names(self, subnet):
    #     dist_names = subnet.get('apic:distinguished_names')
    #     self.assertIsInstance(dist_names, dict)
    #     if subnet['gateway_ip']:
    #         id = subnet['gateway_ip'] + '/' + subnet['cidr'].split('/')[1]
    #         self._verify_dn(dist_names, 'Subnet', ['tn', 'BD', 'subnet'], id)
    #     else:
    #         self._verify_no_dn(dist_names, 'Subnet')

    # def test_subnet_without_gw(self):
    #     # Test create without gateway.
    #     net = self._make_network(self.fmt, 'net', True)
    #     pools = [{'start': '10.0.0.2', 'end': '10.0.0.254'}]
    #     subnet = self._make_subnet(self.fmt, net, None,
    #                                '10.0.0.0/24',
    #                                allocation_pools=pools)['subnet']
    #     subnet_id = subnet['id']
    #     self._verify_subnet_dist_names(subnet)

    #     # Test show.
    #     res = self._show('subnets', subnet_id)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test update.
    #     data = {'subnet': {'name': 'newnameforsubnet'}}
    #     res = self._update('subnets', subnet_id, data)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test update adding gateay.
    #     data = {'subnet': {'gateway_ip': '10.0.0.1'}}
    #     res = self._update('subnets', subnet_id, data)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test show after adding gateway.
    #     res = self._show('subnets', subnet_id)['subnet']
    #     self._verify_subnet_dist_names(res)

    # def test_subnet_with_gw(self):
    #     # Test create.
    #     net = self._make_network(self.fmt, 'net', True)
    #     subnet = self._make_subnet(self.fmt, net, '10.0.1.1',
    #                                '10.0.1.0/24')['subnet']
    #     subnet_id = subnet['id']
    #     self._verify_subnet_dist_names(subnet)

    #     # Test show.
    #     res = self._show('subnets', subnet_id)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test update.
    #     data = {'subnet': {'name': 'newnameforsubnet'}}
    #     res = self._update('subnets', subnet_id, data)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test update removing gateway.
    #     data = {'subnet': {'gateway_ip': None}}
    #     res = self._update('subnets', subnet_id, data)['subnet']
    #     self._verify_subnet_dist_names(res)

    #     # Test show after removing gateway.
    #     res = self._show('subnets', subnet_id)['subnet']
    #     self._verify_subnet_dist_names(res)

    def _verify_address_scope_dist_names(self, a_s):
        id = a_s['id']
        dist_names = a_s.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        self._verify_dn(dist_names, 'VRF', ['tn', 'ctx'], id[:5])

    def test_address_scope(self):
        # Test create.
        a_s = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        a_s_id = a_s['id']
        self._verify_address_scope_dist_names(a_s)

        # Verify AIM resources.
        aim_vrf = self._find_by_dn(
            a_s['apic:distinguished_names']['VRF'],
            aim_resource.VRF)
        self.assertIsNotNone(aim_vrf.name)
        # REVISIT(rkukura): More to verify?

        # Test show.
        res = self._show('address-scopes', a_s_id)['address_scope']
        self._verify_address_scope_dist_names(res)

        # Test update.
        data = {'address_scope': {'name': 'newnamefora_s'}}
        res = self._update('address-scopes', a_s_id, data)['address_scope']
        self._verify_address_scope_dist_names(res)


class TestNetworkMapping(ApicAimTestCase):
    def _get_tenant(self, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        tenant = aim_resource.Tenant(name=tenant_name)
        tenant = self.aim_mgr.get(aim_ctx, tenant)
        if should_exist:
            self.assertIsNotNone(tenant)
        return tenant

    def _get_vrf(self, vrf_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        vrf = aim_resource.VRF(tenant_name=tenant_name,
                               name=vrf_name)
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        if should_exist:
            self.assertIsNotNone(vrf)
        return vrf

    def _get_bd(self, bd_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        bd = aim_resource.BridgeDomain(tenant_name=tenant_name,
                                       name=bd_name)
        bd = self.aim_mgr.get(aim_ctx, bd)
        if should_exist:
            self.assertIsNotNone(bd)
        return bd

    def _get_epg(self, epg_name, tenant_name, app_profile_name,
                 should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_name,
                                         app_profile_name=app_profile_name,
                                         name=epg_name)
        epg = self.aim_mgr.get(aim_ctx, epg)
        if should_exist:
            self.assertIsNotNone(epg)
        return epg

    def _validate(self, name,
                  tenant_name=None,
                  app_profile_name=None,
                  vrf_name='',
                  enable_arp_flood=False,
                  enable_routing=True,
                  limit_ip_learn_to_subnets=False,
                  l2_unknown_unicast_mode='proxy'):
        tenant_name = tenant_name or self._tenant_name
        app_profile_name = app_profile_name or self._app_profile_name

        aim_bd = self._get_bd(name, tenant_name)
        self.assertEqual(tenant_name, aim_bd.tenant_name)
        self.assertEqual(name, aim_bd.name)
        self.assertEqual('', aim_bd.display_name)
        self.assertEqual(vrf_name, aim_bd.vrf_name)
        self.assertEqual(enable_arp_flood, aim_bd.enable_arp_flood)
        self.assertEqual(enable_routing, aim_bd.enable_routing)
        self.assertEqual(limit_ip_learn_to_subnets,
                         aim_bd.limit_ip_learn_to_subnets)
        self.assertEqual(l2_unknown_unicast_mode,
                         aim_bd.l2_unknown_unicast_mode)
        self.assertEqual('', aim_bd.ep_move_detect_mode)

        aim_epg = self._get_epg(name,
                                tenant_name=tenant_name,
                                app_profile_name=app_profile_name)
        self.assertEqual(tenant_name, aim_epg.tenant_name)
        self.assertEqual(app_profile_name, aim_epg.app_profile_name)
        self.assertEqual(name, aim_epg.name)
        self.assertEqual(name, aim_epg.bd_name)
        self.assertEqual([], aim_epg.provided_contract_names)
        self.assertEqual([], aim_epg.consumed_contract_names)

    def test_initial_create(self):
        # # Validate common tenant does not exist yet.
        # aim_tenant = self._get_tenant('common', should_exist=False)
        # self.assertIsNone(aim_tenant)

        # Create and validate network.

        net = self._make_network(self.fmt, 'net1', True)
        name = self._map_name(net['network'])
        self._validate(name, vrf_name='UnroutedVRF',
                       enable_arp_flood=True,
                       enable_routing=False,
                       limit_ip_learn_to_subnets=True,
                       l2_unknown_unicast_mode='proxy')  # REVISIT

        # Validate common tenant created correctly.
        aim_tenant = self._get_tenant('common')
        self.assertEqual('common', aim_tenant.name)
        self.assertEqual(None, aim_tenant.display_name)  # REVISIT

        # Validate shared unrouted VRF created correctly.
        aim_vrf = self._get_vrf('UnroutedVRF', 'common')
        self.assertEqual('common', aim_vrf.tenant_name)
        self.assertEqual('UnroutedVRF', aim_vrf.name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)

    # def test_create_subnet_with_address_scope(self):
    #     net = self._make_network(self.fmt, 'net1', True)
    #     name = self._map_name(net['network'])
    #     self._validate(name, vrf_name='UnroutedVRF')

    #     a_s = self._make_address_scope(self.fmt, 4, name='as1')
    #     a_s_id = a_s['address_scope']['id']
    #     # vrf_name = self._map_name(a_s['address_scope'])

    #     sp = self._make_subnetpool(self.fmt, ['10.0.0.0/8'], name='sp1',
    #                                tenant_id='test-tenant',  # REVISIT
    #                                address_scope_id=a_s_id,
    #                                default_prefixlen=24)
    #     sp_id = sp['subnetpool']['id']

    #     self._make_subnet(self.fmt, net, None, None, subnetpool_id=sp_id)
    #     # REVISIT(rkukura): Should the address_scopes VRF be used
    #     # immediately, or not until connected to a router?
    #     #
    #     # self._validate(name, vrf_name=vrf_name)
    #     self._validate(name, vrf_name='UnroutedVRF')


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
