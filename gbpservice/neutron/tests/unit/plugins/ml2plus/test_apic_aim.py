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
from aim.api import status as aim_status
from aim import config as aim_cfg
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from keystoneclient.v3 import client as ksc_client
from neutron.api import extensions
from neutron import context
from neutron.db import api as db_api
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2 import config
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_l3
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
        return [
            FakeTenant('another_tenant', 'AnotherTenantName'),
            FakeTenant('bad_tenant_id', 'BadTenantIdName'),
            FakeTenant('not_admin', 'NotAdminName'),
            FakeTenant('some_tenant', 'SomeTenantName'),
            FakeTenant('somebody_else', 'SomebodyElseName'),
            FakeTenant('t1', 'T1Name'),
            FakeTenant('tenant1', 'Tenant1Name'),
            FakeTenant('tenant_1', 'Tenant1Name'),
            FakeTenant('tenant_2', 'Tenant2Name'),
            FakeTenant('test-tenant', 'TestTenantName'),
        ]


class FakeKeystoneClient(object):
    def __init__(self, **kwargs):
        self.projects = FakeProjectManager()


# TODO(rkukura): Also run Neutron L3 tests on apic_aim L3 plugin.

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
                      test_l3.L3NatTestCaseMixin, ApicAimTestMixin):

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

        service_plugins = {
            'L3_ROUTER_NAT':
            'gbpservice.neutron.services.apic_aim.l3_plugin.ApicL3Plugin'}

        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)
        self.db_session = db_api.get_session()

        self.initialize_db_config(self.db_session)

        super(ApicAimTestCase, self).setUp(PLUGIN_NAME,
                                           service_plugins=service_plugins)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.port_create_status = 'DOWN'

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = FakeKeystoneClient
        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj
        self.l3_plugin = manager.NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        self.aim_mgr = aim_manager.AimManager()
        self._app_profile_name = self.driver.ap_name
        self._tenant_name = self._map_name({'id': 'test-tenant',
                                            'name': 'TestTenantName'})

    def tearDown(self):
        engine = db_api.get_engine()
        with engine.begin() as conn:
            for table in reversed(
                aim_model_base.Base.metadata.sorted_tables):
                conn.execute(table.delete())
        ksc_client.Client = self.saved_keystone_client
        super(ApicAimTestCase, self).tearDown()

    def _map_name(self, resource):
        # Assumes no conflicts and no substition needed.
        return resource['name'][:40] + '_' + resource['id'][:5]

    def _find_by_dn(self, dn, cls):
        aim_ctx = aim_context.AimContext(self.db_session)
        resource = cls.from_dn(dn)
        return self.aim_mgr.get(aim_ctx, resource)


class TestAimMapping(ApicAimTestCase):
    def _get_tenant(self, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        tenant = aim_resource.Tenant(name=tenant_name)
        tenant = self.aim_mgr.get(aim_ctx, tenant)
        if should_exist:
            self.assertIsNotNone(tenant)
        else:
            self.assertIsNone(tenant)
        return tenant

    def _get_vrf(self, vrf_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        vrf = aim_resource.VRF(tenant_name=tenant_name,
                               name=vrf_name)
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        if should_exist:
            self.assertIsNotNone(vrf)
        else:
            self.assertIsNone(vrf)
        return vrf

    def _get_bd(self, bd_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        bd = aim_resource.BridgeDomain(tenant_name=tenant_name,
                                       name=bd_name)
        bd = self.aim_mgr.get(aim_ctx, bd)
        if should_exist:
            self.assertIsNotNone(bd)
        else:
            self.assertIsNone(bd)
        return bd

    def _get_subnet(self, gw_ip_mask, bd_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        subnet = aim_resource.Subnet(tenant_name=tenant_name,
                                     bd_name=bd_name,
                                     gw_ip_mask=gw_ip_mask)
        subnet = self.aim_mgr.get(aim_ctx, subnet)
        if should_exist:
            self.assertIsNotNone(subnet)
        else:
            self.assertIsNone(subnet)
        return subnet

    def _get_epg(self, epg_name, tenant_name, app_profile_name,
                 should_exist=True):
        session = self.db_session
        aim_ctx = aim_context.AimContext(session)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_name,
                                         app_profile_name=app_profile_name,
                                         name=epg_name)
        epg = self.aim_mgr.get(aim_ctx, epg)
        if should_exist:
            self.assertIsNotNone(epg)
        else:
            self.assertIsNone(epg)
        return epg

    def _get_contract(self, contract_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        contract = aim_resource.Contract(tenant_name=tenant_name,
                                         name=contract_name)
        contract = self.aim_mgr.get(aim_ctx, contract)
        if should_exist:
            self.assertIsNotNone(contract)
        else:
            self.assertIsNone(contract)
        return contract

    def _get_subject(self, subject_name, contract_name, tenant_name,
                     should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        subject = aim_resource.ContractSubject(tenant_name=tenant_name,
                                               contract_name=contract_name,
                                               name=subject_name)
        subject = self.aim_mgr.get(aim_ctx, subject)
        if should_exist:
            self.assertIsNotNone(subject)
        else:
            self.assertIsNone(subject)
        return subject

    def _get_filter(self, filter_name, tenant_name, should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        filter = aim_resource.Filter(tenant_name=tenant_name,
                                     name=filter_name)
        filter = self.aim_mgr.get(aim_ctx, filter)
        if should_exist:
            self.assertIsNotNone(filter)
        else:
            self.assertIsNone(filter)
        return filter

    def _get_filter_entry(self, entry_name, filter_name, tenant_name,
                          should_exist=True):
        session = db_api.get_session()
        aim_ctx = aim_context.AimContext(session)
        entry = aim_resource.FilterEntry(tenant_name=tenant_name,
                                         filter_name=filter_name,
                                         name=entry_name)
        entry = self.aim_mgr.get(aim_ctx, entry)
        if should_exist:
            self.assertIsNotNone(entry)
        else:
            self.assertIsNone(entry)
        return entry

    def _check_dn(self, resource, aim_resource, key):
        dist_names = resource.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        dn = dist_names.get(key)
        self.assertIsInstance(dn, basestring)
        self.assertEqual(aim_resource.dn, dn)

    def _check_no_dn(self, resource, key):
        dist_names = resource.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        self.assertNotIn(key, dist_names)

    def _check_network(self, net, orig_net=None, routers=None, scope=None):
        orig_net = orig_net or net

        # REVISIT(rkukura): Check AIM Tenant here?
        self.assertEqual('test-tenant', net['tenant_id'])

        aname = self._map_name(orig_net)

        router_anames = [self._map_name(router) for router in routers or []]

        if routers:
            if scope:
                vrf_aname = self._map_name(scope)
                vrf_dname = scope['name']
                vrf_tenant_aname = self._tenant_name
                vrf_tenant_dname = None
            else:
                vrf_aname = 'DefaultVRF'
                vrf_dname = 'Default Routed VRF'
                vrf_tenant_aname = self._tenant_name
                vrf_tenant_dname = None
        else:
            vrf_aname = 'UnroutedVRF'
            vrf_dname = 'Common Unrouted VRF'
            vrf_tenant_aname = 'common'
            vrf_tenant_dname = 'Common Tenant'

        aim_bd = self._get_bd(aname,
                              self._tenant_name)
        self.assertEqual(self._tenant_name, aim_bd.tenant_name)
        self.assertEqual(aname, aim_bd.name)
        self.assertEqual(net['name'], aim_bd.display_name)
        self.assertEqual(vrf_aname, aim_bd.vrf_name)
        self.assertTrue(aim_bd.enable_arp_flood)
        if routers:
            self.assertTrue(aim_bd.enable_routing)
        else:
            self.assertFalse(aim_bd.enable_routing)
        self.assertTrue(aim_bd.limit_ip_learn_to_subnets)
        self.assertEqual('proxy', aim_bd.l2_unknown_unicast_mode)
        self.assertEqual('garp', aim_bd.ep_move_detect_mode)
        self._check_dn(net, aim_bd, 'BridgeDomain')

        aim_epg = self._get_epg(aname,
                                tenant_name=self._tenant_name,
                                app_profile_name=self._app_profile_name)
        self.assertEqual(self._tenant_name, aim_epg.tenant_name)
        self.assertEqual(self._app_profile_name, aim_epg.app_profile_name)
        self.assertEqual(aname, aim_epg.name)
        self.assertEqual(net['name'], aim_epg.display_name)
        self.assertEqual(aname, aim_epg.bd_name)
        self.assertItemsEqual(router_anames, aim_epg.provided_contract_names)
        self.assertItemsEqual(router_anames, aim_epg.consumed_contract_names)
        # REVISIT(rkukura): Check openstack_vmm_domain_names and
        # physical_domain_names?
        self._check_dn(net, aim_epg, 'EndpointGroup')

        aim_tenant = self._get_tenant(vrf_tenant_aname)
        self.assertEqual(vrf_tenant_aname, aim_tenant.name)
        self.assertEqual(vrf_tenant_dname, aim_tenant.display_name)

        aim_vrf = self._get_vrf(vrf_aname,
                                vrf_tenant_aname)
        self.assertEqual(vrf_tenant_aname, aim_vrf.tenant_name)
        self.assertEqual(vrf_aname, aim_vrf.name)
        self.assertEqual(vrf_dname, aim_vrf.display_name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)
        self._check_dn(net, aim_vrf, 'VRF')

    def _check_network_deleted(self, net):
        aname = self._map_name(net)

        self._get_bd(aname,
                     self._tenant_name,
                     should_exist=False)

        self._get_epg(aname,
                      tenant_name=self._tenant_name,
                      app_profile_name=self._app_profile_name,
                      should_exist=False)

    def _check_subnet(self, subnet, net, expected_gw_ips, unexpected_gw_ips):
        prefix_len = subnet['cidr'].split('/')[1]

        # REVISIT(rkukura): Check AIM Tenant here?
        self.assertEqual('test-tenant', subnet['tenant_id'])

        net_aname = self._map_name(net)

        for gw_ip in expected_gw_ips:
            gw_ip_mask = gw_ip + '/' + prefix_len
            aim_subnet = self._get_subnet(gw_ip_mask,
                                          net_aname,
                                          self._tenant_name)
            self.assertEqual(self._tenant_name, aim_subnet.tenant_name)
            self.assertEqual(net_aname, aim_subnet.bd_name)
            self.assertEqual(gw_ip_mask, aim_subnet.gw_ip_mask)
            self.assertEqual('private', aim_subnet.scope)
            self.assertEqual(subnet['name'], aim_subnet.display_name)
            self._check_dn(subnet, aim_subnet, gw_ip)

        for gw_ip in unexpected_gw_ips:
            gw_ip_mask = gw_ip + '/' + prefix_len
            self._get_subnet(gw_ip_mask,
                             net_aname,
                             self._tenant_name,
                             should_exist=False)
            self._check_no_dn(subnet, gw_ip)

    def _check_subnet_deleted(self, subnet):
        # REVISIT(rkukura): Anything to check? We could find all the
        # AIM Subnets with the network's bd_name, and make sure none
        # are in this subnet.
        pass

    def _check_address_scope(self, scope, orig_scope=None):
        orig_scope = orig_scope or scope

        # REVISIT(rkukura): Check AIM Tenant here?
        self.assertEqual('test-tenant', scope['tenant_id'])

        aname = self._map_name(orig_scope)

        aim_vrf = self._get_vrf(aname,
                                self._tenant_name)
        self.assertEqual(self._tenant_name, aim_vrf.tenant_name)
        self.assertEqual(aname, aim_vrf.name)
        self.assertEqual(scope['name'], aim_vrf.display_name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)
        self._check_dn(scope, aim_vrf, 'VRF')

    def _check_address_scope_deleted(self, scope):
        aname = self._map_name(scope)

        self._get_vrf(aname,
                      self._tenant_name,
                      should_exist=False)

    def _check_router(self, router, orig_router=None, active=False,
                      scope=None):
        orig_router = orig_router or router

        # REVISIT(rkukura): Check AIM Tenant here?
        self.assertEqual('test-tenant', router['tenant_id'])

        aname = self._map_name(orig_router)

        aim_contract = self._get_contract(aname, self._tenant_name)
        self.assertEqual(self._tenant_name, aim_contract.tenant_name)
        self.assertEqual(aname, aim_contract.name)
        self.assertEqual(router['name'], aim_contract.display_name)
        self.assertEqual('context', aim_contract.scope)  # REVISIT(rkukura)
        self._check_dn(router, aim_contract, 'Contract')

        aim_subject = self._get_subject('route', aname, self._tenant_name)
        self.assertEqual(self._tenant_name, aim_subject.tenant_name)
        self.assertEqual(aname, aim_subject.contract_name)
        self.assertEqual('route', aim_subject.name)
        self.assertEqual(router['name'], aim_subject.display_name)
        self.assertEqual([], aim_subject.in_filters)
        self.assertEqual([], aim_subject.out_filters)
        self.assertEqual(['AnyFilter'], aim_subject.bi_filters)
        self._check_dn(router, aim_subject, 'ContractSubject')

        self._check_any_filter()

        # TODO(rkukura): Once AIM Subnets are exposed on router, pass
        # in expected_gw_ips and use instead of this active flag.
        if active:
            if scope:
                vrf_aname = self._map_name(scope)
                vrf_dname = scope['name']
                vrf_tenant_aname = self._tenant_name
                vrf_tenant_dname = None
            else:
                vrf_aname = 'DefaultVRF'
                vrf_dname = 'Default Routed VRF'
                vrf_tenant_aname = self._tenant_name
                vrf_tenant_dname = None

            aim_tenant = self._get_tenant(vrf_tenant_aname)
            self.assertEqual(vrf_tenant_aname, aim_tenant.name)
            self.assertEqual(vrf_tenant_dname, aim_tenant.display_name)

            aim_vrf = self._get_vrf(vrf_aname,
                                    vrf_tenant_aname)
            self.assertEqual(vrf_tenant_aname, aim_vrf.tenant_name)
            self.assertEqual(vrf_aname, aim_vrf.name)
            self.assertEqual(vrf_dname, aim_vrf.display_name)
            self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)
            self._check_dn(router, aim_vrf, 'VRF')
        else:
            self._check_no_dn(router, 'VRF')

    def _check_router_deleted(self, router):
        aname = self._map_name(router)

        self._get_contract(aname, self._tenant_name, should_exist=False)

        self._get_subject('route', aname, self._tenant_name,
                          should_exist=False)

    def _check_any_filter(self):
        aim_filter = self._get_filter('AnyFilter', self._tenant_name)
        self.assertEqual(self._tenant_name, aim_filter.tenant_name)
        self.assertEqual('AnyFilter', aim_filter.name)
        self.assertEqual('Any Filter', aim_filter.display_name)

        aim_entry = self._get_filter_entry('AnyFilterEntry', 'AnyFilter',
                                           self._tenant_name)
        self.assertEqual(self._tenant_name, aim_entry.tenant_name)
        self.assertEqual('AnyFilter', aim_entry.filter_name)
        self.assertEqual('AnyFilterEntry', aim_entry.name)
        self.assertEqual('Any FilterEntry', aim_entry.display_name)
        self.assertEqual('unspecified', aim_entry.arp_opcode)
        self.assertEqual('unspecified', aim_entry.ether_type)
        self.assertEqual('unspecified', aim_entry.ip_protocol)
        self.assertEqual('unspecified', aim_entry.icmpv4_type)
        self.assertEqual('unspecified', aim_entry.icmpv6_type)
        self.assertEqual('unspecified', aim_entry.source_from_port)
        self.assertEqual('unspecified', aim_entry.source_to_port)
        self.assertEqual('unspecified', aim_entry.dest_from_port)
        self.assertEqual('unspecified', aim_entry.dest_to_port)
        self.assertEqual('unspecified', aim_entry.tcp_flags)
        self.assertFalse(aim_entry.stateful)
        self.assertFalse(aim_entry.fragment_only)

    def test_network_lifecycle(self):
        # Test create.
        orig_net = self._make_network(self.fmt, 'net1', True)['network']
        net_id = orig_net['id']
        self._check_network(orig_net)

        # Test show.
        net = self._show('networks', net_id)['network']
        self._check_network(net)

        # Test update.
        data = {'network': {'name': 'newnamefornet'}}
        net = self._update('networks', net_id, data)['network']
        self._check_network(net, orig_net)

        # Test delete.
        self._delete('networks', net_id)
        self._check_network_deleted(orig_net)

    def test_subnet_lifecycle(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']

        # Test create.
        gw_ip = '10.0.0.1'
        subnet = self._make_subnet(
            self.fmt, net_resp, gw_ip, '10.0.0.0/24')['subnet']
        subnet_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw_ip])

        # Test show.
        subnet = self._show('subnets', subnet_id)['subnet']
        self._check_subnet(subnet, net, [], [gw_ip])

        # Test update.
        data = {'subnet': {'name': 'newnamefornet'}}
        subnet = self._update('subnets', subnet_id, data)['subnet']
        self._check_subnet(subnet, net, [], [gw_ip])

        # Test delete.
        self._delete('subnets', subnet_id)
        self._check_subnet_deleted(subnet)

    def test_address_scope_lifecycle(self):
        # Test create.
        orig_scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = orig_scope['id']
        self._check_address_scope(orig_scope)

        # Test show.
        scope = self._show('address-scopes', scope_id)['address_scope']
        self._check_address_scope(scope)

        # Test update.
        data = {'address_scope': {'name': 'newnameforaddressscope'}}
        scope = self._update('address-scopes', scope_id, data)['address_scope']
        self._check_address_scope(scope, orig_scope)

        # Test delete.
        self._delete('address-scopes', scope_id)
        self._check_address_scope_deleted(orig_scope)

    def test_router_lifecycle(self):
        # Test create.
        orig_router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = orig_router['id']
        self._check_router(orig_router)

        # Test show.
        router = self._show('routers', router_id)['router']
        self._check_router(router)

        # Test update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, orig_router)

        # Test delete.
        self._delete('routers', router_id)
        self._check_router_deleted(orig_router)

    def test_router_interface(self):
        # Create router.
        router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = router['id']
        self._check_router(router)

        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']
        net_id = net['id']
        self._check_network(net)

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        subnet = self._make_subnet(self.fmt, net_resp, gw1_ip,
                                   '10.0.1.0/24')['subnet']
        subnet1_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Create subnet2.
        gw2_ip = '10.0.2.1'
        subnet = self._make_subnet(self.fmt, net_resp, gw2_ip,
                                   '10.0.2.0/24')['subnet']
        subnet2_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Add subnet1 to router by subnet.
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Add subnet2 to router by port.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port2_id = port['id']
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [gw2_ip], [])

        # Remove subnet1 from router by subnet.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [gw2_ip], [])

        # Remove subnet2 from router by port.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

    def test_router_interface_with_address_scope(self):
        # REVISIT(rkukura): Currently follows same workflow as above,
        # but might be sufficient to test with a single subnet with
        # its CIDR allocated from the subnet pool.

        # Create address scope.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = scope['id']
        self._check_address_scope(scope)

        # Create subnet pool.
        pool = self._make_subnetpool(self.fmt, ['10.0.0.0/8'], name='sp1',
                                     tenant_id='test-tenant',  # REVISIT
                                     address_scope_id=scope_id,
                                     default_prefixlen=24)['subnetpool']
        pool_id = pool['id']

        # Create router.
        router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = router['id']
        self._check_router(router, scope=scope)

        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']
        net_id = net['id']
        self._check_network(net)

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        subnet = self._make_subnet(
            self.fmt, net_resp, gw1_ip, '10.0.1.0/24',
            subnetpool_id=pool_id)['subnet']
        subnet1_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Create subnet2.
        gw2_ip = '10.0.2.1'
        subnet = self._make_subnet(
            self.fmt, net_resp, gw2_ip, '10.0.2.0/24',
            subnetpool_id=pool_id)['subnet']
        subnet2_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Add subnet1 to router by subnet.
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True, scope=scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Add subnet2 to router by port.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port2_id = port['id']
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True, scope=scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [gw1_ip], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [gw2_ip], [])

        # Remove subnet1 from router by subnet.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, active=True, scope=scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [gw2_ip], [])

        # Remove subnet2 from router by port.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, scope=scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

    # TODO(rkukura): Test IPv6 and dual stack router interfaces.


class TestSyncState(ApicAimTestCase):
    @staticmethod
    def _get_synced_status(self, context, resource):
        status = aim_status.AciStatus.SYNCED
        return aim_status.AciStatus(sync_status=status)

    @staticmethod
    def _get_pending_status_for_type(resource, type):
        status = (isinstance(resource, type) and
                  aim_status.AciStatus.SYNC_PENDING or
                  aim_status.AciStatus.SYNCED)
        return aim_status.AciStatus(sync_status=status)

    @staticmethod
    def _get_failed_status_for_type(resource, type):
        status = (isinstance(resource, type) and
                  aim_status.AciStatus.SYNC_FAILED or
                  aim_status.AciStatus.SYNC_PENDING)
        return aim_status.AciStatus(sync_status=status)

    def _test_network(self, expected_state):
        net = self._make_network(self.fmt, 'net1', True)['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'])

        net = self._show('networks', net['id'])['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'])

    def test_network_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_network('synced')

    def test_network_bd_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.BridgeDomain)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('build')

    def test_network_bd_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.BridgeDomain)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('error')

    def test_network_epg_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.EndpointGroup)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('build')

    def test_network_epg_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.EndpointGroup)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('error')

    def test_network_vrf_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('build')

    def test_network_vrf_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_network('error')

    def _test_address_scope(self, expected_state):
        scope = self._make_address_scope(self.fmt, 4, name='scope1')[
            'address_scope']
        self.assertEqual(expected_state, scope['apic:synchronization_state'])

        scope = self._show('address-scopes', scope['id'])['address_scope']
        self.assertEqual(expected_state, scope['apic:synchronization_state'])

    def test_address_scope_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_address_scope('synced')

    def test_address_scope_vrf_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_address_scope('build')

    def test_address_scope_vrf_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_address_scope('error')

    def _test_router(self, expected_state):
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

    def test_router_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router('synced')

    def test_router_contract_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.Contract)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('build')

    def test_router_contract_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.Contract)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('error')

    def test_router_subject_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.ContractSubject)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('build')

    def test_router_subject_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.ContractSubject)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('error')

    def _test_router_interface_vrf(self, expected_state):
        net_resp = self._make_network(self.fmt, 'net1', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.0.1', '10.0.0.0/24')['subnet']
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.l3_plugin.add_router_interface(
            context.get_admin_context(), router['id'],
            {'subnet_id': subnet['id']})

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

    def test_router_interface_vrf_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router_interface_vrf('synced')

    def test_router_interface_vrf_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_vrf('build')

    def test_router_interface_vrf_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_vrf('error')

    def _test_router_interface_subnet(self, expected_state):
        net_resp = self._make_network(self.fmt, 'net1', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.0.1', '10.0.0.0/24')['subnet']
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.l3_plugin.add_router_interface(
            context.get_admin_context(), router['id'],
            {'subnet_id': subnet['id']})

        # TODO(rkukura): Enable when exposing Subnets on router is implemented.
        # router = self._show('routers', router['id'])['router']
        # self.assertEqual(expected_state,
        #                  router['apic:synchronization_state'])

        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

    def test_router_interface_subnet_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router_interface_subnet('synced')

    def test_router_interface_subnet_build(self):
        def get_status(self, context, resource):
            return TestSyncState._get_pending_status_for_type(
                resource, aim_resource.Subnet)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_subnet('build')

    def test_router_interface_subnet_error(self):
        def get_status(self, context, resource):
            return TestSyncState._get_failed_status_for_type(
                resource, aim_resource.Subnet)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_subnet('error')


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

    def test_aim_epg_domains(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.VMMDomain(type='OpenStack',
                                                   name='vm1'),
                            overwrite=True)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.VMMDomain(type='OpenStack',
                                                   name='vm2'),
                            overwrite=True)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.PhysicalDomain(name='ph1'),
                            overwrite=True)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.PhysicalDomain(name='ph2'),
                            overwrite=True)
        with self.network(name='net'):
            epg = self.aim_mgr.find(aim_ctx, aim_resource.EndpointGroup)[0]
            self.assertEqual(set(['vm1', 'vm2']),
                             set(epg.openstack_vmm_domain_names))
            self.assertEqual(set(['ph1', 'ph2']),
                             set(epg.physical_domain_names))


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       ApicAimTestCase):
    pass


class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           ApicAimTestCase):
    pass
