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

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import resource as aim_resource
from aim.api import status as aim_status
from aim import config as aim_cfg
from aim import context as aim_context
from aim.db import model_base as aim_model_base

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as extn_db)
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

DN = 'apic:distinguished_names'
CIDR = 'apic:external_cidrs'
PROV = 'apic:external_provided_contracts'
CONS = 'apic:external_consumed_contracts'

aim_resource.ResourceBase.__repr__ = lambda x: x.__dict__.__repr__()


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
        aim_cfg.CONF.register_opts(aim_cfg.global_opts)
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
        self.extension_attributes = ('router:external', DN,
                                     'apic:nat_type', 'apic:snat_host_pool',
                                     CIDR, PROV, CONS)

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

    def _check_dn(self, resource, aim_resource, key):
        dist_names = resource.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        dn = dist_names.get(key)
        self.assertIsInstance(dn, basestring)
        self.assertEqual(aim_resource.dn, dn)

    def _check_no_dn(self, resource, key):
        dist_names = resource.get('apic:distinguished_names')
        if dist_names is not None:
            self.assertIsInstance(dist_names, dict)
            self.assertNotIn(key, dist_names)

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

    def _make_ext_network(self, name, dn=None, nat_type=None, cidrs=None):
        kwargs = {'router:external': True}
        if dn:
            kwargs[DN] = {'ExternalNetwork': dn}
        if nat_type is not None:
            kwargs['apic:nat_type'] = nat_type
        elif getattr(self, 'nat_type', None) is not None:
            kwargs['apic:nat_type'] = self.nat_type
        if cidrs:
            kwargs[CIDR] = cidrs

        return self._make_network(self.fmt, name, True,
                                  arg_list=self.extension_attributes,
                                  **kwargs)['network']


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

    def _check_subnet(self, subnet, net, expected_gws, unexpected_gw_ips):
        prefix_len = subnet['cidr'].split('/')[1]

        # REVISIT(rkukura): Check AIM Tenant here?
        self.assertEqual('test-tenant', subnet['tenant_id'])

        net_aname = self._map_name(net)

        for gw_ip, router in expected_gws:
            gw_ip_mask = gw_ip + '/' + prefix_len
            aim_subnet = self._get_subnet(gw_ip_mask,
                                          net_aname,
                                          self._tenant_name)
            self.assertEqual(self._tenant_name, aim_subnet.tenant_name)
            self.assertEqual(net_aname, aim_subnet.bd_name)
            self.assertEqual(gw_ip_mask, aim_subnet.gw_ip_mask)
            self.assertEqual('private', aim_subnet.scope)
            display_name = ("%s - %s" %
                            (router['name'],
                             (subnet['name'] or subnet['cidr'])))
            self.assertEqual(display_name, aim_subnet.display_name)
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

    def _check_router(self, router, expected_gw_ips, unexpected_gw_ips,
                      orig_router=None, scope=None):
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

        if expected_gw_ips:
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

        # The AIM Subnets are validated in _check_subnet, so just
        # check that their DNs are present and valid.
        dist_names = router.get('apic:distinguished_names')
        for gw_ip in expected_gw_ips:
            self.assertIn(gw_ip, dist_names)
            aim_subnet = self._find_by_dn(dist_names[gw_ip],
                                          aim_resource.Subnet)
            self.assertIsNotNone(aim_subnet)
        for gw_ip in unexpected_gw_ips:
            self.assertNotIn(gw_ip, dist_names)

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
        self._check_router(orig_router, [], [])

        # Test show.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [], [])

        # Test update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [], [], orig_router)

        # Test delete.
        self._delete('routers', router_id)
        self._check_router_deleted(orig_router)

    def test_router_interface(self):
        # Create router.
        orig_router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = orig_router['id']
        self._check_router(orig_router, [], [])

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
        self._check_router(router, [gw1_ip], [])

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Test router update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [gw1_ip], [], orig_router)
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Add subnet2 to router by port.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port2_id = port['id']
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip, gw2_ip], [], orig_router)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[orig_router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [])

        # Remove subnet1 from router by subnet.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw2_ip], [gw1_ip], orig_router)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[orig_router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [])

        # Remove subnet2 from router by port.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [], [gw1_ip, gw2_ip], orig_router)

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
        orig_router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = orig_router['id']
        self._check_router(orig_router, [], [], scope=scope)

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
        self._check_router(router, [gw1_ip], [], scope=scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Test router update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [gw1_ip], [], orig_router, scope)
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Add subnet2 to router by port.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port2_id = port['id']
        info = self.l3_plugin.add_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip, gw2_ip], [], orig_router, scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[orig_router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [])

        # Remove subnet1 from router by subnet.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw2_ip], [gw1_ip], orig_router, scope)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, routers=[orig_router], scope=scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [])

        # Remove subnet2 from router by port.
        info = self.l3_plugin.remove_router_interface(
            context.get_admin_context(), router_id, {'port_id': port2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [], [gw1_ip, gw2_ip], orig_router, scope)

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

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state,
                         router['apic:synchronization_state'])

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

    def _test_external_network(self, expected_state, dn=None, msg=None):
        net = self._make_ext_network('net1', dn=dn)
        self.assertEqual(expected_state, net['apic:synchronization_state'],
                         msg)

        net = self._show('networks', net['id'])['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'],
                         msg)

    def test_external_network(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_external_network('synced',
                                        dn='uni/tn-t1/out-l1/instP-n1')

        for expected_status, status_func in [
                ('build', TestSyncState._get_pending_status_for_type),
                ('error', TestSyncState._get_failed_status_for_type)]:
            for a_res in [aim_resource.ExternalNetwork,
                          aim_resource.EndpointGroup,
                          aim_resource.BridgeDomain,
                          aim_resource.VRF]:
                def get_status(self, context, resource):
                    return status_func(resource, a_res)
                with mock.patch('aim.aim_manager.AimManager.get_status',
                                get_status):
                    self._test_external_network(expected_status,
                                                dn='uni/tn-t1/out-l1/instP-n1',
                                                msg='%s' % a_res)

    def test_unmanaged_external_network(self):
        self._test_external_network('N/A')

    def _test_external_subnet(self, expected_state, dn=None):
        net = self._make_ext_network('net1', dn=dn)
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '10.0.0.1', '10.0.0.0/24')['subnet']

        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

    def test_external_subnet(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_external_subnet('synced',
                                       dn='uni/tn-t1/out-l1/instP-n1')

        for expected_status, status_func in [
                ('build', TestSyncState._get_pending_status_for_type),
                ('error', TestSyncState._get_failed_status_for_type)]:
            def get_status(self, context, resource):
                return status_func(resource, aim_resource.Subnet)
            with mock.patch('aim.aim_manager.AimManager.get_status',
                            get_status):
                self._test_external_subnet(expected_status,
                                           dn='uni/tn-t1/out-l1/instP-n1')

    def test_unmanaged_external_subnet(self):
        self._test_external_subnet('N/A')


class TestPortBinding(ApicAimTestCase):
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


class TestExtensionAttributes(ApicAimTestCase):

    def test_external_network_lifecycle(self):
        session = db_api.get_session()
        extn = extn_db.ExtensionDbMixin()

        # create with APIC DN, nat_typeand default CIDR
        net1 = self._make_ext_network('net1',
                                      dn='uni/tn-t1/out-l1/instP-n1',
                                      nat_type='')

        self.assertEqual('uni/tn-t1/out-l1/instP-n1',
                         net1[DN]['ExternalNetwork'])
        self.assertEqual('', net1['apic:nat_type'])
        self.assertEqual(['0.0.0.0/0'], net1[CIDR])

        # create with nat_type set to default, and CIDR specified
        net2 = self._make_ext_network('net2',
                                      dn='uni/tn-t1/out-l2/instP-n2',
                                      cidrs=['5.5.5.0/24', '10.20.0.0/16'])
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['10.20.0.0/16', '5.5.5.0/24'],
                         sorted(net2[CIDR]))

        # update CIDR
        net2 = self._update('networks', net2['id'],
            {'network': {CIDR: ['20.20.30.0/24']}})['network']
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['20.20.30.0/24'], net2[CIDR])

        net2 = self._update('networks', net2['id'],
            {'network': {CIDR: []}})['network']
        self.assertEqual([], net2[CIDR])

        # create without APIC DN -> this is an unmanaged network
        net3 = self._make_ext_network('net3')
        self.assertTrue(DN not in net3 or 'ExternalNetwork' not in net3[DN])
        self.assertFalse('apic:nat_type' in net3)
        self.assertFalse(CIDR in net3)

        # updating CIDR of unmanaged network is no-op
        net3 = self._update('networks', net3['id'],
            {'network': {CIDR: ['30.30.20.0/24']}})['network']
        self.assertTrue(DN not in net3 or 'ExternalNetwork' not in net3[DN])
        self.assertFalse('apic:nat_type' in net3)
        self.assertFalse(CIDR in net3)

        # delete the external networks
        self._delete('networks', net2['id'])
        self._delete('networks', net1['id'])

        self.assertFalse(extn.get_network_extn_db(session, net1['id']))
        self.assertFalse(extn.get_network_extn_db(session, net2['id']))

    def test_external_network_fail(self):
        # APIC DN not specified
        resp = self._create_network(self.fmt, 'net1', True,
                                    arg_list=self.extension_attributes,
                                    **{'router:external': True,
                                       DN: {'Foo': 'bar'}})
        self.assertEqual(400, resp.status_code)

        # APIC DN is wrong
        resp = self._create_network(self.fmt, 'net1', True,
            arg_list=self.extension_attributes,
            **{'router:external': True,
               DN: {'ExternalNetwork': 'uni/tenant-t1/ext-l1/instP-n2'}})
        self.assertEqual(400, resp.status_code)

        # Update APIC DN, nat-type
        net1 = self._make_ext_network('net1',
                                      dn='uni/tn-t1/out-l1/instP-n1',
                                      nat_type='edge')

        self._update('networks', net1['id'],
            {'network':
             {DN: {'ExternalNetwork': 'uni/tn-t1/out-l1/instP-n2'}}},
            400)
        self._update('networks', net1['id'], {'apic:nat_type': ''}, 400)

    def test_external_subnet_lifecycle(self):
        session = db_api.get_session()
        extn = extn_db.ExtensionDbMixin()

        net1 = self._make_ext_network('net1',
                                      dn='uni/tn-t1/out-l1/instP-n1')
        # create with default value for snat_host_pool
        subnet = self._make_subnet(
            self.fmt, {'network': net1}, '10.0.0.1', '10.0.0.0/24')['subnet']
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertFalse(subnet['apic:snat_host_pool'])

        # Update something other than snat_host_pool
        self._update('subnets', subnet['id'],
                     {'subnet': {'name': 'foo'}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertFalse(subnet['apic:snat_host_pool'])

        # Update snat_host_pool
        self._update('subnets', subnet['id'],
                     {'subnet': {'apic:snat_host_pool': True}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertTrue(subnet['apic:snat_host_pool'])

        self._update('subnets', subnet['id'],
                     {'subnet': {'apic:snat_host_pool': False}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertFalse(subnet['apic:snat_host_pool'])

        # delete subnet
        self._delete('subnets', subnet['id'])
        self.assertFalse(extn.get_subnet_extn_db(session, subnet['id']))

        # Simulate a prior existing subnet (i.e. no extension attrs exist)
        # Get should give default value, and updates should stick
        subnet2 = self._make_subnet(
            self.fmt, {'network': net1}, '20.0.0.1', '20.0.0.0/24')['subnet']
        self._update('subnets', subnet2['id'],
                     {'subnet': {'apic:snat_host_pool': True}})
        with session.begin(subtransactions=True):
            db_obj = session.query(extn_db.SubnetExtensionDb).filter(
                        extn_db.SubnetExtensionDb.subnet_id ==
                        subnet2['id']).one()
            session.delete(db_obj)
        subnet2 = self._show('subnets', subnet2['id'])['subnet']
        self.assertFalse(subnet2['apic:snat_host_pool'])

        self._update('subnets', subnet2['id'],
                     {'subnet': {'apic:snat_host_pool': True}})
        subnet2 = self._show('subnets', subnet2['id'])['subnet']
        self.assertTrue(subnet2['apic:snat_host_pool'])

    def test_router_lifecycle(self):
        session = db_api.get_session()
        extn = extn_db.ExtensionDbMixin()

        # create router with default values
        rtr0 = self._make_router(self.fmt, 'test-tenant',
                                 'router0')['router']
        self.assertEqual([], rtr0[PROV])
        self.assertEqual([], rtr0[CONS])

        # create with specific values
        rtr1 = self._make_router(self.fmt, 'test-tenant', 'router1',
            arg_list=self.extension_attributes,
            **{PROV: ['p1', 'p2', 'k'],
               CONS: ['c1', 'c2', 'k']})['router']
        self.assertEqual(['k', 'p1', 'p2'], sorted(rtr1[PROV]))
        self.assertEqual(['c1', 'c2', 'k'], sorted(rtr1[CONS]))

        # update router
        self._update('routers', rtr1['id'],
                     {'router': {PROV: [], CONS: ['k']}})
        rtr1 = self._show('routers', rtr1['id'])['router']
        self.assertEqual([], rtr1[PROV])
        self.assertEqual(['k'], rtr1[CONS])

        self._update('routers', rtr1['id'],
                     {'router': {PROV: ['p1', 'p2']}})
        rtr1 = self._show('routers', rtr1['id'])['router']
        self.assertEqual(['p1', 'p2'], sorted(rtr1[PROV]))
        self.assertEqual(['k'], rtr1[CONS])

        # delete
        self._delete('routers', rtr1['id'])
        self.assertEqual({PROV: [], CONS: []},
            extn.get_router_extn_db(session, rtr1['id']))

        # Simulate a prior existing router (i.e. no extension attrs exist)
        rtr2 = self._make_router(self.fmt, 'test-tenant', 'router2',
            arg_list=self.extension_attributes,
            **{PROV: ['k'], CONS: ['k']})['router']
        extn.set_router_extn_db(session, rtr2['id'], {PROV: [], CONS: []})
        rtr2 = self._show('routers', rtr2['id'])['router']
        self.assertEqual([], rtr2[PROV])
        self.assertEqual([], rtr2[CONS])

        rtr2 = self._update('routers', rtr2['id'],
                            {'router': {PROV: ['p1', 'p2']}})['router']
        self.assertEqual(['p1', 'p2'], sorted(rtr2[PROV]))
        self.assertEqual([], rtr2[CONS])


class CallRecordWrapper(object):
    # Instrument all method calls in a class to record the call in a mock

    def setUp(self, klass):
        """Returns a mock that records all calls."""
        def record_and_call(func, recorder_func):
            def wrapped(*args, **kwargs):
                ret = func(*args, **kwargs)
                a = args[1:]  # exclude the 'self' argument
                recorder_func(*a, **kwargs)
                return ret
            return wrapped

        self.klass = klass
        recorder = mock.create_autospec(self.klass)
        self.klass.__overridden = {}
        for fn in dir(self.klass):
            val = getattr(self.klass, fn, None)
            if val and callable(val) and not fn.startswith('_'):
                setattr(self.klass, fn,
                        record_and_call(val, getattr(recorder, fn)))
                self.klass.__overridden[fn] = val
        return recorder

    def tearDown(self):
        for k, v in self.klass.__overridden.iteritems():
            setattr(self.klass, k, v)
        del self.klass.__overridden


class TestExternalConnectivityBase(object):

    def setUp(self):
        self.call_wrapper = CallRecordWrapper()
        kls = {'distributed': nat_strategy.DistributedNatStrategy,
               'edge': nat_strategy.EdgeNatStrategy,
               '': nat_strategy.NoNatStrategy}
        self.mock_ns = self.call_wrapper.setUp(kls[self.nat_type])
        super(TestExternalConnectivityBase, self).setUp()

    def tearDown(self):
        self.call_wrapper.tearDown()
        super(TestExternalConnectivityBase, self).tearDown()

    def test_external_network_lifecycle(self):
        net1 = self._make_ext_network('net1',
                                      dn='uni/tn-t1/out-l1/instP-n1',
                                      cidrs=['20.10.0.0/16', '4.4.4.0/24'])
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY,
            aim_resource.L3Outside(tenant_name='t1', name='l1'))
        a_ext_net = aim_resource.ExternalNetwork(
            tenant_name='t1', l3out_name='l1', name='n1')
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['20.10.0.0/16', '4.4.4.0/24'])
        ext_epg = aim_resource.EndpointGroup(
            tenant_name='t1', app_profile_name=self._app_profile_name,
            name='EXT-l1')
        ext_bd = aim_resource.BridgeDomain(tenant_name='t1', name='EXT-l1')
        ext_vrf = aim_resource.VRF(tenant_name='t1', name='EXT-l1')
        self._check_dn(net1, ext_epg, 'EndpointGroup')
        self._check_dn(net1, ext_bd, 'BridgeDomain')
        self._check_dn(net1, ext_vrf, 'VRF')

        net1 = self._show('networks', net1['id'])['network']
        self._check_dn(net1, ext_epg, 'EndpointGroup')
        self._check_dn(net1, ext_bd, 'BridgeDomain')
        self._check_dn(net1, ext_vrf, 'VRF')

        # test no-op CIDR update
        self.mock_ns.reset_mock()
        net1 = self._update('networks', net1['id'],
            {'network': {CIDR: ['4.4.4.0/24', '20.10.0.0/16']}})['network']
        self.mock_ns.update_external_cidrs.assert_not_called()

        # test CIDR update
        self.mock_ns.reset_mock()
        net1 = self._update('networks', net1['id'],
            {'network': {CIDR: ['33.33.33.0/30']}})['network']
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['33.33.33.0/30'])

        # delete
        self.mock_ns.reset_mock()
        self._delete('networks', net1['id'])
        self.mock_ns.delete_l3outside.assert_called_once_with(
            mock.ANY,
            aim_resource.L3Outside(tenant_name='t1', name='l1'))
        self.mock_ns.delete_external_network.assert_called_once_with(
            mock.ANY,
            aim_resource.ExternalNetwork(tenant_name='t1', l3out_name='l1',
                                         name='n1'))

        # create with default CIDR
        self.mock_ns.reset_mock()
        self._make_ext_network('net2',
                               dn='uni/tn-t1/out-l1/instP-n1')
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['0.0.0.0/0'])

    def test_unmanaged_external_network_lifecycle(self):
        net1 = self._make_ext_network('net1')
        self.mock_ns.create_l3outside.assert_not_called()
        self.mock_ns.create_external_network.assert_not_called()
        self.mock_ns.update_external_cidrs.assert_not_called()
        self._check_no_dn(net1, 'EndpointGroup')
        self._check_no_dn(net1, 'BridgeDomain')
        self._check_no_dn(net1, 'VRF')

        self._delete('networks', net1['id'])
        self.mock_ns.delete_l3outside.assert_not_called()
        self.mock_ns.delete_external_network.assert_not_called()

    def test_external_subnet_lifecycle(self):
        net1 = self._make_ext_network('net1',
                                      dn='uni/tn-t1/out-l1/instP-n1')
        subnet = self._make_subnet(
            self.fmt, {'network': net1}, '10.0.0.1', '10.0.0.0/24',
            allocation_pools=[{'start': '10.0.0.2',
                               'end': '10.0.0.250'}])['subnet']
        subnet = self._show('subnets', subnet['id'])['subnet']

        l3out = aim_resource.L3Outside(tenant_name='t1', name='l1')
        self.mock_ns.create_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.1/24')
        ext_sub = aim_resource.Subnet(tenant_name='t1', bd_name='EXT-l1',
                                      gw_ip_mask='10.0.0.1/24')
        self._check_dn(subnet, ext_sub, 'Subnet')

        # Update gateway
        self.mock_ns.reset_mock()
        ext_sub.gw_ip_mask = '10.0.0.251/24'
        self._update('subnets', subnet['id'],
                     {'subnet': {'gateway_ip': '10.0.0.251'}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.mock_ns.delete_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.1/24')
        self.mock_ns.create_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.251/24')
        self._check_dn(subnet, ext_sub, 'Subnet')

        # delete subnet
        self.mock_ns.reset_mock()
        self._delete('subnets', subnet['id'])
        self.mock_ns.delete_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.251/24')

    def test_unmanaged_external_subnet_lifecycle(self):
        net1 = self._make_ext_network('net1')
        subnet = self._make_subnet(
            self.fmt, {'network': net1}, '10.0.0.1', '10.0.0.0/24',
            allocation_pools=[{'start': '10.0.0.2',
                               'end': '10.0.0.250'}])['subnet']

        self.mock_ns.create_subnet.assert_not_called()
        self._check_no_dn(subnet, 'Subnet')
        self.assertEqual('N/A', subnet['apic:synchronization_state'])

        # Update gateway
        self._update('subnets', subnet['id'],
                     {'subnet': {'gateway_ip': '10.0.0.251'}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.mock_ns.delete_subnet.assert_not_called()
        self.mock_ns.create_subnet.assert_not_called()
        self._check_no_dn(subnet, 'Subnet')

        # delete subnet
        self._delete('subnets', subnet['id'])
        self.mock_ns.delete_subnet.assert_not_called()

    def _do_test_router_interface(self, use_addr_scope=False):
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn='uni/tn-t1/out-l1/instP-n1')
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')

        # Each tenant has
        #   1. One subnetpool + address-scope (optional)
        #   2. Two networks with 2 subnets each; subnets come
        #      from the subnetpool if present
        #   3. Two routers with external gateway.
        # Test connects the routers one-by-one to two subnets each,
        # and then removes the router interfaces one-by-one.

        tenants = {'tenant_1': self._map_name({'id': 'tenant_1',
                                               'name': 'Tenant1Name'}),
                   'tenant_2': self._map_name({'id': 'tenant_2',
                                               'name': 'Tenant2Name'})}
        objs = {}
        # Create the networks, subnets, routers etc
        for t in tenants.keys():
            subnetpool = None
            addr_scope = None
            if use_addr_scope:
                addr_scope = self._make_address_scope(
                    self.fmt, 4, name='as1', tenant_id=t)['address_scope']
                subnetpool = self._make_subnetpool(
                    self.fmt, ['10.0.0.0/8'], name='spool1', tenant_id=t,
                    address_scope_id=addr_scope['id'])['subnetpool']
            for ni in range(0, 2):
                net = self._make_network(self.fmt, 'pvt-net%d' % ni, True,
                                        tenant_id=t)['network']
                sp_id = subnetpool['id'] if use_addr_scope else None
                sub1 = self._make_subnet(
                    self.fmt, {'network': net}, '10.%d.1.1' % (10 + ni),
                    '10.%d.1.0/24' % (10 + ni),
                    subnetpool_id=sp_id)['subnet']
                sub2 = self._make_subnet(
                    self.fmt, {'network': net}, '10.%d.2.1' % (10 + ni),
                    '10.%d.2.0/24' % (10 + ni),
                    subnetpool_id=sp_id)['subnet']

                router = self._make_router(
                    self.fmt, t, 'router%d' % ni,
                    arg_list=self.extension_attributes,
                    external_gateway_info={'network_id':
                                           ext_net1['id']},
                    **{PROV: ['pr-%s-%d' % (t, ni)],
                       CONS: ['co-%s-%d' % (t, ni)]})['router']
                objs.setdefault(t, []).append(
                    tuple([router, [sub1, sub2], addr_scope]))
                self.mock_ns.connect_vrf.assert_not_called()

        # Connect the router interfaces to the subnets
        vrf_objs = {}
        for tenant, router_list in objs.iteritems():
            a_vrf = aim_resource.VRF(tenant_name=tenants[tenant],
                                     name='DefaultVRF')
            a_ext_net = aim_resource.ExternalNetwork(
                tenant_name='t1', l3out_name='l1', name='n1')
            for router, subnets, addr_scope in router_list:
                if addr_scope:
                    a_vrf.name = self._map_name(addr_scope)
                contract = self._map_name(router)
                a_ext_net.provided_contract_names.append(contract)
                a_ext_net.provided_contract_names.extend(
                    router[PROV])
                a_ext_net.provided_contract_names.sort()
                a_ext_net.consumed_contract_names.append(contract)
                a_ext_net.consumed_contract_names.extend(
                    router[CONS])
                a_ext_net.consumed_contract_names.sort()

                for idx in range(0, len(subnets)):
                    self.mock_ns.reset_mock()
                    self._router_interface_action('add', router['id'],
                                                  subnets[idx]['id'], None)
                    if idx == 0:
                        cv.assert_called_once_with(mock.ANY, a_ext_net, a_vrf)
                    else:
                        cv.assert_not_called()
            vrf_objs[tenant] = a_ext_net

        # Remove the router interfaces
        for tenant, router_list in objs.iteritems():
            a_vrf = aim_resource.VRF(tenant_name=tenants[tenant],
                                     name='DefaultVRF')
            a_ext_net = vrf_objs.pop(tenant)
            num_router = len(router_list)
            for router, subnets, addr_scope in router_list:
                if addr_scope:
                    a_vrf.name = self._map_name(addr_scope)
                contract = self._map_name(router)
                a_ext_net.provided_contract_names.remove(contract)
                a_ext_net.consumed_contract_names.remove(contract)
                for c in router[PROV]:
                    a_ext_net.provided_contract_names.remove(c)
                for c in router[CONS]:
                    a_ext_net.consumed_contract_names.remove(c)

                for idx in range(0, len(subnets)):
                    self.mock_ns.reset_mock()
                    self._router_interface_action('remove', router['id'],
                                                  subnets[idx]['id'], None)
                    if idx == len(subnets) - 1:
                        num_router -= 1
                        if num_router:
                            cv.assert_called_once_with(mock.ANY, a_ext_net,
                                                       a_vrf)
                        else:
                            dv.assert_called_once_with(mock.ANY, a_ext_net,
                                                       a_vrf)
                    else:
                        cv.assert_not_called()
                        dv.assert_not_called()

        self.mock_ns.reset_mock()
        self._delete('routers', router['id'])
        dv.assert_not_called()

    def test_router_interface(self):
        self._do_test_router_interface(use_addr_scope=False)

    def test_router_interface_addr_scope(self):
        self._do_test_router_interface(use_addr_scope=True)

    def _do_test_router_gateway(self, use_addr_scope=False):
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn='uni/tn-t1/out-l1/instP-n1')
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')
        ext_net2 = self._make_ext_network('ext-net1',
                                          dn='uni/tn-t1/out-l2/instP-n2')
        self._make_subnet(
            self.fmt, {'network': ext_net2}, '200.200.200.1',
            '200.200.200.0/24')

        objs = []
        net = self._make_network(self.fmt, 'pvt-net1', True)['network']
        subnetpool = None
        addr_scope = None
        if use_addr_scope:
            addr_scope = self._make_address_scope(
                self.fmt, 4, name='as1',
                tenant_id=net['tenant_id'])['address_scope']
            subnetpool = self._make_subnetpool(
                self.fmt, ['10.10.0.0/16'],
                name='spool1', address_scope_id=addr_scope['id'],
                tenant_id=net['tenant_id'])['subnetpool']
        sub1 = self._make_subnet(
            self.fmt, {'network': net}, '10.10.1.1',
            '10.10.1.0/24',
            subnetpool_id=subnetpool['id'] if addr_scope else None)['subnet']

        router = self._make_router(
            self.fmt, net['tenant_id'], 'router1',
            arg_list=self.extension_attributes,
            **{PROV: ['pr-1'],
               CONS: ['co-1']})['router']
        objs.append(tuple([router, [sub1]]))

        self._router_interface_action('add', router['id'], sub1['id'], None)
        self.mock_ns.connect_vrf.assert_not_called()

        self.mock_ns.reset_mock()
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net1['id']}}})
        contract = self._map_name(router)
        a_ext_net1 = aim_resource.ExternalNetwork(
            tenant_name='t1', l3out_name='l1', name='n1',
            provided_contract_names=['pr-1', contract],
            consumed_contract_names=['co-1', contract])
        a_vrf = aim_resource.VRF(tenant_name=self._tenant_name,
                                 name='DefaultVRF')
        if use_addr_scope:
            a_vrf.name = self._map_name(addr_scope)
        cv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf)

        self.mock_ns.reset_mock()
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net2['id']}}})
        a_ext_net2 = aim_resource.ExternalNetwork(
            tenant_name='t1', l3out_name='l2', name='n2',
            provided_contract_names=['pr-1', contract],
            consumed_contract_names=['co-1', contract])
        a_ext_net1.provided_contract_names = []
        a_ext_net1.consumed_contract_names = []
        dv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf)
        cv.assert_called_once_with(mock.ANY, a_ext_net2, a_vrf)

        self.mock_ns.reset_mock()
        self._update('routers', router['id'],
                     {'router': {'external_gateway_info': {}}})
        a_ext_net2.provided_contract_names = []
        a_ext_net2.consumed_contract_names = []
        dv.assert_called_once_with(mock.ANY, a_ext_net2, a_vrf)

    def test_router_gateway(self):
        self._do_test_router_gateway(use_addr_scope=False)

    def test_router_gateway_addr_scope(self,):
        self._do_test_router_gateway(use_addr_scope=True)

    def test_router_with_unmanaged_external_network(self):
        ext_net1 = self._make_ext_network('ext-net1')
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')

        net = self._make_network(self.fmt, 'pvt-net1', True)['network']
        sub1 = self._make_subnet(
            self.fmt, {'network': net}, '10.10.1.1',
            '10.10.1.0/24')['subnet']

        router = self._make_router(
            self.fmt, net['tenant_id'], 'router1',
            arg_list=self.extension_attributes,
            external_gateway_info={'network_id': ext_net1['id']},
            **{PROV: ['pr-1'],
               CONS: ['co-1']})['router']

        self._router_interface_action('add', router['id'], sub1['id'], None)
        self.mock_ns.connect_vrf.assert_not_called()

        self._router_interface_action('remove', router['id'], sub1['id'], None)
        self.mock_ns.disconnect_vrf.assert_not_called()

    def _do_test_multiple_router(self, use_addr_scope=False):
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        ext_nets = []
        a_ext_nets = []
        for x in range(0, 2):
            ext_net = self._make_ext_network('ext-net%d' % x,
                dn='uni/tn-t1/out-l%d/instP-n%d' % (x, x))
            self._make_subnet(
                self.fmt, {'network': ext_net}, '100.%d.100.1' % x,
                '100.%d.100.0/24' % x)
            ext_nets.append(ext_net['id'])
            a_ext_net = aim_resource.ExternalNetwork(
                tenant_name='t1', l3out_name='l%d' % x, name='n%d' % x)
            a_ext_nets.append(a_ext_net)

        net = self._make_network(self.fmt, 'pvt-net1', True)['network']
        subnetpool = None
        addr_scope = None
        if use_addr_scope:
            addr_scope = self._make_address_scope(
                self.fmt, 4, name='as1',
                tenant_id=net['tenant_id'])['address_scope']
            subnetpool = self._make_subnetpool(
                self.fmt, ['10.10.0.0/16'],
                name='spool1', address_scope_id=addr_scope['id'],
                tenant_id=net['tenant_id'])['subnetpool']
        sub1 = self._make_subnet(
            self.fmt, {'network': net}, '10.10.1.1',
            '10.10.1.0/24',
            subnetpool_id=subnetpool['id'] if addr_scope else None)['subnet']
        a_vrf = aim_resource.VRF(tenant_name=self._tenant_name,
                                 name='DefaultVRF')
        if use_addr_scope:
            a_vrf.name = self._map_name(addr_scope)

        routers = []
        contracts = []
        for x in range(0, 2):
            r = self._make_router(
                self.fmt, net['tenant_id'], 'router1')['router']
            if x:
                sub_id = None
                intf_port = self._make_port(self.fmt, net['id'],
                        fixed_ips=[{'subnet_id': sub1['id']}])['port']['id']
            else:
                sub_id = sub1['id']
                intf_port = None
            self._router_interface_action('add', r['id'], sub_id,
                                          intf_port)
            routers.append(r['id'])
            contracts.append(self._map_name(r))
        cv.assert_not_called()

        self._add_external_gateway_to_router(routers[0], ext_nets[0])
        a_ext_nets[0].provided_contract_names = [contracts[0]]
        a_ext_nets[0].consumed_contract_names = [contracts[0]]
        cv.assert_called_once_with(mock.ANY, a_ext_nets[0], a_vrf)

        self.mock_ns.reset_mock()
        self._add_external_gateway_to_router(routers[1], ext_nets[1])
        a_ext_nets[1].provided_contract_names = [contracts[1]]
        a_ext_nets[1].consumed_contract_names = [contracts[1]]
        cv.assert_called_once_with(mock.ANY, a_ext_nets[1], a_vrf)

        self.mock_ns.reset_mock()
        self._router_interface_action('remove', routers[0], sub1['id'], None)
        a_ext_nets[0].provided_contract_names = []
        a_ext_nets[0].consumed_contract_names = []
        dv.assert_called_once_with(mock.ANY, a_ext_nets[0], a_vrf)
        cv.assert_not_called()

        self.mock_ns.reset_mock()
        self._router_interface_action('remove', routers[1], sub1['id'], None)
        a_ext_nets[1].provided_contract_names = []
        a_ext_nets[1].consumed_contract_names = []
        dv.assert_called_once_with(mock.ANY, a_ext_nets[1], a_vrf)

    def test_multiple_router(self):
        self._do_test_multiple_router(use_addr_scope=False)

    def test_multiple_router_addr_scope(self):
        self._do_test_multiple_router(use_addr_scope=True)

    def test_floatingip(self):
        net1 = self._make_network(self.fmt, 'pvt-net1', True)['network']
        sub1 = self._make_subnet(
            self.fmt, {'network': net1}, '10.10.1.1', '10.10.1.0/24')
        net2 = self._make_network(self.fmt, 'pvt-net1', True)['network']
        sub2 = self._make_subnet(
            self.fmt, {'network': net2}, '10.10.2.1', '10.10.2.0/24')

        self._register_agent('host1', AGENT_CONF_OPFLEX)
        p = []
        for sub in [sub1, sub2, sub2]:
            with self.port(subnet=sub) as port:
                port = self._bind_port_to_host(port['port']['id'], 'host1')
                port['port']['dns_name'] = None
                p.append(port['port'])

        mock_notif = mock.Mock()
        self.driver.notifier.port_update = mock_notif

        with self.floatingip_no_assoc(sub1) as fip1:
            fip1 = fip1['floatingip']
            self.assertEqual('DOWN', fip1['status'])
            mock_notif.assert_not_called()

            fip1 = self._update('floatingips', fip1['id'],
                                {'floatingip': {'port_id': p[0]['id']}})
            fip1 = fip1['floatingip']
            self.assertEqual('ACTIVE', fip1['status'])
            mock_notif.assert_called_once_with(mock.ANY, p[0])

            mock_notif.reset_mock()
            fip1 = self._update('floatingips', fip1['id'],
                                {'floatingip': {'port_id': None}})
            fip1 = fip1['floatingip']
            self.assertEqual('DOWN', fip1['status'])
            mock_notif.assert_called_once_with(mock.ANY, p[0])

        mock_notif.reset_mock()
        with self.floatingip_with_assoc(port_id=p[1]['id']) as fip2:
            fip2 = fip2['floatingip']
            self.assertEqual('ACTIVE', fip2['status'])
            mock_notif.assert_called_once_with(mock.ANY, p[1])

            mock_notif.reset_mock()
            fip2 = self._update('floatingips', fip2['id'],
                                {'floatingip': {'port_id': p[2]['id']}})
            fip2 = fip2['floatingip']
            calls = [mock.call(mock.ANY, p[1]), mock.call(mock.ANY, p[2])]
            self.assertEqual(len(calls), mock_notif.call_count)
            mock_notif.has_calls(calls)
            self.assertEqual('ACTIVE', fip2['status'])

            mock_notif.reset_mock()
        # fip2 should be deleted at this point
        mock_notif.assert_called_once_with(mock.ANY, p[2])


class TestExternalDistributedNat(TestExternalConnectivityBase,
                                 ApicAimTestCase):
    nat_type = 'distributed'


class TestExternalEdgeNat(TestExternalConnectivityBase,
                          ApicAimTestCase):
    nat_type = 'edge'


class TestExternalNoNat(TestExternalConnectivityBase,
                        ApicAimTestCase):
    nat_type = ''
