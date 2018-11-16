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

import copy
import fixtures
import mock
import netaddr
import six
import testtools

from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim.api import status as aim_status
from aim import config as aim_cfg
from aim import context as aim_context
from aim.db import model_base as aim_model_base
from aim.db import models as aim_models  # noqa
from aim import utils as aim_utils

from keystoneclient.v3 import client as ksc_client
from neutron.api import extensions
from neutron.db import api as db_api
from neutron.db import provisioning_blocks
from neutron.db import segments_db
from neutron.plugins.ml2 import driver_context
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup
from neutron.tests.unit.plugins.ml2 import test_tracked_resources as tr_res
from neutron.tests.unit import testlib_api
from neutron_lib.callbacks import registry
from neutron_lib import constants as n_constants
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from opflexagent import constants as ofcst
from oslo_config import cfg
import webob.exc

from gbpservice.neutron.db import all_models  # noqa
from gbpservice.neutron.extensions import cisco_apic_l3 as l3_ext
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (  # noqa
    config as aimcfg)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as extn_db)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import data_migrations
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import exceptions
from gbpservice.neutron.plugins.ml2plus import patch_neutron
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as pd_api)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_validation as av)

PLUGIN_NAME = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'

AGENT_CONF_OPFLEX = {'alive': True, 'binary': 'somebinary',
                     'topic': 'sometopic',
                     'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
                     'configurations': {
                         'opflex_networks': None,
                         'bridge_mappings': {'physnet1': 'br-eth1'}}}

AGENT_CONF_OVS = {'alive': True, 'binary': 'somebinary',
                  'topic': 'sometopic',
                  'agent_type': n_constants.AGENT_TYPE_OVS,
                  'configurations': {
                      'bridge_mappings': {'physnet1': 'br-eth1',
                                          'physnet2': 'br-eth2',
                                          'physnet3': 'br-eth3'}}}
AGENT_TYPE_DVS = md.AGENT_TYPE_DVS
AGENT_CONF_DVS = {'alive': True, 'binary': 'anotherbinary',
                  'topic': 'anothertopic', 'agent_type': AGENT_TYPE_DVS,
                  'configurations': {'opflex_networks': None}}

AGENT_TYPE_VPP = ofcst.AGENT_TYPE_OPFLEX_VPP
AGENT_CONF_VPP = {'alive': True, 'binary': 'somebinary',
                  'topic': 'sometopic', 'agent_type': AGENT_TYPE_VPP,
                  'configurations': {
                      'opflex_networks': None,
                      'vhostuser_socket_dir': '/var/run/vpp-sockets'}}

AGENT_CONF_OPFLEX_OVS_DPDK = {'alive': True, 'binary': 'somebinary',
                              'topic': 'sometopic',
                              'agent_type': ofcst.AGENT_TYPE_OPFLEX_OVS,
                              'configurations': {
                                  'opflex_networks': None,
                                  'bridge_mappings': {'physnet1': 'br-eth1'},
                                  'vhostuser_socket_dir':
                                      '/var/run/openvswitch',
                                  'datapath_type': 'netdev'}}
BOOKED_PORT_VALUE = 'myBookedPort'

DN = 'apic:distinguished_names'
CIDR = 'apic:external_cidrs'
PROV = 'apic:external_provided_contracts'
CONS = 'apic:external_consumed_contracts'
SNAT_POOL = 'apic:snat_host_pool'
SVI = 'apic:svi'
BGP = 'apic:bgp_enable'
ASN = 'apic:bgp_asn'
BGP_TYPE = 'apic:bgp_type'


def sort_if_list(attr):
    return sorted(attr) if isinstance(attr, list) else attr


def resource_equal(self, other):
    if type(self) != type(other):
        return False
    for attr in self.user_attributes():
        if (sort_if_list(getattr(self, attr, None)) !=
                sort_if_list(getattr(other, attr, None))):
            return False
    return True


aim_resource.ResourceBase.__repr__ = lambda x: x.__dict__.__repr__()

TEST_TENANT_NAMES = {
    'another_tenant': 'AnotherTenantName',
    'bad_tenant_id': 'BadTenantIdName',
    'not_admin': 'NotAdminName',
    'some_tenant': 'SomeTenantName',
    'somebody_else': 'SomebodyElseName',
    't1': 'T1Name',
    'tenant1': 'Tenant1Name',
    'tenant_1': 'Tenant1Name',
    'tenant_2': 'Tenant2Name',
    'test-tenant': 'TestTenantName',
    test_plugin.TEST_TENANT_ID: test_plugin.TEST_TENANT_ID,
}


# REVISIT(rkukura): Use mock for this instead?
class FakeTenant(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name


class FakeProjectManager(object):
    def list(self):
        return [FakeTenant(k, v) for k, v in six.iteritems(TEST_TENANT_NAMES)]

    def get(self, project_id):
        return FakeTenant('test-tenant', 'new_name')


class FakeKeystoneClient(object):
    def __init__(self, **kwargs):
        self.projects = FakeProjectManager()


class AimSqlFixture(fixtures.Fixture):

    # Flag to indicate that the models have been loaded.
    _AIM_TABLES_ESTABLISHED = False

    def _setUp(self):
        # Ensure Neutron has done its setup first.
        self.useFixture(testlib_api.StaticSqlFixture())

        # Register all data models.
        engine = db_api.context_manager.writer.get_engine()
        if not AimSqlFixture._AIM_TABLES_ESTABLISHED:
            aim_model_base.Base.metadata.create_all(engine)
            AimSqlFixture._AIM_TABLES_ESTABLISHED = True

        def clear_tables():
            with engine.begin() as conn:
                for table in reversed(
                        aim_model_base.Base.metadata.sorted_tables):
                    conn.execute(table.delete())

        self.addCleanup(clear_tables)


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

    def _register_agent(self, host, agent_conf):
        agent = {'host': host}
        agent.update(agent_conf)
        self.plugin.create_or_update_agent(
            n_context.get_admin_context(), agent)

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

    def _mock_aim_obj_eq_operator(self):
        self.aim_patch = mock.patch("aim.api.resource.ResourceBase.__eq__",
                                    new=resource_equal)
        self.aim_patch.start()
        self.addCleanup(self.aim_patch.stop)


class ApicAimTestCase(test_address_scope.AddressScopeTestCase,
                      test_l3.L3NatTestCaseMixin, ApicAimTestMixin,
                      test_securitygroup.SecurityGroupsTestCase):

    def setUp(self, mechanism_drivers=None, tenant_network_types=None,
            plugin=None, ext_mgr=None):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        mech = mechanism_drivers or ['logger', 'apic_aim']
        cfg.CONF.set_override('mechanism_drivers', mech,
                group='ml2')
        cfg.CONF.set_override('extension_drivers',
                ['apic_aim', 'port_security', 'dns'],
                group='ml2')
        cfg.CONF.set_override('api_extensions_path', None)
        cfg.CONF.set_override('type_drivers',
                ['opflex', 'local', 'vlan'], group='ml2')
        net_type = tenant_network_types or ['opflex']
        cfg.CONF.set_override('tenant_network_types', net_type,
                group='ml2')
        cfg.CONF.set_override('network_vlan_ranges',
                ['physnet1:1000:1099', 'physnet2:123:165',
                    'physnet3:347:513'], group='ml2_type_vlan')
        service_plugins = {
            'L3_ROUTER_NAT':
            'gbpservice.neutron.services.apic_aim.l3_plugin.ApicL3Plugin'}

        self.useFixture(AimSqlFixture())
        super(ApicAimTestCase, self).setUp(PLUGIN_NAME,
                                           service_plugins=service_plugins)
        self.db_session = db_api.get_writer_session()
        self.initialize_db_config(self.db_session)

        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.port_create_status = 'DOWN'

        self.validation_mgr = av.ValidationManager()

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = FakeKeystoneClient
        self.plugin = directory.get_plugin()
        self.plugin.start_rpc_listeners()
        self.driver = self.plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj
        self.l3_plugin = directory.get_plugin(n_constants.L3)
        self.aim_mgr = aim_manager.AimManager()
        self._app_profile_name = self.driver.ap_name
        self.extension_attributes = ('router:external', DN,
                                     'apic:nat_type', SNAT_POOL,
                                     CIDR, PROV, CONS, SVI,
                                     BGP, BGP_TYPE, ASN
                                     )
        self.name_mapper = apic_mapper.APICNameMapper()
        self.t1_aname = self.name_mapper.project(None, 't1')
        self.t2_aname = self.name_mapper.project(None, 't2')
        self.dn_t1_l1_n1 = ('uni/tn-%s/out-l1/instP-n1' %
                            self.t1_aname)
        self.dn_t1_l2_n2 = ('uni/tn-%s/out-l2/instP-n2' %
                            self.t1_aname)
        # The following is done to stop the neutron code from checking
        # for dhcp agents
        if '_aliases' in self.plugin.__dict__:
            if 'agent' in self.plugin.__dict__['_aliases']:
                self.plugin.__dict__['_aliases'].remove('agent')
            if 'dhcp_agent_scheduler' in self.plugin.__dict__[
                    '_aliases']:
                self.plugin.__dict__['_aliases'].remove(
                        'dhcp_agent_scheduler')
        self._mock_aim_obj_eq_operator()

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        # We need to do the following to avoid non-aim tests
        # picking up the patched version of the method in patch_neutron
        registry._get_callback_manager()._notify_loop = (
            patch_neutron.original_notify_loop)
        super(ApicAimTestCase, self).tearDown()

    def _validate(self):
        # Validate should pass.
        self.assertEqual(
            pd_api.VALIDATION_PASSED, self.validation_mgr.validate())

    def _find_by_dn(self, dn, cls):
        aim_ctx = aim_context.AimContext(self.db_session)
        resource = cls.from_dn(dn)
        return self.aim_mgr.get(aim_ctx, resource)

    def _check_dn_is_resource(self, dns, key, resource):
        dn = dns.pop(key, None)
        self.assertIsInstance(dn, six.string_types)
        self.assertEqual(resource.dn, dn)

    def _check_dn_has_resource(self, dns, key, cls):
        dn = dns.pop(key, None)
        self.assertIsInstance(dn, six.string_types)
        resource = self._find_by_dn(dn, cls)
        self.assertIsNotNone(resource)

    def _check_dn(self, resource, aim_resource, key, dname=None):
        dist_names = resource.get('apic:distinguished_names')
        self.assertIsInstance(dist_names, dict)
        dn = dist_names.get(key)
        self.assertIsInstance(dn, six.string_types)
        self.assertEqual(aim_resource.dn, dn)
        aim_resource = self._find_by_dn(dn, aim_resource.__class__)
        self.assertIsNotNone(aim_resource)
        if dname is None:
            name = resource.get('name')
            self.assertIsInstance(name, six.string_types)
            dname = aim_utils.sanitize_display_name(name)
        self.assertEqual(dname, aim_resource.display_name)

    def _check_no_dn(self, resource, key):
        dist_names = resource.get('apic:distinguished_names')
        if dist_names is not None:
            self.assertIsInstance(dist_names, dict)
            self.assertNotIn(key, dist_names)

    def _check_ip_in_cidr(self, ip_addr, cidr):
        self.assertTrue(netaddr.IPAddress(ip_addr) in netaddr.IPNetwork(cidr))

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'compute:',
                         'device_id': 'someid'}}
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def _bind_dhcp_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'network:dhcp',
                         'device_id': 'someid'}}
        # Create EP with bound port
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

    def _make_address_scope_for_vrf(self, vrf_dn,
                                    ip_version=n_constants.IP_VERSION_4,
                                    expected_status=None,
                                    **kwargs):
        attrs = {'ip_version': ip_version}
        if vrf_dn:
            attrs[DN] = {'VRF': vrf_dn}
        attrs.update(kwargs)

        req = self.new_create_request('address-scopes',
                                      {'address_scope': attrs}, self.fmt)
        neutron_context = n_context.Context('', kwargs.get('tenant_id',
                                                           self._tenant_id))
        req.environ['neutron.context'] = neutron_context

        res = req.get_response(self.ext_api)
        if expected_status:
            self.assertEqual(expected_status, res.status_int)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _get_sg(self, sg_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        sg = aim_resource.SecurityGroup(tenant_name=tenant_name,
                                        name=sg_name)
        sg = self.aim_mgr.get(aim_ctx, sg)
        self.assertIsNotNone(sg)
        return sg

    def _sg_should_not_exist(self, sg_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        sgs = self.aim_mgr.find(
            aim_ctx, aim_resource.SecurityGroup, name=sg_name)
        self.assertEqual([], sgs)

    def _get_sg_subject(self, sg_subject_name, sg_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        sg_subject = aim_resource.SecurityGroupSubject(
            tenant_name=tenant_name, security_group_name=sg_name,
            name=sg_subject_name)
        sg_subject = self.aim_mgr.get(aim_ctx, sg_subject)
        self.assertIsNotNone(sg_subject)
        return sg_subject

    def _get_sg_rule(self, sg_rule_name, sg_subject_name, sg_name,
                     tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        sg_rule = aim_resource.SecurityGroupRule(
            tenant_name=tenant_name, security_group_name=sg_name,
            security_group_subject_name=sg_subject_name, name=sg_rule_name)
        sg_rule = self.aim_mgr.get(aim_ctx, sg_rule)
        self.assertIsNotNone(sg_rule)
        return sg_rule

    def _sg_rule_should_not_exist(self, sg_rule_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        sg_rules = self.aim_mgr.find(
            aim_ctx, aim_resource.SecurityGroupRule, name=sg_rule_name)
        self.assertEqual([], sg_rules)

    def port_notif_verifier(self):
        def verify(plugin_context, port):
            self.assertFalse(plugin_context.session.is_active)
            return mock.DEFAULT
        return verify


class TestAimMapping(ApicAimTestCase):
    def setUp(self):
        self.call_wrapper = CallRecordWrapper()
        self.mock_ns = self.call_wrapper.setUp(
            nat_strategy.DistributedNatStrategy)
        self._actual_scopes = {}
        self._scope_vrf_dnames = {}
        super(TestAimMapping, self).setUp()

    def tearDown(self):
        self.call_wrapper.tearDown()
        super(TestAimMapping, self).tearDown()

    def _get_tenant(self, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        tenant = aim_resource.Tenant(name=tenant_name)
        tenant = self.aim_mgr.get(aim_ctx, tenant)
        self.assertIsNotNone(tenant)
        return tenant

    def _get_vrf(self, vrf_name, tenant_name, should_exist=True):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        vrf = aim_resource.VRF(tenant_name=tenant_name,
                               name=vrf_name)
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        if should_exist:
            self.assertIsNotNone(vrf)
            return vrf
        else:
            self.assertIsNone(vrf)

    def _vrf_should_not_exist(self, vrf_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        vrfs = self.aim_mgr.find(aim_ctx, aim_resource.VRF, name=vrf_name)
        self.assertEqual([], vrfs)

    def _get_bd(self, bd_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        bd = aim_resource.BridgeDomain(tenant_name=tenant_name,
                                       name=bd_name)
        bd = self.aim_mgr.get(aim_ctx, bd)
        self.assertIsNotNone(bd)
        return bd

    def _bd_should_not_exist(self, bd_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        bds = self.aim_mgr.find(
            aim_ctx, aim_resource.BridgeDomain, name=bd_name)
        self.assertEqual([], bds)

    def _l3out_should_not_exist(self, l3out_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        l3outs = self.aim_mgr.find(
            aim_ctx, aim_resource.L3Outside, name=l3out_name)
        self.assertEqual([], l3outs)

    def _get_subnet(self, gw_ip_mask, bd_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        subnet = aim_resource.Subnet(tenant_name=tenant_name,
                                     bd_name=bd_name,
                                     gw_ip_mask=gw_ip_mask)
        subnet = self.aim_mgr.get(aim_ctx, subnet)
        self.assertIsNotNone(subnet)
        return subnet

    def _subnet_should_not_exist(self, gw_ip_mask, bd_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        subnets = self.aim_mgr.find(
            aim_ctx, aim_resource.Subnet, bd_name=bd_name,
            gw_ip_mask=gw_ip_mask)
        self.assertEqual([], subnets)

    def _get_epg(self, epg_name, tenant_name, app_profile_name):
        session = self.db_session
        aim_ctx = aim_context.AimContext(session)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_name,
                                         app_profile_name=app_profile_name,
                                         name=epg_name)
        epg = self.aim_mgr.get(aim_ctx, epg)
        self.assertIsNotNone(epg)
        return epg

    def _epg_should_not_exist(self, epg_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        epgs = self.aim_mgr.find(aim_ctx, aim_resource.EndpointGroup,
                                 name=epg_name)
        self.assertEqual([], epgs)

    def _get_contract(self, contract_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        contract = aim_resource.Contract(tenant_name=tenant_name,
                                         name=contract_name)
        contract = self.aim_mgr.get(aim_ctx, contract)
        self.assertIsNotNone(contract)
        return contract

    def _contract_should_not_exist(self, contract_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        contracts = self.aim_mgr.find(aim_ctx, aim_resource.Contract,
                                      name=contract_name)
        self.assertEqual([], contracts)

    def _get_subject(self, subject_name, contract_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        subject = aim_resource.ContractSubject(tenant_name=tenant_name,
                                               contract_name=contract_name,
                                               name=subject_name)
        subject = self.aim_mgr.get(aim_ctx, subject)
        self.assertIsNotNone(subject)
        return subject

    def _subject_should_not_exist(self, subject_name, contract_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        subjects = self.aim_mgr.find(
            aim_ctx, aim_resource.ContractSubject,
            subject_name=subject_name, name=contract_name)
        self.assertEqual([], subjects)

    def _get_filter(self, filter_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        filter = aim_resource.Filter(tenant_name=tenant_name,
                                     name=filter_name)
        filter = self.aim_mgr.get(aim_ctx, filter)
        self.assertIsNotNone(filter)
        return filter

    def _get_filter_entry(self, entry_name, filter_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        entry = aim_resource.FilterEntry(tenant_name=tenant_name,
                                         filter_name=filter_name,
                                         name=entry_name)
        entry = self.aim_mgr.get(aim_ctx, entry)
        self.assertIsNotNone(entry)
        return entry

    def _get_l3out(self, l3out_name, tenant_name):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        l3out = aim_resource.L3Outside(tenant_name=tenant_name,
                                       name=l3out_name)
        l3out = self.aim_mgr.get(aim_ctx, l3out)
        self.assertIsNotNone(l3out)
        return l3out

    def _get_l3out_ext_net(self, aim_ext_net):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        aim_ext_net = self.aim_mgr.get(aim_ctx, aim_ext_net)
        self.assertIsNotNone(aim_ext_net)
        return aim_ext_net

    def _check_network(self, net, routers=None, scope=None, project=None,
                       vrf=None):
        dns = copy.copy(net.get(DN))

        project = project or net['tenant_id']
        tenant_aname = self.name_mapper.project(None, project)
        self._get_tenant(tenant_aname)

        aname = self.name_mapper.network(None, net['id'])
        router_anames = [self.name_mapper.router(None, router['id'])
                         for router in routers or []]

        if routers:
            if vrf:
                vrf_aname = vrf.name
                vrf_dname = vrf.display_name
                vrf_tenant_aname = vrf.tenant_name
                if vrf.tenant_name != 'common':
                    tenant_aname = vrf.tenant_name
                    vrf_tenant_dname = None
                else:
                    vrf_tenant_dname = ''
            elif scope:
                scope = self._actual_scopes.get(scope['id'], scope)
                vrf_aname = self.name_mapper.address_scope(None, scope['id'])
                vrf_dname = self._scope_vrf_dnames.get(
                    scope['id'], scope['name'])
                vrf_project = scope['tenant_id']
                vrf_tenant_aname = self.name_mapper.project(None, vrf_project)
                tenant_aname = vrf_tenant_aname
                vrf_tenant_dname = TEST_TENANT_NAMES[vrf_project]
            else:
                vrf_aname = 'DefaultVRF'
                vrf_dname = 'DefaultRoutedVRF'
                vrf_tenant_aname = tenant_aname
                vrf_tenant_dname = TEST_TENANT_NAMES[project]
        else:
            if net[SVI]:
                vrf_aname = 'DefaultVRF'
                vrf_dname = 'DefaultRoutedVRF'
                vrf_tenant_aname = tenant_aname
                vrf_tenant_dname = TEST_TENANT_NAMES[project]
            else:
                vrf_aname = self.driver.apic_system_id + '_UnroutedVRF'
                vrf_dname = 'CommonUnroutedVRF'
                vrf_tenant_aname = 'common'
                vrf_tenant_dname = ''

        if net[SVI]:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net[DN]['ExternalNetwork'])
            ext_net = self._get_l3out_ext_net(ext_net)
            l3out = self._get_l3out(ext_net.l3out_name, ext_net.tenant_name)
            self.assertEqual(tenant_aname, l3out.tenant_name)
            self.assertEqual(aname, l3out.name)
            self.assertEqual(net['name'], l3out.display_name)
            self.assertEqual(vrf_aname, l3out.vrf_name)
            self._check_dn_is_resource(dns, 'ExternalNetwork', ext_net)
        else:
            aim_bd = self._get_bd(aname, tenant_aname)
            self.assertEqual(tenant_aname, aim_bd.tenant_name)
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
            self._check_dn_is_resource(dns, 'BridgeDomain', aim_bd)

            aim_epg = self._get_epg(aname, tenant_aname,
                                    self._app_profile_name)
            self.assertEqual(tenant_aname, aim_epg.tenant_name)
            self.assertEqual(self._app_profile_name, aim_epg.app_profile_name)
            self.assertEqual(aname, aim_epg.name)
            self.assertEqual(net['name'], aim_epg.display_name)
            self.assertEqual(aname, aim_epg.bd_name)
            self.assertItemsEqual(router_anames,
                                  aim_epg.provided_contract_names)
            self.assertItemsEqual(router_anames,
                                  aim_epg.consumed_contract_names)
            # REVISIT(rkukura): Check openstack_vmm_domain_names and
            # physical_domain_names?
            self._check_dn_is_resource(dns, 'EndpointGroup', aim_epg)

        aim_tenant = self._get_tenant(vrf_tenant_aname)
        self.assertEqual(vrf_tenant_aname, aim_tenant.name)
        if vrf_tenant_dname is not None:
            self.assertEqual(vrf_tenant_dname, aim_tenant.display_name)

        aim_vrf = self._get_vrf(vrf_aname, vrf_tenant_aname)
        self.assertEqual(vrf_tenant_aname, aim_vrf.tenant_name)
        self.assertEqual(vrf_aname, aim_vrf.name)
        self.assertEqual(vrf_dname, aim_vrf.display_name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)
        self._check_dn_is_resource(dns, 'VRF', aim_vrf)

        self.assertFalse(dns)

    def _check_network_deleted(self, net):
        aname = self.name_mapper.network(None, net['id'])
        if net[SVI]:
            self._l3out_should_not_exist(aname)
        else:
            self._bd_should_not_exist(aname)
            self._epg_should_not_exist(aname)

    def _check_subnet(self, subnet, net, expected_gws, unexpected_gw_ips,
                      scope=None, project=None):
        dns = copy.copy(subnet.get(DN))
        prefix_len = subnet['cidr'].split('/')[1]

        scope = scope and self._actual_scopes.get(scope['id'], scope)
        project = project or (scope or net)['tenant_id']
        tenant_aname = self.name_mapper.project(None, project)
        self._get_tenant(tenant_aname)

        net_aname = self.name_mapper.network(None, net['id'])

        if not net[SVI]:
            for gw_ip, router in expected_gws:
                gw_ip_mask = gw_ip + '/' + prefix_len
                aim_subnet = self._get_subnet(gw_ip_mask, net_aname,
                                              tenant_aname)
                self.assertEqual(tenant_aname, aim_subnet.tenant_name)
                self.assertEqual(net_aname, aim_subnet.bd_name)
                self.assertEqual(gw_ip_mask, aim_subnet.gw_ip_mask)
                self.assertEqual('public', aim_subnet.scope)
                display_name = ("%s-%s" %
                                (router['name'],
                                 (subnet['name'] or subnet['cidr'])))
                display_name = aim_utils.sanitize_display_name(display_name)
                self.assertEqual(display_name, aim_subnet.display_name)
                self._check_dn_is_resource(dns, gw_ip, aim_subnet)

        for gw_ip in unexpected_gw_ips:
            gw_ip_mask = gw_ip + '/' + prefix_len
            self._subnet_should_not_exist(gw_ip_mask, net_aname)
            self._check_no_dn(subnet, gw_ip)

        self.assertFalse(dns)

    def _check_subnet_deleted(self, subnet):
        # REVISIT(rkukura): Anything to check? We could find all the
        # AIM Subnets with the network's bd_name, and make sure none
        # are in this subnet.
        pass

    def _check_address_scope(self, scope):
        dns = copy.copy(scope.get(DN))

        actual_scope = self._actual_scopes.get(scope['id'], scope)
        dname = self._scope_vrf_dnames.get(
            actual_scope['id'], actual_scope['name'])

        tenant_aname = self.name_mapper.project(
            None, actual_scope['tenant_id'])
        self._get_tenant(tenant_aname)

        aname = self.name_mapper.address_scope(None, actual_scope['id'])

        aim_vrf = self._get_vrf(aname, tenant_aname)
        self.assertEqual(tenant_aname, aim_vrf.tenant_name)
        self.assertEqual(aname, aim_vrf.name)
        self.assertEqual(dname, aim_vrf.display_name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)
        self._check_dn_is_resource(dns, 'VRF', aim_vrf)

        self.assertFalse(dns)

    def _check_address_scope_deleted(self, scope):
        aname = self.name_mapper.address_scope(None, scope['id'])
        self._vrf_should_not_exist(aname)

    def _check_sg(self, sg):
        tenant_aname = self.name_mapper.project(None, sg['tenant_id'])
        self._get_tenant(tenant_aname)

        aim_sg = self._get_sg(sg['id'], tenant_aname)
        self.assertEqual(tenant_aname, aim_sg.tenant_name)
        self.assertEqual(sg['id'], aim_sg.name)
        self.assertEqual(sg['name'], aim_sg.display_name)

        # check those SG rules including the default ones
        for sg_rule in sg.get('security_group_rules', []):
            self._check_sg_rule(sg['id'], sg_rule)

    def _check_sg_rule(self, sg_id, sg_rule):
        tenant_aname = self.name_mapper.project(None, sg_rule['tenant_id'])
        self._get_tenant(tenant_aname)

        aim_sg_rule = self._get_sg_rule(
            sg_rule['id'], 'default', sg_id, tenant_aname)
        self.assertEqual(tenant_aname, aim_sg_rule.tenant_name)
        self.assertEqual(sg_id, aim_sg_rule.security_group_name)
        self.assertEqual('default',
                         aim_sg_rule.security_group_subject_name)
        self.assertEqual(sg_rule['id'], aim_sg_rule.name)
        self.assertEqual(sg_rule['direction'], aim_sg_rule.direction)
        self.assertEqual(sg_rule['ethertype'].lower(),
                         aim_sg_rule.ethertype)
        self.assertEqual('reflexive', aim_sg_rule.conn_track)
        self.assertEqual(([sg_rule['remote_ip_prefix']] if
                          sg_rule['remote_ip_prefix'] else []),
                         aim_sg_rule.remote_ips)
        self.assertEqual((sg_rule['protocol'] if
                          sg_rule['protocol'] else 'unspecified'),
                         aim_sg_rule.ip_protocol)
        self.assertEqual((str(sg_rule['port_range_min']) if
                          sg_rule['port_range_min'] else 'unspecified'),
                         aim_sg_rule.from_port)
        self.assertEqual((str(sg_rule['port_range_max']) if
                          sg_rule['port_range_max'] else 'unspecified'),
                         aim_sg_rule.to_port)

    def _check_router(self, router, expected_gw_ips, scopes=None,
                      unscoped_project=None, is_svi_net=False):
        dns = copy.copy(router.get(DN))
        aname = self.name_mapper.router(None, router['id'])

        aim_contract = self._get_contract(aname, 'common')
        self.assertEqual('common', aim_contract.tenant_name)
        self.assertEqual(aname, aim_contract.name)
        self.assertEqual(router['name'], aim_contract.display_name)
        self.assertEqual('context', aim_contract.scope)  # REVISIT(rkukura)
        self._check_dn_is_resource(dns, 'Contract', aim_contract)

        aim_subject = self._get_subject('route', aname, 'common')
        self.assertEqual('common', aim_subject.tenant_name)
        self.assertEqual(aname, aim_subject.contract_name)
        self.assertEqual('route', aim_subject.name)
        self.assertEqual(router['name'], aim_subject.display_name)
        self.assertEqual([], aim_subject.in_filters)
        self.assertEqual([], aim_subject.out_filters)
        self.assertEqual([self.driver.apic_system_id + '_AnyFilter'],
                         aim_subject.bi_filters)
        self._check_dn_is_resource(dns, 'ContractSubject', aim_subject)

        if expected_gw_ips:
            if unscoped_project:
                self._check_router_vrf(
                    'DefaultVRF', 'DefaultRoutedVRF', unscoped_project,
                    dns, 'no_scope-VRF')

            for scope in scopes or []:
                actual_scope = self._actual_scopes.get(scope['id'], scope)
                dname = self._scope_vrf_dnames.get(
                    actual_scope['id'], actual_scope['name'])
                self._check_router_vrf(
                    self.name_mapper.address_scope(None, actual_scope['id']),
                    dname, actual_scope['tenant_id'], dns,
                    'as_%s-VRF' % scope['id'])

        # The AIM Subnets are validated in _check_subnet, so just
        # check that their DNs are present and valid.
        if not is_svi_net:
            for gw_ip in expected_gw_ips:
                self._check_dn_has_resource(dns, gw_ip, aim_resource.Subnet)

        self.assertFalse(dns)

    def _check_router_vrf(self, aname, dname, project_id, dns, key):
        tenant_aname = self.name_mapper.project(None, project_id)
        tenant_dname = TEST_TENANT_NAMES[project_id]

        aim_tenant = self._get_tenant(tenant_aname)
        self.assertEqual(tenant_aname, aim_tenant.name)
        self.assertEqual(tenant_dname, aim_tenant.display_name)

        aim_vrf = self._get_vrf(aname, tenant_aname)
        self.assertEqual(tenant_aname, aim_vrf.tenant_name)
        self.assertEqual(aname, aim_vrf.name)
        self.assertEqual(dname, aim_vrf.display_name)
        self.assertEqual('enforced', aim_vrf.policy_enforcement_pref)

        self._check_dn_is_resource(dns, key, aim_vrf)

    def _check_router_deleted(self, router):
        aname = self.name_mapper.router(None, router['id'])
        self._subject_should_not_exist('route', aname)
        self._contract_should_not_exist(aname)

    def _check_any_filter(self):
        aname = self.driver.apic_system_id + '_AnyFilter'
        aim_filter = self._get_filter(aname, 'common')
        self.assertEqual('common', aim_filter.tenant_name)
        self.assertEqual(aname, aim_filter.name)
        self.assertEqual('AnyFilter', aim_filter.display_name)

        aim_entry = self._get_filter_entry('AnyFilterEntry', aname,
                                           'common')
        self.assertEqual('common', aim_entry.tenant_name)
        self.assertEqual(aname, aim_entry.filter_name)
        self.assertEqual('AnyFilterEntry', aim_entry.name)
        self.assertEqual('AnyFilterEntry', aim_entry.display_name)
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

    def test_static_resources(self):
        # Check common Tenant.
        tenant = self._get_tenant('common')
        self.assertEqual('common', tenant.name)
        self.assertEqual('', tenant.display_name)
        self.assertEqual('', tenant.descr)

        # Check unrouted VRF.
        vrf_aname = self.driver.apic_system_id + '_UnroutedVRF'
        vrf = self._get_vrf(vrf_aname, 'common')
        self.assertEqual('common', vrf.tenant_name)
        self.assertEqual(vrf_aname, vrf.name)
        self.assertEqual('CommonUnroutedVRF', vrf.display_name)
        self.assertEqual('enforced', vrf.policy_enforcement_pref)

        # Check any Filter.
        self._check_any_filter()

        # Check default SecurityGroup.
        sg_aname = self.driver.apic_system_id + '_DefaultSecurityGroup'
        sg = self._get_sg(sg_aname, 'common')
        self.assertEqual('common', sg.tenant_name)
        self.assertEqual(sg_aname, sg.name)
        self.assertEqual('DefaultSecurityGroup', sg.display_name)

        # Check default SecurityGroupSubject.
        sg_subject = self._get_sg_subject('default', sg_aname, 'common')
        self.assertEqual('common', sg_subject.tenant_name)
        self.assertEqual(sg_aname, sg_subject.security_group_name)
        self.assertEqual('default', sg_subject.name)
        self.assertEqual(
            'DefaultSecurityGroupSubject', sg_subject.display_name)

        # Check ARP egress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'arp_egress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('arp_egress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupArpEgressRule', sg_rule.display_name)
        self.assertEqual('egress', sg_rule.direction)
        self.assertEqual('arp', sg_rule.ethertype)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('unspecified', sg_rule.from_port)
        self.assertEqual('unspecified', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check ARP inress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'arp_ingress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('arp_ingress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupArpIngressRule', sg_rule.display_name)
        self.assertEqual('ingress', sg_rule.direction)
        self.assertEqual('arp', sg_rule.ethertype)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('unspecified', sg_rule.from_port)
        self.assertEqual('unspecified', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check DHCP egress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'dhcp_egress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('dhcp_egress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupDhcpEgressRule', sg_rule.display_name)
        self.assertEqual('egress', sg_rule.direction)
        self.assertEqual('ipv4', sg_rule.ethertype)
        self.assertEqual('udp', sg_rule.ip_protocol)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('67', sg_rule.from_port)
        self.assertEqual('67', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check DHCP ingress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'dhcp_ingress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('dhcp_ingress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupDhcpIngressRule', sg_rule.display_name)
        self.assertEqual('ingress', sg_rule.direction)
        self.assertEqual('ipv4', sg_rule.ethertype)
        self.assertEqual('udp', sg_rule.ip_protocol)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('68', sg_rule.from_port)
        self.assertEqual('68', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check DHCP6 egress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'dhcp6_egress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('dhcp6_egress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupDhcp6EgressRule', sg_rule.display_name)
        self.assertEqual('egress', sg_rule.direction)
        self.assertEqual('ipv6', sg_rule.ethertype)
        self.assertEqual('udp', sg_rule.ip_protocol)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('547', sg_rule.from_port)
        self.assertEqual('547', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check DHCP6 ingress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'dhcp6_ingress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('dhcp6_ingress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupDhcp6IngressRule', sg_rule.display_name)
        self.assertEqual('ingress', sg_rule.direction)
        self.assertEqual('ipv6', sg_rule.ethertype)
        self.assertEqual('udp', sg_rule.ip_protocol)
        self.assertEqual([], sg_rule.remote_ips)
        self.assertEqual('546', sg_rule.from_port)
        self.assertEqual('546', sg_rule.to_port)
        self.assertEqual('normal', sg_rule.conn_track)

        # Check ICMP6 ingress SecurityGroupRule.
        sg_rule = self._get_sg_rule(
            'icmp6_ingress', 'default', sg_aname, 'common')
        self.assertEqual('common', sg_rule.tenant_name)
        self.assertEqual(sg_aname, sg_rule.security_group_name)
        self.assertEqual('default', sg_rule.security_group_subject_name)
        self.assertEqual('icmp6_ingress', sg_rule.name)
        self.assertEqual(
            'DefaultSecurityGroupIcmp6IngressRule', sg_rule.display_name)
        self.assertEqual('ingress', sg_rule.direction)
        self.assertEqual('ipv6', sg_rule.ethertype)
        self.assertEqual('icmpv6', sg_rule.ip_protocol)
        self.assertEqual(['::/0'], sg_rule.remote_ips)
        self.assertEqual('unspecified', sg_rule.from_port)
        self.assertEqual('unspecified', sg_rule.to_port)
        self.assertEqual('reflexive', sg_rule.conn_track)

    def test_network_lifecycle(self):
        # Test create.
        net = self._make_network(self.fmt, 'net1', True)['network']
        net_id = net['id']
        self._check_network(net)

        # Test show.
        net = self._show('networks', net_id)['network']
        self._check_network(net)

        # Test update.
        data = {'network': {'name': 'newnamefornet'}}
        net = self._update('networks', net_id, data)['network']
        self._check_network(net)

        # Test delete.
        self._delete('networks', net_id)
        self._check_network_deleted(net)

    def test_svi_network_lifecycle(self):
        session = db_api.get_writer_session()
        extn = extn_db.ExtensionDbMixin()

        # test create.
        net = self._make_network(self.fmt, 'net1', True)['network']
        self.assertEqual(False, net[SVI])

        net = self._make_network(self.fmt, 'net2', True,
                                 arg_list=self.extension_attributes,
                                 **{'apic:svi': 'True'}
                                 )['network']
        self.assertEqual(True, net[SVI])
        self._check_network(net)

        # updating SVI flag is not allowed
        self._update('networks', net['id'], {SVI: 'False'}, 400)
        self.assertEqual(True, net[SVI])
        self._check_network(net)

        # Test update the name.
        data = {'network': {'name': 'newnamefornet'}}
        net = self._update('networks', net['id'], data)['network']
        self._check_network(net)

        # test delete
        self._delete('networks', net['id'])
        self.assertFalse(extn.get_network_extn_db(session, net['id']))
        self._check_network_deleted(net)

    def test_security_group_lifecycle(self):
        # Test create
        sg = self._make_security_group(self.fmt,
                                       'sg1', 'test')['security_group']
        sg_id = sg['id']
        self._check_sg(sg)

        # Test show.
        sg = self._show('security-groups', sg_id)['security_group']
        self._check_sg(sg)

        # Test update.
        data = {'security_group': {'name': 'new_sg_name'}}
        sg = self._update('security-groups', sg_id, data)['security_group']
        self._check_sg(sg)

        # Test adding rules
        rule1 = self._build_security_group_rule(
            sg_id, 'ingress', n_constants.PROTO_NAME_TCP, '22', '23',
            remote_ip_prefix='1.1.1.1/0', remote_group_id=None,
            ethertype=n_constants.IPv4)
        rules = {'security_group_rules': [rule1['security_group_rule']]}
        sg_rule = self._make_security_group_rule(
            self.fmt, rules)['security_group_rules'][0]
        self._check_sg_rule(sg_id, sg_rule)
        sg = self._show('security-groups', sg_id)['security_group']
        self._check_sg(sg)

        # Test show rule
        sg_rule = self._show('security-group-rules',
                             sg_rule['id'])['security_group_rule']
        self._check_sg_rule(sg_id, sg_rule)

        # Test delete which will delete all the rules too
        self._delete('security-groups', sg_id)
        self._sg_should_not_exist(sg_id)
        self._sg_rule_should_not_exist(sg_rule['id'])

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
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = scope['id']
        self._check_address_scope(scope)

        # Test show.
        scope = self._show('address-scopes', scope_id)['address_scope']
        self._check_address_scope(scope)

        # Test update.
        data = {'address_scope': {'name': 'newnameforaddressscope'}}
        scope = self._update('address-scopes', scope_id, data)['address_scope']
        self._check_address_scope(scope)

        # Test delete.
        self._delete('address-scopes', scope_id)
        self._check_address_scope_deleted(scope)

    def test_router_lifecycle(self):
        # Test create.
        router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = router['id']
        self._check_router(router, [])

        # Test show.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [])

        # Test update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [])

        # Test delete.
        self._delete('routers', router_id)
        self._check_router_deleted(router)

    def _test_router_interface(self, is_svi=False):
        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        self._register_agent('host1', AGENT_CONF_OPFLEX)

        # Create router.
        router = self._make_router(
            self.fmt, self._tenant_id, 'router1')['router']
        router_id = router['id']
        self._check_router(router, [])

        # Create network.
        if not is_svi:
            net_resp = self._make_network(self.fmt, 'net1', True)
        else:
            net_resp = self._make_network(self.fmt, 'net1', True,
                                          arg_list=self.extension_attributes,
                                          **{'apic:svi': 'True'})
        net = net_resp['network']
        net_id = net['id']
        self._check_network(net)

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        subnet = self._make_subnet(self.fmt, net_resp, gw1_ip,
                                   '10.0.1.0/24')['subnet']
        subnet1_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Create port on subnet1.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.100'}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']
        port['dns_name'] = ''
        port_calls = [mock.call(mock.ANY, port)]

        # Create subnet2.
        if not is_svi:
            gw2_ip = '10.0.2.1'
            subnet = self._make_subnet(self.fmt, net_resp, gw2_ip,
                                       '10.0.2.0/24')['subnet']
            subnet2_id = subnet['id']
            self._check_subnet(subnet, net, [], [gw2_ip])

            # Create port on subnet2.
            fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': '10.0.2.100'}]
            port = self._make_port(self.fmt, net_id,
                                   fixed_ips=fixed_ips)['port']
            port = self._bind_port_to_host(port['id'], 'host1')['port']
            port['dns_name'] = ''
            port_calls.append(mock.call(mock.ANY, port))

        # Add subnet1 to router by subnet.
        mock_notif.reset_mock()
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Verify ports were notified.
        mock_notif.assert_has_calls(port_calls, any_order=True)

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip], unscoped_project=self._tenant_id,
                           is_svi_net=is_svi)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, [router])

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Check subnet2.
        if not is_svi:
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Test router update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [gw1_ip], unscoped_project=self._tenant_id,
                           is_svi_net=is_svi)
        self._check_subnet(subnet, net, [(gw1_ip, router)], [])

        # Add subnet2 to router by port.
        if not is_svi:
            fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
            port = self._make_port(self.fmt, net_id,
                                   fixed_ips=fixed_ips)['port']
            port2_id = port['id']
            mock_notif.reset_mock()
            info = self.l3_plugin.add_router_interface(
                n_context.get_admin_context(), router_id,
                {'port_id': port2_id})
            self.assertIn(subnet2_id, info['subnet_ids'])

            # Verify ports were not notified.
            mock_notif.assert_not_called()

            # Check router.
            router = self._show('routers', router_id)['router']
            self._check_router(
                router, [gw1_ip, gw2_ip], unscoped_project=self._tenant_id,
                is_svi_net=is_svi)

            # Check network.
            net = self._show('networks', net_id)['network']
            self._check_network(net, [router])
            # Check subnet1.
            subnet = self._show('subnets', subnet1_id)['subnet']
            self._check_subnet(subnet, net, [(gw1_ip, router)], [])
            # Check subnet2.
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [(gw2_ip, router)], [])

        # Remove subnet1 from router by subnet.
        mock_notif.reset_mock()
        info = self.l3_plugin.remove_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        if not is_svi:
            # Verify ports were not notified.
            mock_notif.assert_not_called()
            self._check_router(router, [gw2_ip],
                               unscoped_project=self._tenant_id,
                               is_svi_net=is_svi)
        else:
            # Verify ports were notified.
            mock_notif.assert_has_calls(port_calls, any_order=True)
            self._check_router(router, [], unscoped_project=self._tenant_id,
                               is_svi_net=is_svi)

        # Check network.
        net = self._show('networks', net_id)['network']
        if not is_svi:
            self._check_network(net, [router])
        else:
            self._check_network(net)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        if not is_svi:
            # Check subnet2.
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [(gw2_ip, router)], [])

            # Remove subnet2 from router by port.
            mock_notif.reset_mock()
            info = self.l3_plugin.remove_router_interface(
                n_context.get_admin_context(), router_id,
                {'port_id': port2_id})
            self.assertIn(subnet2_id, info['subnet_ids'])

            # Verify ports were notified.
            mock_notif.assert_has_calls(port_calls, any_order=True)
            # Check router.
            router = self._show('routers', router_id)['router']
            self._check_router(router, [])
            # Check network.
            net = self._show('networks', net_id)['network']
            self._check_network(net)
            # Check subnet1.
            subnet = self._show('subnets', subnet1_id)['subnet']
            self._check_subnet(subnet, net, [], [gw1_ip])
            # Check subnet2.
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [], [gw2_ip])

    def test_router_interface(self):
        self._test_router_interface()

    def test_router_interface_svi(self):
        self._test_router_interface(is_svi=True)

    def test_router_interface_svi_preexist_not_allowed(self):
        self._register_agent('host1', AGENT_CONF_OPFLEX)

        # Create router.
        router = self._make_router(
            self.fmt, self._tenant_id, 'router1')['router']
        router_id = router['id']

        # Create network.
        net_resp = self._make_network(
            self.fmt, 'net2', True, arg_list=self.extension_attributes,
            **{'apic:svi': 'True',
               DN: {'ExternalNetwork': self.dn_t1_l1_n1}})
        net = net_resp['network']
        net_id = net['id']

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        subnet = self._make_subnet(self.fmt, net_resp, gw1_ip,
                                   '10.0.1.0/24')['subnet']
        subnet1_id = subnet['id']

        # Create port on subnet1.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.100'}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']

        # Connect to router should fail.
        self.assertRaises(exceptions.PreExistingSVICannotBeConnectedToRouter,
                          self.l3_plugin.add_router_interface,
                          n_context.get_admin_context(), router_id,
                          {'subnet_id': subnet1_id})

    def test_preexist_svi_can_not_use_same_l3out(self):
        self._make_network(
            self.fmt, 'net1', True, arg_list=self.extension_attributes,
            **{'apic:svi': 'True',
               DN: {'ExternalNetwork': self.dn_t1_l1_n1}})

        # Create another SVI network with same l3out should fail.
        self.assertRaises(webob.exc.HTTPClientError, self._make_network,
                          self.fmt, 'net2', True,
                          arg_list=self.extension_attributes,
                          **{'apic:svi': 'True',
                             DN: {'ExternalNetwork': self.dn_t1_l1_n1}})

    def test_only_one_subnet_allowed_in_svi(self):
        # Create network.
        net_resp = self._make_network(
            self.fmt, 'net2', True, arg_list=self.extension_attributes,
            **{'apic:svi': 'True'})

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        self._make_subnet(self.fmt, net_resp, gw1_ip,
                          '10.0.1.0/24')['subnet']

        # Create subnet2 should fail.
        gw2_ip = '10.0.2.1'
        self.assertRaises(webob.exc.HTTPClientError, self._make_subnet,
                          self.fmt, net_resp, gw2_ip, '10.0.2.0/24')

    def _test_router_interface_with_address_scope(self, is_svi=False):
        # REVISIT(rkukura): Currently follows same workflow as above,
        # but might be sufficient to test with a single subnet with
        # its CIDR allocated from the subnet pool.

        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        self._register_agent('host1', AGENT_CONF_OPFLEX)

        # Create address scope.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = scope['id']
        self._check_address_scope(scope)

        # Create subnet pool.
        pool = self._make_subnetpool(self.fmt, ['10.0.0.0/8'], name='sp1',
                                     tenant_id=self._tenant_id,
                                     address_scope_id=scope_id,
                                     default_prefixlen=24)['subnetpool']
        pool_id = pool['id']

        # Create router.
        router = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']
        router_id = router['id']
        self._check_router(router, [], scopes=[scope])

        # Create network.
        if not is_svi:
            net_resp = self._make_network(self.fmt, 'net1', True)
        else:
            net_resp = self._make_network(self.fmt, 'net1', True,
                                          arg_list=self.extension_attributes,
                                          **{'apic:svi': 'True'})
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

        # Create port on subnet1.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.100'}]
        port = self._make_port(self.fmt, net_id, fixed_ips=fixed_ips)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']
        port['dns_name'] = ""
        port['project_id'] = port['tenant_id']
        port_calls = [mock.call(mock.ANY, port)]

        # Create subnet2.
        if not is_svi:
            gw2_ip = '10.0.2.1'
            subnet = self._make_subnet(
                self.fmt, net_resp, gw2_ip, '10.0.2.0/24',
                subnetpool_id=pool_id)['subnet']
            subnet2_id = subnet['id']
            self._check_subnet(subnet, net, [], [gw2_ip])
            # Create port on subnet2.
            fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': '10.0.2.100'}]
            port = self._make_port(self.fmt, net_id,
                                   fixed_ips=fixed_ips)['port']
            port = self._bind_port_to_host(port['id'], 'host1')['port']
            port['dns_name'] = ''
            port['project_id'] = port['tenant_id']
            port_calls.append(mock.call(mock.ANY, port))

        # Add subnet1 to router by subnet.
        mock_notif.reset_mock()
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Verify ports were notified.
        mock_notif.assert_has_calls(port_calls, any_order=True)

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip], scopes=[scope],
                           is_svi_net=is_svi)

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, [router], scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)

        # Check subnet2.
        if not is_svi:
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [], [gw2_ip])

        # Test subnet update.
        data = {'subnet': {'name': 'newnameforsubnet'}}
        subnet = self._update('subnets', subnet1_id, data)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)

        # Test router update.
        data = {'router': {'name': 'newnameforrouter'}}
        router = self._update('routers', router_id, data)['router']
        self._check_router(router, [gw1_ip], scopes=[scope],
                           is_svi_net=is_svi)
        self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)

        # Add subnet2 to router by port.
        if not is_svi:
            fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': gw2_ip}]
            port = self._make_port(self.fmt, net_id,
                                   fixed_ips=fixed_ips)['port']
            port2_id = port['id']
            mock_notif.reset_mock()
            info = self.l3_plugin.add_router_interface(
                n_context.get_admin_context(), router_id,
                {'port_id': port2_id})
            self.assertIn(subnet2_id, info['subnet_ids'])
            # Verify ports were not notified.
            mock_notif.assert_not_called()
            # Check router.
            router = self._show('routers', router_id)['router']
            self._check_router(router, [gw1_ip, gw2_ip], scopes=[scope],
                               is_svi_net=is_svi)
            # Check network.
            net = self._show('networks', net_id)['network']
            self._check_network(net, [router], scope)
            # Check subnet1.
            subnet = self._show('subnets', subnet1_id)['subnet']
            self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)
            # Check subnet2.
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [(gw2_ip, router)], [], scope)

        # Remove subnet1 from router by subnet.
        mock_notif.reset_mock()
        info = self.l3_plugin.remove_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        if not is_svi:
            # Verify ports were not notified.
            mock_notif.assert_not_called()
            self._check_router(router, [gw2_ip], scopes=[scope],
                               is_svi_net=is_svi)
        else:
            # Verify ports were notified.
            mock_notif.assert_has_calls(port_calls, any_order=True)
            self._check_router(router, [], scopes=[scope],
                               is_svi_net=is_svi)

        # Check network.
        net = self._show('networks', net_id)['network']
        if not is_svi:
            self._check_network(net, [router], scope)
        else:
            self._check_network(net, [], scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        if not is_svi:
            # Check subnet2.
            subnet = self._show('subnets', subnet2_id)['subnet']
            self._check_subnet(subnet, net, [(gw2_ip, router)], [], scope)
            # Remove subnet2 from router by port.
            mock_notif.reset_mock()
            info = self.l3_plugin.remove_router_interface(
                n_context.get_admin_context(), router_id,
                {'port_id': port2_id})
            self.assertIn(subnet2_id, info['subnet_ids'])
            # Verify ports were notified.
            mock_notif.assert_has_calls(port_calls, any_order=True)
            # Check router.
            router = self._show('routers', router_id)['router']
            self._check_router(router, [], scopes=[scope])
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
        self._test_router_interface_with_address_scope()

    def test_router_interface_with_address_scope_svi(self):
        self._test_router_interface_with_address_scope(is_svi=True)

    def test_keystone_notification_endpoint(self):
        self.driver.aim.get = mock.Mock(return_value=True)
        self.driver.aim.update = mock.Mock()
        self.driver.aim.delete = mock.Mock()
        self.driver.project_name_cache.purge_gbp = mock.Mock()
        payload = {}
        payload['resource_info'] = 'test-tenant'
        keystone_ep = md.KeystoneNotificationEndpoint(self.driver)

        # first test with project.updated event
        keystone_ep.info(None, None, 'identity.project.updated', payload, None)
        tenant_name = self.name_mapper.project(None, 'test-tenant')
        tenant = aim_resource.Tenant(name=tenant_name)
        self.driver.aim.update.assert_called_once_with(
            mock.ANY, tenant, display_name='new_name')

        # test again with project.deleted event
        self.driver.enable_keystone_notification_purge = True
        keystone_ep.info(None, None, 'identity.project.deleted', payload, None)
        self.assertEqual(keystone_ep.tenant, 'test-tenant')
        self.driver.project_name_cache.purge_gbp.assert_called_once_with(
                                                                keystone_ep)
        ap = aim_resource.ApplicationProfile(tenant_name=tenant_name,
                                             name=self.driver.ap_name)
        tenant = aim_resource.Tenant(name=tenant_name)
        exp_calls = [
            mock.call(mock.ANY, ap),
            mock.call(mock.ANY, tenant)]
        self._check_call_list(exp_calls, self.driver.aim.delete.call_args_list)

    def test_multi_scope_routing_with_unscoped_pools(self):
        self._test_multi_scope_routing(True)

    def test_multi_scope_routing_without_unscoped_pools(self):
        self._test_multi_scope_routing(False)

    def _test_multi_scope_routing(self, use_unscoped_pools):
        # REVISIT: Re-enable testing with non-isomorphic scopes on the
        # same network once they are supported. Also, test with shared
        # scopes?

        # Get default unscoped routed VRF DNs for main and sharing
        # projects.
        tenant_aname = self.name_mapper.project(None, self._tenant_id)
        main_vrf = aim_resource.VRF(
            tenant_name=tenant_aname, name='DefaultVRF').dn
        tenant_aname = self.name_mapper.project(None, 'tenant_2')
        shared_vrf = aim_resource.VRF(
            tenant_name=tenant_aname, name='DefaultVRF').dn

        # Create a v6 scope and pool.
        scope6 = self._make_address_scope(
            self.fmt, 6, name='as6')['address_scope']
        scope6_id = scope6['id']
        self._check_address_scope(scope6)
        scope46i_vrf = scope6['apic:distinguished_names']['VRF']
        pool6 = self._make_subnetpool(
            self.fmt, ['2001:db8:1::0/56'], name='sp6',
            tenant_id=self._tenant_id,
            address_scope_id=scope6_id)['subnetpool']
        pool6_id = pool6['id']

        # Create isomorphic v4 scope and pool.
        scope4i = self._make_address_scope_for_vrf(
            scope46i_vrf, 4, name='as4i')['address_scope']
        scope4i_id = scope4i['id']
        self._actual_scopes[scope4i_id] = scope6
        self._scope_vrf_dnames[scope4i_id] = 'as4i-as6'
        self._scope_vrf_dnames[scope6_id] = 'as4i-as6'
        self._check_address_scope(scope4i)
        pool4i = self._make_subnetpool(
            self.fmt, ['10.1.0.0/16'], name='sp4i', tenant_id=self._tenant_id,
            address_scope_id=scope4i_id, default_prefixlen=24)['subnetpool']
        pool4i_id = pool4i['id']

        # Create non-isomorphic v4 scope and pool.
        scope4n = self._make_address_scope(
            self.fmt, 4, name='as4n')['address_scope']
        scope4n_id = scope4n['id']
        self._check_address_scope(scope4n)
        scope4n_vrf = scope4n['apic:distinguished_names']['VRF']
        pool4n = self._make_subnetpool(
            self.fmt, ['10.2.0.0/16'], name='sp4n', tenant_id=self._tenant_id,
            address_scope_id=scope4n_id, default_prefixlen=24)['subnetpool']
        pool4n_id = pool4n['id']

        # Create unscoped pools if required.
        if use_unscoped_pools:
            pool4u = self._make_subnetpool(
                self.fmt, ['10.3.0.0/16', '10.4.0.0/16'], name='sp4u',
                tenant_id=self._tenant_id, default_prefixlen=24)['subnetpool']
            pool4u_id = pool4u['id']
            pool6u = self._make_subnetpool(
                self.fmt, ['2001:db8:1::0/56'], name='sp6u',
                tenant_id=self._tenant_id)['subnetpool']
            pool6u_id = pool6u['id']
        else:
            pool4u_id = None
            pool6u_id = None

        # Create network with subnets using first v4 scope and v6 scope.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net1 = net_resp['network']
        self._check_network(net1)
        gw4i1_ip = '10.1.1.1'
        subnet4i1 = self._make_subnet(
            self.fmt, net_resp, gw4i1_ip, '10.1.1.0/24',
            subnetpool_id=pool4i_id)['subnet']
        self._check_subnet(subnet4i1, net1, [], [gw4i1_ip])
        gw61_ip = '2001:db8:1:1::1'
        subnet61 = self._make_subnet(
            self.fmt, net_resp, gw61_ip, '2001:db8:1:1::0/64',
            ip_version=6, subnetpool_id=pool6_id)['subnet']
        self._check_subnet(subnet61, net1, [], [gw61_ip])

        # Create network with subnets using second v4 scope and v6 scope.
        net_resp = self._make_network(self.fmt, 'net2', True)
        net2 = net_resp['network']
        self._check_network(net2)
        gw4n2_ip = '10.2.1.1'
        subnet4n2 = self._make_subnet(
            self.fmt, net_resp, gw4n2_ip, '10.2.1.0/24',
            subnetpool_id=pool4n_id)['subnet']
        self._check_subnet(subnet4n2, net2, [], [gw4n2_ip])
        gw62_ip = '2001:db8:1:2::1'
        subnet62 = self._make_subnet(
            self.fmt, net_resp, gw62_ip, '2001:db8:1:2::0/64',
            ip_version=6, subnetpool_id=pool6_id)['subnet']
        self._check_subnet(subnet62, net2, [], [gw62_ip])

        # Create network with unscoped subnets.
        net_resp = self._make_network(self.fmt, 'net3', True)
        net3 = net_resp['network']
        self._check_network(net3)
        gw43_ip = '10.3.1.1'
        subnet43 = self._make_subnet(
            self.fmt, net_resp, gw43_ip, '10.3.1.0/24',
            subnetpool_id=pool4u_id)['subnet']
        self._check_subnet(subnet43, net3, [], [gw43_ip])
        gw63_ip = '2001:db8:1:3::1'
        subnet63 = self._make_subnet(
            self.fmt, net_resp, gw63_ip, '2001:db8:1:3::0/64',
            ip_version=6, subnetpool_id=pool6u_id)['subnet']
        self._check_subnet(subnet63, net3, [], [gw63_ip])

        # Create shared network with unscoped subnets.
        net_resp = self._make_network(
            self.fmt, 'net4', True, tenant_id='tenant_2', shared=True)
        net4 = net_resp['network']
        self._check_network(net4)
        gw44_ip = '10.4.1.1'
        subnet44 = self._make_subnet(
            self.fmt, net_resp, gw44_ip, '10.4.1.0/24',
            subnetpool_id=pool4u_id)['subnet']
        self._check_subnet(subnet44, net4, [], [gw44_ip])
        gw64_ip = '2001:db8:1:4::1'
        subnet64 = self._make_subnet(
            self.fmt, net_resp, gw64_ip, '2001:db8:1:4::0/64',
            ip_version=6, subnetpool_id=pool6u_id)['subnet']
        self._check_subnet(subnet64, net4, [], [gw64_ip])

        # Create two external networks with subnets.
        ext_net1 = self._make_ext_network(
            'ext-net1', dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')
        ext_net2 = self._make_ext_network(
            'ext-net2', dn=self.dn_t1_l2_n2)
        self._make_subnet(
            self.fmt, {'network': ext_net2}, '200.200.200.1',
            '200.200.200.0/24')

        def add(subnet):
            # REVISIT: Adding by port would work, but adding shared
            # network interface by subnet fails without admin context.
            #
            # router_ctx = n_context.Context(None, self._tenant_id)
            router_ctx = n_context.get_admin_context()
            info = self.l3_plugin.add_router_interface(
                router_ctx, router_id, {'subnet_id': subnet['id']})
            self.assertIn(subnet['id'], info['subnet_ids'])

        def remove(subnet):
            # REVISIT: Removing by port should work, but removing
            # shared network interface by subnet fails without admin
            # context.
            #
            # router_ctx = n_context.Context(None, self._tenant_id)
            router_ctx = n_context.get_admin_context()
            info = self.l3_plugin.remove_router_interface(
                router_ctx, router_id, {'subnet_id': subnet['id']})
            self.assertIn(subnet['id'], info['subnet_ids'])

        def check(nets, scopes, unscoped_project):
            router = self._show('routers', router_id)['router']
            expected_gw_ips = []
            for net, routed_subnets, unrouted_subnets, scope, project in nets:
                net = self._show('networks', net['id'])['network']
                self._check_network(
                    net, [router] if routed_subnets else [], scope, project)
                for subnet in routed_subnets:
                    gw_ip = subnet['gateway_ip']
                    expected_gw_ips.append(gw_ip)
                    subnet = self._show('subnets', subnet['id'])['subnet']
                    self._check_subnet(
                        subnet, net, [(gw_ip, router)], [], scope, project)
                for subnet in unrouted_subnets:
                    gw_ip = subnet['gateway_ip']
                    subnet = self._show('subnets', subnet['id'])['subnet']
                    self._check_subnet(
                        subnet, net, [], [gw_ip], scope, project)
            self._check_router(
                router, expected_gw_ips, scopes, unscoped_project)

        def check_ns(disconnect_vrf_dns, from_net_dn,
                     connect_vrf_dns, to_net_dn):
            def check_calls(mock, expected_vrf_dns, expected_net_dn):
                # REVISIT: We should be able to use assert_has_calls()
                # since assert_called_once_with() works in
                # TestExternalConnectivityBase, but args don't seem to
                # match when they should.
                vrf_dns = []
                for args, _ in mock.call_args_list:
                    _, net, vrf = args
                    self.assertEqual(expected_net_dn, net.dn)
                    vrf_dns.append(vrf.dn)
                self.assertEqual(sorted(expected_vrf_dns), sorted(vrf_dns))

            check_calls(
                self.mock_ns.disconnect_vrf, disconnect_vrf_dns, from_net_dn)
            check_calls(
                self.mock_ns.connect_vrf, connect_vrf_dns, to_net_dn)
            self.mock_ns.reset_mock()

        # Create router.
        router = self._make_router(
            self.fmt, self._tenant_id, 'router1',
            external_gateway_info={'network_id': ext_net1['id']})['router']
        router_id = router['id']
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [], [subnet43, subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [], None)
        check_ns([], None, [], None)

        # Add first scoped v4 subnet to router, which should connect
        # the isomorphic VRF to ext_net1.
        add(subnet4i1)
        check([(net1, [subnet4i1], [subnet61], scope4i, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [], [subnet43, subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4i], None)
        check_ns([], None, [scope46i_vrf], self.dn_t1_l1_n1)

        # Add first scoped v6 subnet to router, which should not
        # effect external connectivity.
        add(subnet61)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [], [subnet43, subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4i, scope6], None)
        check_ns([], None, [], None)

        # Add first unscoped v6 subnet to router, which should connect
        # the default VRF to ext_net1.
        add(subnet63)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [subnet63], [subnet43], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4i, scope6], self._tenant_id)
        check_ns([], None, [main_vrf], self.dn_t1_l1_n1)

        # REVISIT: Enable when non-isomorphic network routing is
        # supported.
        #
        # Add second scoped v6 subnet to router, which should connect
        # its VRF to ext_net1.
        # add(subnet62)
        # check([(net1, [subnet4i1, subnet61], [], scope4i, None),
        #        (net2, [subnet62], [subnet4n2], scope6, None),
        #        (net3, [subnet63], [subnet43], None, None),
        #        (net4, [], [subnet44, subnet64], None, None)],
        #       [scope4i, scope6], self._tenant_id)

        # Add second scoped v4 subnet to router, which should connect
        # its VRF to ext_net1.
        add(subnet4n2)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet63], [subnet43], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4i, scope4n, scope6], self._tenant_id)
        check_ns([], None, [scope4n_vrf], self.dn_t1_l1_n1)

        # Add first unscoped v4 subnet to router, which should not
        # effect external connectivity.
        add(subnet43)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4i, scope4n, scope6], self._tenant_id)
        check_ns([], None, [], None)

        # Add shared unscoped v4 subnet to router, which should move
        # unscoped topology but not scoped topologies, and should
        # disconnect tenant's own VRF from ext_net1 and connect
        # sharing tenant's VRF to ext_net1.
        add(subnet44)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet44], [subnet64], None, 'tenant_2')],
              [scope4i, scope4n, scope6], 'tenant_2')
        check_ns([main_vrf], self.dn_t1_l1_n1, [shared_vrf], self.dn_t1_l1_n1)

        # Add shared unscoped v6 subnet to router, which should not
        # effect external connectivity.
        add(subnet64)
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet44, subnet64], [], None, 'tenant_2')],
              [scope4i, scope4n, scope6], 'tenant_2')
        check_ns([], None, [], None)

        # Update router with new gateway, which should disconnect all
        # VRFs from ext_net1 and connect them to ext_net2.
        self._update('routers', router_id,
                     {'router': {'external_gateway_info':
                                 {'network_id': ext_net2['id']}}})
        check([(net1, [subnet4i1, subnet61], [], scope4i, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet44, subnet64], [], None, 'tenant_2')],
              [scope4i, scope4n, scope6], 'tenant_2')
        check_ns([scope46i_vrf, scope4n_vrf, shared_vrf], self.dn_t1_l1_n1,
                 [scope46i_vrf, scope4n_vrf, shared_vrf], self.dn_t1_l2_n2)

        # Remove first scoped v4 subnet from router, which should not
        # effect external connectivity.
        remove(subnet4i1)
        check([(net1, [subnet61], [subnet4i1], scope6, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet44, subnet64], [], None, 'tenant_2')],
              [scope4n, scope6], 'tenant_2')
        check_ns([], None, [], None)

        # Remove first scoped v6 subnet from router, which should
        # disconnect isomorphic VRF from ext_net2.
        remove(subnet61)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet44, subnet64], [], None, 'tenant_2')],
              [scope4n], 'tenant_2')
        check_ns([scope46i_vrf], self.dn_t1_l2_n2, [], None)

        # Remove shared unscoped v4 subnet from router, which should
        # not effect external connecivity.
        remove(subnet44)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, 'tenant_2'),
               (net4, [subnet64], [subnet44], None, 'tenant_2')],
              [scope4n], 'tenant_2')
        check_ns([], None, [], None)

        # Remove shared unscoped v6 subnet from router, which should
        # move remaining unscoped topology back to original tenant,
        # and should disconnect sharing tenant's VRF from ext_net2 and
        # connect tenant's own VRF to ext_net1.
        remove(subnet64)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43, subnet63], [], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4n], self._tenant_id)
        check_ns([shared_vrf], self.dn_t1_l2_n2, [main_vrf], self.dn_t1_l2_n2)

        # Remove first unscoped v6 subnet from router, which should
        # not effect external connectivity.
        remove(subnet63)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [subnet4n2], [subnet62], scope4n, None),
               (net3, [subnet43], [subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [scope4n], self._tenant_id)
        check_ns([], None, [], None)

        # Remove second scoped v4 subnet from router, which should
        # disconnect its VRF from ext_net2.
        remove(subnet4n2)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [subnet43], [subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [], self._tenant_id)
        check_ns([scope4n_vrf], self.dn_t1_l2_n2, [], None)

        # Remove second unscoped v4 subnet from router, which should
        # disconnect the default VRF from ext_net2.
        remove(subnet43)
        check([(net1, [], [subnet4i1, subnet61], None, None),
               (net2, [], [subnet4n2, subnet62], None, None),
               (net3, [], [subnet43, subnet63], None, None),
               (net4, [], [subnet44, subnet64], None, None)],
              [], None)
        check_ns([main_vrf], self.dn_t1_l2_n2, [], None)

        # REVISIT: Enable when non-isomorphic network routing is
        # supported.
        #
        # Remove second scoped v6 subnet from router.
        # remove(subnet62)
        # check([(net1, [], [subnet4i1, subnet61], None, None),
        #        (net2, [], [subnet4n2, subnet62], None, None),
        #        (net3, [], [subnet43, subnet63], None, None),
        #        (net4, [], [subnet44, subnet64], None, None)],
        #       [], None)
        # check_ns(...)

    def test_shared_address_scope(self):
        # Create shared scope as tenant_1.
        scope = self._make_address_scope(
            self.fmt, 4, admin=True, name='as1', tenant_id='tenant_1',
            shared=True)['address_scope']
        scope_id = scope['id']
        self._check_address_scope(scope)

        # Create shared pool as tenant_1.
        pool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], admin=True, name='sp1',
            tenant_id='tenant_1', address_scope_id=scope_id,
            default_prefixlen=24, shared=True)['subnetpool']
        pool_id = pool['id']

        # Create router as tenant_2.
        router = self._make_router(
            self.fmt, 'tenant_2', 'router1')['router']
        router_id = router['id']
        self._check_router(router, [], scopes=[scope])

        # Create network as tenant_2.
        net_resp = self._make_network(self.fmt, 'net1', True,
                                      tenant_id='tenant_2')
        net = net_resp['network']
        net_id = net['id']
        self._check_network(net)

        # Create subnet1 as tenant_2.
        gw1_ip = '10.0.1.1'
        subnet = self._make_subnet(
            self.fmt, net_resp, gw1_ip, '10.0.1.0/24',
            subnetpool_id=pool_id, tenant_id='tenant_2')['subnet']
        subnet1_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Add subnet1 to router.
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip], scopes=[scope])

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, [router], scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)

        # Create subnet2 as tenant_2.
        gw2_ip = '10.0.2.1'
        subnet = self._make_subnet(
            self.fmt, net_resp, gw2_ip, '10.0.2.0/24',
            subnetpool_id=pool_id, tenant_id='tenant_2')['subnet']
        subnet2_id = subnet['id']
        self._check_subnet(subnet, net, [], [gw2_ip])

        # Add subnet2 to router.
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip, gw2_ip], scopes=[scope])

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, [router], scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [(gw1_ip, router)], [], scope)

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [], scope)

        # Remove subnet1 from router.
        info = self.l3_plugin.remove_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw2_ip], scopes=[scope])

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net, [router], scope)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [(gw2_ip, router)], [], scope)

        # Remove subnet2 from router.
        info = self.l3_plugin.remove_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [])

        # Check network.
        net = self._show('networks', net_id)['network']
        self._check_network(net)

        # Check subnet1.
        subnet = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet, net, [], [gw1_ip])

        # Check subnet2.
        subnet = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet, net, [], [gw2_ip])

    def test_shared_network(self):
        # REVISIT: This test is partially redundant with
        # test_shared_network_topologies, so consider combining them.

        # Create router as tenant_1.
        router = self._make_router(
            self.fmt, 'tenant_1', 'router')['router']
        router_id = router['id']
        router_ctx = n_context.Context(None, 'tenant_1')
        self._check_router(router, [])

        # Create net1 as tenant_1.
        net1_resp = self._make_network(
            self.fmt, 'net1', True, tenant_id='tenant_1')
        net1 = net1_resp['network']
        net1_id = net1['id']
        self._check_network(net1)

        # Create subnet1.
        gw1_ip = '10.0.1.1'
        subnet1 = self._make_subnet(
            self.fmt, net1_resp, gw1_ip, '10.0.1.0/24')['subnet']
        subnet1_id = subnet1['id']
        self._check_subnet(subnet1, net1, [], [gw1_ip])

        # Create shared net2 as tenant_2.
        net2_resp = self._make_network(
            self.fmt, 'net2', True, tenant_id='tenant_2', shared=True)
        net2 = net2_resp['network']
        net2_id = net2['id']
        self._check_network(net2)

        # Create subnet2 as tenant_1.
        gw2_ip = '10.0.2.1'
        subnet2 = self._make_subnet(
            self.fmt, net2_resp, gw2_ip, '10.0.2.0/24',
            tenant_id='tenant_1')['subnet']
        subnet2_id = subnet2['id']
        self._check_subnet(subnet2, net2, [], [gw2_ip])

        # Create net3 as tenant_1.
        net3_resp = self._make_network(
            self.fmt, 'net3', True, tenant_id='tenant_1')
        net3 = net3_resp['network']
        net3_id = net3['id']
        self._check_network(net3)

        # Create subnet3.
        gw3_ip = '10.0.3.1'
        subnet3 = self._make_subnet(
            self.fmt, net3_resp, gw3_ip, '10.0.3.0/24')['subnet']
        subnet3_id = subnet3['id']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

        # Add subnet1 to router.
        info = self.l3_plugin.add_router_interface(
            router_ctx, router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip], unscoped_project='tenant_1')

        # Check net1.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1, [router])

        # Check subnet1.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [(gw1_ip, router)], [])

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2)

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [], [gw2_ip])

        # Check net3.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3)

        # Check subnet3.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

        # Add subnet2 to router.
        info = self.l3_plugin.add_router_interface(
            router_ctx, router_id, {'subnet_id': subnet2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(
            router, [gw1_ip, gw2_ip], unscoped_project='tenant_2')

        # Check net1, which should be moved to tenant_2.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1, [router], project='tenant_2')

        # Check subnet1, which should be moved to tenant_2.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [(gw1_ip, router)], [],
                           project='tenant_2')

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2, [router])

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [(gw2_ip, router)], [])

        # Check net3.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3)

        # Check subnet3.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

        # Add subnet3 to router.
        info = self.l3_plugin.add_router_interface(
            router_ctx, router_id, {'subnet_id': subnet3_id})
        self.assertIn(subnet3_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(
            router, [gw1_ip, gw2_ip, gw3_ip], unscoped_project='tenant_2')

        # Check net1, which should still be moved to tenant_2.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1, [router], project='tenant_2')

        # Check subnet1, which should still be moved to tenant_2.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [(gw1_ip, router)], [],
                           project='tenant_2')

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2, [router])

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [(gw2_ip, router)], [])

        # Check net3, which should be moved to tenant_2.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3, [router], project='tenant_2')

        # Check subnet3, which should be moved to tenant_2.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [(gw3_ip, router)], [],
                           project='tenant_2')

        # Remove subnet3 from router.
        info = self.l3_plugin.remove_router_interface(
            router_ctx, router_id, {'subnet_id': subnet3_id})
        self.assertIn(subnet3_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(
            router, [gw1_ip, gw2_ip], unscoped_project='tenant_2')

        # Check net1, which should still be moved to tenant_2.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1, [router], project='tenant_2')

        # Check subnet1, which should still be moved to tenant_2.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [(gw1_ip, router)], [],
                           project='tenant_2')

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2, [router])

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [(gw2_ip, router)], [])

        # Check net3, which should be moved back to tenant_1.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3)

        # Check subnet3, which should be moved back to tenant_1.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

        # Remove subnet2 from router.
        info = self.l3_plugin.remove_router_interface(
            router_ctx, router_id, {'subnet_id': subnet2_id})
        self.assertIn(subnet2_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [gw1_ip], unscoped_project='tenant_1')

        # Check net1, which should be moved back to tenant_1.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1, [router])

        # Check subnet1, which should be moved back to tenant_1.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [(gw1_ip, router)], [])

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2)

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [], [gw2_ip])

        # Check net3.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3)

        # Check subnet3.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

        # Remove subnet1 from router.
        info = self.l3_plugin.remove_router_interface(
            router_ctx, router_id, {'subnet_id': subnet1_id})
        self.assertIn(subnet1_id, info['subnet_ids'])

        # Check router.
        router = self._show('routers', router_id)['router']
        self._check_router(router, [], unscoped_project='tenant_1')

        # Check net1.
        net1 = self._show('networks', net1_id)['network']
        self._check_network(net1)

        # Check subnet1.
        subnet1 = self._show('subnets', subnet1_id)['subnet']
        self._check_subnet(subnet1, net1, [], [gw1_ip])

        # Check net2.
        net2 = self._show('networks', net2_id)['network']
        self._check_network(net2)

        # Check subnet2.
        subnet2 = self._show('subnets', subnet2_id)['subnet']
        self._check_subnet(subnet2, net2, [], [gw2_ip])

        # Check net3.
        net3 = self._show('networks', net3_id)['network']
        self._check_network(net3)

        # Check subnet3.
        subnet3 = self._show('subnets', subnet3_id)['subnet']
        self._check_subnet(subnet3, net3, [], [gw3_ip])

    def test_shared_network_topologies(self):
        def make_net(number, project, shared=False):
            name = 'net%s' % number
            net_resp = self._make_network(
                self.fmt, name, True, tenant_id=project, shared=shared)
            net = net_resp['network']
            net_id = net['id']
            self._check_network(net)
            cidr = '10.0.%s.0/24' % number
            subnet = self._make_subnet(
                self.fmt, net_resp, None, cidr, tenant_id=project)['subnet']
            subnet_id = subnet['id']
            self._check_subnet(subnet, net, [], [])
            ip = '10.0.%s.100' % number
            fixed_ips = [{'subnet_id': subnet_id, 'ip_address': ip}]
            port = self._make_port(
                self.fmt, net_id, fixed_ips=fixed_ips,
                tenant_id=project)['port']
            port_id = port['id']
            port = self._bind_port_to_host(port_id, 'host1')['port']
            port['dns_name'] = ''
            return net_id, subnet_id, port

        def make_router(letter, project):
            name = 'router%s' % letter
            router = self._make_router(self.fmt, project, name)['router']
            self._check_router(router, [])
            return router

        def add_interface(router, net_id, subnet_id, gw_ip, project):
            fixed_ips = [{'subnet_id': subnet_id, 'ip_address': gw_ip}]
            port = self._make_port(
                self.fmt, net_id, fixed_ips=fixed_ips,
                tenant_id=project)['port']
            router_ctx = n_context.Context(None, project)
            info = self.l3_plugin.add_router_interface(
                router_ctx, router['id'], {'port_id': port['id']})
            self.assertIn(subnet_id, info['subnet_ids'])

        def remove_interface(router, net_id, subnet_id, gw_ip, project):
            router_ctx = n_context.Context(None, project)
            info = self.l3_plugin.remove_router_interface(
                router_ctx, router['id'], {'subnet_id': subnet_id})
            self.assertIn(subnet_id, info['subnet_ids'])

        def check_net(net_id, subnet_id, routers, expected_gws,
                      unexpected_gw_ips, project):
            net = self._show('networks', net_id)['network']
            self._check_network(net, routers, project=project)
            subnet = self._show('subnets', subnet_id)['subnet']
            self._check_subnet(
                subnet, net, expected_gws, unexpected_gw_ips, project=project)

        def check_router(router, expected_gw_ips, project):
            router = self._show('routers', router['id'])['router']
            self._check_router(
                router, expected_gw_ips, unscoped_project=project)

        def check_default_vrf(project, should_exist):
            tenant_name = self.name_mapper.project(None, project)
            vrf = self._get_vrf('DefaultVRF', tenant_name, should_exist)
            if should_exist:
                self.assertEqual(tenant_name, vrf.tenant_name)
                self.assertEqual('DefaultVRF', vrf.name)
                self.assertEqual('DefaultRoutedVRF', vrf.display_name)
                self.assertEqual('enforced', vrf.policy_enforcement_pref)

        def check_port_notify(ports=None):
            if not ports:
                mock_notif.assert_not_called()
            else:
                calls = [mock.call(mock.ANY, port) for port in ports]
                mock_notif.assert_has_calls(calls, any_order=True)
                mock_notif.reset_mock()

        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        self._register_agent('host1', AGENT_CONF_OPFLEX)

        t1 = 'tenant_1'
        t2 = 'tenant_2'

        net1, sn1, p1 = make_net(1, t1)
        net2, sn2, p2 = make_net(2, t1)
        net3, sn3, p3 = make_net(3, t1)
        net4, sn4, p4 = make_net(4, t2, True)

        rA = make_router('A', t1)
        rB = make_router('B', t1)
        rC = make_router('C', t1)

        gw1A = '10.0.1.1'
        gw2A = '10.0.2.1'
        gw2B = '10.0.2.2'
        gw3B = '10.0.3.2'
        gw3C = '10.0.3.3'
        gw4C = '10.0.4.3'

        # Check initial state with no routing.
        check_router(rA, [], None)
        check_router(rB, [], None)
        check_router(rC, [], None)
        check_net(net1, sn1, [], [], [gw1A], t1)
        check_net(net2, sn2, [], [], [gw2A, gw2B], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, False)
        check_default_vrf(t2, False)
        self._validate()

        # Add subnet 1 to router A, which should create tenant 1's
        # default VRF.
        add_interface(rA, net1, sn1, gw1A, t1)
        check_port_notify([p1])
        check_router(rA, [gw1A], t1)
        check_router(rB, [], None)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [], [], [gw2A, gw2B], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Add subnet 2 to router A.
        add_interface(rA, net2, sn2, gw2A, t1)
        check_port_notify([p2])
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [], None)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA], [(gw2A, rA)], [gw2B], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Add subnet 2 to router B.
        add_interface(rB, net2, sn2, gw2B, t1)
        check_port_notify()
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B], t1)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Add subnet 3 to router B.
        add_interface(rB, net3, sn3, gw3B, t1)
        check_port_notify([p3])
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B, gw3B], t1)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [rB], [(gw3B, rB)], [gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Add subnet 3 to router C.
        add_interface(rC, net3, sn3, gw3C, t1)
        check_port_notify()
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B, gw3B], t1)
        check_router(rC, [gw3C], t1)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Add shared subnet 4 to router C, which should move router
        # C's topology (networks 1, 2 and 3 and routers A, B and C) to
        # tenant 2, create tenant 2's default VRF, and delete tenant
        # 1's default VRF.
        add_interface(rC, net4, sn4, gw4C, t1)
        check_port_notify([p1, p2, p3])
        check_router(rA, [gw1A, gw2A], t2)
        check_router(rB, [gw2B, gw3B], t2)
        check_router(rC, [gw3C, gw4C], t2)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t2)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t2)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t2)
        check_net(net4, sn4, [rC], [(gw4C, rC)], [], t2)
        check_default_vrf(t1, False)
        check_default_vrf(t2, True)
        self._validate()

        # Remove subnet 3 from router B, which should move router B's
        # topology (networks 1 and 2 and routers A and B) to tenant 1
        # and create tenant 1's default VRF.
        remove_interface(rB, net3, sn3, gw3B, t1)
        check_port_notify([p1, p2])
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B], t1)
        check_router(rC, [gw3C, gw4C], t2)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [rC], [(gw3C, rC)], [gw3B], t2)
        check_net(net4, sn4, [rC], [(gw4C, rC)], [], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, True)
        self._validate()

        # Add subnet 3 back to router B, which should move router B's
        # topology (networks 1 and 2 and routers A and B) to tenant 2
        # again and delete tenant 1's default VRF.
        add_interface(rB, net3, sn3, gw3B, t1)
        check_port_notify([p1, p2])
        check_router(rA, [gw1A, gw2A], t2)
        check_router(rB, [gw2B, gw3B], t2)
        check_router(rC, [gw3C, gw4C], t2)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t2)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t2)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t2)
        check_net(net4, sn4, [rC], [(gw4C, rC)], [], t2)
        check_default_vrf(t1, False)
        check_default_vrf(t2, True)
        self._validate()

        # Remove subnet 2 from router B, which should move network 2's
        # topology (networks 1 and 2 and router A) back to tenant 1
        # and create tenant 1's default VRF
        remove_interface(rB, net2, sn2, gw2B, t1)
        check_port_notify([p1, p2])
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw3B], t2)
        check_router(rC, [gw3C, gw4C], t2)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA], [(gw2A, rA)], [gw2B], t1)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t2)
        check_net(net4, sn4, [rC], [(gw4C, rC)], [], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, True)
        self._validate()

        # Add subnet 2 back to router B, which should move network 2's
        # topology (networks 1 and 2 and router A) to tenant 2 again
        # and delete tenant 1's default VRF.
        add_interface(rB, net2, sn2, gw2B, t1)
        check_port_notify([p1, p2])
        check_router(rA, [gw1A, gw2A], t2)
        check_router(rB, [gw2B, gw3B], t2)
        check_router(rC, [gw3C, gw4C], t2)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t2)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t2)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t2)
        check_net(net4, sn4, [rC], [(gw4C, rC)], [], t2)
        check_default_vrf(t1, False)
        check_default_vrf(t2, True)
        self._validate()

        # Remove subnet 4 from router C, which should move network 3's
        # topology (networks 1, 2 and 3 and routers A and B) to tenant
        # 1, create tenant 1's default VRF, and delete tenant 2's
        # default VRF.
        remove_interface(rC, net4, sn4, gw4C, t1)
        check_port_notify([p1, p2, p3])
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B, gw3B], t1)
        check_router(rC, [gw3C], t1)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [rB, rC], [(gw3B, rB), (gw3C, rC)], [], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)
        self._validate()

        # Remove subnet 3 from router C.
        remove_interface(rC, net3, sn3, gw3C, t1)
        check_port_notify()
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw2B, gw3B], t1)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA, rB], [(gw2A, rA), (gw2B, rB)], [], t1)
        check_net(net3, sn3, [rB], [(gw3B, rB)], [gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)

        # Remove subnet 2 from router B.
        remove_interface(rB, net2, sn2, gw2B, t1)
        check_port_notify()
        check_router(rA, [gw1A, gw2A], t1)
        check_router(rB, [gw3B], t1)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [rA], [(gw2A, rA)], [gw2B], t1)
        check_net(net3, sn3, [rB], [(gw3B, rB)], [gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)

        # Remove subnet 2 from router A.
        remove_interface(rA, net2, sn2, gw2A, t1)
        check_port_notify([p2])
        check_router(rA, [gw1A], t1)
        check_router(rB, [gw3B], t1)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [], [], [gw2A, gw2B], t1)
        check_net(net3, sn3, [rB], [(gw3B, rB)], [gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)

        # Remove subnet 3 from router B.
        remove_interface(rB, net3, sn3, gw3B, t1)
        check_port_notify([p3])
        check_router(rA, [gw1A], t1)
        check_router(rB, [], None)
        check_router(rC, [], None)
        check_net(net1, sn1, [rA], [(gw1A, rA)], [], t1)
        check_net(net2, sn2, [], [], [gw2A, gw2B], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, True)
        check_default_vrf(t2, False)

        # Remove subnet 1 from router A, which should delete tenant
        # 1's default VRF.
        remove_interface(rA, net1, sn1, gw1A, t1)
        check_port_notify([p1])
        check_router(rA, [], None)
        check_router(rB, [], None)
        check_router(rC, [], None)
        check_net(net1, sn1, [], [], [gw1A], t1)
        check_net(net2, sn2, [], [], [gw2A, gw2B], t1)
        check_net(net3, sn3, [], [], [gw3B, gw3C], t1)
        check_net(net4, sn4, [], [], [gw4C], t2)
        check_default_vrf(t1, False)
        check_default_vrf(t2, False)
        self._validate()

    def test_address_scope_pre_existing_vrf(self):
        aim_ctx = aim_context.AimContext(self.db_session)

        self.aim_mgr.create(
            aim_ctx, aim_resource.Tenant(name=self.t1_aname, monitored=True))
        vrf = aim_resource.VRF(tenant_name=self.t1_aname, name='ctx1',
                               display_name='CTX1', monitored=True)
        self.aim_mgr.create(aim_ctx, vrf)

        # create
        scope = self._make_address_scope_for_vrf(vrf.dn,
                                                 name='as1')['address_scope']
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        self.assertEqual('CTX1', vrf.display_name)

        # update name -> no-op for AIM object
        self._update('address-scopes', scope['id'],
                     {'address_scope': {'name': 'as2'}})
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        self.assertEqual('CTX1', vrf.display_name)

        # delete
        self._delete('address-scopes', scope['id'])
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        self.assertIsNotNone(vrf)
        self.assertEqual('CTX1', vrf.display_name)

    def test_network_in_address_scope_pre_existing_vrf(self, common_vrf=False):
        aim_ctx = aim_context.AimContext(self.db_session)

        if not common_vrf:
            tenant = aim_resource.Tenant(
                name=self.t1_aname,
                display_name=TEST_TENANT_NAMES['t1'],
                monitored=True)
            self.aim_mgr.create(aim_ctx, tenant)
        vrf = aim_resource.VRF(
            tenant_name='common' if common_vrf else self.t1_aname,
            name='ctx1', monitored=True)
        vrf = self.aim_mgr.create(aim_ctx, vrf)

        scope = self._make_address_scope_for_vrf(vrf.dn,
                                                 name='as1')['address_scope']

        pool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='sp', address_scope_id=scope['id'],
            tenant_id=scope['tenant_id'], default_prefixlen=24)['subnetpool']

        net = self._make_network(self.fmt, 'net1', True)['network']
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '10.0.1.1', '10.0.1.0/24',
            subnetpool_id=pool['id'])['subnet']
        self._check_network(net)

        router = self._make_router(self.fmt, self._tenant_id,
                                   'router1')['router']
        self._router_interface_action('add', router['id'], subnet['id'], None)
        net = self._show('networks', net['id'])['network']
        self._check_network(net, routers=[router], vrf=vrf)

        self._router_interface_action('remove', router['id'], subnet['id'],
                                      None)
        net = self._show('networks', net['id'])['network']
        self._check_network(net)

    def test_network_in_address_scope_pre_existing_common_vrf(self):
        self.test_network_in_address_scope_pre_existing_vrf(common_vrf=True)

    def _test_default_subnetpool(self, prefix, sn1, gw1, sn2, gw2, sn3, gw3):
        # Create a non-default non-shared SP
        subnetpool = self._make_subnetpool(
            self.fmt, [prefix], name='spool1',
            tenant_id='t1')['subnetpool']
        net = self._make_network(self.fmt, 'pvt-net1', True,
                                 tenant_id='t1')['network']
        sub = self._make_subnet(
            self.fmt, {'network': net,
                       }, gw1, sn1,
            tenant_id='t1',
            ip_version=subnetpool['ip_version'])['subnet']
        self.assertIsNone(sub['subnetpool_id'])
        # Make SP default
        data = {'subnetpool': {'is_implicit': True}}
        self._update('subnetpools', subnetpool['id'], data)
        # Make a new network since Subnets hosted on the same network must be
        # allocated from the same subnet pool
        net = self._make_network(self.fmt, 'pvt-net2', True,
                                 tenant_id='t1')['network']
        # Create another subnet
        sub = self._make_subnet(
            self.fmt, {'network': net}, gw2,
            sn2, tenant_id='t1',
            ip_version=subnetpool['ip_version'])['subnet']
        # This time, SP ID is set
        self.assertEqual(subnetpool['id'], sub['subnetpool_id'])
        # Create a shared SP in a different tenant
        subnetpool_shared = self._make_subnetpool(
            self.fmt, [prefix], name='spool1', is_implicit=True,
            shared=True, tenant_id='t2', admin=True)['subnetpool']
        # A subnet created in T1 still gets the old pool ID
        sub = self._make_subnet(
            self.fmt, {'network': net}, gw3,
            sn3, tenant_id='t1',
            ip_version=subnetpool_shared['ip_version'])['subnet']
        # This time, SP ID is set
        self.assertEqual(subnetpool['id'], sub['subnetpool_id'])
        # Creating a subnet somewhere else, however, will get the SP ID from
        # the shared SP
        net = self._make_network(self.fmt, 'pvt-net3', True,
                                 tenant_id='t3')['network']
        sub = self._make_subnet(
            self.fmt, {'network': net}, gw1,
            sn1, tenant_id='t3',
            ip_version=subnetpool_shared['ip_version'])['subnet']
        self.assertEqual(subnetpool_shared['id'], sub['subnetpool_id'])

    def test_default_subnetpool(self):
        # First do a set with the v4 address family
        self._test_default_subnetpool('10.0.0.0/8',
                                      '10.0.1.0/24', '10.0.1.1',
                                      '10.0.2.0/24', '10.0.2.1',
                                      '10.0.3.0/24', '10.0.3.1')
        # Do the same test with v6 (v4 still present), using the same tenants
        # and shared properties. Since they are different address families,
        # it should not conflict
        self._test_default_subnetpool('2001:db8::1/56',
                                      '2001:db8:0:1::0/64', '2001:db8:0:1::1',
                                      '2001:db8:0:2::0/64', '2001:db8:0:2::1',
                                      '2001:db8:0:3::0/64', '2001:db8:0:3::1')

    def test_implicit_subnetpool(self):
        # Create implicit SP (non-shared)
        sp = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='spool1',
            tenant_id='t1', is_implicit=True)['subnetpool']
        self.assertTrue(sp['is_implicit'])
        # Update is_implicit to false
        sp = self._update(
            'subnetpools', sp['id'],
            {'subnetpool': {'is_implicit': False}})['subnetpool']
        self.assertFalse(sp['is_implicit'])
        # Update to True
        sp = self._update(
            'subnetpools', sp['id'],
            {'subnetpool': {'is_implicit': True}})['subnetpool']
        self.assertTrue(sp['is_implicit'])
        # Create another implicit in the same family, same tenant, it will fail
        self.assertRaises(webob.exc.HTTPClientError, self._make_subnetpool,
                          self.fmt, ['11.0.0.0/8'], name='spool1',
                          tenant_id='t1', is_implicit=True)
        # Create another implicit in different family, same tenant, it succeeds
        sp2 = self._make_subnetpool(
            self.fmt, ['2001:db8:1::0/56'], name='spool1',
            is_implicit=True, tenant_id='t1')['subnetpool']
        self.assertTrue(sp2['is_implicit'])

        # Create a normal SP, will succeed
        sp2 = self._make_subnetpool(
            self.fmt, ['11.0.0.0/8'], name='spool2',
            tenant_id='t1')['subnetpool']
        self.assertFalse(sp2['is_implicit'])
        # Try to update to implicit, will fail
        self._update('subnetpools', sp2['id'],
                     {'subnetpool': {'is_implicit': True}},
                     expected_code=webob.exc.HTTPBadRequest.code)
        # Create a shared implicit SP in a different tenant
        sp3 = self._make_subnetpool(
            self.fmt, ['11.0.0.0/8'], name='spoolShared',
            tenant_id='t2', shared=True, admin=True,
            is_implicit=True)['subnetpool']
        self.assertTrue(sp3['is_implicit'])
        # Update SP shared state is not supported by Neutron

        # Create another shared implicit in the same family, it will fail
        self.assertRaises(webob.exc.HTTPClientError, self._make_subnetpool,
                          self.fmt, ['12.0.0.0/8'], name='spool3',
                          tenant_id='t3', shared=True,
                          admin=True, is_implicit=True)

        # Create a shared implicit SP in a different address family
        sp3 = self._make_subnetpool(
            self.fmt, ['2001:db8:2::0/56'], name='spoolSharedv6',
            tenant_id='t2', shared=True, admin=True,
            is_implicit=True)['subnetpool']
        self.assertTrue(sp3['is_implicit'])

    def test_dhcp_provisioning_blocks_inserted_on_update(self):
        ctx = n_context.get_admin_context()
        plugin = directory.get_plugin()

        def _fake_dhcp_agent():
            agent = mock.Mock()
            plugin = directory.get_plugin()
            return mock.patch.object(
                plugin, 'get_dhcp_agents_hosting_networks',
                return_value=[agent]).start()

        dhcp_agt_mock = _fake_dhcp_agent()
        update_dict = {'binding:host_id': 'newhost'}

        def _host_agents(self, agent_type):
            if agent_type == ofcst.AGENT_TYPE_OPFLEX_OVS:
                fake_agent = {"alive": False}
                return [fake_agent]

        orig_host_agents = getattr(driver_context.PortContext, "host_agents")
        setattr(driver_context.PortContext, "host_agents", _host_agents)

        with self.port() as port:
            with mock.patch.object(provisioning_blocks,
                                   'add_provisioning_component') as ap:
                port['port'].update(update_dict)
                plugin.update_port(ctx, port['port']['id'], port)
                ap.assert_called()

        setattr(driver_context.PortContext, "host_agents", orig_host_agents)
        dhcp_agt_mock.stop()


class TestTrackedResources(tr_res.TestTrackedResources, ApicAimTestCase):

    def setUp(self, **kwargs):
        super(TestTrackedResources, self).setUp(**kwargs)
        for patch in mock.mock._patch._active_patches:
            if patch.attribute == '_ensure_default_security_group':
                patch.stop()


class TestSyncState(ApicAimTestCase):
    @staticmethod
    def _get_synced_status(self, context, resource, **kwargs):
        status = aim_status.AciStatus.SYNCED

        aim_ctx = context
        aim_mgr = aim_manager.AimManager()
        res_type, res_id = aim_mgr._get_status_params(aim_ctx, resource)
        if not res_type:
            return None
        return aim_mgr.create(
            aim_ctx, aim_status.AciStatus(
                resource_root=resource.root, sync_status=status,
                resource_type=res_type,
                resource_dn=resource.dn,
                resource_id=res_id), overwrite=True)

    @staticmethod
    def _get_pending_status_for_type(context, resource, type, **kwargs):
        status = (isinstance(resource, type) and
                  aim_status.AciStatus.SYNC_PENDING or
                  aim_status.AciStatus.SYNCED)

        aim_ctx = context
        aim_mgr = aim_manager.AimManager()
        res_type, res_id = aim_mgr._get_status_params(aim_ctx, resource)
        if not res_type:
            return None
        return aim_mgr.create(
            aim_ctx, aim_status.AciStatus(
                resource_root=resource.root, sync_status=status,
                resource_type=res_type,
                resource_dn=resource.dn,
                resource_id=res_id), overwrite=True)

    @staticmethod
    def _get_failed_status_for_type(context, resource, type, **kwargs):
        status = (isinstance(resource, type) and
                  aim_status.AciStatus.SYNC_FAILED or
                  aim_status.AciStatus.SYNC_PENDING)

        aim_ctx = context
        aim_mgr = aim_manager.AimManager()
        res_type, res_id = aim_mgr._get_status_params(aim_ctx, resource)
        if not res_type:
            return None
        return aim_mgr.create(
            aim_ctx, aim_status.AciStatus(
                resource_root=resource.root, sync_status=status,
                resource_type=res_type,
                resource_dn=resource.dn,
                resource_id=res_id), overwrite=True)

    _aim_get_statuses = aim_manager.AimManager.get_statuses

    @staticmethod
    def _mocked_get_statuses(self, context, resources):
        for res in resources:
            self.get_status(context, res)
        return TestSyncState._aim_get_statuses(self, context, resources)

    def _test_network(self, expected_state):
        net = self._make_network(self.fmt, 'net1', True)['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'])

        net = self._show('networks', net['id'])['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'])

        net = self._list(
            'networks', query_params=('id=%s' % net['id']))['networks'][0]
        self.assertEqual(expected_state, net['apic:synchronization_state'])

    def test_network_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('synced')

    def test_network_bd_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.BridgeDomain)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('build')

    def test_network_bd_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.BridgeDomain)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('error')

    def test_network_epg_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.EndpointGroup)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('build')

    def test_network_epg_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.EndpointGroup)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('error')

    def test_network_vrf_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('build')

    def test_network_vrf_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_network('error')

    def _test_address_scope(self, expected_state):
        scope = self._make_address_scope(self.fmt, 4, name='scope1')[
            'address_scope']
        self.assertEqual(expected_state, scope['apic:synchronization_state'])

        scope = self._show('address-scopes', scope['id'])['address_scope']
        self.assertEqual(expected_state, scope['apic:synchronization_state'])

        scope = self._list(
            'address-scopes',
            query_params=('id=%s' % scope['id']))['address_scopes'][0]
        self.assertEqual(expected_state, scope['apic:synchronization_state'])

    def test_address_scope_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_address_scope('synced')

    def test_address_scope_vrf_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_address_scope('build')

    def test_address_scope_vrf_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_address_scope('error')

    def _test_router(self, expected_state):
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

        router = self._list(
            'routers',
            query_params=('id=%s' % router['id']))['routers'][0]
        self.assertEqual(expected_state, router['apic:synchronization_state'])

    def test_router_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router('synced')

    def test_router_contract_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.Contract)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('build')

    def test_router_contract_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.Contract)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('error')

    def test_router_subject_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.ContractSubject)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('build')

    def test_router_subject_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.ContractSubject)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router('error')

    def _test_router_interface_vrf(self, expected_state):
        net_resp = self._make_network(self.fmt, 'net1', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.0.1', '10.0.0.0/24')['subnet']
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router['id'],
            {'subnet_id': subnet['id']})

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state, router['apic:synchronization_state'])

        router = self._list(
            'routers',
            query_params=('id=%s' % router['id']))['routers'][0]
        self.assertEqual(expected_state, router['apic:synchronization_state'])

    def test_router_interface_vrf_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router_interface_vrf('synced')

    def test_router_interface_vrf_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_vrf('build')

    def test_router_interface_vrf_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.VRF)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_vrf('error')

    def _test_router_interface_subnet(self, expected_state):
        net_resp = self._make_network(self.fmt, 'net1', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.0.1', '10.0.0.0/24')['subnet']
        router = self._make_router(self.fmt, 'test-tenant', 'router1')[
            'router']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router['id'],
            {'subnet_id': subnet['id']})

        router = self._show('routers', router['id'])['router']
        self.assertEqual(expected_state,
                         router['apic:synchronization_state'])

        router = self._list(
            'routers',
            query_params=('id=%s' % router['id']))['routers'][0]
        self.assertEqual(expected_state, router['apic:synchronization_state'])

        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

        subnet = self._list(
            'subnets', query_params=('id=%s' % subnet['id']))['subnets'][0]
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

    def test_router_interface_subnet_synced(self):
        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_router_interface_subnet('synced')

    def test_router_interface_subnet_build(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_pending_status_for_type(
                context, resource, aim_resource.Subnet)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_subnet('build')

    def test_router_interface_subnet_error(self):
        def get_status(self, context, resource, create_if_absent=True):
            return TestSyncState._get_failed_status_for_type(
                context, resource, aim_resource.Subnet)

        with mock.patch('aim.aim_manager.AimManager.get_status', get_status):
            self._test_router_interface_subnet('error')

    def _test_external_network(self, expected_state, dn=None, msg=None):
        net = self._make_ext_network('net1', dn=dn)
        self.assertEqual(expected_state, net['apic:synchronization_state'],
                         msg)
        net = self._show('networks', net['id'])['network']
        self.assertEqual(expected_state, net['apic:synchronization_state'],
                         msg)

        net = self._list(
            'networks', query_params=('id=%s' % net['id']))['networks'][0]
        self.assertEqual(expected_state, net['apic:synchronization_state'])

    def test_external_network(self):
        ext_net = aim_resource.ExternalNetwork.from_dn(self.dn_t1_l1_n1)
        ext_net.monitored = True
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.create(aim_ctx, ext_net)

        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            with mock.patch('aim.aim_manager.AimManager.get_statuses',
                            TestSyncState._mocked_get_statuses):
                self._test_external_network('synced',
                                            dn=self.dn_t1_l1_n1)

        for expected_status, status_func in [
                ('build', TestSyncState._get_pending_status_for_type),
                ('error', TestSyncState._get_failed_status_for_type)]:
            for a_res in [aim_resource.ExternalNetwork,
                          aim_resource.EndpointGroup,
                          aim_resource.BridgeDomain,
                          aim_resource.VRF]:
                def get_status(self, context, resource, create_if_absent=True):
                    return status_func(context, resource, a_res)
                with mock.patch('aim.aim_manager.AimManager.get_status',
                                get_status):
                    with mock.patch('aim.aim_manager.AimManager.get_statuses',
                                    TestSyncState._mocked_get_statuses):
                        self._test_external_network(expected_status,
                                                    dn=self.dn_t1_l1_n1,
                                                    msg='%s' % a_res)

    def test_unmanaged_external_network(self):
        self._test_external_network('N/A')

    def _test_external_subnet(self, expected_state, dn=None):
        net = self._make_ext_network('net1', dn=dn)
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '10.0.0.1', '10.0.0.0/24')['subnet']

        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

        subnet = self._list(
            'subnets', query_params=('id=%s' % subnet['id']))['subnets'][0]
        self.assertEqual(expected_state, subnet['apic:synchronization_state'])

        self._delete("subnets", subnet['id'])

    def test_external_subnet(self):
        ext_net = aim_resource.ExternalNetwork.from_dn(self.dn_t1_l1_n1)
        ext_net.monitored = True
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.create(aim_ctx, ext_net)

        with mock.patch('aim.aim_manager.AimManager.get_status',
                        TestSyncState._get_synced_status):
            self._test_external_subnet('synced',
                                       dn=self.dn_t1_l1_n1)

        for expected_status, status_func in [
                ('build', TestSyncState._get_pending_status_for_type),
                ('error', TestSyncState._get_failed_status_for_type)]:
            def get_status(self, context, resource, **kwargs):
                return status_func(context, resource, aim_resource.Subnet)
            with mock.patch('aim.aim_manager.AimManager.get_status',
                            get_status):
                self._test_external_subnet(expected_status,
                                           dn=self.dn_t1_l1_n1)

    def test_unmanaged_external_subnet(self):
        self._test_external_subnet('N/A')


class TestTopology(ApicAimTestCase):
    def test_network_subnets_on_same_router(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net_id = net_resp['network']['id']

        # Create router.
        router1_id = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']['id']

        # Create subnet and add to router.
        subnet1_id = self._make_subnet(
            self.fmt, net_resp, '10.0.1.1', '10.0.1.0/24')['subnet']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router1_id,
            {'subnet_id': subnet1_id})

        # Create 2nd subnet and add to router.
        subnet2_id = self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24')['subnet']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router1_id,
            {'subnet_id': subnet2_id})

        # Create another router.
        router2_id = self._make_router(
            self.fmt, 'test-tenant', 'router2')['router']['id']

        # Create 3rd subnet and verify adding to 2nd router fails.
        subnet3_id = self._make_subnet(
            self.fmt, net_resp, '10.0.3.1', '10.0.3.0/24')['subnet']['id']
        self.assertRaises(
            exceptions.UnsupportedRoutingTopology,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router2_id,
            {'subnet_id': subnet3_id})

        # Verify adding 1st subnet to 2nd router fails.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.100'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.assertRaises(
            exceptions.UnsupportedRoutingTopology,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router2_id, {'port_id': port_id})

        # Verify adding 2nd subnet to 2nd router fails.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': '10.0.2.100'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.assertRaises(
            exceptions.UnsupportedRoutingTopology,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router2_id, {'port_id': port_id})

        # REVISIT: The following tests are temporary. This override
        # flag and these tests should be removed when a better
        # solution is implemented for supporting multiple external
        # segments with an L3P in GBP.

        # Verify adding 3rd subnet to 2nd router succeeds with
        # override flag.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router2_id,
            {'subnet_id': subnet3_id,
             l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION: True})

        # Verify adding 1st subnet to 2nd router succeeds with
        # override flag.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.101'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router2_id,
            {'port_id': port_id,
             l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION: True})

        # Verify adding 2nd subnet to 2nd router succeeds with
        # override flag.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': '10.0.2.101'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router2_id,
            {'port_id': port_id,
             l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION: True})

    def test_network_subnet_on_multple_routers(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net_id = net_resp['network']['id']

        # Create router.
        router1_id = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']['id']

        # Create subnet and add to router.
        subnet1_id = self._make_subnet(
            self.fmt, net_resp, '10.0.1.1', '10.0.1.0/24')['subnet']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router1_id,
            {'subnet_id': subnet1_id})

        # Create 2nd router.
        router2_id = self._make_router(
            self.fmt, 'test-tenant', 'router2')['router']['id']

        # Add same subnet to 2nd router.
        fixed_ips = [{'subnet_id': subnet1_id, 'ip_address': '10.0.1.100'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router2_id,
            {'port_id': port_id})

        # Create 2nd subnet and verify adding to either router fails.
        subnet2_id = self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24')['subnet']['id']
        self.assertRaises(
            exceptions.UnsupportedRoutingTopology,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router1_id,
            {'subnet_id': subnet2_id})
        self.assertRaises(
            exceptions.UnsupportedRoutingTopology,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router2_id,
            {'subnet_id': subnet2_id})

        # REVISIT: The following tests are temporary. This override
        # flag and these tests should be removed when a better
        # solution is implemented for supporting multiple external
        # segments with an L3P in GBP.

        # Verify adding 2nd subnet to 1st router succeeds with
        # override flag.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router1_id,
            {'subnet_id': subnet2_id,
             l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION: True})

        # Verify adding 2nd subnet to 2nd router succeeds with
        # override flag.
        fixed_ips = [{'subnet_id': subnet2_id, 'ip_address': '10.0.2.100'}]
        port_id = self._make_port(
            self.fmt, net_id, fixed_ips=fixed_ips)['port']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router2_id,
            {'port_id': port_id,
             l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION: True})

    def test_reject_routing_shared_networks_from_different_projects(self):
        # Create router as tenant_1.
        router_id = self._make_router(
            self.fmt, 'tenant_1', 'router')['router']['id']
        router_ctx = n_context.get_admin_context()

        # Create shared net1 and subnet1 as tenant_1.
        net1_resp = self._make_network(
            self.fmt, 'net1', True, tenant_id='tenant_1', shared=True)
        gw1_ip = '10.0.1.1'
        subnet1_id = self._make_subnet(
            self.fmt, net1_resp, gw1_ip, '10.0.1.0/24',
            tenant_id='tenant_1')['subnet']['id']

        # Create shared net2 and subnet2 as tenant_2.
        net2_resp = self._make_network(
            self.fmt, 'net2', True, tenant_id='tenant_2', shared=True)
        gw2_ip = '10.0.2.1'
        subnet2_id = self._make_subnet(
            self.fmt, net2_resp, gw2_ip, '10.0.2.0/24',
            tenant_id='tenant_2')['subnet']['id']

        # Create shared net3 and subnet3 as tenant_1.
        net3_resp = self._make_network(
            self.fmt, 'net3', True, tenant_id='tenant_1', shared=True)
        gw3_ip = '10.0.3.1'
        subnet3_id = self._make_subnet(
            self.fmt, net3_resp, gw3_ip, '10.0.3.0/24',
            tenant_id='tenant_1')['subnet']['id']

        # Add shared subnet1 from tenant_1 to router.
        self.l3_plugin.add_router_interface(
            router_ctx, router_id, {'subnet_id': subnet1_id})

        # Verify adding shared subnet2 tenant_2 to router fails.
        self.assertRaises(
            exceptions.UnscopedSharedNetworkProjectConflict,
            self.l3_plugin.add_router_interface,
            router_ctx, router_id, {'subnet_id': subnet2_id})

        # Add shared subnet3 from tenant_1 to router.
        self.l3_plugin.add_router_interface(
            router_ctx, router_id, {'subnet_id': subnet3_id})

    def test_reject_update_scope_of_routed_pool(self):
        # TODO(rkukura): When implemented, change this to verify
        # updates that are topologically impossible are rejected. For
        # now, all updates of a subnetpool's addresss_scope_id are
        # reject if that subnetpool is associated with any router.

        # Create address_scope.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = scope['id']

        # Create subnetpool without address_scope.
        pool = self._make_subnetpool(self.fmt, ['10.1.0.0/16'], name='sp1',
                                     tenant_id='test-tenant',  # REVISIT
                                     default_prefixlen=24)['subnetpool']
        pool_id = pool['id']

        # Create network with subnet using the subnetpool.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net_id = net_resp['network']['id']
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.1.0.1', '10.1.0.0/24',
            subnetpool_id=pool_id)['subnet']
        subnet1_id = subnet['id']

        # Verify network is not associated with address_scope.
        net = self._show('networks', net_id)['network']
        self.assertIsNone(net['ipv4_address_scope'])

        # Associate subnetpool with address_scope.
        data = {'subnetpool': {'address_scope_id': scope_id}}
        self._update('subnetpools', pool_id, data)

        # Verify network is associated with address_scope.
        net = self._show('networks', net_id)['network']
        self.assertEqual(scope_id, net['ipv4_address_scope'])

        # Disassociate subnetpool from address_scope.
        data = {'subnetpool': {'address_scope_id': None}}
        self._update('subnetpools', pool_id, data)

        # Verify network is not associated with address_scope.
        net = self._show('networks', net_id)['network']
        self.assertIsNone(net['ipv4_address_scope'])

        # Create router and add subnet.
        router_id = self._make_router(
            self.fmt, 'test-tenant', 'router1')['router']['id']
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})

        # Verify associating subnetpool with address_scope fails.
        data = {'subnetpool': {'address_scope_id': scope_id}}
        result = self._update('subnetpools', pool_id, data,
                              webob.exc.HTTPBadRequest.code)
        self.assertEqual('ScopeUpdateNotSupported',
                         result['NeutronError']['type'])

    def test_reject_non_isomorphic_network_routing(self):
        # Create v6 scope and pool.
        scope = self._make_address_scope(
            self.fmt, 6, name='as6')['address_scope']
        scope6_id = scope['id']
        scope6_vrf = scope['apic:distinguished_names']['VRF']
        pool = self._make_subnetpool(
            self.fmt, ['2001:db8:1::0/56'], name='sp6',
            tenant_id=self._tenant_id,
            address_scope_id=scope6_id)['subnetpool']
        pool6_id = pool['id']

        # Create isomorphic v4 scope and pool.
        scope = self._make_address_scope_for_vrf(
            scope6_vrf, 4, name='as4i')['address_scope']
        scope4i_id = scope['id']
        pool = self._make_subnetpool(
            self.fmt, ['10.1.0.0/16'], name='sp4i', tenant_id=self._tenant_id,
            address_scope_id=scope4i_id, default_prefixlen=24)['subnetpool']
        pool4i_id = pool['id']

        # Create non-isomorphic v4 scope and pool.
        scope = self._make_address_scope(
            self.fmt, 4, name='as4n')['address_scope']
        scope4n_id = scope['id']
        pool = self._make_subnetpool(
            self.fmt, ['10.2.0.0/16'], name='sp4n', tenant_id=self._tenant_id,
            address_scope_id=scope4n_id)['subnetpool']
        pool4n_id = pool['id']

        # Create network with isomorphic scoped v4 and v6 subnets.
        net_resp = self._make_network(self.fmt, 'net1', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.1.1.1', '10.1.1.0/24',
            subnetpool_id=pool4i_id)['subnet']
        subnet14_id = subnet['id']
        subnet = self._make_subnet(
            self.fmt, net_resp, '2001:db8:1:1::1', '2001:db8:1:1::0/64',
            ip_version=6, subnetpool_id=pool6_id)['subnet']
        subnet16_id = subnet['id']

        # Create network with non-isomorphic scoped v4 and v6 subnets.
        net_resp = self._make_network(self.fmt, 'net2', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.2.1.1', '10.2.1.0/24',
            subnetpool_id=pool4n_id)['subnet']
        subnet24_id = subnet['id']
        subnet = self._make_subnet(
            self.fmt, net_resp, '2001:db8:1:2::1', '2001:db8:1:2::0/64',
            ip_version=6, subnetpool_id=pool6_id)['subnet']
        subnet26_id = subnet['id']

        # Create network with unscoped v4 and scoped v6 subnets.
        net_resp = self._make_network(self.fmt, 'net3', True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.3.1.1', '10.3.1.0/24')['subnet']
        subnet34_id = subnet['id']
        subnet = self._make_subnet(
            self.fmt, net_resp, '2001:db8:1:3::1', '2001:db8:1:3::0/64',
            ip_version=6, subnetpool_id=pool6_id)['subnet']
        subnet36_id = subnet['id']

        # Create router.
        router_id = self._make_router(
            self.fmt, self._tenant_id, 'router1')['router']['id']

        # Verify adding isomorphic scoped subnets on network succeeds.
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet14_id})
        self.assertIn(subnet14_id, info['subnet_ids'])
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet16_id})
        self.assertIn(subnet16_id, info['subnet_ids'])

        # Verify adding non-isomorphic scoped subnets on network fails.
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet24_id})
        self.assertIn(subnet24_id, info['subnet_ids'])
        self.assertRaises(
            exceptions.NonIsomorphicNetworkRoutingUnsupported,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet26_id})

        # Verify adding scoped and unscoped subnets on network fails.
        info = self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet34_id})
        self.assertIn(subnet34_id, info['subnet_ids'])
        self.assertRaises(
            exceptions.NonIsomorphicNetworkRoutingUnsupported,
            self.l3_plugin.add_router_interface,
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet36_id})

    # REVISIT: Add test_reject_v4_scope_with_different_v6_scopes.

    def test_unscoped_subnetpool_subnets_with_router(self):
        # Test that subnets from a subnetpool that has no address-scope
        # can be connected to a router.
        sp = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='spool1',
            tenant_id='t1', shared=True, admin=True)['subnetpool']
        net = self._make_network(self.fmt, 'net', True, tenant_id='t1',
                                 shared=True)

        sub1 = self._make_subnet(self.fmt, net, '10.10.10.1',
                                 '10.10.10.0/24', sp['id'],
                                 tenant_id='t1')['subnet']
        sub2 = self._make_subnet(self.fmt, net, '10.10.20.1',
                                 '10.10.20.0/24', sp['id'],
                                 tenant_id='t1')['subnet']
        sub3 = self._make_subnet(self.fmt, net, '10.20.10.1',
                                 '10.20.10.0/24', sp['id'],
                                 tenant_id='t2')['subnet']

        rtr = self._make_router(self.fmt, 't1', 'rtr')['router']

        self._router_interface_action('add', rtr['id'], sub1['id'], None)
        self._router_interface_action('add', rtr['id'], sub2['id'], None)
        self._router_interface_action('add', rtr['id'], sub3['id'], None)


class TestMigrations(ApicAimTestCase, db.DbMixin):
    def test_apic_aim_persist(self):
        aim_ctx = aim_context.AimContext(self.db_session)

        # Create a normal address scope and delete its mapping.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope1_id = scope['id']
        scope1_vrf = scope[DN]['VRF']
        mapping = self._get_address_scope_mapping(self.db_session, scope1_id)
        with self.db_session.begin():
            self.db_session.delete(mapping)

        # Create an address scope with pre-existing VRF, delete its
        # mapping, and create record in old DB table.
        tenant = aim_resource.Tenant(name=self.t1_aname, monitored=True)
        self.aim_mgr.create(aim_ctx, tenant)
        vrf = aim_resource.VRF(
            tenant_name=self.t1_aname, name='pre_existing', monitored=True)
        self.aim_mgr.create(aim_ctx, vrf)
        scope = self._make_address_scope_for_vrf(vrf.dn)['address_scope']
        scope2_id = scope['id']
        scope2_vrf = scope[DN]['VRF']
        self.assertEqual(vrf.dn, scope2_vrf)
        mapping = self._get_address_scope_mapping(self.db_session, scope2_id)
        with self.db_session.begin():
            self.db_session.delete(mapping)
        old_db = data_migrations.DefunctAddressScopeExtensionDb(
            address_scope_id=scope2_id, vrf_dn=scope2_vrf)
        with self.db_session.begin():
            self.db_session.add(old_db)

        # Create a normal network and delete its mapping.
        net = self._make_network(self.fmt, 'net1', True)['network']
        net1_id = net['id']
        net1_bd = net[DN]['BridgeDomain']
        net1_epg = net[DN]['EndpointGroup']
        net1_vrf = net[DN]['VRF']
        mapping = self._get_network_mapping(self.db_session, net1_id)
        with self.db_session.begin():
            self.db_session.delete(mapping)

        # Create an external network and delete its mapping.
        net = self._make_ext_network('net2', dn=self.dn_t1_l1_n1)
        net2_id = net['id']
        net2_bd = net[DN]['BridgeDomain']
        net2_epg = net[DN]['EndpointGroup']
        net2_vrf = net[DN]['VRF']
        mapping = self._get_network_mapping(self.db_session, net2_id)
        with self.db_session.begin():
            self.db_session.delete(mapping)

        # Create an unmanaged external network and verify it has no
        # mapping.
        net = self._make_ext_network('net3')
        net3_id = net['id']
        mapping = self._get_network_mapping(self.db_session, net3_id)
        self.assertIsNone(mapping)

        # Verify normal address scope is missing DN.
        scope = self._show('address-scopes', scope1_id)['address_scope']
        self.assertNotIn('VRF', scope[DN])

        # Verify address scope with pre-existing VRF is missing DN.
        scope = self._show('address-scopes', scope2_id)['address_scope']
        self.assertNotIn('VRF', scope[DN])

        # Verify normal network is missing DNs.
        net = self._show('networks', net1_id)['network']
        self.assertNotIn('BridgeDomain', net[DN])
        self.assertNotIn('EndpointGroup', net[DN])
        self.assertNotIn('VRF', net[DN])

        # Verify external network is missing DNs.
        net = self._show('networks', net2_id)['network']
        self.assertNotIn('BridgeDomain', net[DN])
        self.assertNotIn('EndpointGroup', net[DN])
        self.assertNotIn('VRF', net[DN])

        # Verify unmanaged external network has no DNs.
        net = self._show('networks', net3_id)['network']
        self.assertNotIn('BridgeDomain', net[DN])
        self.assertNotIn('EndpointGroup', net[DN])
        self.assertNotIn('VRF', net[DN])

        # Perform the data migration.
        data_migrations.do_apic_aim_persist_migration(self.db_session)

        # Verify normal address scope is successfully migrated.
        scope = self._show('address-scopes', scope1_id)['address_scope']
        self.assertEqual(scope1_vrf, scope[DN]['VRF'])

        # Verify address scope with pre-existing VRF is successfully
        # migrated.
        scope = self._show('address-scopes', scope2_id)['address_scope']
        self.assertEqual(scope2_vrf, scope[DN]['VRF'])

        # Verify normal network is successfully migrated.
        net = self._show('networks', net1_id)['network']
        self.assertEqual(net1_bd, net[DN]['BridgeDomain'])
        self.assertEqual(net1_epg, net[DN]['EndpointGroup'])
        self.assertEqual(net1_vrf, net[DN]['VRF'])

        # Verify external network is successfully migrated.
        net = self._show('networks', net2_id)['network']
        self.assertEqual(net2_bd, net[DN]['BridgeDomain'])
        self.assertEqual(net2_epg, net[DN]['EndpointGroup'])
        self.assertEqual(net2_vrf, net[DN]['VRF'])

        # Verify unmanaged external network has no mapping or DNs.
        mapping = self._get_network_mapping(self.db_session, net3_id)
        self.assertIsNone(mapping)
        net = self._show('networks', net3_id)['network']
        self.assertNotIn('BridgeDomain', net[DN])
        self.assertNotIn('EndpointGroup', net[DN])
        self.assertNotIn('VRF', net[DN])

        # Verify deleting normal address scope deletes VRF.
        self._delete('address-scopes', scope1_id)
        vrf = self._find_by_dn(scope1_vrf, aim_resource.VRF)
        self.assertIsNone(vrf)

        # Verify deleting address scope with pre-existing VRF does not
        # delete VRF.
        self._delete('address-scopes', scope2_id)
        vrf = self._find_by_dn(scope2_vrf, aim_resource.VRF)
        self.assertIsNotNone(vrf)

        # Verify deleting normal network deletes BD and EPG.
        self._delete('networks', net1_id)
        bd = self._find_by_dn(net1_bd, aim_resource.BridgeDomain)
        self.assertIsNone(bd)
        epg = self._find_by_dn(net1_epg, aim_resource.EndpointGroup)
        self.assertIsNone(epg)

        # Verify deleting external network deletes BD and EPG.
        self._delete('networks', net2_id)
        bd = self._find_by_dn(net2_bd, aim_resource.BridgeDomain)
        self.assertIsNone(bd)
        epg = self._find_by_dn(net2_epg, aim_resource.EndpointGroup)
        self.assertIsNone(epg)

    def test_ap_name_change(self):
        self.tenant_1 = 't1'
        net = self._make_ext_network(
            'net2', dn='uni/tn-common/out-l1/instP-n1')
        self._make_subnet(self.fmt, {'network': net}, '10.0.1.1',
                          '10.0.1.0/24')

        addr_scope = self._make_address_scope(
            self.fmt, 4, name='as1', tenant_id=self.tenant_1)['address_scope']
        subnetpool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='spool1', tenant_id=self.tenant_1,
            address_scope_id=addr_scope['id'])['subnetpool']
        net_int = self._make_network(self.fmt, 'pvt-net', True,
                                     tenant_id=self.tenant_1)['network']
        sp_id = subnetpool['id']
        sub = self._make_subnet(
            self.fmt, {'network': net_int}, '10.10.1.1', '10.10.1.0/24',
            subnetpool_id=sp_id)['subnet']
        router = self._make_router(
            self.fmt, self.tenant_1, 'router',
            arg_list=self.extension_attributes,
            external_gateway_info={'network_id': net['id']})['router']
        self._router_interface_action('add', router['id'], sub['id'], None)

        aim = self.aim_mgr
        aim_ctx = aim_context.AimContext(self.db_session)
        ns = self.driver._nat_type_to_strategy(None)
        ext_net = aim_resource.ExternalNetwork.from_dn(
            net[DN]['ExternalNetwork'])
        l3out = aim_resource.L3Outside(tenant_name=ext_net.tenant_name,
                                       name=ext_net.l3out_name)
        right_res = ns.get_l3outside_resources(aim_ctx, l3out)
        for res in copy.deepcopy(right_res):
            if isinstance(res, aim_resource.ApplicationProfile):
                aim.delete(aim_ctx, res)
                res.name = self.driver.ap_name
                wrong_ap = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.EndpointGroup):
                aim.delete(aim_ctx, res)
                res.app_profile_name = self.driver.ap_name
                res.bd_name = 'EXT-%s' % l3out.name
                wrong_epg = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.BridgeDomain):
                aim.delete(aim_ctx, res)
                res.name = 'EXT-%s' % l3out.name
                wrong_bd = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.Contract):
                aim.delete(aim_ctx, res)
                res.name = 'EXT-%s' % l3out.name
                wrong_ctr = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.Filter):
                aim.delete(aim_ctx, res)
                res.name = 'EXT-%s' % l3out.name
                wrong_flt = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.FilterEntry):
                aim.delete(aim_ctx, res)
                res.filter_name = 'EXT-%s' % l3out.name
                wrong_entry = aim.create(aim_ctx, res)
            if isinstance(res, aim_resource.ContractSubject):
                aim.delete(aim_ctx, res)
                res.contract_name = 'EXT-%s' % l3out.name
                wrong_sbj = aim.create(aim_ctx, res)

        ns.common_scope = None
        wrong_res = ns.get_l3outside_resources(aim_ctx, l3out)
        self.assertEqual(len(right_res), len(wrong_res))
        self.assertNotEqual(sorted(right_res), sorted(wrong_res))

        data_migrations.do_ap_name_change(self.db_session, cfg.CONF)
        # Verify new model
        ns = self.driver._nat_type_to_strategy(None)
        final_res = ns.get_l3outside_resources(aim_ctx, l3out)
        self.assertEqual(sorted(right_res), sorted(final_res))
        self.assertIsNone(aim.get(aim_ctx, wrong_ap))
        self.assertIsNone(aim.get(aim_ctx, wrong_epg))
        self.assertIsNone(aim.get(aim_ctx, wrong_bd))
        self.assertIsNone(aim.get(aim_ctx, wrong_ctr))
        self.assertIsNone(aim.get(aim_ctx, wrong_flt))
        self.assertIsNone(aim.get(aim_ctx, wrong_entry))
        self.assertIsNone(aim.get(aim_ctx, wrong_sbj))
        self.assertIsNotNone(ns.get_subnet(aim_ctx, l3out, '10.0.1.1/24'))
        # Top level objects are scoped
        for r in final_res:
            if any(isinstance(r, x) for x in [aim_resource.ApplicationProfile,
                                              aim_resource.BridgeDomain,
                                              aim_resource.Contract,
                                              aim_resource.Filter]):
                self.assertTrue(r.name.startswith(self.driver.apic_system_id),
                                '%s name: %s' % (type(r), r.name))
        self._update('routers', router['id'],
                     {'router': {'external_gateway_info': {}}})
        self._delete('networks', net['id'])
        for r in final_res:
            self.assertIsNone(aim.get(aim_ctx, r),
                              'Resource: %s still in AIM' % r)

    def test_security_group_migration_sanity(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        self._make_network(self.fmt, 'net1', True)
        sgs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroup)
        for sg in sgs:
            self.aim_mgr.delete(aim_ctx, sg)
        sgs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroup)
        self.assertEqual([], sgs)
        sgsubs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupSubject)
        for sgsub in sgsubs:
            self.aim_mgr.delete(aim_ctx, sgsub)
        sgsubs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupSubject)
        self.assertEqual([], sgsubs)
        sgrules = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupRule)
        for sgrule in sgrules:
            self.aim_mgr.delete(aim_ctx, sgrule)
        sgrules = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupRule)
        self.assertEqual([], sgrules)
        data_migrations.do_apic_aim_security_group_migration(self.db_session)
        sgs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroup)
        self.assertIsNotNone(sgs)
        sgsubs = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupSubject)
        self.assertIsNotNone(sgsubs)
        sgrules = self.aim_mgr.find(aim_ctx, aim_resource.SecurityGroupRule)
        self.assertIsNotNone(sgrules)


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

    def test_bind_opflex_agent_with_firewall_enabled(self):
        self.driver.enable_iptables_firewall = True
        self._register_agent('host1', AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        port = self._bind_port_to_host(port_id, 'host1')['port']
        self.assertEqual('ovs', port['binding:vif_type'])
        self.assertEqual({'port_filter': True, 'ovs_hybrid_plug': True},
                         port['binding:vif_details'])

    def test_bind_unsupported_vnic_type(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        vnic_arg = {'binding:vnic_type': 'macvtap'}
        port = self._make_port(self.fmt, net['network']['id'],
                               arg_list=('binding:vnic_type',),
                               **vnic_arg)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']
        self.assertEqual('binding_failed', port['binding:vif_type'])

    def test_bind_vnic_direct_port(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')

        vnic_arg = {'binding:vnic_type': 'direct'}
        p1 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('binding:vnic_type',),
                             **vnic_arg)['port']
        p2 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('binding:vnic_type',),
                             **vnic_arg)['port']

        # Bind to non-opflex host
        p1 = self._bind_port_to_host(p1['id'], 'host1')['port']
        self.assertNotEqual('binding_failed', p1['binding:vif_type'])
        p1_ctx = self.plugin.get_bound_port_context(
            n_context.get_admin_context(), p1['id'])
        self.assertEqual('opflex', p1_ctx.top_bound_segment['network_type'])
        self.assertEqual('vlan', p1_ctx.bottom_bound_segment['network_type'])

        # Bind to opflex host
        self._register_agent('host2', AGENT_CONF_OPFLEX)
        p2 = self._bind_port_to_host(p2['id'], 'host2')['port']
        self.assertNotEqual('binding_failed', p2['binding:vif_type'])
        p2_ctx = self.plugin.get_bound_port_context(
            n_context.get_admin_context(), p2['id'])
        self.assertEqual('opflex', p2_ctx.top_bound_segment['network_type'])
        self.assertEqual('vlan', p2_ctx.bottom_bound_segment['network_type'])

    def test_bind_fabric_router_port(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        port = self._bind_port_to_host(port_id, 'fabric')['port']
        self.assertEqual('fabric', port['binding:vif_type'])
        self.assertEqual({'port_filter': False},
                         port['binding:vif_details'])
        self.assertEqual(n_constants.PORT_STATUS_ACTIVE, port['status'])

    def test_bind_port_ovs_dpdk(self):
        self._register_agent('host1', AGENT_CONF_OPFLEX_OVS_DPDK)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        port = self._bind_port_to_host(port_id, 'host1')['port']
        self.assertEqual('vhostuser', port['binding:vif_type'])
        self.assertEqual(
            {'datapath_type': 'netdev', 'port_filter': False,
             'ovs_hybrid_plug': False, 'vhostuser_ovs_plug': True,
             'vhostuser_mode': 'server', 'vhostuser_socket':
                 AGENT_CONF_OPFLEX_OVS_DPDK['configurations'][
                     'vhostuser_socket_dir'] + '/' + ('vhu' + port_id)[:14]},
            port['binding:vif_details'])

    def test_bind_port_vpp(self):
        self._register_agent('host1', AGENT_CONF_VPP)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        port = self._bind_port_to_host(port_id, 'host1')['port']
        self.assertEqual('vhostuser', port['binding:vif_type'])
        self.assertEqual({'port_filter': False, 'ovs_hybrid_plug': False,
                          'vhostuser_ovs_plug': False,
                          'vhostuser_vpp_plug': True,
                          'vhostuser_mode': 'server',
                          'vhostuser_socket': AGENT_CONF_VPP['configurations'][
                              'vhostuser_socket_dir'] + '/' + (
                              ('vhu' + port_id)[:14])},
                         port['binding:vif_details'])

    # TODO(rkukura): Add tests for opflex, local and unsupported
    # network_type values.


class TestPortBindingDvs(ApicAimTestCase):

    def setUp(self):
        super(TestPortBindingDvs, self).setUp()
        self.driver._dvs_notifier = mock.MagicMock()
        self.driver.dvs_notifier.bind_port_call = mock.Mock(
            return_value={'key': BOOKED_PORT_VALUE})

    def _get_expected_pg(self, net):
        return ('prj_' + net['tenant_id'] + '|' +
                self.driver.ap_name + '|' + 'net_' + net['id'])

    def _verify_dvs_notifier(self, notifier, port, host):
        # can't use getattr() with mock, so use eval instead
        try:
            dvs_mock = eval('self.driver.dvs_notifier.' + notifier)
        except Exception:
            self.assertTrue(False,
                            "The method " + notifier + " was not called")
            return

        self.assertTrue(dvs_mock.called)
        a1, a2, a3, a4 = dvs_mock.call_args[0]
        self.assertEqual(a1['id'], port['id'])
        if a2:
            self.assertEqual(a2['id'], port['id'])
        self.assertEqual(a4, host)

    def test_bind_port_dvs(self):
        # Register a DVS agent
        self._register_agent('host1', AGENT_CONF_DVS)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        port = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = port['id']
        self.assertEqual(net['network']['id'], port['network_id'])
        new_port = self._bind_port_to_host(port_id, 'host1')
        # Called on the network's tenant
        expected_pg = self._get_expected_pg(net['network'])
        pg = new_port['port']['binding:vif_details']['dvs_port_group_name']
        self.assertEqual(expected_pg, pg)
        port_key = new_port['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(BOOKED_PORT_VALUE, port_key)
        self._verify_dvs_notifier('update_postcommit_port_call', port, 'host1')
        self._delete('ports', port_id)
        self._verify_dvs_notifier('delete_port_call', port, 'host1')

    def test_bind_port_dvs_with_opflex_diff_hosts(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1', AGENT_CONF_OPFLEX)
        self._register_agent('h2', AGENT_CONF_DVS)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        p1 = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = p1['id']
        # Bind a VLAN port after registering a DVS agent
        self.assertEqual(net['network']['id'], p1['network_id'])
        newp1 = self._bind_port_to_host(p1['id'], 'h2')
        expected_pg = self._get_expected_pg(net['network'])
        vif_det = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_det.get('dvs_port_group_name', None))
        self.assertEqual(expected_pg, vif_det.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h2')
        self._delete('ports', port_id)
        self._verify_dvs_notifier('delete_port_call', p1, 'h2')

    def test_bind_ports_opflex_same_host(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1', AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        p1 = self._make_port(self.fmt, net['network']['id'])['port']
        port_id = p1['id']
        # Bind a VLAN port after registering a DVS agent
        self.assertEqual(net['network']['id'], p1['network_id'])
        newp1 = self._bind_port_to_host(p1['id'], 'h1')
        # Called on the network's tenant
        vif_det = newp1['port']['binding:vif_details']
        self.assertIsNone(vif_det.get('dvs_port_group_name', None))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock = self.driver.dvs_notifier.update_postcommit_port_call
        dvs_mock.assert_not_called()
        dvs_mock = self.driver.dvs_notifier.delete_port_call
        self._delete('ports', port_id)
        dvs_mock.assert_not_called()
        self.driver.dvs_notifier.reset_mock()
        p2 = self._make_port(self.fmt, net['network']['id'])['port']
        self.assertEqual(net['network']['id'], p2['network_id'])
        newp2 = self._bind_dhcp_port_to_host(p2['id'], 'h1')
        # Called on the network's tenant
        vif_det = newp2['port']['binding:vif_details']
        self.assertIsNone(vif_det.get('dvs_port_group_name', None))
        port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock.assert_not_called()
        self._delete('ports', newp2['port']['id'])
        dvs_mock = self.driver.dvs_notifier.delete_port_call
        dvs_mock.assert_not_called()

    def test_bind_ports_dvs_with_opflex_same_host(self):
        # Register an OpFlex agent and DVS agent
        self._register_agent('h1', AGENT_CONF_DVS)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')
        p1 = self._make_port(self.fmt, net['network']['id'])['port']
        # Bind a VLAN port after registering a DVS agent
        self.assertEqual(net['network']['id'], p1['network_id'])
        # Bind port to trigger path binding
        newp1 = self._bind_port_to_host(p1['id'], 'h1')
        # Called on the network's tenant
        expected_pg = self._get_expected_pg(net['network'])
        vif_det = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_det.get('dvs_port_group_name', None))
        self.assertEqual(expected_pg, vif_det.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        self._verify_dvs_notifier('update_postcommit_port_call', p1, 'h1')
        self._delete('ports', newp1['port']['id'])
        self._verify_dvs_notifier('delete_port_call', p1, 'h1')
        self.driver.dvs_notifier.reset_mock()
        p2 = self._make_port(self.fmt, net['network']['id'])['port']
        self.assertEqual(net['network']['id'], p2['network_id'])
        # Bind port to trigger path binding
        newp2 = self._bind_dhcp_port_to_host(p2['id'], 'h1')
        # Called on the network's tenant
        vif_det = newp2['port']['binding:vif_details']
        self.assertIsNone(vif_det.get('dvs_port_group_name', None))
        port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock = self.driver.dvs_notifier.update_postcommit_port_call
        dvs_mock.assert_not_called()
        self._delete('ports', newp2['port']['id'])
        dvs_mock = self.driver.dvs_notifier.delete_port_call
        dvs_mock.assert_not_called()


class TestDomains(ApicAimTestCase):

    # REVISIT: Does this test anything that is not covered by
    # TestPortOnPhysicalNode.test_mixed_ports_on_network_with_default_domains?
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
        self._make_network(self.fmt, 'net', True)
        epg = self.aim_mgr.find(aim_ctx, aim_resource.EndpointGroup)[0]
        self.assertEqual(set([]),
                         set(epg.openstack_vmm_domain_names))
        self.assertEqual(set([]),
                         set(epg.physical_domain_names))


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2BasicGet(test_plugin.TestBasicGet,
                      ApicAimTestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            ApicAimTestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2PortsV2(test_plugin.TestPortsV2,
                     ApicAimTestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        ApicAimTestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       ApicAimTestCase):
    pass


# REVISIT: Skipping inherited ML2 tests to reduce UT run time.
@testtools.skip('Skipping test class')
class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           ApicAimTestCase):
    pass


class TestExtensionAttributes(ApicAimTestCase):

    def test_bgp_enabled_network_lifecycle(self):
        session = db_api.get_writer_session()
        extn = extn_db.ExtensionDbMixin()

        # Test create SVI network without BGP.
        net1 = self._make_network(self.fmt, 'net1', True,
                                  arg_list=self.extension_attributes,
                                  **{'apic:svi': 'True'})['network']
        self.assertEqual(True, net1[SVI])
        self.assertEqual(False, net1[BGP])
        self.assertEqual("default_export", net1[BGP_TYPE])
        self.assertEqual("0", net1[ASN])

        # Test create non-SVI network with BGP.
        resp = self._create_network(self.fmt, 'net11', True,
                                  arg_list=self.extension_attributes,
                                  **{'apic:svi': 'False',
                                     BGP: True,
                                     BGP_TYPE: "default_export",
                                     ASN: "65000"})
        self.assertEqual(resp.status_code, 400)
        res = self.deserialize(self.fmt, resp)
        self.assertIn("Invalid input for operation: Network has to be "
                      "created as svi type(--apic:svi True)"
                      " to enable BGP or to set BGP parameters",
                      res['NeutronError']['message'])

        # Test create SVI network with BGP.
        net2 = self._make_network(self.fmt, 'net2', True,
                                  arg_list = self.extension_attributes,
                                  ** {'apic:svi': True,
                                      BGP: True,
                                      ASN: "65000"})['network']
        self.assertEqual(True, net2[BGP])
        self.assertEqual("default_export", net2[BGP_TYPE])
        self.assertEqual("65000", net2[ASN])

        # Test update non-SVI network with BGP.
        net11 = self._make_network(self.fmt, 'net11', True,
                                  arg_list=self.extension_attributes
                                   )['network']
        data = {'network': {BGP: True,
                            BGP_TYPE: "default_export",
                            ASN: "100"}}
        req = self.new_update_request('networks', data, net11['id'],
                                      self.fmt)
        resp = req.get_response(self.api)
        self.assertEqual(resp.status_code, 400)
        res = self.deserialize(self.fmt, resp)
        self.assertIn("Invalid input for operation: Network has to be "
                      "created as svi type(--apic:svi True)"
                      " to enable BGP or to set BGP parameters",
                      res['NeutronError']['message'])

        # Test update SVI network with BGP.
        net1 = self._update('networks', net1['id'],
                            {'network': {BGP: True,
                                         BGP_TYPE: "",
                                         ASN: "100"}})['network']
        self.assertEqual(True, net1[BGP])
        self.assertEqual("", net1[BGP_TYPE])
        self.assertEqual("100", net1[ASN])

        # Test delete.
        self._delete('networks', net1['id'])
        self.assertFalse(extn.get_network_extn_db(session, net1['id']))
        self._delete('networks', net2['id'])
        self.assertFalse(extn.get_network_extn_db(session, net2['id']))

    def test_network_with_nested_domain_lifecycle(self):
        session = db_api.get_session()
        extn = extn_db.ExtensionDbMixin()
        vlan_dict = {'vlans_list': ['2', '3', '4', '3'],
                     'vlan_ranges': [{'start': '6', 'end': '9'},
                                     {'start': '11', 'end': '14'}]}
        expt_vlans = [2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14]
        kwargs = {'apic:nested_domain_name': 'myk8s',
                  'apic:nested_domain_type': 'k8s',
                  'apic:nested_domain_infra_vlan': '4093',
                  'apic:nested_domain_service_vlan': '1000',
                  'apic:nested_domain_node_network_vlan': '1001',
                  'apic:nested_domain_allowed_vlans': vlan_dict,
                  }

        net1 = self._make_network(self.fmt, 'net1', True,
                                  arg_list=tuple(kwargs.keys()),
                                  **kwargs)['network']
        self.assertEqual('myk8s', net1['apic:nested_domain_name'])
        self.assertEqual('k8s', net1['apic:nested_domain_type'])
        self.assertEqual(4093, net1['apic:nested_domain_infra_vlan'])
        self.assertEqual(1000, net1['apic:nested_domain_service_vlan'])
        self.assertEqual(1001, net1['apic:nested_domain_node_network_vlan'])
        self.assertItemsEqual(expt_vlans,
                net1['apic:nested_domain_allowed_vlans'])

        vlan_dict = {'vlans_list': ['2', '3', '4', '3']}
        expt_vlans = [2, 3, 4]
        data = {'network': {'apic:nested_domain_name': 'new-myk8s',
                            'apic:nested_domain_type': 'new-k8s',
                            'apic:nested_domain_infra_vlan': '1093',
                            'apic:nested_domain_service_vlan': '2000',
                            'apic:nested_domain_node_network_vlan': '2001',
                            'apic:nested_domain_allowed_vlans': vlan_dict}}
        req = self.new_update_request('networks', data, net1['id'],
                                      self.fmt)
        resp = req.get_response(self.api)
        self.assertEqual(resp.status_code, 200)
        net1 = self.deserialize(self.fmt, resp)['network']
        self.assertEqual('new-myk8s', net1['apic:nested_domain_name'])
        self.assertEqual('new-k8s', net1['apic:nested_domain_type'])
        self.assertEqual(1093, net1['apic:nested_domain_infra_vlan'])
        self.assertEqual(2000, net1['apic:nested_domain_service_vlan'])
        self.assertEqual(2001, net1['apic:nested_domain_node_network_vlan'])
        self.assertItemsEqual(expt_vlans,
                net1['apic:nested_domain_allowed_vlans'])

        # Test delete.
        self._delete('networks', net1['id'])
        self.assertFalse(extn.get_network_extn_db(session, net1['id']))
        db_vlans = (session.query(
            extn_db.NetworkExtNestedDomainAllowedVlansDb).filter_by(
                network_id=net1['id']).all())
        self.assertEqual([], db_vlans)

    def test_external_network_lifecycle(self):
        session = db_api.get_reader_session()
        extn = extn_db.ExtensionDbMixin()

        # create with APIC DN, nat_typeand default CIDR
        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1,
                                      nat_type='')

        self.assertEqual(self.dn_t1_l1_n1,
                         net1[DN]['ExternalNetwork'])
        self.assertEqual('', net1['apic:nat_type'])
        self.assertEqual(['0.0.0.0/0'], net1[CIDR])

        net1 = self._list(
            'networks', query_params=('id=%s' % net1['id']))['networks'][0]
        self.assertEqual(self.dn_t1_l1_n1,
                         net1[DN]['ExternalNetwork'])
        self.assertEqual('', net1['apic:nat_type'])
        self.assertEqual(['0.0.0.0/0'], net1[CIDR])

        # create with nat_type set to default, and CIDR specified
        net2 = self._make_ext_network('net2',
                                      dn=self.dn_t1_l2_n2,
                                      cidrs=['5.5.5.0/24', '10.20.0.0/16'])
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['10.20.0.0/16', '5.5.5.0/24'],
                         sorted(net2[CIDR]))

        net2 = self._list(
            'networks', query_params=('id=%s' % net2['id']))['networks'][0]
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['10.20.0.0/16', '5.5.5.0/24'],
                         sorted(net2[CIDR]))

        # update CIDR
        net2 = self._update('networks', net2['id'],
            {'network': {CIDR: ['20.20.30.0/24']}})['network']
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['20.20.30.0/24'], net2[CIDR])

        net2 = self._list(
            'networks', query_params=('id=%s' % net2['id']))['networks'][0]
        self.assertEqual('distributed', net2['apic:nat_type'])
        self.assertEqual(['20.20.30.0/24'], net2[CIDR])

        net2 = self._update('networks', net2['id'],
            {'network': {CIDR: []}})['network']
        self.assertEqual([], net2[CIDR])

        net2 = self._list(
            'networks', query_params=('id=%s' % net2['id']))['networks'][0]
        self.assertEqual([], net2[CIDR])

        # create without APIC DN -> this is an unmanaged network
        net3 = self._make_ext_network('net3')
        self.assertTrue(DN not in net3 or 'ExternalNetwork' not in net3[DN])
        self.assertFalse('apic:nat_type' in net3)
        self.assertFalse(CIDR in net3)

        net3 = self._list(
            'networks', query_params=('id=%s' % net3['id']))['networks'][0]
        self.assertTrue(DN not in net3 or 'ExternalNetwork' not in net3[DN])
        self.assertFalse('apic:nat_type' in net3)
        self.assertFalse(CIDR in net3)

        # updating CIDR of unmanaged network is no-op
        net3 = self._update('networks', net3['id'],
            {'network': {CIDR: ['30.30.20.0/24']}})['network']
        self.assertTrue(DN not in net3 or 'ExternalNetwork' not in net3[DN])
        self.assertFalse('apic:nat_type' in net3)
        self.assertFalse(CIDR in net3)

        net3 = self._list(
            'networks', query_params=('id=%s' % net3['id']))['networks'][0]
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
                                      dn=self.dn_t1_l1_n1,
                                      nat_type='edge')

        self._update('networks', net1['id'],
            {'network':
             {DN: {'ExternalNetwork': 'uni/tn-t1/out-l1/instP-n2'}}},
            400)
        self._update('networks', net1['id'], {'apic:nat_type': ''}, 400)

    def test_external_subnet_lifecycle(self):
        session = db_api.get_reader_session()
        extn = extn_db.ExtensionDbMixin()

        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1)
        # create with default value for snat_host_pool
        subnet = self._make_subnet(
            self.fmt, {'network': net1}, '10.0.0.1', '10.0.0.0/24')['subnet']
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.assertFalse(subnet[SNAT_POOL])

        subnet = self._list(
            'subnets', query_params=('id=%s' % subnet['id']))['subnets'][0]
        self.assertFalse(subnet[SNAT_POOL])

        # Update something other than snat_host_pool
        subnet = self._update('subnets', subnet['id'],
                              {'subnet': {'name': 'foo'}})['subnet']
        self.assertFalse(subnet[SNAT_POOL])

        # Update snat_host_pool
        subnet = self._update('subnets', subnet['id'],
            {'subnet': {SNAT_POOL: True}})['subnet']
        self.assertTrue(subnet[SNAT_POOL])

        subnet = self._list(
            'subnets', query_params=('id=%s' % subnet['id']))['subnets'][0]
        self.assertTrue(subnet[SNAT_POOL])

        subnet = self._update('subnets', subnet['id'],
            {'subnet': {SNAT_POOL: False}})['subnet']
        self.assertFalse(subnet[SNAT_POOL])

        subnet = self._list(
            'subnets', query_params=('id=%s' % subnet['id']))['subnets'][0]
        self.assertFalse(subnet[SNAT_POOL])

        # delete subnet
        self._delete('subnets', subnet['id'])
        self.assertFalse(extn.get_subnet_extn_db(session, subnet['id']))

        # Simulate a prior existing subnet (i.e. no extension attrs exist)
        # Get should give default value, and updates should stick
        subnet2 = self._make_subnet(
            self.fmt, {'network': net1}, '20.0.0.1', '20.0.0.0/24')['subnet']
        self._update('subnets', subnet2['id'],
                     {'subnet': {SNAT_POOL: True}})
        with session.begin(subtransactions=True):
            db_obj = session.query(extn_db.SubnetExtensionDb).filter(
                        extn_db.SubnetExtensionDb.subnet_id ==
                        subnet2['id']).one()
            session.delete(db_obj)
        subnet2 = self._show('subnets', subnet2['id'])['subnet']
        self.assertFalse(subnet2[SNAT_POOL])

        subnet2 = self._update('subnets', subnet2['id'],
            {'subnet': {SNAT_POOL: True}})['subnet']
        self.assertTrue(subnet2[SNAT_POOL])

        subnet2 = self._list(
            'subnets', query_params=('id=%s' % subnet2['id']))['subnets'][0]
        self.assertTrue(subnet2[SNAT_POOL])

    def test_router_lifecycle(self):
        session = db_api.get_reader_session()
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

        rtr1 = self._list(
            'routers', query_params=('id=%s' % rtr1['id']))['routers'][0]
        self.assertEqual([], rtr1[PROV])
        self.assertEqual(['k'], rtr1[CONS])

        self._update('routers', rtr1['id'],
                     {'router': {PROV: ['p1', 'p2']}})
        rtr1 = self._show('routers', rtr1['id'])['router']
        self.assertEqual(['p1', 'p2'], sorted(rtr1[PROV]))
        self.assertEqual(['k'], rtr1[CONS])

        rtr1 = self._list(
            'routers', query_params=('id=%s' % rtr1['id']))['routers'][0]
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

        rtr2 = self._list(
            'routers', query_params=('id=%s' % rtr2['id']))['routers'][0]
        self.assertEqual([], rtr2[PROV])
        self.assertEqual([], rtr2[CONS])

        rtr2 = self._update('routers', rtr2['id'],
                            {'router': {PROV: ['p1', 'p2']}})['router']
        self.assertEqual(['p1', 'p2'], sorted(rtr2[PROV]))
        self.assertEqual([], rtr2[CONS])

        rtr2 = self._list(
            'routers', query_params=('id=%s' % rtr2['id']))['routers'][0]
        self.assertEqual(['p1', 'p2'], sorted(rtr2[PROV]))
        self.assertEqual([], rtr2[CONS])

    def test_address_scope_lifecycle(self):
        session = db_api.get_writer_session()
        aim_ctx = aim_context.AimContext(db_session=session)

        # Create VRF.
        self.aim_mgr.create(
            aim_ctx, aim_resource.Tenant(name=self.t1_aname, monitored=True))
        vrf = aim_resource.VRF(tenant_name=self.t1_aname, name='ctx1',
                               monitored=True)
        self.aim_mgr.create(aim_ctx, vrf)

        # Create v4 scope with pre-existing APIC DN.
        scope4 = self._make_address_scope_for_vrf(vrf.dn)['address_scope']
        self._check_dn(scope4, vrf, 'VRF')

        scope = self._show('address-scopes', scope4['id'])['address_scope']
        self._check_dn(scope, vrf, 'VRF')

        # Create (isomorphic) v6 scope with same APIC DN.
        scope6 = self._make_address_scope_for_vrf(
            vrf.dn, n_constants.IP_VERSION_6)['address_scope']
        self._check_dn(scope6, vrf, 'VRF')

        scope = self._show('address-scopes', scope6['id'])['address_scope']
        self._check_dn(scope6, vrf, 'VRF')

        # Delete scopes.
        self._delete('address-scopes', scope4['id'])
        self._delete('address-scopes', scope6['id'])
        vrf = self.aim_mgr.get(aim_ctx, vrf)
        self.assertIsNotNone(vrf)

    def test_isomorphic_address_scopes_lifecycle(self):
        # Create initial v4 scope.
        scope4 = self._make_address_scope(
            self.fmt, 4, name='as4')['address_scope']
        dn = scope4['apic:distinguished_names']['VRF']
        vrf = self._find_by_dn(dn, aim_resource.VRF)
        self._check_dn(scope4, vrf, 'VRF', 'as4')

        # Create isomorphic v6 scope, using v4 scope's pre-existing
        # DN.
        scope6 = self._make_address_scope_for_vrf(
            dn, n_constants.IP_VERSION_6, name='as6')['address_scope']
        self.assertEqual(dn, scope6['apic:distinguished_names']['VRF'])
        self._check_dn(scope6, vrf, 'VRF', 'as4-as6')

        # Update v4 scope name.
        data = {'address_scope': {'name': ''}}
        self._update('address-scopes', scope4['id'], data)
        self._check_dn(scope4, vrf, 'VRF', 'as6')

        # Update v4 scope name again.
        data = {'address_scope': {'name': 'x4'}}
        self._update('address-scopes', scope4['id'], data)
        self._check_dn(scope4, vrf, 'VRF', 'x4-as6')

        # Update v6 scope name.
        data = {'address_scope': {'name': 'x6'}}
        self._update('address-scopes', scope6['id'], data)
        self._check_dn(scope6, vrf, 'VRF', 'x4-x6')

        # Delete v4 scope.
        self._delete('address-scopes', scope4['id'])
        self._check_dn(scope6, vrf, 'VRF', 'x6')

        # Delete v6 scope.
        self._delete('address-scopes', scope6['id'])
        vrf = self._find_by_dn(dn, aim_resource.VRF)
        self.assertIsNone(vrf)

        # Create another initial v4 scope.
        scope4 = self._make_address_scope(
            self.fmt, 4, name='as')['address_scope']
        dn = scope4['apic:distinguished_names']['VRF']
        vrf = self._find_by_dn(dn, aim_resource.VRF)
        self._check_dn(scope4, vrf, 'VRF', 'as')

        # Create isomorphic v6 scope, using v4 scope's pre-existing
        # DN, with same name.
        scope6 = self._make_address_scope_for_vrf(
            dn, n_constants.IP_VERSION_6, name='as')['address_scope']
        self.assertEqual(dn, scope6['apic:distinguished_names']['VRF'])
        self._check_dn(scope6, vrf, 'VRF', 'as')

        # Update v4 scope name to not match.
        data = {'address_scope': {'name': 'as4'}}
        self._update('address-scopes', scope4['id'], data)
        self._check_dn(scope4, vrf, 'VRF', 'as4-as')

        # Delete v6 scope.
        self._delete('address-scopes', scope6['id'])
        self._check_dn(scope4, vrf, 'VRF', 'as4')

        # Delete v4 scope.
        self._delete('address-scopes', scope4['id'])
        vrf = self._find_by_dn(dn, aim_resource.VRF)
        self.assertIsNone(vrf)

    def test_address_scope_fail(self):
        # APIC DN not specified
        resp = self._make_address_scope_for_vrf(None, expected_status=400,
                                                **{DN: {}})
        self.assertIn('Invalid input for apic:distinguished_names',
                      resp['NeutronError']['message'])

        # APIC DN is wrong
        resp = self._make_address_scope_for_vrf('uni/tn-1',
                                                expected_status=400)
        self.assertIn('is not valid VRF DN', resp['NeutronError']['message'])

        # Update APIC DN
        aim_ctx = aim_context.AimContext(
                db_session=db_api.get_writer_session())
        self.aim_mgr.create(
            aim_ctx, aim_resource.Tenant(name=self.t1_aname, monitored=True))
        vrf = aim_resource.VRF(tenant_name=self.t1_aname, name='default',
                               monitored=True)
        self.aim_mgr.create(aim_ctx, vrf)
        scope = self._make_address_scope_for_vrf(vrf.dn)

        self._update('address-scopes', scope['address_scope']['id'],
                     {'address_scope':
                      {DN: {'VRF': 'uni/tn-%s/ctx-default2' % self.t2_aname}}},
                     400)

        # Pre-existing VRF already used
        resp = self._make_address_scope_for_vrf(vrf.dn, expected_status=400)
        self.assertIn('is already in use by address-scope',
                      resp['NeutronError']['message'])

        # Orchestrated VRF already used
        with self.address_scope() as scope1:
            scope1 = scope1['address_scope']
            resp = self._make_address_scope_for_vrf(scope1[DN]['VRF'],
                                                    expected_status=400)
            self.assertIn('is already in use by address-scope',
                          resp['NeutronError']['message'])


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
        for k, v in six.iteritems(self.klass.__overridden):
            setattr(self.klass, k, v)
        del self.klass.__overridden


class TestExternalConnectivityBase(object):
    tenant_1 = 'tenant_1'
    tenant_2 = 'tenant_2'

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

    def fix_l3out_vrf(self, l3out_tenant_name, l3out_name, vrf_name):
        pass

    def test_external_network_lifecycle(self):
        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1,
                                      cidrs=['20.10.0.0/16', '4.4.4.0/24'])
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY,
            aim_resource.L3Outside(tenant_name=self.t1_aname, name='l1'),
            vmm_domains=[])
        a_ext_net = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1')
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['20.10.0.0/16', '4.4.4.0/24'])
        ext_epg = aim_resource.EndpointGroup(
            tenant_name=self.t1_aname, app_profile_name=self._app_profile_name,
            name='EXT-l1')
        ext_bd = aim_resource.BridgeDomain(
            tenant_name=self.t1_aname, name='EXT-l1')
        ext_vrf = aim_resource.VRF(tenant_name=self.t1_aname, name='EXT-l1')
        self._check_dn(net1, ext_epg, 'EndpointGroup', 'EXT-l1')
        self._check_dn(net1, ext_bd, 'BridgeDomain', 'EXT-l1')
        self._check_dn(net1, ext_vrf, 'VRF', 'EXT-l1')

        net1 = self._show('networks', net1['id'])['network']
        self._check_dn(net1, ext_epg, 'EndpointGroup', 'EXT-l1')
        self._check_dn(net1, ext_bd, 'BridgeDomain', 'EXT-l1')
        self._check_dn(net1, ext_vrf, 'VRF', 'EXT-l1')
        self._validate()

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
        self._validate()

        # delete
        self.mock_ns.reset_mock()
        self._delete('networks', net1['id'])
        self.mock_ns.delete_l3outside.assert_called_once_with(
            mock.ANY,
            aim_resource.L3Outside(tenant_name=self.t1_aname, name='l1'))
        self.mock_ns.delete_external_network.assert_called_once_with(
            mock.ANY,
            aim_resource.ExternalNetwork(
                tenant_name=self.t1_aname, l3out_name='l1', name='n1'))

        # create with default CIDR
        self.mock_ns.reset_mock()
        self._make_ext_network('net2',
                               dn=self.dn_t1_l1_n1)
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['0.0.0.0/0'])
        self._validate()

    def test_unmanaged_external_network_lifecycle(self):
        net1 = self._make_ext_network('net1')
        self.mock_ns.create_l3outside.assert_not_called()
        self.mock_ns.create_external_network.assert_not_called()
        self.mock_ns.update_external_cidrs.assert_not_called()
        self._check_no_dn(net1, 'EndpointGroup')
        self._check_no_dn(net1, 'BridgeDomain')
        self._check_no_dn(net1, 'VRF')
        self._validate()

        self._delete('networks', net1['id'])
        self.mock_ns.delete_l3outside.assert_not_called()
        self.mock_ns.delete_external_network.assert_not_called()

    def test_external_subnet_lifecycle(self):
        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1)
        subnet = self._make_subnet(
            self.fmt, {'network': net1}, '10.0.0.1', '10.0.0.0/24',
            allocation_pools=[{'start': '10.0.0.2',
                               'end': '10.0.0.250'}])['subnet']
        subnet = self._show('subnets', subnet['id'])['subnet']

        l3out = aim_resource.L3Outside(tenant_name=self.t1_aname, name='l1')
        self.mock_ns.create_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.1/24')
        ext_sub = aim_resource.Subnet(
            tenant_name=self.t1_aname, bd_name='EXT-l1',
            gw_ip_mask='10.0.0.1/24')
        self._check_dn(subnet, ext_sub, 'Subnet')
        self._validate()

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
        self._validate()

        # Update gateway to None
        self.mock_ns.reset_mock()
        self._update('subnets', subnet['id'],
                     {'subnet': {'gateway_ip': None}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.mock_ns.delete_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.251/24')
        self.mock_ns.create_subnet.assert_not_called()
        self._check_no_dn(subnet, 'Subnet')
        self._validate()

        # Update gateway from None
        self.mock_ns.reset_mock()
        ext_sub.gw_ip_mask = '10.0.0.251/24'
        self._update('subnets', subnet['id'],
                     {'subnet': {'gateway_ip': '10.0.0.251'}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.mock_ns.delete_subnet.assert_not_called()
        self.mock_ns.create_subnet.assert_called_once_with(
            mock.ANY, l3out, '10.0.0.251/24')
        self._check_dn(subnet, ext_sub, 'Subnet')
        self._validate()

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
        self._validate()

        # Update gateway
        self._update('subnets', subnet['id'],
                     {'subnet': {'gateway_ip': '10.0.0.251'}})
        subnet = self._show('subnets', subnet['id'])['subnet']
        self.mock_ns.delete_subnet.assert_not_called()
        self.mock_ns.create_subnet.assert_not_called()
        self._check_no_dn(subnet, 'Subnet')
        self._validate()

        # delete subnet
        self._delete('subnets', subnet['id'])
        self.mock_ns.delete_subnet.assert_not_called()

    # This will be invoked for non-NoNat strategies
    def _check_bd_l3out(self, aim_ctx, bridge_domain, l3out_name):
        bridge_domain = self.aim_mgr.get(aim_ctx, bridge_domain)
        self.assertEqual([], bridge_domain.l3out_names)

    def _do_test_router_interface(self, use_addr_scope=False,
                                  single_tenant=False):
        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn=self.dn_t1_l1_n1)
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

        objs = {}
        tenants = ([self.tenant_1] if single_tenant
                   else [self.tenant_1, self.tenant_2])
        # Create the networks, subnets, routers etc
        for t in tenants:
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
        self._validate()

        # Connect the router interfaces to the subnets
        vrf_objs = {}
        for tenant, router_list in six.iteritems(objs):
            tenant_aname = self.name_mapper.project(None, tenant)
            a_vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                     name='DefaultVRF')
            a_ext_net = aim_resource.ExternalNetwork(
                tenant_name=self.t1_aname, l3out_name='l1', name='n1')
            for router, subnets, addr_scope in router_list:
                if addr_scope:
                    a_vrf.name = self.name_mapper.address_scope(
                        None, addr_scope['id'])
                self.fix_l3out_vrf(self.t1_aname, 'l1', a_vrf.name)
                contract = self.name_mapper.router(None, router['id'])
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

                    aname = self.name_mapper.network(
                        None, subnets[idx]['network_id'])
                    aim_bd = aim_resource.BridgeDomain(
                        tenant_name=tenant_aname, name=aname)
                    self._check_bd_l3out(aim_ctx, aim_bd, 'l1')

                    self._validate()
            vrf_objs[tenant] = a_ext_net

        # Remove the router interfaces
        for tenant, router_list in six.iteritems(objs):
            tenant_aname = self.name_mapper.project(None, tenant)
            a_vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                     name='DefaultVRF')
            a_ext_net = vrf_objs.pop(tenant)
            num_router = len(router_list)
            for router, subnets, addr_scope in router_list:
                if addr_scope:
                    a_vrf.name = self.name_mapper.address_scope(
                        None, addr_scope['id'])
                self.fix_l3out_vrf(self.t1_aname, 'l1', a_vrf.name)
                contract = self.name_mapper.router(None, router['id'])
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
                    aname = self.name_mapper.network(
                        None, subnets[idx]['network_id'])
                    aim_bd = aim_resource.BridgeDomain(
                        tenant_name=tenant_aname, name=aname)
                    # Last subnet being dis-connected from the router
                    if idx == len(subnets) - 1:
                        num_router -= 1
                        if num_router:
                            cv.assert_called_once_with(mock.ANY, a_ext_net,
                                                       a_vrf)
                        else:
                            dv.assert_called_once_with(mock.ANY, a_ext_net,
                                                       a_vrf)
                        aim_bd = self.aim_mgr.get(aim_ctx, aim_bd)
                        self.assertEqual([], aim_bd.l3out_names)
                    else:
                        cv.assert_not_called()
                        dv.assert_not_called()
                        self._check_bd_l3out(aim_ctx, aim_bd, 'l1')

                    self._validate()

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
                                          dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')
        ext_net2 = self._make_ext_network('ext-net2',
                                          dn=self.dn_t1_l2_n2)
        self._make_subnet(
            self.fmt, {'network': ext_net2}, '200.200.200.1',
            '200.200.200.0/24')

        objs = []
        net = self._make_network(self.fmt, 'pvt-net1', True,
                                 tenant_id=self.tenant_1)['network']
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

        tenant_aname = self.name_mapper.project(
            None, net['tenant_id'])  # REVISIT
        a_vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                 name='DefaultVRF')
        if use_addr_scope:
            a_vrf.name = self.name_mapper.address_scope(None, addr_scope['id'])
        self.fix_l3out_vrf(self.t1_aname, 'l1', a_vrf.name)
        self.fix_l3out_vrf(self.t1_aname, 'l2', a_vrf.name)

        self.mock_ns.reset_mock()
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net1['id']}}})
        contract = self.name_mapper.router(None, router['id'])
        a_ext_net1 = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1',
            provided_contract_names=sorted(['pr-1', contract]),
            consumed_contract_names=sorted(['co-1', contract]))
        cv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf)

        self.mock_ns.reset_mock()
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net2['id']}}})
        a_ext_net2 = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l2', name='n2',
            provided_contract_names=sorted(['pr-1', contract]),
            consumed_contract_names=sorted(['co-1', contract]))
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

    def test_router_gateway_addr_scope(self):
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

        session = db_api.get_reader_session()
        aim_ctx = aim_context.AimContext(session)
        tenant_aname = self.name_mapper.project(None, net['tenant_id'])
        aname = self.name_mapper.network(None, net['id'])
        aim_bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                           name=aname)
        aim_bd = self.aim_mgr.get(aim_ctx, aim_bd)
        self.assertEqual([], aim_bd.l3out_names)

        self._router_interface_action('remove', router['id'], sub1['id'], None)
        self.mock_ns.disconnect_vrf.assert_not_called()

    def _do_test_multiple_router(self, use_addr_scope=False,
                                 shared_l3out=False):
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        net = self._make_network(self.fmt, 'pvt-net1', True,
                                 tenant_id=self.tenant_1)['network']
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
        tenant_aname = self.name_mapper.project(
            None, net['tenant_id'])  # REVISIT
        a_vrf = aim_resource.VRF(tenant_name=tenant_aname,
                                 name='DefaultVRF')
        if use_addr_scope:
            a_vrf.name = self.name_mapper.address_scope(None, addr_scope['id'])

        ext_nets = []
        a_ext_nets = []
        for x in range(0, 2):
            dn = (self.dn_t1_l1_n1 if shared_l3out else
                  'uni/tn-%s/out-l%d/instP-n%d' % (self.t1_aname, x, x))
            ext_net = self._make_ext_network('ext-net%d' % x, dn=dn)
            self._make_subnet(
                self.fmt, {'network': ext_net}, '100.%d.100.1' % x,
                '100.%d.100.0/24' % x)
            ext_nets.append(ext_net['id'])
            a_ext_net = aim_resource.ExternalNetwork.from_dn(dn)
            a_ext_nets.append(a_ext_net)
            self.fix_l3out_vrf(self.t1_aname, 'l%d' % x, a_vrf.name)
        # Note: With shared_l3out=True, a_ext_net[0] and a_ext_net[1] are one
        # and the same APIC external network

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
            contracts.append(self.name_mapper.router(None, r['id']))
        cv.assert_not_called()
        self._validate()

        self._add_external_gateway_to_router(routers[0], ext_nets[0])
        a_ext_nets[0].provided_contract_names = [contracts[0]]
        a_ext_nets[0].consumed_contract_names = [contracts[0]]
        cv.assert_called_once_with(mock.ANY, a_ext_nets[0], a_vrf)
        self._validate()

        self.mock_ns.reset_mock()
        self._add_external_gateway_to_router(routers[1], ext_nets[1])
        if shared_l3out:
            a_ext_nets[1].provided_contract_names = sorted(contracts)
            a_ext_nets[1].consumed_contract_names = sorted(contracts)
        else:
            a_ext_nets[1].provided_contract_names = [contracts[1]]
            a_ext_nets[1].consumed_contract_names = [contracts[1]]
        cv.assert_called_once_with(mock.ANY, a_ext_nets[1], a_vrf)
        self._validate()

        self.mock_ns.reset_mock()
        self._router_interface_action('remove', routers[0], sub1['id'], None)
        if shared_l3out:
            a_ext_nets[0].provided_contract_names = [contracts[1]]
            a_ext_nets[0].consumed_contract_names = [contracts[1]]
            cv.assert_called_once_with(mock.ANY, a_ext_nets[0], a_vrf)
            dv.assert_not_called()
        else:
            a_ext_nets[0].provided_contract_names = []
            a_ext_nets[0].consumed_contract_names = []
            dv.assert_called_once_with(mock.ANY, a_ext_nets[0], a_vrf)
            cv.assert_not_called()
        self._validate()

        self.mock_ns.reset_mock()
        self._router_interface_action('remove', routers[1], sub1['id'], None)
        a_ext_nets[1].provided_contract_names = []
        a_ext_nets[1].consumed_contract_names = []
        dv.assert_called_once_with(mock.ANY, a_ext_nets[1], a_vrf)
        self._validate()

    def test_multiple_router(self):
        self._do_test_multiple_router(use_addr_scope=False)

    def test_multiple_router_addr_scope(self):
        self._do_test_multiple_router(use_addr_scope=True)

    def test_multiple_router_shared_l3out(self):
        self._do_test_multiple_router(use_addr_scope=False,
                                      shared_l3out=True)

    def test_multiple_router_addr_scope_shared_l3out(self):
        self._do_test_multiple_router(use_addr_scope=True,
                                      shared_l3out=True)

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
                port['port']['dns_name'] = ''
                p.append(port['port'])

        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        with self.floatingip_no_assoc(sub1) as fip1:
            fip1 = fip1['floatingip']
            self.assertEqual('DOWN', fip1['status'])
            # this notification is for SNAT info recalculation
            mock_notif.assert_called_once_with(mock.ANY, p[0])

            mock_notif.reset_mock()
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
            # notification on p[2] is for SNAT info recalculation
            mock_notif.has_calls([mock.call(mock.ANY, p[1]),
                                  mock.call(mock.ANY, p[2])],
                                 any_order=True)

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

    def test_port_notif_router_interface_op(self):
        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        self._register_agent('host1', AGENT_CONF_OPFLEX)

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn=self.dn_t1_l1_n1)
        self.fix_l3out_vrf(self.t1_aname, 'l1', 'DefaultVRF')
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')

        net = self._make_network(self.fmt, 'pvt-net1', True,
                                 tenant_id=self.tenant_1)['network']
        sub = self._make_subnet(
            self.fmt, {'network': net}, '10.10.1.1', '10.10.1.0/24')['subnet']
        port_calls = []
        for x in range(0, 2):
            with self.port(subnet={'subnet': sub}) as p:
                p = self._bind_port_to_host(p['port']['id'], 'host1')['port']
                p['dns_name'] = ''
                port_calls.append(mock.call(mock.ANY, p))

        router = self._make_router(
            self.fmt, net['tenant_id'], 'router1')['router']

        # set external gateway - expect no notifications
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net1['id']}}})
        mock_notif.assert_not_called()

        # connect subnet to router - notifications expected
        self._router_interface_action('add', router['id'], sub['id'], None)
        mock_notif.assert_has_calls(port_calls, any_order=True)

        # disconnect subnet from router - notifications expected
        mock_notif.reset_mock()
        self._router_interface_action('remove', router['id'], sub['id'], None)
        mock_notif.assert_has_calls(port_calls, any_order=True)

    def test_port_notif_router_gateway_op(self):
        mock_notif = mock.Mock(side_effect=self.port_notif_verifier())
        self.driver.notifier.port_update = mock_notif

        self._register_agent('host1', AGENT_CONF_OPFLEX)

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn=self.dn_t1_l1_n1)
        self.fix_l3out_vrf(self.t1_aname, 'l1', 'DefaultVRF')
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')

        net = self._make_network(self.fmt, 'pvt-net1', True,
                                 tenant_id=self.tenant_1)['network']
        port_calls = []
        subnets = []
        for x in range(0, 2):
            sub = self._make_subnet(
                self.fmt, {'network': net}, '10.10.%d.1' % x,
                '10.10.%d.0/24' % x)
            with self.port(subnet=sub) as p:
                p = self._bind_port_to_host(p['port']['id'], 'host1')['port']
                p['dns_name'] = ''
                subnets.append(sub['subnet'])
                port_calls.append(mock.call(mock.ANY, p))

        # add router - expect notifications
        router = self._make_router(
            self.fmt, net['tenant_id'], 'router1')['router']
        for sub in subnets:
            self._router_interface_action('add', router['id'], sub['id'], None)
        mock_notif.assert_has_calls(port_calls, any_order=True)

        # set external gateway - expect notifications
        mock_notif.reset_mock()
        self._update('routers', router['id'],
                     {'router':
                      {'external_gateway_info': {'network_id':
                                                 ext_net1['id']}}})
        mock_notif.assert_has_calls(port_calls, any_order=True)

        # unset external gateway - expect notifications
        mock_notif.reset_mock()
        self._update('routers', router['id'],
                     {'router': {'external_gateway_info': {}}})
        mock_notif.assert_has_calls(port_calls, any_order=True)

    def test_shared_unscoped_network(self):
        # 0. Initial state: Router r1 is connected to external-network
        # 1. Create unshared network net1 in tenant tenant_1, then connect
        #    it to router r1
        # 2. Create shared network net2 in tenant tenant_2, then connect
        #    it to router r1
        # 3. Create unshared network net3 in tenant test-tenant, then connect
        #    it to router r1
        # 4. Disconnect net3 from r1
        # 5. Disconnect net2 from r1
        # 6. Disconnect net1 from r1

        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        ext_net1 = self._make_ext_network('ext-net1',
                                          dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')
        router = self._make_router(
            self.fmt, ext_net1['tenant_id'], 'router1',
            external_gateway_info={'network_id': ext_net1['id']})['router']
        cv.assert_not_called()
        dv.assert_not_called()

        contract = self.name_mapper.router(None, router['id'])
        a_ext_net1 = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1',
            provided_contract_names=[contract],
            consumed_contract_names=[contract])
        a_ext_net1_no_contracts = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1')

        # 1. Create unshared network net1 in tenant tenant_1, then connect
        #    it to router r1
        net1 = self._make_network(self.fmt, 'net1', True,
                                 tenant_id='tenant_1')['network']
        sub1 = self._make_subnet(self.fmt, {'network': net1},
                                 '10.10.10.1', '10.10.10.0/24')['subnet']
        self._router_interface_action('add', router['id'], sub1['id'], None)
        a_vrf1 = aim_resource.VRF(
            tenant_name=self.name_mapper.project(None, 'tenant_1'),
            name='DefaultVRF')
        cv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf1)
        dv.assert_not_called()

        # 2. Create shared network net2 in tenant tenant_2, then connect
        #    it to router r1
        self.mock_ns.reset_mock()
        net2 = self._make_network(self.fmt, 'net2', True,
                                 tenant_id='tenant_2', shared=True)['network']
        sub2 = self._make_subnet(self.fmt, {'network': net2},
                                 '20.20.20.1', '20.20.20.0/24')['subnet']
        self._router_interface_action('add', router['id'], sub2['id'], None)
        a_vrf2 = aim_resource.VRF(
            tenant_name=self.name_mapper.project(None, 'tenant_2'),
            name='DefaultVRF')
        cv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf2)
        dv.assert_called_once_with(mock.ANY, a_ext_net1_no_contracts, a_vrf1)

        # 3. Create unshared network net3 in tenant test-tenant, then connect
        #    it to router r1
        self.mock_ns.reset_mock()
        net3 = self._make_network(self.fmt, 'net3', True,
                                 tenant_id='test-tenant')['network']
        sub3 = self._make_subnet(self.fmt, {'network': net3},
                                 '30.30.30.1', '30.30.30.0/24')['subnet']
        self._router_interface_action('add', router['id'], sub3['id'], None)
        cv.assert_not_called()
        dv.assert_not_called()

        # 4. Disconnect net3 from r1
        self.mock_ns.reset_mock()
        self._router_interface_action('remove', router['id'], sub3['id'], None)
        cv.assert_not_called()
        dv.assert_not_called()

        # 5. Disconnect net2 from r1
        self.mock_ns.reset_mock()
        self._router_interface_action('remove', router['id'], sub2['id'], None)
        cv.assert_called_once_with(mock.ANY, a_ext_net1, a_vrf1)
        dv.assert_called_once_with(mock.ANY, a_ext_net1_no_contracts, a_vrf2)

        # 6. Disconnect net1 from r1
        self.mock_ns.reset_mock()
        self._router_interface_action('remove', router['id'], sub1['id'], None)
        cv.assert_not_called()
        dv.assert_called_once_with(mock.ANY, a_ext_net1_no_contracts, a_vrf1)

    def test_address_scope_pre_existing_vrf(self):
        cv = self.mock_ns.connect_vrf
        dv = self.mock_ns.disconnect_vrf

        aim_ctx = aim_context.AimContext(self.db_session)

        # create pre-existing VRF
        vrf = aim_resource.VRF(tenant_name='common', name='ctx1',
                               monitored=True)
        vrf = self.aim_mgr.create(aim_ctx, vrf)
        vrf.monitored = False

        # create address-scope for pre-existing VRF
        scope = self._make_address_scope_for_vrf(vrf.dn,
                                                 name='as1')['address_scope']

        pool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='sp', address_scope_id=scope['id'],
            tenant_id=scope['tenant_id'], default_prefixlen=24)['subnetpool']

        # create external stuff
        ext_net1 = self._make_ext_network('ext-net1',
                                          dn=self.dn_t1_l1_n1)
        self.fix_l3out_vrf(self.t1_aname, 'l1', vrf.name)
        self._make_subnet(
            self.fmt, {'network': ext_net1}, '100.100.100.1',
            '100.100.100.0/24')
        router = self._make_router(self.fmt, self._tenant_id,
           'router1',
           external_gateway_info={'network_id': ext_net1['id']})['router']

        contract = self.name_mapper.router(None, router['id'])
        a_ext_net1 = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1',
            provided_contract_names=[contract],
            consumed_contract_names=[contract])

        # create private stuff
        net = self._make_network(self.fmt, 'net1', True)['network']
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '10.0.1.1', '10.0.1.0/24',
            subnetpool_id=pool['id'])['subnet']

        cv.assert_not_called()
        dv.assert_not_called()

        self._router_interface_action('add', router['id'], subnet['id'], None)
        cv.assert_called_once_with(mock.ANY, a_ext_net1, vrf)
        dv.assert_not_called()

        self.mock_ns.reset_mock()
        a_ext_net1.provided_contract_names = []
        a_ext_net1.consumed_contract_names = []
        self._router_interface_action('remove', router['id'], subnet['id'],
                                      None)
        cv.assert_not_called()
        dv.assert_called_once_with(mock.ANY, a_ext_net1, vrf)

    def _create_domains_and_mappings(self, ctx, mappings, create_hds=False):
        # The vmm_domains contains the domains that should be
        # associated in the create_l3outside call in AIM
        vmm_domains = []
        for dom in mappings:
            if dom['type'] == 'OpenStack':
                self.aim_mgr.create(ctx,
                                    aim_resource.VMMDomain(type=dom['type'],
                                                           name=dom['name']),
                                    overwrite=True)
                if (not create_hds and dom['host'] == '*') or (
                    create_hds and dom['host'] != '*'):
                    vmm_domains.append({'name': dom['name'],
                                        'type': dom['type']})
            if create_hds:
                hd_mapping = aim_infra.HostDomainMappingV2(
                    host_name=dom['host'], domain_name=dom['name'],
                    domain_type=dom['type'])
                self.aim_mgr.create(ctx, hd_mapping)
        return vmm_domains

    def _test_external_network_lifecycle_with_domains(self, create_hds=False):
        mappings = [{'host': 'opflex-1', 'name': 'vm1', 'type': 'OpenStack'},
                    {'host': 'opflex-2', 'name': 'vm2', 'type': 'OpenStack'},
                    {'host': 'esx-1', 'name': 'vm3', 'type': 'VMware'},
                    {'host': '*', 'name': 'vm1', 'type': 'OpenStack'},
                    {'host': '*', 'name': 'vm2', 'type': 'OpenStack'},
                    {'host': '*', 'name': 'vm3', 'type': 'VMware'},
                    {'host': 'h1', 'name': 'ph1', 'type': 'PhysDom'},
                    {'host': 'h2', 'name': 'ph2', 'type': 'PhysDom'},
                    {'host': 'h3', 'name': 'ph3', 'type': 'PhysDom'}]
        aim_ctx = aim_context.AimContext(self.db_session)
        # test setup
        vmm_domains = self._create_domains_and_mappings(aim_ctx, mappings,
                                                        create_hds=create_hds)

        self._register_agent('opflex-1', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-2', AGENT_CONF_OPFLEX)
        self._make_ext_network('net1',
                               dn=self.dn_t1_l1_n1,
                               cidrs=['20.10.0.0/16', '4.4.4.0/24'])
        if self.nat_type is not 'distributed' and self.nat_type is not 'edge':
            vmm_domains = []
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY,
            aim_resource.L3Outside(tenant_name=self.t1_aname, name='l1'),
            vmm_domains=vmm_domains)
        a_ext_net = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1')
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['20.10.0.0/16', '4.4.4.0/24'])
        ext_epg = self.aim_mgr.find(aim_ctx, aim_resource.EndpointGroup,
                                    tenant_name=self.t1_aname,
                                    app_profile_name=self._app_profile_name,
                                    name='EXT-l1')
        self.assertEqual(1, len(ext_epg))
        self.assertEqual(ext_epg[0].vmm_domains, vmm_domains)
        self._validate()

    def test_external_network_default_domains(self):
        self._test_external_network_lifecycle_with_domains()

    def test_external_network_host_domains(self):
        self._test_external_network_lifecycle_with_domains(create_hds=True)

    def test_shared_l3out_external_cidr(self):
        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1,
                                      cidrs=['1.2.3.0/20', '20.10.0.0/16',
                                             '4.4.4.0/24'])
        a_ext_net = aim_resource.ExternalNetwork.from_dn(self.dn_t1_l1_n1)
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net, ['1.2.3.0/20', '20.10.0.0/16', '4.4.4.0/24'])

        self.mock_ns.reset_mock()
        self._make_ext_network('net2',
                               dn=self.dn_t1_l1_n1,
                               cidrs=['50.60.0.0/28', '1.2.3.0/20'])
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net,
            ['1.2.3.0/20', '20.10.0.0/16', '4.4.4.0/24', '50.60.0.0/28'])

        self.mock_ns.reset_mock()
        net1 = self._update('networks', net1['id'],
            {'network': {CIDR: ['4.3.3.0/30', '20.10.0.0/16']}})['network']
        self.mock_ns.update_external_cidrs.assert_called_once_with(
            mock.ANY, a_ext_net,
            ['1.2.3.0/20', '20.10.0.0/16', '4.3.3.0/30', '50.60.0.0/28'])

    def test_shared_l3out_network_delete(self):
        # Test reference counting of shared L3outs

        net1 = self._make_ext_network('net1', dn=self.dn_t1_l1_n1)
        a_l3out = aim_resource.L3Outside(tenant_name=self.t1_aname, name='l1')
        a_ext_net = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n1')
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY, a_l3out, vmm_domains=[])
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)

        # create second network that shares APIC l3out and external-network
        self.mock_ns.reset_mock()
        net2 = self._make_ext_network('net2', dn=self.dn_t1_l1_n1)
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY, a_l3out, vmm_domains=[])
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)

        # create third network that shares APIC l3out only
        self.mock_ns.reset_mock()
        net3 = self._make_ext_network(
            'net3', dn=('uni/tn-%s/out-l1/instP-n2' % self.t1_aname))
        a_ext_net3 = aim_resource.ExternalNetwork(
            tenant_name=self.t1_aname, l3out_name='l1', name='n2')
        self.mock_ns.create_l3outside.assert_called_once_with(
            mock.ANY, a_l3out, vmm_domains=[])
        self.mock_ns.create_external_network.assert_called_once_with(
            mock.ANY, a_ext_net3)

        # delete net2
        self.mock_ns.reset_mock()
        self._delete('networks', net2['id'])
        self.mock_ns.delete_l3outside.assert_not_called()
        self.mock_ns.delete_external_network.assert_not_called()

        # delete net1
        self.mock_ns.reset_mock()
        self._delete('networks', net1['id'])
        self.mock_ns.delete_l3outside.assert_not_called()
        self.mock_ns.delete_external_network.assert_called_once_with(
            mock.ANY, a_ext_net)

        # delete net3
        self.mock_ns.reset_mock()
        self._delete('networks', net3['id'])
        self.mock_ns.delete_l3outside.assert_called_once_with(
            mock.ANY, a_l3out)
        self.mock_ns.delete_external_network.assert_called_once_with(
            mock.ANY, a_ext_net3)

    def test_shared_l3out_external_subnet_overlap(self):
        net1 = self._make_ext_network('net1', dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': net1}, '100.100.100.1',
            '100.100.100.0/24')

        net2 = self._make_ext_network('net2', dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': net2}, '200.200.200.1',
            '200.200.200.0/24')

        res = self._create_subnet(self.fmt,
                                  net_id=net2['id'],
                                  cidr="100.100.100.128/28",
                                  gateway_ip="100.100.100.129",
                                  expected_res_status=400)
        res = self.deserialize(self.fmt, res)
        self.assertEqual('ExternalSubnetOverlapInL3Out',
                         res['NeutronError']['type'])

        res = self._create_subnet(self.fmt,
                                  net_id=net1['id'],
                                  cidr="200.200.0.0/16",
                                  gateway_ip="200.200.0.129",
                                  expected_res_status=400)
        res = self.deserialize(self.fmt, res)
        self.assertEqual('ExternalSubnetOverlapInL3Out',
                         res['NeutronError']['type'])


class TestExternalDistributedNat(TestExternalConnectivityBase,
                                 ApicAimTestCase):
    nat_type = 'distributed'


class TestExternalEdgeNat(TestExternalConnectivityBase,
                          ApicAimTestCase):
    nat_type = 'edge'


class TestExternalNoNat(TestExternalConnectivityBase,
                        ApicAimTestCase):
    nat_type = ''
    tenant_1 = 't1'
    tenant_2 = 'common'

    def fix_l3out_vrf(self, l3out_tenant_name, l3out_name, vrf_name):
        l3out = aim_resource.L3Outside(tenant_name=l3out_tenant_name,
                                       name=l3out_name)
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.update(aim_ctx, l3out, vrf_name=vrf_name)

    def _validate(self):
        # REVISIT: Validation does not currently work for these NoNat
        # tests because the L3Out's vrf_name is not updated as in
        # fix_l3out_vrf(), resulting in L3OutsideVrfChangeDisallowed
        # exception from NoNatStrategy.connect_vrf(). A more realistic
        # test using correctly setup monitored pre-existing
        # ExternalNetwork resources should avoid this issue.
        pass

    def test_shared_unscoped_network(self):
        # Skip test since the topology tested is not valid with no-NAT
        pass

    def test_router_interface(self):
        self._do_test_router_interface(use_addr_scope=False,
                                       single_tenant=True)

    def _check_bd_l3out(self, aim_ctx, bridge_domain, l3out_name):
        bridge_domain = self.aim_mgr.get(aim_ctx, bridge_domain)
        self.assertEqual([l3out_name], bridge_domain.l3out_names)


class TestSnatIpAllocation(ApicAimTestCase):

    def test_get_alloc_ip(self):
        admin_ctx = n_context.get_admin_context()
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        sub1 = self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/29')['subnet']
        sub2 = self._make_subnet(
            self.fmt, {'network': ext_net}, '200.100.100.1',
            '200.100.100.0/28')['subnet']

        # No SNAT pools -> no allocation possible
        alloc = self.driver.get_or_allocate_snat_ip(admin_ctx, 'h0', ext_net)
        self.assertIsNone(alloc)

        # Add one SNAT pool
        self._update('subnets', sub1['id'],
                     {'subnet': {SNAT_POOL: True}})

        # Allocate IP and then verify that same IP is returned on get
        for x in range(0, 5):
            alloc = self.driver.get_or_allocate_snat_ip(admin_ctx,
                                                        'h%d' % x, ext_net)
            self._check_ip_in_cidr(alloc['host_snat_ip'], sub1['cidr'])
            self.assertEqual({'host_snat_ip': alloc['host_snat_ip'],
                              'gateway_ip': '100.100.100.1',
                              'prefixlen': 29}, alloc)
            alloc = self.driver.get_or_allocate_snat_ip(admin_ctx,
                                                        'h%d' % x, ext_net)
            self._check_ip_in_cidr(alloc['host_snat_ip'], sub1['cidr'])
            self.assertEqual({'host_snat_ip': alloc['host_snat_ip'],
                              'gateway_ip': '100.100.100.1',
                              'prefixlen': 29}, alloc)

        # First pool exhausted, no further allocations possible
        alloc = self.driver.get_or_allocate_snat_ip(admin_ctx, 'h5', ext_net)
        self.assertIsNone(alloc)

        # Add a second pool and try to re-allocate
        self._update('subnets', sub2['id'],
                     {'subnet': {SNAT_POOL: True}})
        alloc = self.driver.get_or_allocate_snat_ip(admin_ctx, 'h5', ext_net)
        self._check_ip_in_cidr(alloc['host_snat_ip'], sub2['cidr'])
        self.assertEqual({'host_snat_ip': alloc['host_snat_ip'],
                          'gateway_ip': '200.100.100.1',
                          'prefixlen': 28}, alloc)

    def test_snat_pool_flag_update_no_ip(self):
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        sub1 = self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/29')['subnet']
        self._update('subnets', sub1['id'],
                     {'subnet': {SNAT_POOL: True}})

        self._update('subnets', sub1['id'],
                     {'subnet': {SNAT_POOL: False}})
        self._update('subnets', sub1['id'],
                     {'subnet': {SNAT_POOL: True}})

        self._delete('subnets', sub1['id'])

    def test_snat_pool_flag_update_with_ip(self):
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        sub1 = self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/29')['subnet']
        self._update('subnets', sub1['id'],
                     {'subnet': {SNAT_POOL: True}})

        alloc = self.driver.get_or_allocate_snat_ip(
            n_context.get_admin_context(), 'h0', ext_net)
        self.assertIsNotNone(alloc)
        self._update('subnets', sub1['id'],
            {'subnet': {SNAT_POOL: False}}, expected_code=409)
        self._delete('subnets', sub1['id'], expected_code=409)

    def _setup_router_with_ext_net(self):
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/24')

        net = self._make_network(self.fmt, 'pvt-net1', True)['network']
        pvt_sub = self._make_subnet(
            self.fmt, {'network': net}, '10.10.1.1',
            '10.10.1.0/24')['subnet']

        rtr = self._make_router(
            self.fmt, net['tenant_id'], 'router1',
            external_gateway_info={'network_id': ext_net['id']})['router']
        self._router_interface_action('add', rtr['id'], pvt_sub['id'], None)

        sub2 = self._make_subnet(
            self.fmt, {'network': ext_net}, '200.100.100.1',
            '200.100.100.0/29')['subnet']
        self._update('subnets', sub2['id'],
                     {'subnet': {SNAT_POOL: True}})
        alloc = self.driver.get_or_allocate_snat_ip(
            n_context.get_admin_context(), 'h0', ext_net)
        self.assertIsNotNone(alloc)

        return sub2, rtr, pvt_sub

    def _get_snat_ports(self, snat_subnet):
        snat_ports = self._list('ports',
            query_params=('network_id=%s' % snat_subnet['network_id'])
        )['ports']
        return [p for p in snat_ports
                if p['fixed_ips'][0]['subnet_id'] == snat_subnet['id']]

    def test_snat_port_delete_on_router_gw_clear(self):
        snat_sub, rtr, _ = self._setup_router_with_ext_net()
        self.assertTrue(self._get_snat_ports(snat_sub))

        self._update('routers', rtr['id'],
                     {'router': {'external_gateway_info': None}})
        self.assertFalse(self._get_snat_ports(snat_sub))
        self._update('subnets', snat_sub['id'],
                     {'subnet': {SNAT_POOL: False}})

    def test_snat_port_delete_on_router_intf_remove(self):
        snat_sub, rtr, pvt_sub = self._setup_router_with_ext_net()
        self.assertTrue(self._get_snat_ports(snat_sub))

        self._router_interface_action('remove', rtr['id'], pvt_sub['id'],
                                      None)
        self.assertFalse(self._get_snat_ports(snat_sub))
        self._update('subnets', snat_sub['id'],
                     {'subnet': {SNAT_POOL: False}})

    def test_floatingip_alloc_in_snat_pool(self):
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        snat_sub = self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/24')['subnet']
        self._update('subnets', snat_sub['id'],
                     {'subnet': {SNAT_POOL: True}})

        # allocate FIP by subnet
        res = self._create_floatingip(self.fmt, ext_net['id'],
                                      subnet_id=snat_sub['id'])
        self.assertEqual(400, res.status_int)
        res = self.deserialize(self.fmt, res)
        self.assertEqual('SnatPoolCannotBeUsedForFloatingIp',
                         res['NeutronError']['type'])

        # allocate FIP by external address
        res = self._make_floatingip(self.fmt, ext_net['id'],
                                    floating_ip='100.100.100.10',
                                    http_status=400)
        self.assertEqual('SnatPoolCannotBeUsedForFloatingIp',
                         res['NeutronError']['type'])

    def test_floatingip_alloc_in_non_snat_pool(self):
        ext_net = self._make_ext_network('ext-net1',
                                         dn=self.dn_t1_l1_n1)
        snat_sub = self._make_subnet(
            self.fmt, {'network': ext_net}, '100.100.100.1',
            '100.100.100.0/24')['subnet']
        self._update('subnets', snat_sub['id'],
                     {'subnet': {SNAT_POOL: True}})

        fip_sub1 = self._make_subnet(
            self.fmt, {'network': ext_net}, '200.100.100.1',
            '200.100.100.0/29')['subnet']
        self._make_subnet(
            self.fmt, {'network': ext_net}, '250.100.100.1',
            '250.100.100.0/29')

        # FIP with subnet
        fip1 = self._create_floatingip(self.fmt, ext_net['id'],
                                       subnet_id=fip_sub1['id'])
        self.assertEqual(201, fip1.status_int)
        fip1 = self.deserialize(self.fmt, fip1)['floatingip']
        self._check_ip_in_cidr(fip1['floating_ip_address'], fip_sub1['cidr'])

        # FIP with external-address
        fip2 = self._make_floatingip(self.fmt, ext_net['id'],
                                     floating_ip='250.100.100.3')['floatingip']
        self.assertEqual('250.100.100.3', fip2['floating_ip_address'])

        # FIP with no IP specifications - exhaust all available IPs
        ips = netaddr.IPSet(['200.100.100.0/29', '250.100.100.0/29'])
        for x in range(0, 8):
            fip = self._make_floatingip(self.fmt, ext_net['id'])['floatingip']
            self.assertTrue(fip['floating_ip_address'] in ips)


class TestPortVlanNetwork(ApicAimTestCase):

    def setUp(self, **kwargs):
        if kwargs.get('mechanism_drivers') is None:
            kwargs['mechanism_drivers'] = ['logger', 'openvswitch', 'apic_aim']
        if kwargs.get('tenant_network_types') is None:
            kwargs['tenant_network_types'] = ['vlan']
        super(TestPortVlanNetwork, self).setUp(**kwargs)

        aim_ctx = aim_context.AimContext(self.db_session)
        self.hlink1 = aim_infra.HostLink(
            host_name='h1',
            interface_name='eth0',
            path='topology/pod-1/paths-102/pathep-[eth1/7]')
        self._register_agent('h1', AGENT_CONF_OVS)
        self.aim_mgr.create(aim_ctx, self.hlink1)

        self.expected_binding_info = [('openvswitch', 'vlan')]

    def _net_2_epg(self, network):
        if network['router:external']:
            epg = aim_resource.EndpointGroup.from_dn(
                network['apic:distinguished_names']['EndpointGroup'])
        else:
            epg = aim_resource.EndpointGroup(
                tenant_name=self.name_mapper.project(
                    None, network['tenant_id']),
                app_profile_name=self._app_profile_name,
                name=self.name_mapper.network(None, network['id']))
        return epg

    def _check_binding(self, port_id, expected_binding_info=None):
        port_context = self.plugin.get_bound_port_context(
            n_context.get_admin_context(), port_id)
        self.assertIsNotNone(port_context)
        binding_info = [(bl['bound_driver'],
                         bl['bound_segment']['network_type'])
                        for bl in port_context.binding_levels]
        self.assertEqual(expected_binding_info or self.expected_binding_info,
                         binding_info)
        self.assertEqual(port_context.top_bound_segment['physical_network'],
                         port_context.bottom_bound_segment['physical_network'])
        return port_context.bottom_bound_segment['segmentation_id']

    def _check_no_dynamic_segment(self, network_id):
        dyn_segments = segments_db.get_network_segments(
            n_context.get_admin_context(), network_id,
            filter_dynamic=True)
        self.assertEqual(0, len(dyn_segments))

    def _do_test_port_lifecycle(self, external_net=False):
        aim_ctx = aim_context.AimContext(self.db_session)

        if external_net:
            net1 = self._make_ext_network('net1',
                                          dn=self.dn_t1_l1_n1)
        else:
            net1 = self._make_network(self.fmt, 'net1', True)['network']

        hlink2 = aim_infra.HostLink(
            host_name='h2',
            interface_name='eth0',
            path='topology/pod-1/paths-201/pathep-[eth1/19]')
        self.aim_mgr.create(aim_ctx, hlink2)
        self._register_agent('h2', AGENT_CONF_OVS)

        epg = self._net_2_epg(net1)
        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                # unbound port -> no static paths expected
                epg = self.aim_mgr.get(aim_ctx, epg)
                self.assertEqual([], epg.static_paths)
                self._validate()

                # bind to host h1
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_h1 = self._check_binding(p1['port']['id'])
                epg = self.aim_mgr.get(aim_ctx, epg)
                self.assertEqual(
                    [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_h1,
                      'host': 'h1'}],
                    epg.static_paths)
                self._validate()

                # move port to host h2
                p1 = self._bind_port_to_host(p1['port']['id'], 'h2')
                vlan_h2 = self._check_binding(p1['port']['id'])
                epg = self.aim_mgr.get(aim_ctx, epg)
                self.assertEqual(
                    [{'path': hlink2.path, 'encap': 'vlan-%s' % vlan_h2,
                      'host': 'h2'}],
                    epg.static_paths)
                self._validate()

                # delete port
                self._delete('ports', p1['port']['id'])
                self._check_no_dynamic_segment(net1['id'])
                epg = self.aim_mgr.get(aim_ctx, epg)
                self.assertEqual([], epg.static_paths)
                self._validate()

    def test_port_lifecycle_internal_network(self):
        self._do_test_port_lifecycle()

    def test_port_lifecycle_external_network(self):
        self._do_test_port_lifecycle(external_net=True)

    def test_pre_existing_l3out_svi_bgp(self):
        aim_ctx = aim_context.AimContext(self.db_session)

        net1 = self._make_network(
            self.fmt, 'net1', True,
            arg_list=self.extension_attributes,
            **{'apic:svi': 'True',
               DN: {'ExternalNetwork': self.dn_t1_l1_n1},
               'apic:bgp_enable': 'True',
               'apic:bgp_asn': '2'})['network']
        net2 = self._make_network(
            self.fmt, 'net2', True,
            arg_list=self.extension_attributes,
            **{'apic:svi': 'True',
                DN: {'ExternalNetwork': self.dn_t1_l2_n2}})['network']

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                # bind p1 to host h1
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_p1 = self._check_binding(p1['port']['id'])
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    net1[DN]['ExternalNetwork'])

                l3out_np = aim_resource.L3OutNodeProfile(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    name=md.L3OUT_NODE_PROFILE_NAME)
                l3out_np = self.aim_mgr.get(aim_ctx, l3out_np)
                self.assertEqual(l3out_np.name, md.L3OUT_NODE_PROFILE_NAME)
                l3out_ip = aim_resource.L3OutInterfaceProfile(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    name=md.L3OUT_IF_PROFILE_NAME)
                l3out_ip = self.aim_mgr.get(aim_ctx, l3out_ip)
                self.assertEqual(l3out_ip.name, md.L3OUT_IF_PROFILE_NAME)

                l3out_if = aim_resource.L3OutInterface(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path)
                l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                self.assertEqual(l3out_if.encap, 'vlan-%s' % vlan_p1)
                self.assertEqual(l3out_if.secondary_addr_a_list,
                                 [{'addr': '10.0.0.1/24'}])
                primary = netaddr.IPNetwork(l3out_if.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path,
                    addr=subnet)
                bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                self.assertEqual(bgp_peer.asn, '2')
                self._delete('ports', p1['port']['id'])
                self._check_no_dynamic_segment(net1['id'])
                l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                self.assertIsNone(l3out_if)
                bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                self.assertIsNone(bgp_peer)

        with self.subnet(network={'network': net2}) as sub2:
            with self.port(subnet=sub2) as p2:
                # bind p2 to host h1
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                vlan_p2 = self._check_binding(p2['port']['id'])
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    net2[DN]['ExternalNetwork'])
                l3out_if2 = aim_resource.L3OutInterface(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path)
                l3out_if2 = self.aim_mgr.get(aim_ctx, l3out_if2)
                self.assertEqual(l3out_if2.encap, 'vlan-%s' % vlan_p2)
                self.assertEqual(l3out_if2.secondary_addr_a_list,
                                 [{'addr': '10.0.0.1/24'}])
                # Check for no bgp peer status on l3out
                primary = netaddr.IPNetwork(l3out_if2.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_no_peer = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path,
                    addr=subnet)
                bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_no_peer)
                self.assertIsNone(bgp_no_peer)

                # test bgp enable update trigger
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: True,
                                                 ASN: "3"}})['network']
                primary = netaddr.IPNetwork(l3out_if2.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer2 = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path,
                    addr=subnet)
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '3')
                # test bgp disable update trigger
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: False}})['network']
                bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_no_peer)
                # test bgp type update
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: True,
                                                 BGP_TYPE: ""}})['network']
                bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_no_peer)
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP_TYPE: "default_export"
                                                 }})['network']
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '3')
                # test bgp asn update
                net2 = self._update('networks', net2['id'],
                                    {'network': {ASN: "6"
                                                 }})['network']
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '6')

                self._delete('ports', p2['port']['id'])
                self._check_no_dynamic_segment(net2['id'])

    def _test_multiple_ports_on_host(self, is_svi=False, bgp_enabled=False):
        aim_ctx = aim_context.AimContext(self.db_session)

        if not is_svi:
            net1 = self._make_network(self.fmt, 'net1', True)['network']
            epg = self._net_2_epg(net1)
        else:
            if bgp_enabled:
                net1 = self._make_network(self.fmt, 'net1', True,
                                      arg_list=self.extension_attributes,
                                      **{'apic:svi': 'True',
                                         'apic:bgp_enable': 'True',
                                         'apic:bgp_asn': '2'})['network']
            else:
                net1 = self._make_network(self.fmt, 'net1', True,
                                          arg_list=self.extension_attributes,
                                          **{'apic:svi': 'True'})['network']

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                # bind p1 to host h1
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_p1 = self._check_binding(p1['port']['id'])
                if not is_svi:
                    epg = self.aim_mgr.get(aim_ctx, epg)
                    self.assertEqual(
                        [{'path': self.hlink1.path,
                          'encap': 'vlan-%s' % vlan_p1, 'host': 'h1'}],
                        epg.static_paths)
                else:
                    ext_net = aim_resource.ExternalNetwork.from_dn(
                        net1[DN]['ExternalNetwork'])

                    l3out_np = aim_resource.L3OutNodeProfile(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        name=md.L3OUT_NODE_PROFILE_NAME)
                    l3out_np = self.aim_mgr.get(aim_ctx, l3out_np)
                    self.assertEqual(l3out_np.name, md.L3OUT_NODE_PROFILE_NAME)
                    l3out_ip = aim_resource.L3OutInterfaceProfile(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        name=md.L3OUT_IF_PROFILE_NAME)
                    l3out_ip = self.aim_mgr.get(aim_ctx, l3out_ip)
                    self.assertEqual(l3out_ip.name, md.L3OUT_IF_PROFILE_NAME)

                    l3out_node = aim_resource.L3OutNode(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        node_path='topology/pod-1/node-102')
                    l3out_node = self.aim_mgr.get(aim_ctx, l3out_node)
                    apic_router_id = l3out_node.router_id

                    l3out_if = aim_resource.L3OutInterface(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                        interface_path=self.hlink1.path)
                    l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                    self.assertEqual(l3out_if.encap, 'vlan-%s' % vlan_p1)
                    self.assertEqual(l3out_if.secondary_addr_a_list,
                                     [{'addr': '10.0.0.1/24'}])
                    if bgp_enabled:
                        primary = netaddr.IPNetwork(l3out_if.primary_addr_a)
                        subnet = str(primary.cidr)
                        bgp_peer = aim_resource.L3OutInterfaceBgpPeerP(
                            tenant_name=ext_net.tenant_name,
                            l3out_name=ext_net.l3out_name,
                            node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                            interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                            interface_path=self.hlink1.path,
                            addr=subnet)
                        bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                        self.assertEqual(bgp_peer.asn, '2')

                with self.port(subnet=sub1) as p2:
                    # bind p2 to host h1
                    p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                    vlan_p2 = self._check_binding(p2['port']['id'])
                    self.assertEqual(vlan_p1, vlan_p2)
                    if not is_svi:
                        epg = self.aim_mgr.get(aim_ctx, epg)
                        self.assertEqual(
                            [{'path': self.hlink1.path,
                              'encap': 'vlan-%s' % vlan_p2, 'host': 'h1'}],
                            epg.static_paths)
                    else:
                        l3out_node = self.aim_mgr.get(aim_ctx, l3out_node)
                        self.assertEqual(l3out_node.router_id, apic_router_id)
                        l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                        self.assertEqual(l3out_if.encap, 'vlan-%s' % vlan_p1)
                        self.assertEqual(l3out_if.secondary_addr_a_list,
                                         [{'addr': '10.0.0.1/24'}])
                        if bgp_enabled:
                            bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                            self.assertEqual(bgp_peer.asn, '2')

                    self._delete('ports', p2['port']['id'])
                    self._check_binding(p1['port']['id'])
                    if not is_svi:
                        epg = self.aim_mgr.get(aim_ctx, epg)
                        self.assertEqual(
                            [{'path': self.hlink1.path,
                              'encap': 'vlan-%s' % vlan_p1, 'host': 'h1'}],
                            epg.static_paths)
                    else:
                        l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                        self.assertEqual(l3out_if.encap, 'vlan-%s' % vlan_p1)
                        self.assertEqual(l3out_if.secondary_addr_a_list,
                                         [{'addr': '10.0.0.1/24'}])
                        if bgp_enabled:
                            bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                            self.assertEqual(bgp_peer.asn, '2')

                self._delete('ports', p1['port']['id'])
                self._check_no_dynamic_segment(net1['id'])
                if not is_svi:
                    epg = self.aim_mgr.get(aim_ctx, epg)
                    self.assertEqual([], epg.static_paths)
                else:
                    l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                    self.assertIsNone(l3out_if)
                    if bgp_enabled:
                        bgp_peer = self.aim_mgr.get(aim_ctx, bgp_peer)
                        self.assertIsNone(bgp_peer)

    def test_multiple_ports_on_host(self):
        self._test_multiple_ports_on_host()

    def test_multiple_ports_on_host_svi(self):
        self._test_multiple_ports_on_host(is_svi=True)
        self._test_multiple_ports_on_host(is_svi=True, bgp_enabled=True)

    def _test_multiple_networks_on_host(self, is_svi=False, bgp_enabled=False):
        aim_ctx = aim_context.AimContext(self.db_session)

        if not is_svi:
            net1 = self._make_network(self.fmt, 'net1', True)['network']
            epg1 = self._net_2_epg(net1)
        else:
            if bgp_enabled:
                net1 = self._make_network(self.fmt, 'net1', True,
                                      arg_list=self.extension_attributes,
                                      **{'apic:svi': 'True',
                                         'apic:bgp_enable': 'True',
                                         'apic:bgp_asn': '2'})['network']
            else:
                net1 = self._make_network(self.fmt, 'net1', True,
                                          arg_list=self.extension_attributes,
                                          **{'apic:svi': 'True'})['network']

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                # bind p1 to host h1
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_p1 = self._check_binding(p1['port']['id'])

        if not is_svi:
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(
                [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'}],
                epg1.static_paths)
            net2 = self._make_network(self.fmt, 'net2', True)['network']
            epg2 = self._net_2_epg(net2)
        else:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net1[DN]['ExternalNetwork'])
            l3out_node1 = aim_resource.L3OutNode(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                node_path='topology/pod-1/node-102')
            l3out_node1 = self.aim_mgr.get(aim_ctx, l3out_node1)

            l3out_if1 = aim_resource.L3OutInterface(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=self.hlink1.path)
            l3out_if1 = self.aim_mgr.get(aim_ctx, l3out_if1)
            self.assertEqual(l3out_if1.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            if bgp_enabled:
                primary = netaddr.IPNetwork(l3out_if1.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer1 = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path,
                    addr=subnet)
                bgp_peer1 = self.aim_mgr.get(aim_ctx, bgp_peer1)
                self.assertEqual(bgp_peer1.asn, '2')

            net2 = self._make_network(self.fmt, 'net2', True,
                                      arg_list=self.extension_attributes,
                                      **{'apic:svi': 'True'})['network']

        with self.subnet(network={'network': net2}) as sub2:
            with self.port(subnet=sub2) as p2:
                # bind p2 to host h1
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                vlan_p2 = self._check_binding(p2['port']['id'])

        self.assertNotEqual(vlan_p1, vlan_p2)

        if not is_svi:
            epg2 = self.aim_mgr.get(aim_ctx, epg2)
            self.assertEqual(
                [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p2,
                  'host': 'h1'}],
                epg2.static_paths)
        else:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net2[DN]['ExternalNetwork'])
            l3out_node2 = aim_resource.L3OutNode(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                node_path='topology/pod-1/node-102')
            l3out_node2 = self.aim_mgr.get(aim_ctx, l3out_node2)
            self.assertEqual(l3out_node1.router_id, l3out_node2.router_id)
            l3out_if2 = aim_resource.L3OutInterface(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=self.hlink1.path)
            l3out_if2 = self.aim_mgr.get(aim_ctx, l3out_if2)
            self.assertEqual(l3out_if2.encap, 'vlan-%s' % vlan_p2)
            self.assertEqual(l3out_if2.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            # Check for no bgp peer status on l3out
            primary = netaddr.IPNetwork(l3out_if2.primary_addr_a)
            subnet = str(primary.cidr)
            bgp_no_peer = aim_resource.L3OutInterfaceBgpPeerP(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=self.hlink1.path,
                addr=subnet)
            bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_no_peer)
            self.assertIsNone(bgp_no_peer)

            if bgp_enabled:
                # test bgp enable update trigger
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: True,
                                                 ASN: "3"}})['network']
                primary = netaddr.IPNetwork(l3out_if2.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer2 = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path,
                    addr=subnet)
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '3')
                # test bgp disable update trigger
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: False}})['network']
                bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_no_peer)
                # test bgp type update
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP: True,
                                                 BGP_TYPE: ""}})['network']
                bgp_no_peer = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_no_peer)
                net2 = self._update('networks', net2['id'],
                                    {'network': {BGP_TYPE: "default_export"
                                                 }})['network']
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '3')
                # test bgp asn update
                net2 = self._update('networks', net2['id'],
                                    {'network': {ASN: "6"
                                                 }})['network']
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '6')

        self._delete('ports', p2['port']['id'])
        self._check_no_dynamic_segment(net2['id'])
        if not is_svi:
            epg2 = self.aim_mgr.get(aim_ctx, epg2)
            self.assertEqual([], epg2.static_paths)

            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(
                [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'}],
                epg1.static_paths)
        else:
            l3out_if1 = self.aim_mgr.get(aim_ctx, l3out_if1)
            self.assertEqual(l3out_if1.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            l3out_if2 = self.aim_mgr.get(aim_ctx, l3out_if2)
            self.assertIsNone(l3out_if2)
            if bgp_enabled:
                bgp_peer1 = self.aim_mgr.get(aim_ctx, bgp_peer1)
                self.assertEqual(bgp_peer1.asn, '2')
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_peer2)

    def test_multiple_networks_on_host(self):
        self._test_multiple_networks_on_host()

    def test_multiple_networks_on_host_svi(self):
        self._test_multiple_networks_on_host(is_svi=True)
        self._test_multiple_networks_on_host(is_svi=True, bgp_enabled=True)

    def _test_ports_with_2_hostlinks(self, is_svi=False, bgp_enabled=False):
        aim_ctx = aim_context.AimContext(self.db_session)
        hlink_1a = aim_infra.HostLink(
            host_name='h1',
            interface_name='eth1',
            path='topology/pod-1/paths-102/pathep-[eth1/8]')
        hlink_1b = aim_infra.HostLink(
            host_name='h1',
            interface_name='eth2',
            path='topology/pod-1/paths-102/pathep-[eth1/9]')
        self.aim_mgr.create(aim_ctx, hlink_1a)
        self.aim_mgr.create(aim_ctx, hlink_1b)
        hlink_net_lable1 = aim_infra.HostLinkNetworkLabel(
            host_name='h1', network_label='physnet3',
            interface_name='eth1')
        hlink_net_lable2 = aim_infra.HostLinkNetworkLabel(
            host_name='h1', network_label='physnet3',
            interface_name='eth2')
        hlink_net_lable3 = aim_infra.HostLinkNetworkLabel(
            host_name='h1', network_label='physnet2',
            interface_name='eth999')
        self.aim_mgr.create(aim_ctx, hlink_net_lable1)
        self.aim_mgr.create(aim_ctx, hlink_net_lable2)
        self.aim_mgr.create(aim_ctx, hlink_net_lable3)

        net_type = cfg.CONF.ml2.tenant_network_types[0]
        if not is_svi:
            net1 = self._make_network(
                self.fmt, 'net1', True,
                arg_list=('provider:physical_network',
                          'provider:network_type'),
                **{'provider:physical_network': 'physnet3',
                   'provider:network_type': net_type})['network']
            epg1 = self._net_2_epg(net1)
        else:
            if bgp_enabled:
                net1 = self._make_network(
                    self.fmt, 'net1', True,
                    arg_list=('provider:physical_network',
                              'provider:network_type', SVI,
                              BGP, BGP_TYPE, ASN),
                    **{'provider:physical_network': 'physnet3',
                       'provider:network_type': net_type,
                       'apic:svi': 'True',
                       'apic:bgp_enable': 'True',
                       'apic:bgp_asn': '3'})['network']
            else:
                net1 = self._make_network(
                    self.fmt, 'net1', True,
                    arg_list=('provider:physical_network',
                              'provider:network_type', SVI),
                    **{'provider:physical_network': 'physnet3',
                       'provider:network_type': net_type,
                       'apic:svi': 'True'})['network']

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                # bind p1 to host h1
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_p1 = self._check_binding(p1['port']['id'])

        if not is_svi:
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(
                [{'path': hlink_1a.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'},
                 {'path': hlink_1b.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'}],
                epg1.static_paths)
        else:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net1[DN]['ExternalNetwork'])
            l3out_node1a = aim_resource.L3OutNode(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                node_path='topology/pod-1/node-102')
            l3out_node1a = self.aim_mgr.get(aim_ctx, l3out_node1a)
            l3out_if1a = aim_resource.L3OutInterface(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=hlink_1a.path)
            l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
            self.assertEqual(l3out_if1a.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1a.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])

            l3out_node1b = aim_resource.L3OutNode(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                node_path='topology/pod-1/node-102')
            l3out_node1b = self.aim_mgr.get(aim_ctx, l3out_node1b)
            self.assertEqual(l3out_node1a.router_id,
                             l3out_node1b.router_id)
            l3out_if1b = aim_resource.L3OutInterface(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=hlink_1b.path)
            l3out_if1b = self.aim_mgr.get(aim_ctx, l3out_if1b)
            self.assertEqual(l3out_if1b.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1b.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            self.assertEqual(l3out_if1a.primary_addr_a,
                             l3out_if1b.primary_addr_a)
            if bgp_enabled:
                primary = netaddr.IPNetwork(l3out_if1a.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer1a = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=hlink_1a.path,
                    addr=subnet)
                bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                self.assertEqual(bgp_peer1a.asn, '3')
                primary = netaddr.IPNetwork(l3out_if1b.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer1b = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=hlink_1b.path,
                    addr=subnet)
                bgp_peer1b = self.aim_mgr.get(aim_ctx, bgp_peer1b)
                self.assertEqual(bgp_peer1b.asn, '3')

        # test the fallback
        if not is_svi:
            net2 = self._make_network(
                self.fmt, 'net2', True,
                arg_list=('provider:physical_network',
                          'provider:network_type'),
                **{'provider:physical_network': 'physnet2',
                   'provider:network_type': net_type})['network']
            epg2 = self._net_2_epg(net2)
        else:
            if not bgp_enabled:
                net2 = self._make_network(
                    self.fmt, 'net2', True,
                    arg_list=('provider:physical_network',
                              'provider:network_type', SVI),
                    **{'provider:physical_network': 'physnet2',
                       'provider:network_type': net_type,
                       'apic:svi': 'True'})['network']
            else:
                net2 = self._make_network(
                    self.fmt, 'net2', True,
                    arg_list=('provider:physical_network',
                              'provider:network_type', SVI,
                              BGP, BGP_TYPE, ASN),
                    **{'provider:physical_network': 'physnet2',
                       'provider:network_type': net_type,
                       'apic:svi': 'True',
                       'apic:bgp_enable': 'True',
                       'apic:bgp_asn': '4'})['network']

        with self.subnet(network={'network': net2}) as sub2:
            with self.port(subnet=sub2) as p2:
                # bind p2 to host h1
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                vlan_p2 = self._check_binding(p2['port']['id'])

        self.assertNotEqual(vlan_p1, vlan_p2)

        host_links = self.aim_mgr.find(aim_ctx, aim_infra.HostLink,
                                       host_name='h1')
        if not is_svi:
            epg2 = self.aim_mgr.get(aim_ctx, epg2)
            self.assertEqual(
                sorted(
                    [{'path': host_links[0].path, 'encap': 'vlan-%s' % vlan_p2,
                      'host': 'h1'},
                     {'path': host_links[1].path, 'encap': 'vlan-%s' % vlan_p2,
                      'host': 'h1'},
                     {'path': host_links[2].path, 'encap': 'vlan-%s' % vlan_p2,
                      'host': 'h1'}]),
                sorted(epg2.static_paths))
        else:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net2[DN]['ExternalNetwork'])
            l3out_if2 = aim_resource.L3OutInterface(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                interface_path=host_links[0].path)
            l3out_if2 = self.aim_mgr.get(aim_ctx, l3out_if2)
            self.assertEqual(l3out_if2.encap, 'vlan-%s' % vlan_p2)
            self.assertEqual(l3out_if2.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            if bgp_enabled:
                primary = netaddr.IPNetwork(l3out_if2.primary_addr_a)
                subnet = str(primary.cidr)
                bgp_peer2 = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=host_links[0].path,
                    addr=subnet)
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertEqual(bgp_peer2.asn, '4')

        self._delete('ports', p2['port']['id'])
        self._check_no_dynamic_segment(net2['id'])

        if not is_svi:
            epg2 = self.aim_mgr.get(aim_ctx, epg2)
            self.assertEqual([], epg2.static_paths)
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(
                [{'path': hlink_1a.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'},
                 {'path': hlink_1b.path, 'encap': 'vlan-%s' % vlan_p1,
                  'host': 'h1'}],
                epg1.static_paths)
        else:
            l3out_if2 = self.aim_mgr.get(aim_ctx, l3out_if2)
            self.assertIsNone(l3out_if2)
            if bgp_enabled:
                bgp_peer2 = self.aim_mgr.get(aim_ctx, bgp_peer2)
                self.assertIsNone(bgp_peer2)
            l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
            self.assertEqual(l3out_if1a.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1a.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            l3out_if1b = self.aim_mgr.get(aim_ctx, l3out_if1b)
            self.assertEqual(l3out_if1b.encap, 'vlan-%s' % vlan_p1)
            self.assertEqual(l3out_if1b.secondary_addr_a_list,
                             [{'addr': '10.0.0.1/24'}])
            self.assertEqual(l3out_if1a.primary_addr_a,
                             l3out_if1b.primary_addr_a)
            if bgp_enabled:
                bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                self.assertEqual(bgp_peer1a.asn, '3')
                bgp_peer1b = self.aim_mgr.get(aim_ctx, bgp_peer1b)
                self.assertEqual(bgp_peer1b.asn, '3')
        self._delete('ports', p1['port']['id'])
        self._check_no_dynamic_segment(net1['id'])

        if not is_svi:
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual([], epg1.static_paths)
        else:
            l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
            self.assertIsNone(l3out_if1a)
            l3out_if1b = self.aim_mgr.get(aim_ctx, l3out_if1b)
            self.assertIsNone(l3out_if1b)
            if bgp_enabled:
                bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                self.assertIsNone(bgp_peer1a)
                bgp_peer1b = self.aim_mgr.get(aim_ctx, bgp_peer1b)
                self.assertIsNone(bgp_peer1b)
        self.aim_mgr.delete(aim_ctx, hlink_1a)
        self.aim_mgr.delete(aim_ctx, hlink_1b)
        self.aim_mgr.delete(aim_ctx, hlink_net_lable1)
        self.aim_mgr.delete(aim_ctx, hlink_net_lable2)
        self.aim_mgr.delete(aim_ctx, hlink_net_lable3)

    def test_ports_with_2_hostlinks(self):
        self._test_ports_with_2_hostlinks()

    def test_ports_with_2_hostlinks_svi(self):
        self._test_ports_with_2_hostlinks(is_svi=True)
        self._test_ports_with_2_hostlinks(is_svi=True, bgp_enabled=True)

    def _test_network_on_multiple_hosts(self, is_svi=False, bgp_enabled=False):
        aim_ctx = aim_context.AimContext(self.db_session)

        if not is_svi:
            net1 = self._make_network(self.fmt, 'net1', True)['network']
            epg1 = self._net_2_epg(net1)
        else:
            if bgp_enabled:
                net1 = self._make_network(
                    self.fmt, 'net1', True,
                    arg_list=self.extension_attributes,
                    **{'apic:svi': 'True',
                       'apic:bgp_enable': 'True',
                       'apic:bgp_asn': '5'})['network']
            else:
                net1 = self._make_network(self.fmt, 'net1', True,
                                          arg_list=self.extension_attributes,
                                          **{'apic:svi': 'True'})['network']

        hlink2 = aim_infra.HostLink(
            host_name='h2',
            interface_name='eth0',
            path='topology/pod-1/paths-201/pathep-[eth1/19]')
        self.aim_mgr.create(aim_ctx, hlink2)
        self._register_agent('h2', AGENT_CONF_OVS)

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
                vlan_p1 = self._check_binding(p1['port']['id'])
            with self.port(subnet=sub1) as p2:
                p2 = self._bind_port_to_host(p2['port']['id'], 'h2')
                vlan_p2 = self._check_binding(p2['port']['id'])

            self.assertEqual(vlan_p1, vlan_p2)

            if not is_svi:
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(
                    [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p1,
                      'host': 'h1'},
                     {'path': hlink2.path, 'encap': 'vlan-%s' % vlan_p2,
                      'host': 'h2'}],
                    sorted(epg1.static_paths, key=lambda x: x['path']))
            else:
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    net1[DN]['ExternalNetwork'])
                l3out_node1a = aim_resource.L3OutNode(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    node_path='topology/pod-1/node-102')
                l3out_node1a = self.aim_mgr.get(aim_ctx, l3out_node1a)
                l3out_if1a = aim_resource.L3OutInterface(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=self.hlink1.path)
                l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
                self.assertEqual(l3out_if1a.encap, 'vlan-%s' % vlan_p1)
                self.assertEqual(l3out_if1a.secondary_addr_a_list,
                                 [{'addr': '10.0.0.1/24'}])

                l3out_node1b = aim_resource.L3OutNode(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    node_path='topology/pod-1/node-201')
                l3out_node1b = self.aim_mgr.get(aim_ctx, l3out_node1b)
                self.assertNotEqual(l3out_node1a.router_id,
                                    l3out_node1b.router_id)
                l3out_if1b = aim_resource.L3OutInterface(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                    interface_path=hlink2.path)
                l3out_if1b = self.aim_mgr.get(aim_ctx, l3out_if1b)
                self.assertEqual(l3out_if1b.encap, 'vlan-%s' % vlan_p1)
                self.assertEqual(l3out_if1b.secondary_addr_a_list,
                                 [{'addr': '10.0.0.1/24'}])
                self.assertNotEqual(l3out_if1a.primary_addr_a,
                                    l3out_if1b.primary_addr_a)
                if bgp_enabled:
                    primary = netaddr.IPNetwork(l3out_if1a.primary_addr_a)
                    subnet = str(primary.cidr)
                    bgp_peer1a = aim_resource.L3OutInterfaceBgpPeerP(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                        interface_path=self.hlink1.path,
                        addr=subnet)
                    bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                    self.assertEqual(bgp_peer1a.asn, '5')
                    primary = netaddr.IPNetwork(l3out_if1b.primary_addr_a)
                    subnet = str(primary.cidr)
                    bgp_peer1b = aim_resource.L3OutInterfaceBgpPeerP(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                        interface_path=hlink2.path,
                        addr=subnet)
                    bgp_peer1b = self.aim_mgr.get(aim_ctx, bgp_peer1b)
                    self.assertEqual(bgp_peer1b.asn, '5')

            self._delete('ports', p2['port']['id'])
            if not is_svi:
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(
                    [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p1,
                      'host': 'h1'}],
                    epg1.static_paths)
            else:
                l3out_if1b = self.aim_mgr.get(aim_ctx, l3out_if1b)
                self.assertIsNone(l3out_if1b)
                l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
                self.assertEqual(l3out_if1a.encap, 'vlan-%s' % vlan_p1)
                self.assertEqual(l3out_if1a.secondary_addr_a_list,
                                 [{'addr': '10.0.0.1/24'}])
                if bgp_enabled:
                    bgp_peer1b = self.aim_mgr.get(aim_ctx, bgp_peer1b)
                    self.assertIsNone(bgp_peer1b)
                    bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                    self.assertEqual(bgp_peer1a.asn, '5')
            self._delete('ports', p1['port']['id'])
            self._check_no_dynamic_segment(net1['id'])

            if not is_svi:
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual([], epg1.static_paths)
            else:
                l3out_if1a = self.aim_mgr.get(aim_ctx, l3out_if1a)
                self.assertIsNone(l3out_if1a)
                if bgp_enabled:
                    bgp_peer1a = self.aim_mgr.get(aim_ctx, bgp_peer1a)
                    self.assertIsNone(bgp_peer1a)
        self.aim_mgr.delete(aim_ctx, hlink2)

    def test_network_on_multiple_hosts(self):
        self._test_network_on_multiple_hosts()

    def test_network_on_multiple_hosts_svi(self):
        self._test_network_on_multiple_hosts(is_svi=True)
        self._test_network_on_multiple_hosts(is_svi=True, bgp_enabled=True)

    def test_svi_exhausted_router_id_pool(self):
        self.driver.apic_router_id_pool = '199.199.199.1'
        self.driver.apic_router_id_subnet = netaddr.IPSet(
            [self.driver.apic_router_id_pool])
        aim_ctx = aim_context.AimContext(self.db_session)
        net1 = self._make_network(self.fmt, 'net1', True,
                                  arg_list=self.extension_attributes,
                                  **{'apic:svi': 'True'})['network']
        hlink2 = aim_infra.HostLink(
            host_name='h2',
            interface_name='eth0',
            path='topology/pod-1/paths-201/pathep-[eth1/19]')
        self.aim_mgr.create(aim_ctx, hlink2)
        self._register_agent('h2', AGENT_CONF_OVS)

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'h1')
            with self.port(subnet=sub1) as p2:
                result = self._bind_port_to_host(p2['port']['id'], 'h2')
                self.assertEqual('ExhaustedApicRouterIdPool',
                                 result['NeutronError']['type'])

    def test_port_binding_missing_hostlink(self):
        aim_ctx = aim_context.AimContext(self.db_session)

        net1 = self._make_network(self.fmt, 'net1', True)['network']
        epg1 = self._net_2_epg(net1)

        self._register_agent('h-42', AGENT_CONF_OVS)

        with self.subnet(network={'network': net1}) as sub1:
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'h-42')
                self._check_binding(p1['port']['id'])

                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual([], epg1.static_paths)

            hlink42 = aim_infra.HostLink(host_name='h42',
                                         interface_name='eth0')
            self.aim_mgr.create(aim_ctx, hlink42)
            with self.port(subnet=sub1) as p2:
                p2 = self._bind_port_to_host(p2['port']['id'], 'h-42')
                self._check_binding(p2['port']['id'])

                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual([], epg1.static_paths)

    def _test_topology_rpc_no_ports(self, is_svi=False):
        nctx = n_context.get_admin_context()
        aim_ctx = aim_context.AimContext(self.db_session)

        if is_svi:
            net1 = self._make_network(self.fmt, 'net1', True,
                                      arg_list=self.extension_attributes,
                                      **{'apic:svi': 'True'})['network']
        else:
            net1 = self._make_network(self.fmt, 'net1', True)['network']
            epg1 = self._net_2_epg(net1)

        # add hostlink for h10
        self.driver.update_link(nctx, 'h10', 'eth0', 'A:A', 101, 1, 19, '2',
                               'topology/pod-2/paths-101/pathep-[eth1/19]')
        expected_hlink10 = aim_infra.HostLink(host_name='h10',
            interface_name='eth0', interface_mac='A:A',
            switch_id='101', module='1', port='19', pod_id='2',
            path='topology/pod-2/paths-101/pathep-[eth1/19]')
        self.assertEqual(expected_hlink10,
                         self.aim_mgr.get(aim_ctx, expected_hlink10))
        if is_svi:
            ext_net = aim_resource.ExternalNetwork.from_dn(
                net1[DN]['ExternalNetwork'])
            l3out_node1 = aim_resource.L3OutNode(
                tenant_name=ext_net.tenant_name,
                l3out_name=ext_net.l3out_name,
                node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                node_path='topology/pod-2/node-101')
            self.assertIsNone(self.aim_mgr.get(aim_ctx, l3out_node1))
        else:
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual([], epg1.static_paths)
        # remove hostlink for h10
        self.driver.delete_link(nctx, 'h10', 'eth0', 'A:A', 0, 0, 0)
        self.assertIsNone(self.aim_mgr.get(aim_ctx, expected_hlink10))
        if is_svi:
            self.assertIsNone(self.aim_mgr.get(aim_ctx, l3out_node1))
        else:
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual([], epg1.static_paths)

    def test_topology_rpc_no_ports(self):
        self._test_topology_rpc_no_ports()

    def test_topology_rpc_no_ports_svi(self):
        self._test_topology_rpc_no_ports(is_svi=True)

    def _test_topology_rpc(self, is_svi=False):
        nctx = n_context.get_admin_context()
        aim_ctx = aim_context.AimContext(self.db_session)
        nets = []
        epgs = []
        vlans = []
        self._register_agent('h10', AGENT_CONF_OVS)

        for x in range(0, 2):
            if is_svi:
                net = self._make_network(self.fmt, 'net%d' % x, True,
                                         arg_list=self.extension_attributes,
                                         **{'apic:svi': 'True'})['network']
                nets.append(net)
            else:
                net = self._make_network(self.fmt, 'net%d' % x,
                                         True)['network']
                epgs.append(self._net_2_epg(net))

            with self.subnet(network={'network': net}) as sub:
                with self.port(subnet=sub) as p:
                    p = self._bind_port_to_host(p['port']['id'], 'h10')
                    vlans.append(self._check_binding(p['port']['id']))

            if is_svi:
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    net[DN]['ExternalNetwork'])
                l3out_node = aim_resource.L3OutNode(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    node_path='topology/pod-2/node-101')
                self.assertIsNone(self.aim_mgr.get(aim_ctx, l3out_node))
            else:
                epgs[x] = self.aim_mgr.get(aim_ctx, epgs[x])
                self.assertEqual([], epgs[x].static_paths)

        expected_hlink10 = aim_infra.HostLink(host_name='h10',
            interface_name='eth0', interface_mac='A:A',
            switch_id='101', module='1', port='19', pod_id='2',
            path='topology/pod-2/paths-101/pathep-[eth1/19]')

        def check_epg_static_paths(link_path):
            for x in range(0, len(epgs)):
                epgs[x] = self.aim_mgr.get(aim_ctx, epgs[x])
                expected_path = ([{'path': link_path,
                                   'encap': 'vlan-%s' % vlans[x],
                                   'host': 'h10'}]
                                if link_path else [])
                self.assertEqual(expected_path, epgs[x].static_paths)

        def check_svi_paths(link_path):
            for x in range(0, len(nets)):
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    nets[x][DN]['ExternalNetwork'])
                l3out_node = aim_resource.L3OutNode(
                    tenant_name=ext_net.tenant_name,
                    l3out_name=ext_net.l3out_name,
                    node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                    node_path='topology/pod-2/node-101')
                l3out_node = self.aim_mgr.get(aim_ctx, l3out_node)
                self.assertIsNotNone(l3out_node)
                if link_path:
                    l3out_if = aim_resource.L3OutInterface(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                        interface_path=link_path)
                    l3out_if = self.aim_mgr.get(aim_ctx, l3out_if)
                    self.assertEqual(l3out_if.encap, 'vlan-%s' % vlans[x])
                    self.assertEqual(l3out_if.secondary_addr_a_list,
                                     [{'addr': '10.0.0.1/24'}])
                else:
                    l3out_if = aim_resource.L3OutInterface(
                        tenant_name=ext_net.tenant_name,
                        l3out_name=ext_net.l3out_name,
                        node_profile_name=md.L3OUT_NODE_PROFILE_NAME,
                        interface_profile_name=md.L3OUT_IF_PROFILE_NAME,
                        interface_path=expected_hlink10.path)
                    self.assertIsNone(self.aim_mgr.get(aim_ctx, l3out_if))

        # add hostlink for h10
        self.driver.update_link(nctx, 'h10', 'eth0', 'A:A', 101, 1, 19, '2',
                                'topology/pod-2/paths-101/pathep-[eth1/19]')
        self.assertEqual(expected_hlink10,
                         self.aim_mgr.get(aim_ctx, expected_hlink10))
        if is_svi:
            check_svi_paths(expected_hlink10.path)
        else:
            check_epg_static_paths(expected_hlink10.path)

        # update link
        self.driver.update_link(nctx, 'h10', 'eth0', 'A:A', 101, 1, 42, '2',
                                'topology/pod-2/paths-101/pathep-[eth1/42]')
        expected_hlink10.port = '42'
        expected_hlink10.path = 'topology/pod-2/paths-101/pathep-[eth1/42]'
        self.assertEqual(expected_hlink10,
                         self.aim_mgr.get(aim_ctx, expected_hlink10))
        if is_svi:
            check_svi_paths(expected_hlink10.path)
        else:
            check_epg_static_paths(expected_hlink10.path)

        # add another link (VPC like)
        self.driver.update_link(nctx, 'h10', 'eth1', 'B:B', 201, 1, 24, '2',
                                'topology/pod-2/paths-101/pathep-[eth1/42]')
        expected_hlink10_sec = aim_infra.HostLink(host_name='h10',
            interface_name='eth1', interface_mac='B:B',
            switch_id='201', module='1', port='24', pod_id='2',
            path='topology/pod-2/paths-101/pathep-[eth1/42]')
        self.assertEqual(expected_hlink10_sec,
                         self.aim_mgr.get(aim_ctx, expected_hlink10_sec))
        if is_svi:
            check_svi_paths(expected_hlink10.path)
        else:
            check_epg_static_paths(expected_hlink10.path)

        # remove second link
        self.driver.delete_link(nctx, 'h10', 'eth1', 'B:B', 0, 0, 0)
        self.assertIsNone(self.aim_mgr.get(aim_ctx, expected_hlink10_sec))
        if is_svi:
            check_svi_paths(expected_hlink10.path)
        else:
            check_epg_static_paths(expected_hlink10.path)

        # remove first link
        self.driver.delete_link(nctx, 'h10', 'eth0', 'A:A', 0, 0, 0)
        self.assertIsNone(self.aim_mgr.get(aim_ctx, expected_hlink10))
        if is_svi:
            check_svi_paths(None)
        else:
            check_epg_static_paths(None)

    def test_topology_rpc(self):
        self._test_topology_rpc()

    def test_topology_rpc_svi(self):
        self._test_topology_rpc(is_svi=True)


class TestPortOnPhysicalNode(TestPortVlanNetwork):
    # Tests for binding port on physical node where another ML2 mechanism
    # driver completes port binding.

    def setUp(self, mechanism_drivers=None):
        super(TestPortOnPhysicalNode, self).setUp(
            mechanism_drivers=mechanism_drivers,
            tenant_network_types=['opflex'])
        self.expected_binding_info = [('apic_aim', 'opflex'),
                                      ('openvswitch', 'vlan')]

    def _doms(self, domains, with_type=True):
        if with_type:
            return [(str(dom['name']), str(dom['type']))
                    for dom in domains]
        else:
            return [str(dom['name']) for dom in domains]

    def test_mixed_ports_on_network(self):
        aim_ctx = aim_context.AimContext(self.db_session)

        self._register_agent('opflex-1', AGENT_CONF_OPFLEX)

        net1 = self._make_network(
            self.fmt, 'net1', True,
            arg_list=('provider:physical_network', 'provider:network_type'),
            **{'provider:physical_network': 'physnet3',
               'provider:network_type': 'opflex'})['network']
        epg1 = self._net_2_epg(net1)

        with self.subnet(network={'network': net1}) as sub1:
            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                self._check_binding(p1['port']['id'],
                    expected_binding_info=[('apic_aim', 'opflex')])
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual([], epg1.static_paths)
                self._validate()

            # port on non-opflex host
            with self.port(subnet=sub1) as p2:
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                vlan_p2 = self._check_binding(p2['port']['id'])
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(
                    [{'path': self.hlink1.path, 'encap': 'vlan-%s' % vlan_p2,
                      'host': 'h1'}],
                    epg1.static_paths)
                self._validate()

    def test_mixed_ports_on_network_with_default_domains(self):
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
        self._register_agent('opflex-1', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-2', AGENT_CONF_OPFLEX)
        net1 = self._make_network(
            self.fmt, 'net1', True,
            arg_list=('provider:physical_network', 'provider:network_type'),
            **{'provider:physical_network': 'physnet3',
               'provider:network_type': 'opflex'})['network']
        epg1 = self._net_2_epg(net1)

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                self._validate()
                # move port to another host
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-2')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                self._validate()
                # delete port
                self._delete('ports', p1['port']['id'])
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))

            # port on non-opflex host
            with self.port(subnet=sub1) as p2:
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph1', 'ph2']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                self._validate()
                # move port to another host
                p2 = self._bind_port_to_host(p2['port']['id'], 'h2')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph1', 'ph2']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                self._validate()
                # delete port
                self._delete('ports', p2['port']['id'])
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack'),
                                      ('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph1', 'ph2']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))

    def test_update_sg_rule_with_remote_group_set(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']

        # Create subnet
        subnet = self._make_subnet(self.fmt, net_resp, '10.0.1.1',
                                   '10.0.1.0/24')['subnet']
        subnet_id = subnet['id']

        # Create port on subnet
        fixed_ips = [{'subnet_id': subnet_id, 'ip_address': '10.0.1.100'}]
        port = self._make_port(self.fmt, net['id'],
                               fixed_ips=fixed_ips)['port']
        default_sg_id = port['security_groups'][0]
        default_sg = self._show('security-groups',
                                default_sg_id)['security_group']
        for sg_rule in default_sg['security_group_rules']:
            if sg_rule['remote_group_id'] and sg_rule['ethertype'] == 'IPv4':
                break
        tenant_aname = self.name_mapper.project(None, default_sg['tenant_id'])
        aim_sg_rule = self._get_sg_rule(
            sg_rule['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, ['10.0.1.100'])

        # add another rule with remote_group_id set
        rule1 = self._build_security_group_rule(
            default_sg_id, 'ingress', n_constants.PROTO_NAME_TCP, '22', '23',
            remote_group_id=default_sg_id, ethertype=n_constants.IPv4)
        rules = {'security_group_rules': [rule1['security_group_rule']]}
        sg_rule1 = self._make_security_group_rule(
            self.fmt, rules)['security_group_rules'][0]
        aim_sg_rule = self._get_sg_rule(
            sg_rule1['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, ['10.0.1.100'])

        # delete SG from port
        data = {'port': {'security_groups': []}}
        port = self._update('ports', port['id'], data)['port']
        aim_sg_rule = self._get_sg_rule(
            sg_rule['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, [])
        aim_sg_rule = self._get_sg_rule(
            sg_rule1['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, [])

        # add SG to port
        data = {'port': {'security_groups': [default_sg_id]}}
        port = self._update('ports', port['id'], data)['port']
        aim_sg_rule = self._get_sg_rule(
             sg_rule['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, ['10.0.1.100'])
        aim_sg_rule = self._get_sg_rule(
            sg_rule1['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, ['10.0.1.100'])

        self._delete('ports', port['id'])
        aim_sg_rule = self._get_sg_rule(
            sg_rule['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, [])
        aim_sg_rule = self._get_sg_rule(
            sg_rule1['id'], 'default', default_sg_id, tenant_aname)
        self.assertEqual(aim_sg_rule.remote_ips, [])

    def test_mixed_ports_on_network_with_specific_domains(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='opflex-1',
                                                   domain_name='vm1',
                                                   domain_type='OpenStack')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='opflex-2',
                                                   domain_name='vm2',
                                                   domain_type='OpenStack')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='opflex-2a',
                                                   domain_name='vm2',
                                                   domain_type='OpenStack')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='*',
                                                   domain_name='vm3',
                                                   domain_type='OpenStack')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='h1',
                                                   domain_name='ph1',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='h2',
                                                   domain_name='ph2',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='h2a',
                                                   domain_name='ph2',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='*',
                                                   domain_name='ph3',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        self._register_agent('opflex-1', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-2', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-2a', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-3', AGENT_CONF_OPFLEX)
        net1 = self._make_network(
            self.fmt, 'net1', True,
            arg_list=('provider:physical_network', 'provider:network_type'),
            **{'provider:physical_network': 'physnet3',
               'provider:network_type': 'opflex'})['network']
        epg1 = self._net_2_epg(net1)

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                # move port to another host
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-2')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
            # create another port on a host that belongs to the same domain
            with self.port(subnet=sub1) as p1a:
                p1a = self._bind_port_to_host(p1a['port']['id'], 'opflex-2a')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm2', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
            # delete 1st port
            self._delete('ports', p1['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([('vm2', 'OpenStack')]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))
            # delete the last port
            self._delete('ports', p1a['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))
            # create another port on a host that belongs to the wildcard domain
            with self.port(subnet=sub1) as p3:
                p3 = self._bind_port_to_host(p3['port']['id'], 'opflex-3')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm3', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
            # delete the wildcard port -- the domain should still
            # be associated, since we aren't identifying all of the
            # host-specific mappings
            self._delete('ports', p3['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([('vm3', 'OpenStack')]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))

            # port on non-opflex host
            with self.port(subnet=sub1) as p2:
                p2 = self._bind_port_to_host(p2['port']['id'], 'h1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm3', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph1']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                # move port to another host
                p2 = self._bind_port_to_host(p2['port']['id'], 'h2')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm3', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph2']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
            # create another port on a host that belongs to the same domain
            with self.port(subnet=sub1) as p2a:
                p2a = self._bind_port_to_host(p2a['port']['id'], 'h2a')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm3', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph2']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))

            # delete 1st port
            self._delete('ports', p2['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([('vm3', 'OpenStack')]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set(['ph2']),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))
            # delete the last port
            self._delete('ports', p2a['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([('vm3', 'OpenStack')]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))
            # create another port on a host that belongs
            # to the wildcard mapping
            with self.port(subnet=sub1) as p3:
                p3 = self._bind_port_to_host(p3['port']['id'], 'h3')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm3', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set(['ph3']),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
            # delete the wildcard port -- the domain should still
            # be associated, since we aren't identifying all of the
            # host-specific mappings
            self._delete('ports', p3['port']['id'])
            epg1 = self.aim_mgr.get(aim_ctx, epg1)
            self.assertEqual(set([('vm3', 'OpenStack')]),
                             set(self._doms(epg1.vmm_domains)))
            self.assertEqual(set(['ph3']),
                             set(self._doms(epg1.physical_domains,
                                            with_type=False)))

    def test_no_host_domain_mappings(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.VMMDomain(type='OpenStack',
                                                   name='ostack1'),
                            overwrite=True)
        self.aim_mgr.create(aim_ctx,
                            aim_resource.VMMDomain(type='VMware',
                                                   name='vmware1'),
                            overwrite=True)
        self._register_agent('opflex-1', AGENT_CONF_OPFLEX)
        self._register_agent('opflex-2', AGENT_CONF_OPFLEX)
        net1 = self._make_network(
            self.fmt, 'net1', True,
            arg_list=('provider:physical_network', 'provider:network_type'),
            **{'provider:physical_network': 'physnet3',
               'provider:network_type': 'opflex'})['network']
        epg1 = self._net_2_epg(net1)

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('ostack1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                # move port to another host
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-2')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('ostack1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))

    def _external_net_test_setup(self, aim_ctx, domains, mappings,
                                 agents, nat_type=None):
        for domain in domains:
            self.aim_mgr.create(aim_ctx,
                                aim_resource.VMMDomain(type=domain['type'],
                                                       name=domain['name'],
                                overwrite=True))
        for mapping in mappings:
            hd_mapping = aim_infra.HostDomainMappingV2(
                host_name=mapping['host'],
                domain_name=mapping['name'],
                domain_type=mapping['type'])
            self.aim_mgr.create(aim_ctx, hd_mapping)
        for agent in agents:
            self._register_agent(agent, AGENT_CONF_OPFLEX)
        net1 = self._make_ext_network('net1',
                                      dn=self.dn_t1_l1_n1,
                                      nat_type=nat_type)
        epg1 = self._net_2_epg(net1)
        epg1 = self.aim_mgr.get(aim_ctx, epg1)
        return net1, epg1

    def test_no_nat_external_net_default_domains(self):
        # no-NAT external networks rely on port-binding
        # to dynamically associate domains to the external EPG
        aim_ctx = aim_context.AimContext(self.db_session)
        domains = [{'type': 'OpenStack', 'name': 'cloud-rtp-1-VMM'},
                   {'type': 'OpenStack', 'name': 'vm1'}]
        mappings = []
        agents = ['opflex-1', 'opflex-2']
        net1, epg1 = self._external_net_test_setup(aim_ctx, domains,
                                                   mappings, agents,
                                                   nat_type='')

        self.assertEqual(set([]),
                         set(self._doms(epg1.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(epg1.physical_domains,
                                        with_type=False)))

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                      ('vm1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                with self.port(subnet=sub1) as p2:
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind the port - should still have both, since
                    # we don't know that we can delete the wildcard entry
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    p1 = self._bind_port_to_host(p1['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind port 1 -- domains left in place, as all default
                    # domain cases should leave domains associated (to keep
                    # backwards compatibility).
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))

    def test_no_nat_external_net_specific_domains(self):
        # no-NAT external networks rely on port-binding
        # to dynamically associate domains to the external EPG
        aim_ctx = aim_context.AimContext(self.db_session)
        domains = [{'type': 'OpenStack', 'name': 'cloud-rtp-1-VMM'},
                   {'type': 'OpenStack', 'name': 'vm1'}]
        mappings = [{'type': 'OpenStack',
                     'host': '*',
                     'name': 'cloud-rtp-1-VMM'},
                    {'type': 'OpenStack',
                     'host': 'opflex-1',
                     'name': 'vm1'}]
        agents = ['opflex-1', 'opflex-2']
        net1, epg1 = self._external_net_test_setup(aim_ctx, domains,
                                                   mappings, agents,
                                                   nat_type='')

        self.assertEqual(set([]),
                         set(self._doms(epg1.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(epg1.physical_domains,
                                        with_type=False)))

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('vm1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                with self.port(subnet=sub1) as p2:
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind the port - should still have both, since
                    # we don't know that we can delete the wildcard entry
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    p1 = self._bind_port_to_host(p1['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind port 1 -- should remove all domains, as
                    # there aren't any ports left in the EPG
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))

    def test_nat_external_net_specific_domains(self):
        # no-NAT external networks rely on port-binding
        # to dynamically associate domains to the external EPG
        aim_ctx = aim_context.AimContext(self.db_session)
        domains = [{'type': 'OpenStack', 'name': 'cloud-rtp-1-VMM'},
                   {'type': 'OpenStack', 'name': 'vm1'}]
        mappings = [{'type': 'OpenStack',
                     'host': '*',
                     'name': 'cloud-rtp-1-VMM'},
                    {'type': 'OpenStack',
                     'host': 'opflex-1',
                     'name': 'vm1'}]
        agents = ['opflex-1', 'opflex-1']
        net1, epg1 = self._external_net_test_setup(aim_ctx, domains,
                                                   mappings, agents)

        self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                              ('vm1', 'OpenStack')]),
                         set(self._doms(epg1.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(epg1.physical_domains,
                                        with_type=False)))

        with self.subnet(network={'network': net1}) as sub1:

            # "normal" port on opflex host
            with self.port(subnet=sub1) as p1:
                p1 = self._bind_port_to_host(p1['port']['id'], 'opflex-1')
                epg1 = self.aim_mgr.get(aim_ctx, epg1)
                self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                      ('vm1', 'OpenStack')]),
                                 set(self._doms(epg1.vmm_domains)))
                self.assertEqual(set([]),
                                 set(self._doms(epg1.physical_domains,
                                                with_type=False)))
                with self.port(subnet=sub1) as p2:
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind the port - should still have both, since
                    # we don't know that we can delete the wildcard entry
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    p2 = self._bind_port_to_host(p2['port']['id'], 'opflex-2')
                    p1 = self._bind_port_to_host(p1['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))
                    # unbind port 1 -- should remove all domains, as
                    # there aren't any ports left in the EPG
                    p2 = self._bind_port_to_host(p2['port']['id'], None)
                    epg1 = self.aim_mgr.get(aim_ctx, epg1)
                    self.assertEqual(set([('cloud-rtp-1-VMM', 'OpenStack'),
                                          ('vm1', 'OpenStack')]),
                                     set(self._doms(epg1.vmm_domains)))
                    self.assertEqual(set([]),
                                     set(self._doms(epg1.physical_domains,
                                                    with_type=False)))


class TestPortOnPhysicalNodeSingleDriver(TestPortOnPhysicalNode):
    # Tests for binding port on physical node where no other ML2 mechanism
    # driver fulfills port binding.

    def setUp(self, service_plugins=None):
        super(TestPortOnPhysicalNodeSingleDriver, self).setUp(
            mechanism_drivers=['logger', 'apic_aim'])
        self.expected_binding_info = [('apic_aim', 'opflex'),
                                      ('apic_aim', 'vlan')]
