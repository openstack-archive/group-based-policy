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

from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

import copy
import hashlib
import mock
import netaddr

from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim.api import status as aim_status
from aim import context as aim_context
from keystoneclient.v3 import client as ksc_client
from netaddr import IPSet
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.callbacks import registry
from neutron.common import utils as n_utils
from neutron import context as nctx
from neutron.db import api as db_api
from neutron.db.models import securitygroup as sg_models
from neutron.extensions import dns
from neutron import manager
from neutron.notifiers import nova
from neutron.plugins.common import constants as service_constants
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants as n_constants
from opflexagent import constants as ocst
from oslo_config import cfg
from oslo_utils import uuidutils
import webob.exc

from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy.common import utils
from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_mapping as aimd)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.services.grouppolicy.drivers import nsp_manager
from gbpservice.neutron.tests.unit.plugins.ml2plus import (
    test_apic_aim as test_aim_md)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_neutron_resources_driver as test_nr_base)


ML2PLUS_PLUGIN = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'
DEFAULT_FILTER_ENTRY = {'arp_opcode': u'unspecified',
                        'dest_from_port': u'unspecified',
                        'dest_to_port': u'unspecified',
                        'ether_type': u'unspecified',
                        'fragment_only': False,
                        'icmpv4_type': u'unspecified',
                        'icmpv6_type': u'unspecified',
                        'ip_protocol': u'unspecified',
                        'source_from_port': u'unspecified',
                        'source_to_port': u'unspecified',
                        'stateful': False,
                        'tcp_flags': u'unspecified'}
AGENT_TYPE = ocst.AGENT_TYPE_OPFLEX_OVS
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'opflex_networks': None,
                                 'bridge_mappings': {'physnet1': 'br-eth1'}}}
AGENT_TYPE_DVS = md.AGENT_TYPE_DVS
AGENT_CONF_DVS = {'alive': True, 'binary': 'somebinary',
                  'topic': 'sometopic', 'agent_type': AGENT_TYPE_DVS,
                  'configurations': {'opflex_networks': None}}

BOOKED_PORT_VALUE = 'myBookedPort'


AP = cisco_apic.AP
BD = cisco_apic.BD
DN = cisco_apic.DIST_NAMES
EPG = cisco_apic.EPG
EXTERNAL_NETWORK = cisco_apic.EXTERNAL_NETWORK
SNAT_HOST_POOL = cisco_apic.SNAT_HOST_POOL
VRF = cisco_apic.VRF
CIDR = 'apic:external_cidrs'
PROV = 'apic:external_provided_contracts'
CONS = 'apic:external_consumed_contracts'


def aim_object_to_dict(obj):
    result = {}
    for key, value in obj.__dict__.items():
        if key in obj.user_attributes():
            result[key] = value
    return result


class AIMBaseTestCase(test_nr_base.CommonNeutronBaseTestCase,
                      test_ext_base.ExtensionDriverTestBase,
                      test_aim_md.ApicAimTestMixin,
                      test_address_scope.AddressScopeTestCase):
    _extension_drivers = ['aim_extension', 'apic_segmentation_label',
                          'apic_allowed_vm_name']
    _extension_path = None

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              l3_plugin=None, sc_plugin=None, trunk_plugin=None, **kwargs):
        core_plugin = core_plugin or ML2PLUS_PLUGIN
        if not l3_plugin:
            l3_plugin = "apic_aim_l3"
        # The dummy driver configured here is meant to be the second driver
        # invoked and helps in rollback testing. We mock the dummy driver
        # methods to raise an exception and validate that DB operations
        # performed up until that point (including those in the aim_mapping)
        # driver are rolled back.
        policy_drivers = policy_drivers or ['aim_mapping', 'dummy']
        if not cfg.CONF.group_policy.extension_drivers:
            config.cfg.CONF.set_override(
                'extension_drivers', self._extension_drivers,
                group='group_policy')
        if self._extension_path:
            config.cfg.CONF.set_override(
                'api_extensions_path', self._extension_path)
        self.agent_conf = AGENT_CONF
        ml2_opts = ml2_options or {'mechanism_drivers': ['logger', 'apic_aim'],
                                   'extension_drivers': ['apic_aim',
                                                         'port_security',
                                                         'dns'],
                                   'type_drivers': ['opflex', 'local', 'vlan'],
                                   'tenant_network_types': ['opflex']}
        amap.ApicMappingDriver.get_apic_manager = mock.Mock()
        self._default_es_name = 'default'
        self.useFixture(test_aim_md.AimSqlFixture())
        super(AIMBaseTestCase, self).setUp(
            policy_drivers=policy_drivers, core_plugin=core_plugin,
            ml2_options=ml2_opts, l3_plugin=l3_plugin,
            sc_plugin=sc_plugin, trunk_plugin=trunk_plugin)
        self.db_session = db_api.get_session()
        self.initialize_db_config(self.db_session)
        self.l3_plugin = manager.NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')
        cfg.CONF.set_override(
            'default_external_segment_name', self._default_es_name,
            group='group_policy_implicit_policy')

        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = test_aim_md.FakeKeystoneClient

        self.first_tenant_id = test_plugin.TEST_TENANT_ID
        self._tenant_id = self.first_tenant_id
        self._neutron_context = nctx.Context(
            '', kwargs.get('tenant_id', self._tenant_id),
            is_admin=False)
        self._neutron_context._session = self.db_session
        self._neutron_admin_context = nctx.get_admin_context()

        self._aim_mgr = None
        self._aim_context = aim_context.AimContext(
            self._neutron_context.session)
        self._dummy = None
        self._name_mapper = None
        self._driver = None
        nova_client = mock.patch(
            'gbpservice.neutron.services.grouppolicy.drivers.cisco.'
            'apic.nova_client.NovaClient.get_server').start()
        vm = mock.Mock()
        vm.name = 'someid'
        nova_client.return_value = vm

        self.extension_attributes = ('router:external', DN, 'apic:svi',
                                     'apic:nat_type', 'apic:snat_host_pool',
                                     CIDR, PROV, CONS)
        # REVISIT: Note that the aim_driver sets create_auto_ptg to
        # True by default, hence this feature is always ON by default.
        # However, as a better unit testing strategy, we turn this OFF
        # for the base case, and turn it ON for select set of tests
        # which test in addition to what has been already tested in the
        # base case. It can be evaluated in the future if the base
        # testing strategy itself should evolve to always test with
        # the feature turned ON.
        self.driver.create_auto_ptg = False
        self._t1_aname = self.name_mapper.project(None, 't1')
        self._dn_t1_l1_n1 = ('uni/tn-%s/out-l1/instP-n1' % self._t1_aname)
        self._mock_aim_obj_eq_operator()

    def tearDown(self):
        ksc_client.Client = self.saved_keystone_client
        # We need to do the following to avoid non-aim tests
        # picking up the patched version of the method in patch_neutron
        registry._get_callback_manager()._notify_loop = (
            patch_neutron.original_notify_loop)
        super(AIMBaseTestCase, self).tearDown()

    def _setup_external_network(self, name, dn=None, router_tenant=None):
        DN = 'apic:distinguished_names'
        kwargs = {'router:external': True}
        if dn:
            kwargs[DN] = {'ExternalNetwork': dn}
        extn_attr = ('router:external', DN,
                     'apic:nat_type', 'apic:snat_host_pool')

        net = self._make_network(self.fmt, name, True,
                                 arg_list=extn_attr,
                                 **kwargs)['network']
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '100.100.0.1',
            '100.100.0.0/16')['subnet']
        router = self._make_router(
            self.fmt, router_tenant or net['tenant_id'], 'router1',
            external_gateway_info={'network_id': net['id']})['router']
        return net, router, subnet

    def _bind_port_to_host(self, port_id, host):
        data = {'port': {'binding:host_id': host,
                         'device_owner': 'compute:',
                         'device_id': 'someid'}}
        return super(AIMBaseTestCase, self)._bind_port_to_host(
            port_id, host, data=data)

    def _bind_other_port_to_host(self, port_id, host,
                                 owner=n_constants.DEVICE_OWNER_DHCP):
        data = {'port': {'binding:host_id': host,
                         'device_owner': owner,
                         'device_id': 'someid'}}
        return super(AIMBaseTestCase, self)._bind_port_to_host(
            port_id, host, data=data)

    def _make_address_scope_for_vrf(self, vrf_dn, ip_version=4,
                                    expected_status=None, **kwargs):
        attrs = {'ip_version': ip_version}
        if vrf_dn:
            attrs[DN] = {'VRF': vrf_dn}
        attrs.update(kwargs)

        req = self.new_create_request('address-scopes',
                                      {'address_scope': attrs}, self.fmt)
        neutron_context = nctx.Context('', kwargs.get('tenant_id',
                                                      self._tenant_id))
        req.environ['neutron.context'] = neutron_context

        res = req.get_response(self.ext_api)
        if expected_status:
            self.assertEqual(expected_status, res.status_int)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    @property
    def driver(self):
        # aim_mapping policy driver reference
        if not self._driver:
            self._driver = (
                self._gbp_plugin.policy_driver_manager.policy_drivers[
                    'aim_mapping'].obj)
        return self._driver

    @property
    def dummy(self):
        # dummy policy driver reference
        if not self._dummy:
            self._dummy = (
                self._gbp_plugin.policy_driver_manager.policy_drivers[
                    'dummy'].obj)
        return self._dummy

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

    def _switch_to_tenant1(self):
        self._tenant_id = self.first_tenant_id
        self._neutron_context.tenant = self._tenant_id

    def _switch_to_tenant2(self):
        self._tenant_id = 'test_tenant-2'
        self._neutron_context.tenant = self._tenant_id

    def _show_subnet(self, id):
        req = self.new_show_request('subnets', id, fmt=self.fmt)
        return self.deserialize(self.fmt,
                                req.get_response(self.api))['subnet']

    def _show_port(self, id):
        req = self.new_show_request('ports', id, fmt=self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))['port']

    def _show_network(self, id):
        req = self.new_show_request('networks', id, fmt=self.fmt)
        return self.deserialize(self.fmt,
                                req.get_response(self.api))['network']

    def _show_subnetpool(self, id):
        req = self.new_show_request('subnetpools', id, fmt=self.fmt)
        return self.deserialize(self.fmt,
                                req.get_response(self.api))['subnetpool']

    def _test_aim_resource_status(self, aim_resource_obj, gbp_resource):
        aim_status = self.aim_mgr.get_status(
            self._aim_context, aim_resource_obj)
        if aim_status.is_error():
            self.assertEqual(gp_const.STATUS_ERROR, gbp_resource['status'])
        elif aim_status.is_build():
            self.assertEqual(gp_const.STATUS_BUILD, gbp_resource['status'])
        else:
            self.assertEqual(gp_const.STATUS_ACTIVE, gbp_resource['status'])

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

    def _validate_status(self, show_method, resource_id):
        # This validation is used in the case where GBP resource status is
        # derived from Neutron and AIM resources which it maps to. In this
        # test we manipulate the state of AIM resources to test that the
        # different status states are correctly reflected in the L2P.
        AIM_STATUS = aim_status.AciStatus.SYNC_PENDING

        def mock_get_aim_status(aim_context, aim_resource,
                                create_if_absent=True):
            astatus = aim_status.AciStatus(resource_root=aim_resource.root)
            astatus.sync_status = AIM_STATUS
            return astatus

        orig_get_status = self.aim_mgr.get_status

        res = getattr(self, show_method)(resource_id, expected_res_status=200)[
            show_method[5:]]
        self.assertEqual(gp_const.STATUS_BUILD, res['status'])
        AIM_STATUS = aim_status.AciStatus.SYNCED
        # Temporarily patch aim_mgr.get_status to set status from test
        self.aim_mgr.get_status = mock_get_aim_status
        res = getattr(self, show_method)(resource_id, expected_res_status=200)[
            show_method[5:]]
        self.assertEqual(gp_const.STATUS_ACTIVE, res['status'])
        AIM_STATUS = aim_status.AciStatus.SYNC_FAILED
        res = getattr(self, show_method)(resource_id, expected_res_status=200)[
            show_method[5:]]
        self.assertEqual(gp_const.STATUS_ERROR, res['status'])
        # Restore aim_mgr.get_status
        self.aim_mgr.get_status = orig_get_status

    def _validate_implicit_contracts_created(self, l3p_id, l2p=None):
        aim_tenant_name = md.COMMON_TENANT_NAME
        if l2p:
            net = self._plugin.get_network(self._context, l2p['network_id'])
            default_epg_dn = net['apic:distinguished_names']['EndpointGroup']
            default_epg = self.aim_mgr.get(self._aim_context,
                                           aim_resource.EndpointGroup.from_dn(
                                               default_epg_dn))
            default_epg_provided_contract_names = (
                default_epg.provided_contract_names[:])
            for acontract in default_epg_provided_contract_names:
                if not acontract.endswith(l3p_id):
                    default_epg_provided_contract_names.remove(acontract)
            self.assertEqual(2, len(default_epg_provided_contract_names))

            default_epg_consumed_contract_names = (
                default_epg.consumed_contract_names[:])
            for acontract in default_epg_consumed_contract_names:
                if not acontract.endswith(l3p_id):
                    default_epg_consumed_contract_names.remove(acontract)
            self.assertEqual(1, len(default_epg_consumed_contract_names))

        contracts = [alib.SERVICE_PREFIX, alib.IMPLICIT_PREFIX]

        for contract_name_prefix in contracts:
            contract_name = str(self.name_mapper.l3_policy(
                self._neutron_context.session, l3p_id,
                prefix=contract_name_prefix))
            aim_contracts = self.aim_mgr.find(
                self._aim_context, aim_resource.Contract, name=contract_name)
            for acontract in aim_contracts[:]:
                # Remove contracts created by MD or created for other tenants
                if not acontract.name.endswith(l3p_id):
                    aim_contracts.remove(acontract)
            self.assertEqual(1, len(aim_contracts))
            if l2p:
                self.assertTrue(contract_name in
                                default_epg.provided_contract_names)

            aim_contract_subjects = self.aim_mgr.find(
                self._aim_context, aim_resource.ContractSubject,
                name=contract_name)
            for acontractsub in aim_contract_subjects[:]:
                # Remove contract_subjects created by MD or created
                # for other tenants
                if not acontractsub.name.endswith(l3p_id):
                    aim_contract_subjects.remove(acontractsub)
            self.assertEqual(1, len(aim_contract_subjects))
            self.assertEqual(0, len(aim_contract_subjects[0].in_filters))
            self.assertEqual(0, len(aim_contract_subjects[0].out_filters))
            if contract_name_prefix == alib.SERVICE_PREFIX:
                self.assertEqual(11, len(aim_contract_subjects[0].bi_filters))
            else:
                self.assertEqual(1, len(aim_contract_subjects[0].bi_filters))
                if l2p:
                    self.assertTrue(contract_name in
                                    default_epg.consumed_contract_names)

        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter,
            tenant_name=aim_tenant_name)
        for afilter in aim_filters[:]:
            # Remove filters created by MD or created for other tenants
            if not afilter.name.endswith(l3p_id):
                aim_filters.remove(afilter)

        self.assertEqual(12, len(aim_filters))

        aim_filter_entries = self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry,
            tenant_name=aim_tenant_name)
        for afilterentry in aim_filter_entries[:]:
            # Remove filter_entries created by MD or created for other tenants
            if not afilterentry.filter_name.endswith(l3p_id):
                aim_filter_entries.remove(afilterentry)

        self.assertEqual(12, len(aim_filter_entries))

        entries_attrs = alib.get_service_contract_filter_entries().values()
        entries_attrs.extend(alib.get_arp_filter_entry().values())
        expected_entries_attrs = []
        for entry in entries_attrs:
            new_entry = copy.deepcopy(DEFAULT_FILTER_ENTRY)
            new_entry.update(alib.map_to_aim_filter_entry(entry))
            expected_entries_attrs.append(
                {k: unicode(new_entry[k]) for k in new_entry})
        entries_attrs = [aim_object_to_dict(x) for x in aim_filter_entries]
        observed_entries_attrs = []
        for entry in entries_attrs:
            observed_entries_attrs.append(
                {k: unicode(entry[k]) for k in entry if k not in [
                    'name', 'display_name', 'filter_name', 'tenant_name',
                    'monitored']})
        self.assertItemsEqual(expected_entries_attrs, observed_entries_attrs)

    def _validate_implicit_contracts_exist(self, l3p_id):
        self._validate_implicit_contracts_created(l3p_id)

    def _validate_implicit_contracts_deleted(self, l3p_id):
        aim_tenant_name = md.COMMON_TENANT_NAME
        contracts = [alib.SERVICE_PREFIX, alib.IMPLICIT_PREFIX]

        for contract_name_prefix in contracts:
            contract_name = str(self.name_mapper.l3_policy(
                self._neutron_context.session, l3p_id,
                prefix=contract_name_prefix))
            aim_contracts = self.aim_mgr.find(
                self._aim_context, aim_resource.Contract, name=contract_name)
            for acontract in aim_contracts[:]:
                # Remove contracts created by MD or created for other tenants
                if not acontract.name.endswith(l3p_id):
                    aim_contracts.remove(acontract)
            self.assertEqual(0, len(aim_contracts))
            aim_contract_subjects = self.aim_mgr.find(
                self._aim_context, aim_resource.ContractSubject,
                name=contract_name)
            for acontractsub in aim_contract_subjects[:]:
                # Remove contract_subjects created by MD or created
                # for other tenants
                if not acontractsub.name.endswith(l3p_id):
                    aim_contract_subjects.remove(acontractsub)
            self.assertEqual(0, len(aim_contract_subjects))

        aim_filter_entries = self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry,
            tenant_name=aim_tenant_name)
        for afilterentry in aim_filter_entries[:]:
            # Remove filter_entries created by MD or created for other tenants
            if not afilterentry.filter_name.endswith(l3p_id):
                aim_filter_entries.remove(afilterentry)
        self.assertEqual(0, len(aim_filter_entries))

        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter,
            tenant_name=aim_tenant_name)
        for afilter in aim_filters[:]:
            # Remove filters created by MD or created for other tenants
            if not afilter.name.endswith(l3p_id):
                aim_filters.remove(afilter)

        self.assertEqual(0, len(aim_filters))

    def _extend_subnet_prefixes(self, prefixes, l3p, subnetpools_version):
        if subnetpools_version:
            for spool_id in l3p[subnetpools_version]:
                prefixes.extend(self._show_subnetpool(spool_id)['prefixes'])

    # TODO(tbachman): change isomorphic default to False, once
    #                 non-isomorphic VRFs are supported
    def _validate_create_l3_policy(self, l3p, subnetpool_prefixes=None,
                                   compare_subnetpool_shared_attr=True,
                                   isomorphic=True):
        # subnetpool_prefixes should be set only when the l3p has only
        # one subnetpool configured; if not, the default None value should
        # be used and the subnetpools should be validated in the calling test
        # function.
        # compare_subnetpool_shared_attr is set to False in the case explicit
        # unshared subnetpool is created on shared address_scope.
        prefixes_list = []
        ascp_ids = []
        ip_versions = []
        subnetpools_versions = []
        ip_version = l3p['ip_version']
        if ip_version == 4 or ip_version == 46:
            subnetpools_versions.append('subnetpools_v4')
            ascp_ids.append(l3p['address_scope_v4_id'])
            ip_versions.append(4)
        if ip_version == 6 or ip_version == 46:
            subnetpools_versions.append('subnetpools_v6')
            ascp_ids.append(l3p['address_scope_v6_id'])
            ip_versions.append(6)
        if subnetpool_prefixes:
            for version in subnetpools_versions:
                self._extend_subnet_prefixes(prefixes_list, l3p, version)
            self.assertItemsEqual(subnetpool_prefixes, prefixes_list)

        params = {'ids': ascp_ids}
        req = self.new_list_request('address-scopes',
                                    params=params, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        ascopes = res['address_scopes']
        for ascope in ascopes:
            self.assertIn(ascope['ip_version'], ip_versions)
            self.assertEqual(l3p['shared'], ascope['shared'])
        if len(ascopes) == 2 and isomorphic:
            self.assertEqual(ascopes[0][DN][VRF], ascopes[1][DN][VRF])
        self.assertEqual(gp_const.STATUS_BUILD, l3p['status'])
        self.assertIsNotNone(ascp_ids)
        routers = l3p['routers']
        self.assertIsNotNone(routers)
        self.assertEqual(len(routers), 1)
        router_id = routers[0]
        for version in subnetpools_versions:
            sp_id = l3p[version][0]
            subpool = self._show_subnetpool(sp_id)
            req = self.new_show_request('subnetpools', sp_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.api))
            subpool = res['subnetpool']
            self.assertIn(subpool['prefixes'][0], l3p['ip_pool'])
            self.assertIn(subpool['ip_version'], ip_versions)
            if compare_subnetpool_shared_attr:
                self.assertEqual(l3p['shared'], subpool['shared'])
        router = self._get_object('routers', router_id, self.ext_api)['router']
        self.assertEqual('l3p_l3p1', router['name'])
        self._validate_implicit_contracts_created(l3p['id'])
        # L3P's shared flag update is not supported for aim_mapping
        res = self.update_l3_policy(
            l3p['id'], shared=(not l3p['shared']),
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('SharedAttributeUpdateNotSupported',
                         res['NeutronError']['type'])

    def _validate_delete_l3_policy(self, l3p,
                                   explicit_address_scope=False,
                                   explicit_subnetpool=False,
                                   v4_default=False, v6_default=False):
        ascp_ids = []
        subnetpools_versions = []
        ip_version = l3p['ip_version']
        if ip_version == 4 or ip_version == 46:
            subnetpools_versions.append('subnetpools_v4')
            ascp_ids.append(l3p['address_scope_v4_id'])
        if ip_version == 6 or ip_version == 46:
            subnetpools_versions.append('subnetpools_v6')
            ascp_ids.append(l3p['address_scope_v6_id'])
        router_id = l3p['routers'][0]
        req = self.new_delete_request('l3_policies', l3p['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        for version in subnetpools_versions:
            sp_id = l3p[version][0]
            req = self.new_show_request('subnetpools', sp_id, fmt=self.fmt)
            res = req.get_response(self.api)
            if explicit_subnetpool or (
                   version == 'subnetpools_v4' and v4_default) or (
                   version == 'subnetpools_v6' and v6_default):
                self.assertEqual(webob.exc.HTTPOk.code, res.status_int)
            else:
                self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        params = {'ids': ascp_ids}
        req = self.new_list_request('address-scopes',
                                    params=params, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        if explicit_address_scope or v4_default or v6_default:
            self.assertEqual(webob.exc.HTTPOk.code, res.status_int)
        else:
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['address_scopes'], [])
        req = self.new_show_request('routers', router_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        self._validate_implicit_contracts_deleted(l3p['id'])
        # TODO(Sumit): Add test for implicit address_scope not deleted
        # when it has associated subnetpools

    def _get_provided_consumed_prs_lists(self, shared=False):
        prs_dict = {}
        prs_type = ['provided', 'consumed']
        for ptype in prs_type:
            rules = self._create_3_direction_rules(shared)
            prs = self.create_policy_rule_set(
                name="ctr", shared=shared,
                policy_rules=[x['id'] for x in rules])['policy_rule_set']
            prs_dict[ptype] = prs
        return prs_dict

    def _make_ext_subnet(self, network_name, cidr, tenant_id=None, dn=None,
                         nat_type=None, ext_cidrs=None, enable_dhcp=True,
                         shared_net=False):
        kwargs = {'router:external': True}
        if dn:
            kwargs[DN] = {'ExternalNetwork': dn}
        if nat_type is not None:
            kwargs['apic:nat_type'] = nat_type
        elif getattr(self, 'nat_type', None) is not None:
            kwargs['apic:nat_type'] = self.nat_type
        if ext_cidrs:
            kwargs[CIDR] = ext_cidrs
        if shared_net:
            kwargs['shared'] = True
        if tenant_id:
            kwargs['tenant_id'] = tenant_id

        net = self._make_network(self.fmt, network_name, True,
                                 arg_list=self.extension_attributes,
                                 **kwargs)['network']
        gw = str(netaddr.IPAddress(netaddr.IPNetwork(cidr).first + 1))
        subnet = self._make_subnet(
            self.fmt, {'network': net}, gw, cidr,
            enable_dhcp=enable_dhcp,
            tenant_id=(kwargs.get('tenant_id') or self._tenant_id))['subnet']
        return subnet

    def _router_gw(self, router):
        gw = router['external_gateway_info']
        return gw['network_id'] if gw else None

    def _show_all(self, resource_type, ids):
        resource_type_plural = resource_type + 's'  # Won't work always
        return [self._show(resource_type_plural, res_id)[resource_type]
                for res_id in ids]

    def _delete_prs_dicts_and_rules(self, prs_dicts):
        for prs in prs_dicts:
            prs_id = prs_dicts[prs]['id']
            rules = prs_dicts[prs]['policy_rules']
            self.delete_policy_rule_set(prs_id, expected_res_status=204)
            for rule in rules:
                self.delete_policy_rule(rule, expected_res_status=204)

    def _validate_contracts(self, ptg, aim_epg, prs_lists, l2p):
        l3p_id = l2p['l3_policy_id']
        implicit_contract_name = str(self.name_mapper.l3_policy(
            self._neutron_context.session, l3p_id,
            prefix=alib.IMPLICIT_PREFIX))
        service_contract_name = str(self.name_mapper.l3_policy(
            self._neutron_context.session, l3p_id,
            prefix=alib.SERVICE_PREFIX))
        l3p = self.show_l3_policy(l3p_id, expected_res_status=200)
        router_id = l3p['l3_policy']['routers'][0]
        router_contract_name = self.name_mapper.router(
            self._neutron_context.session, router_id)
        expected_prov_contract_names = []
        expected_cons_contract_names = []
        if ptg['id'].startswith(aimd.AUTO_PTG_PREFIX):
            expected_prov_contract_names = [implicit_contract_name,
                                            service_contract_name,
                                            router_contract_name]
            expected_cons_contract_names = [implicit_contract_name,
                                            router_contract_name]
        else:
            expected_prov_contract_names = [implicit_contract_name]
            expected_cons_contract_names = [implicit_contract_name,
                                            service_contract_name]
        if prs_lists['provided']:
            aim_prov_contract_name = str(self.name_mapper.policy_rule_set(
                self._neutron_context.session, prs_lists['provided']['id']))
            expected_prov_contract_names.append(aim_prov_contract_name)

        self.assertItemsEqual(expected_prov_contract_names,
                              aim_epg.provided_contract_names)

        if prs_lists['consumed']:
            aim_cons_contract_name = str(self.name_mapper.policy_rule_set(
                self._neutron_context.session, prs_lists['consumed']['id']))
            expected_cons_contract_names.append(aim_cons_contract_name)

        self.assertItemsEqual(expected_cons_contract_names,
                              aim_epg.consumed_contract_names)

    def _validate_router_interface_created(self, num_address_families=1):
        # check port is created on default router
        ports = self._plugin.get_ports(self._context)
        total_ports = total_subnets = num_address_families
        self.assertEqual(total_ports, len(ports))
        routers = self._l3_plugin.get_routers(self._context)
        self.assertEqual(1, len(routers))
        subnets = self._plugin.get_subnets(self._context)
        self.assertEqual(total_subnets, len(subnets))
        subnet_ids = [subnet['id'] for subnet in subnets]
        for port in ports:
            self.assertEqual('network:router_interface',
                             port['device_owner'])
            self.assertEqual(routers[0]['id'],
                             port['device_id'])
            self.assertEqual(1, len(port['fixed_ips']))
            self.assertIn(port['fixed_ips'][0]['subnet_id'], subnet_ids)

    def _test_policy_target_group_aim_mappings(self, ptg, prs_lists, l2p,
                                               num_address_families=1):
        self._validate_router_interface_created(
            num_address_families=num_address_families)

        ptg_id = ptg['id']
        if ptg['id'].startswith(aimd.AUTO_PTG_PREFIX):
            # the test policy.json restricts auto-ptg access to admin
            ptg_show = self.show_policy_target_group(
                ptg_id, is_admin_context=True,
                expected_res_status=200)['policy_target_group']
        else:
            ptg_show = self.show_policy_target_group(
                ptg_id, expected_res_status=200)['policy_target_group']
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg_id)
        aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
        aim_app_profile_name = self.driver.aim_mech_driver.ap_name
        aim_app_profiles = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        req = self.new_show_request('networks', l2p['network_id'],
                                    fmt=self.fmt)
        net = self.deserialize(self.fmt,
                               req.get_response(self.api))['network']
        bd = self.aim_mgr.get(
            self._aim_context, aim_resource.BridgeDomain.from_dn(
                net['apic:distinguished_names']['BridgeDomain']))
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)
        if not ptg['id'].startswith(aimd.AUTO_PTG_PREFIX):
            # display_name of default EPG should not be mutated
            # if the name of the auto-ptg is edited, but should
            # and this should be validated in the auto-ptg tests
            epg_display_name = ptg['name'].replace(' ', '_')
            self.assertEqual(epg_display_name, aim_epgs[0].display_name)
        self.assertEqual(bd.name, aim_epgs[0].bd_name)

        self._validate_contracts(ptg, aim_epgs[0], prs_lists, l2p)

        self.assertEqual(aim_epgs[0].dn,
                         ptg['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg)
        self.assertEqual(aim_epgs[0].dn,
                         ptg_show['apic:distinguished_names']['EndpointGroup'])
        self._test_aim_resource_status(aim_epgs[0], ptg_show)

    def _validate_l2_policy_deleted(self, l2p, implicit_l3p=True):
        l2p_id = l2p['id']
        l3p_id = l2p['l3_policy_id']
        network_id = l2p['network_id']
        self.delete_l2_policy(l2p_id, expected_res_status=204)
        self.show_l2_policy(l2p_id, expected_res_status=404)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        l2ps = self._gbp_plugin.get_l2_policies(
            self._neutron_context)
        if len(l2ps) == 0:
            apic_tenant_name = self.name_mapper.project(None, self._tenant_id)
            epgs = self.aim_mgr.find(
                self._aim_context, aim_resource.EndpointGroup,
                tenant_name=apic_tenant_name)
            self.assertEqual(0, len(epgs))
            if implicit_l3p:
                self.show_l3_policy(l3p_id, expected_res_status=404)
            else:
                self._validate_implicit_contracts_exist(l3p_id)

    def _get_nsp_ptg_fip_mapping(self, ptg_id):
        ctx = nctx.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            return (ctx.session.query(
                        nsp_manager.ServicePolicyPTGFipMapping).
                    filter_by(policy_target_group_id=ptg_id).
                    all())

    def _validate_contract_subject_filters(
        self, contract_subject, policy_rules):
        self.assertFalse(contract_subject.bi_filters)

        expected_in_filters = []
        expected_out_filters = []

        for idx in range(0, len(policy_rules)):
            pc = self.show_policy_classifier(
                policy_rules[idx]['policy_classifier_id'])['policy_classifier']
            fwd_filter = self.name_mapper.policy_rule(None,
                                                      policy_rules[idx]['id'])
            protocol = pc['protocol']
            if protocol in alib.REVERSIBLE_PROTOCOLS:
                rev_filter = 'reverse-%s' % fwd_filter
            else:
                rev_filter = None

            direction = pc['direction']
            if direction == gp_const.GP_DIRECTION_IN:
                expected_in_filters.append(fwd_filter)
                if rev_filter:
                    expected_out_filters.append(rev_filter)
            elif direction == gp_const.GP_DIRECTION_OUT:
                expected_out_filters.append(fwd_filter)
                if rev_filter:
                    expected_in_filters.append(rev_filter)
            else:
                expected_in_filters.append(fwd_filter)
                expected_out_filters.append(fwd_filter)
                if rev_filter:
                    expected_in_filters.append(rev_filter)
                    expected_out_filters.append(rev_filter)

        self.assertItemsEqual(expected_in_filters,
                              contract_subject.in_filters)
        self.assertItemsEqual(expected_out_filters,
                              contract_subject.out_filters)

    def _validate_merged_status(self, contract, contract_subject, prs):
        merged_status = self.driver._merge_aim_status(
            self._neutron_context.session,
            [contract, contract_subject])
        self.assertEqual(merged_status, prs['status'])

    def _validate_policy_rule_set_aim_mapping(self, prs, rules):
        self.show_policy_rule_set(prs['id'], expected_res_status=200)
        aim_contract_name = str(self.name_mapper.policy_rule_set(
            self._neutron_context.session, prs['id']))
        aim_contracts = self.aim_mgr.find(
            self._aim_context, aim_resource.Contract, name=aim_contract_name)
        self.assertEqual(1, len(aim_contracts))
        self.assertEqual(prs['name'], aim_contracts[0].display_name)
        aim_contract_subjects = self.aim_mgr.find(
            self._aim_context, aim_resource.ContractSubject,
            name=aim_contract_name)
        self.assertEqual(1, len(aim_contract_subjects))
        self._validate_contract_subject_filters(
            aim_contract_subjects[0], rules)
        self._validate_merged_status(
            aim_contracts[0], aim_contract_subjects[0], prs)

    def _validate_policy_rule_deleted(self, prs):
        aim_contract_name = str(self.name_mapper.policy_rule_set(
            self._neutron_context.session, prs['id']))
        self.show_policy_rule_set(prs['id'], expected_res_status=404)
        aim_contracts = self.aim_mgr.find(
            self._aim_context, aim_resource.Contract, name=aim_contract_name)
        self.assertEqual(0, len(aim_contracts))

    def _check_ip_in_cidr(self, ip_addr, cidr):
        self.assertTrue(netaddr.IPAddress(ip_addr) in netaddr.IPNetwork(cidr))


class TestGBPStatus(AIMBaseTestCase):

    def test_status_merging(self):
        gbp_active = {'status': gp_const.STATUS_ACTIVE}
        gbp_objs = [gbp_active, gbp_active]
        mstatus = self.driver._merge_gbp_status(gbp_objs)
        self.assertEqual(gp_const.STATUS_ACTIVE, mstatus)

        gbp_build = {'status': gp_const.STATUS_BUILD}
        gbp_objs = [gbp_active, gbp_build]
        mstatus = self.driver._merge_gbp_status(gbp_objs)
        self.assertEqual(gp_const.STATUS_BUILD, mstatus)

        gbp_error = {'status': gp_const.STATUS_ERROR}
        gbp_objs = [gbp_active, gbp_build, gbp_error]
        mstatus = self.driver._merge_gbp_status(gbp_objs)
        self.assertEqual(gp_const.STATUS_ERROR, mstatus)


class TestAIMStatus(AIMBaseTestCase):

    def test_status_merging(self):

        def mock_get_aim_status(aim_context, aim_resource,
                                create_if_absent=True):
            astatus = aim_status.AciStatus(resource_root=aim_resource.root)
            if aim_resource.status == '':
                return
            elif aim_resource.status == 'build':
                astatus.sync_status = aim_status.AciStatus.SYNC_PENDING
            elif aim_resource.status == 'error':
                astatus.sync_status = aim_status.AciStatus.SYNC_FAILED
            else:
                astatus.sync_status = aim_status.AciStatus.SYNCED
            return astatus

        orig_get_status = self.aim_mgr.get_status
        self.aim_mgr.get_status = mock_get_aim_status

        aim_active = aim_resource.Tenant(name='active')
        aim_active.status = 'active'
        aim_objs_active = [aim_active, aim_active, aim_active]
        mstatus = self.driver._merge_aim_status(self._neutron_context.session,
                                                aim_objs_active)
        self.assertEqual(gp_const.STATUS_ACTIVE, mstatus)

        aim_build = aim_resource.Tenant(name='build')
        aim_build.status = 'build'
        aim_none = aim_resource.Tenant(name='none')
        aim_none.status = ''
        aim_objs_build = [aim_active, aim_active, aim_build]
        mstatus = self.driver._merge_aim_status(self._neutron_context.session,
                                                aim_objs_build)
        self.assertEqual(gp_const.STATUS_BUILD, mstatus)
        aim_objs_build = [aim_active, aim_active, aim_none]
        mstatus = self.driver._merge_aim_status(self._neutron_context.session,
                                                aim_objs_build)
        self.assertEqual(gp_const.STATUS_BUILD, mstatus)

        aim_error = aim_resource.Tenant(name='error')
        aim_error.status = 'error'
        aim_objs_error = [aim_active, aim_build, aim_error]
        mstatus = self.driver._merge_aim_status(self._neutron_context.session,
                                                aim_objs_error)
        self.assertEqual(gp_const.STATUS_ERROR, mstatus)

        self.aim_mgr.get_status = orig_get_status


class TestL3Policy(AIMBaseTestCase):

    def _test_update_l3_policy_subnetpool(
        self, l3p, prefixes, ip_version=4, implicit_pool=True, shared=False,
        tenant_id=None, subnet_prefix_length=24):
        if ip_version == 4 or ip_version == 46:
            subnetpools_version = 'subnetpools_v4'
            ascp_id = l3p['address_scope_v4_id']
        if ip_version == 6 or ip_version == 46:
            subnetpools_version = 'subnetpools_v6'
            ascp_id = l3p['address_scope_v6_id']
        implicit_subpool = []
        if implicit_pool:
            implicit_subpool = l3p['subnetpools_v4'] if ip_version == 4 else (
                l3p['subnetpools_v6'])

        if not tenant_id:
            tenant_id = self._tenant_id

        sp2 = self._make_subnetpool(
            self.fmt, prefixes, name='sp2', address_scope_id=ascp_id,
            tenant_id=tenant_id, shared=shared)['subnetpool']
        self.assertEqual(ascp_id, sp2['address_scope_id'])
        self.assertEqual(prefixes, sp2['prefixes'])
        implicit_ip_pool = l3p['ip_pool']
        implicit_subnet_prefix_length = l3p['subnet_prefix_length']
        # Preserve existing subnetpools including implicitly created subnetpool
        new_subnetpools = implicit_subpool + [sp2['id']]
        attrs = {'id': l3p['id'], subnetpools_version: new_subnetpools}
        l3p = self.update_l3_policy(**attrs)['l3_policy']
        prefixlist = [prefix.strip() for prefix in l3p['ip_pool'].split(',')]
        implicitlist = [prefix.strip()
                        for prefix in implicit_ip_pool.split(',')]
        for prefix in prefixlist:
            self.assertIn(prefix, prefixes + implicitlist)
        self.assertEqual(l3p['subnet_prefix_length'], subnet_prefix_length)
        self.assertItemsEqual(new_subnetpools, l3p[subnetpools_version])
        attrs = {'id': l3p['id'], subnetpools_version: implicit_subpool}
        l3p = self.update_l3_policy(**attrs)['l3_policy']
        self.assertEqual(implicit_ip_pool, l3p['ip_pool'])
        self.assertEqual(implicit_subnet_prefix_length,
                         l3p['subnet_prefix_length'])
        self.assertItemsEqual(implicit_subpool, l3p[subnetpools_version])
        req = self.new_delete_request('subnetpools', sp2['id'])
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)

    def _extend_ip_pool(self, ip_pool, prefixes):
        if ip_pool:
            return ','.join(ip_pool.split(',') + prefixes.split(','))
        else:
            return prefixes

    # TODO(tbachman): change isomorphic default to False, once
    #                 non-isomorphic VRFs are supported
    def _create_l3_policy_for_lifecycle_tests(
        self, explicit_address_scope=False, explicit_subnetpool=False,
        ip_version=4, ip_pool=None, subnet_prefix_length=24,
        tenant_id=None, shared=False, v4_default=False,
        v6_default=False, isomorphic=True,
        no_address_scopes=False):

        if not tenant_id:
            tenant_id = self._tenant_id

        attrs = {'name': 'l3p1', 'ip_version': ip_version, 'shared': shared,
                 'ip_pool': ip_pool,
                 'subnet_prefix_length': subnet_prefix_length}

        address_scope_v4 = address_scope_v6 = None
        if explicit_address_scope or v4_default or v6_default:
            if ip_version == 4 or ip_version == 46:
                address_scope_v4 = self._make_address_scope(
                    self.fmt, 4, name='as1v4',
                    shared=shared)['address_scope']
                if not v4_default:
                    attrs['address_scope_v4_id'] = address_scope_v4['id']
            if ip_version == 6 or ip_version == 46:
                if ((isomorphic and address_scope_v4) or
                        (v4_default and v6_default)):
                    address_scope_v6 = self._make_address_scope_for_vrf(
                        address_scope_v4[DN][VRF],
                        6, name='as1v6', shared=shared)['address_scope']
                    self.assertEqual(address_scope_v6[DN],
                        address_scope_v4[DN])
                else:
                    address_scope_v6 = self._make_address_scope(
                        self.fmt, 6, name='as1v6',
                        shared=shared)['address_scope']
                if not v6_default:
                    attrs['address_scope_v6_id'] = address_scope_v6['id']

        ip_pool_v4 = ip_pool_v6 = None
        if ip_version == 4 or ip_version == 46:
            if not ip_pool:
                ip_pool_v4 = '192.168.0.0/16'
                if explicit_subnetpool or v4_default:
                    sp = self._make_subnetpool(
                        self.fmt, [ip_pool_v4], name='sp1v4',
                        is_default=v4_default,
                        address_scope_id=address_scope_v4['id'],
                        tenant_id=tenant_id, shared=shared)['subnetpool']
                    if explicit_subnetpool:
                        attrs['subnetpools_v4'] = [sp['id']]
        if ip_version == 6 or ip_version == 46:
            if not ip_pool:
                ip_pool_v6 = 'fd6d:8d64:af0c::/64'
                if explicit_subnetpool or v6_default:
                    sp = self._make_subnetpool(
                        self.fmt, [ip_pool_v6], name='sp1v6',
                        is_default=v6_default,
                        address_scope_id=address_scope_v6['id'],
                        tenant_id=tenant_id, shared=shared)['subnetpool']
                    if explicit_subnetpool:
                        attrs['subnetpools_v6'] = [sp['id']]
        if ip_pool_v4 and not v4_default and not no_address_scopes:
            attrs['ip_pool'] = self._extend_ip_pool(attrs['ip_pool'],
                                                    ip_pool_v4)
        if ip_pool_v6 and not v6_default and not no_address_scopes:
            attrs['ip_pool'] = self._extend_ip_pool(attrs['ip_pool'],
                                                    ip_pool_v6)

        # Create L3 policy with implicit address_scope, subnetpool and router
        l3p = self.create_l3_policy(**attrs)['l3_policy']
        self._validate_create_l3_policy(l3p,
            utils.convert_ip_pool_string_to_list(l3p['ip_pool']),
            isomorphic=isomorphic)
        self._validate_status('show_l3_policy', l3p['id'])
        return l3p

    # TODO(tbachman): change isomorphic default to False, once
    #                 non-isomorphic VRFs are supported
    def _test_l3_policy_lifecycle(self, explicit_address_scope=False,
                                  explicit_subnetpool=False,
                                  ip_version=4, ip_pool=None,
                                  subnet_prefix_length=24, tenant_id=None,
                                  shared=False, v4_default=False,
                                  v6_default=False, isomorphic=True,
                                  no_address_scopes=False):
        l3p = self._create_l3_policy_for_lifecycle_tests(
            explicit_address_scope=explicit_address_scope,
            explicit_subnetpool=explicit_subnetpool, ip_version=ip_version,
            ip_pool=ip_pool, subnet_prefix_length=subnet_prefix_length,
            tenant_id=tenant_id, shared=shared,
            v4_default=v4_default,
            v6_default=v6_default,
            isomorphic=isomorphic,
            no_address_scopes=no_address_scopes)
        if not tenant_id:
            tenant_id = l3p['tenant_id']

        if ip_version == 4 or ip_version == 46:
            self._test_update_l3_policy_subnetpool(
                l3p, prefixes=['10.0.0.0/8'], ip_version=4, shared=shared,
                tenant_id=tenant_id)
        if ip_version == 6 or ip_version == 46:
            self._test_update_l3_policy_subnetpool(
                l3p, prefixes=['fd6d:8d64:af0c:1::/64'], ip_version=6,
                shared=shared, tenant_id=tenant_id)
        # TODO(Sumit): Test update of other relevant attributes

        self._validate_delete_l3_policy(
            l3p, explicit_address_scope=explicit_address_scope,
            explicit_subnetpool=explicit_subnetpool,
            v4_default=v4_default, v6_default=v6_default)

    def test_unshared_l3_policy_v4_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle()

    def test_shared_l3_policy_v4_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle(shared=True)

    def test_unshared_l3_policy_v6_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=6)

    def test_shared_l3_policy_v6_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=6, shared=True)

    def test_unshared_l3_policy_dual_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46)

    def test_unshared_l3_policy_dual_lifecycle_implicit_2_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46,
            v4_default=True, v6_default=True)

    def test_unshared_l3_policy_dual_lifecycle_implicit_3_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, v4_default=True)

    def test_unshared_l3_policy_dual_lifecycle_implicit_4_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, v6_default=True)

    def test_shared_l3_policy_dual_lifecycle_implicit_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, shared=True)

    def test_shared_l3_policy_dual_lifecycle_implicit_2_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, shared=True,
                                       v4_default=True, v6_default=True)

    def test_shared_l3_policy_dual_lifecycle_implicit_3_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, shared=True,
                                       v4_default=True)

    def test_shared_l3_policy_dual_lifecycle_implicit_4_address_scope(self):
        self._test_l3_policy_lifecycle(ip_version=46, shared=True,
                                       v6_default=True)

    def test_unshared_l3_policy_lifecycle_explicit_address_scope_v4(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True)

    def test_shared_l3_policy_lifecycle_explicit_address_scope_v4(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
                                       shared=True)

    def test_unshared_l3_policy_lifecycle_explicit_address_scope_v6(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=6)

    def test_shared_l3_policy_lifecycle_explicit_address_scope_v6(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=6, shared=True)

    def test_unshared_l3_policy_lifecycle_explicit_address_scope_dual(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=46)

    def test_unshared_l3_policy_lifecycle_explicit_address_scope_iso(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=46, isomorphic=True)

    def test_shared_l3_policy_lifecycle_explicit_address_scope_dual(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=46, shared=True)

    def test_shared_l3_policy_lifecycle_explicit_address_scope_iso(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
            ip_version=46, shared=True, isomorphic=True)

    def test_unshared_create_l3_policy_explicit_subnetpool_v4(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
                                       explicit_subnetpool=True)

    def test_shared_create_l3_policy_explicit_subnetpool_v4(self):
        self._test_l3_policy_lifecycle(explicit_address_scope=True,
                                       explicit_subnetpool=True, shared=True)

    def test_unshared_create_l3_policy_explicit_subnetpool_v6(self):
        self._test_l3_policy_lifecycle(
            explicit_address_scope=True, explicit_subnetpool=True,
            ip_version=6)

    def test_shared_create_l3_policy_explicit_subnetpool_v6(self):
        self._test_l3_policy_lifecycle(
            explicit_address_scope=True, explicit_subnetpool=True,
            ip_version=6, shared=True)

    def test_unshared_create_l3_policy_explicit_subnetpool_dual(self):
        self._test_l3_policy_lifecycle(
            explicit_address_scope=True, explicit_subnetpool=True,
            ip_version=46, ip_pool=None)

    def test_shared_create_l3_policy_explicit_subnetpool_dual(self):
        self._test_l3_policy_lifecycle(
            explicit_address_scope=True, explicit_subnetpool=True,
            ip_version=46, shared=True)

    def test_unshared_l3_policy_lifecycle_no_address_scope(self):
        self.assertRaises(webob.exc.HTTPClientError,
                          self._test_l3_policy_lifecycle,
                          no_address_scopes=True)

    def test_unshared_l3_policy_lifecycle_no_address_scope(self):
        with self.address_scope(ip_version=4, shared=True) as ascpv4:
            ascpv4 = ascpv4['address_scope']
            with self.address_scope(ip_version=6, shared=True) as ascpv6:
                ascpv6 = ascpv6['address_scope']
                self.assertRaises(webob.exc.HTTPClientError,
                                  self.create_l3_policy,
                                  ip_version=46,
                                  address_scope_v4_id=ascpv4['id'],
                                  address_scope_v6_id=ascpv6['id'])

    def test_create_l3p_shared_addr_scp_explicit_unshared_subnetpools(self):
        with self.address_scope(ip_version=4, shared=True) as ascpv4:
            ascpv4 = ascpv4['address_scope']
            with self.subnetpool(
                name='sp1v4', prefixes=['192.168.0.0/16'],
                tenant_id=ascpv4['tenant_id'], default_prefixlen=24,
                address_scope_id=ascpv4['id'], shared=False) as sp1v4:
                sp1v4 = sp1v4['subnetpool']
                # As admin, create a subnetpool in a different tenant
                # but associated with the same address_scope
                sp2v4 = self._make_subnetpool(
                    self.fmt, ['10.1.0.0/16'], name='sp2v4',
                    tenant_id='test-tenant-2', address_scope_id=ascpv4['id'],
                    default_prefixlen=24, shared=False,
                    admin=True)['subnetpool']
                l3p = self.create_l3_policy(
                    name="l3p1", subnetpools_v4=[sp1v4['id'], sp2v4['id']]
                )['l3_policy']
                self.assertEqual(ascpv4['id'], sp1v4['address_scope_id'])
                self.assertEqual(ascpv4['id'], l3p['address_scope_v4_id'])
                for prefix in sp1v4['prefixes'] + sp2v4['prefixes']:
                    self.assertIn(prefix, l3p['ip_pool'])
                self.assertEqual(24, l3p['subnet_prefix_length'])
                self._validate_create_l3_policy(
                    l3p, compare_subnetpool_shared_attr=False)
                self.assertEqual(2, len(l3p['subnetpools_v4']))
                sp3v4 = self._make_subnetpool(
                    self.fmt, ['10.2.0.0/16'], name='sp3v4',
                    tenant_id='test-tenant-3', address_scope_id=ascpv4['id'],
                    default_prefixlen=24, shared=False,
                    admin=True)['subnetpool']
                l3p = self.update_l3_policy(
                    l3p['id'],
                    subnetpools_v4=[sp1v4['id'], sp2v4['id'], sp3v4['id']])[
                        'l3_policy']
                self.assertEqual(3, len(l3p['subnetpools_v4']))
                self._validate_create_l3_policy(
                    l3p, compare_subnetpool_shared_attr=False)
                self._validate_delete_l3_policy(
                    l3p, explicit_address_scope=True, explicit_subnetpool=True)

    def _test_update_l3_policy_replace_implicit_subnetpool(
        self, in_use=False, shared=False):
        if in_use:
            # We will create a L2P with auto-ptg so that a subnet
            # is created that is associated with the implcit
            # subnetpool of the l3p
            self.driver.create_auto_ptg = True

        l3p = self._create_l3_policy_for_lifecycle_tests(shared=shared)
        ascp_id = l3p['address_scope_v4_id']
        implicit_ip_pool = l3p['ip_pool']
        implicit_subnet_prefix_length = l3p['subnet_prefix_length']
        implicit_subpool_id = l3p['subnetpools_v4'][0]

        # if address_scope is shared, use a different tenant for subnetpool
        # to simulate cross-tenant scenario
        sp_tenant_id = 'test-tenant-2' if shared else self._tenant_id
        new_prefixes = ['10.0.0.0/16']
        # if address_scope is shared, subnetpool is created in a different
        # tenant, so use admin role
        sp2 = self._make_subnetpool(
            self.fmt, new_prefixes, name='sp2', address_scope_id=ascp_id,
            tenant_id=sp_tenant_id, admin=shared)['subnetpool']
        self.assertEqual(ascp_id, sp2['address_scope_id'])
        self.assertEqual(new_prefixes, sp2['prefixes'])

        attrs = {'id': l3p['id'], 'subnetpools_v4': [sp2['id']]}
        if in_use:
            # Add an L2 Policy to the L3 Policy, with create_auto_ptg = True,
            # which will create a PTG for the L2P
            l2p = self.create_l2_policy(name="l2p0",
                                        l3_policy_id=l3p['id'])['l2_policy']
            attrs['expected_res_status'] = webob.exc.HTTPBadRequest.code
            # Try replacing the existing prefix/subnetpool with the one
            # created above -- it should fail
            self.update_l3_policy(**attrs)
            # Remove the L2 policy, so that we can now replace the
            # subnetpool
            self.delete_l2_policy(l2p['id'], expected_res_status=204)
            attrs['expected_res_status'] = webob.exc.HTTPOk.code

        l3p = self.update_l3_policy(**attrs)['l3_policy']

        self.assertEqual(sp2['id'], l3p['subnetpools_v4'][0])
        for prefix in sp2['prefixes']:
            self.assertIn(prefix, l3p['ip_pool'])
        self.assertNotEqual(implicit_ip_pool, l3p['ip_pool'])

        if implicit_subnet_prefix_length:
            self.assertEqual(implicit_subnet_prefix_length,
                             l3p['subnet_prefix_length'])

        # implicit subnetpool is deleted
        req = self.new_show_request('subnetpools', implicit_subpool_id,
                                    fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Reset in case it was set earlier
        self.driver.create_auto_ptg = False

    def test_update_unshared_l3_policy_replace_implicit_subnetpool(self):
        self._test_update_l3_policy_replace_implicit_subnetpool()

    def test_update_shared_l3_policy_replace_implicit_subnetpool(self):
        self._test_update_l3_policy_replace_implicit_subnetpool(shared=True)

    def test_update_shared_l3_policy_replace_in_use_implicit_subnetpool(self):
        self._test_update_l3_policy_replace_implicit_subnetpool(in_use=True,
                                                                shared=True)

    def _check_routers_connections(self, l3p, ext_nets, eps, subnets):
        routers = self._show_all('router', l3p['routers'])
        routers = [r for r in routers if self._router_gw(r)]

        self.assertEqual(len(ext_nets), len(routers))
        self.assertEqual(sorted(ext_nets),
                         sorted([self._router_gw(r) for r in routers]))
        session = self._neutron_context.session
        for ext_net, ep in zip(ext_nets, eps):
            router = [r for r in routers if self._router_gw(r) == ext_net]
            prov = sorted([str(self.name_mapper.policy_rule_set(session, c))
                           for c in ep['provided_policy_rule_sets']])
            cons = sorted([str(self.name_mapper.policy_rule_set(session, c))
                           for c in ep['consumed_policy_rule_sets']])
            self.assertEqual(prov, sorted(router[0][PROV]))
            self.assertEqual(cons, sorted(router[0][CONS]))

        subnets = sorted(subnets)
        for router in routers:
            intf_ports = self._list('ports',
               query_params=('device_id=' + router['id'] +
                             '&device_owner=network:router_interface')
            )['ports']
            intf_subnets = sorted([p['fixed_ips'][0]['subnet_id']
                                   for p in intf_ports if p['fixed_ips']])
            self.assertEqual(subnets, intf_subnets,
                             'Router %s' % router['name'])

    def test_external_segment_routers(self):
        ess = []
        eps = []
        ext_nets = []
        for x in range(0, 2):
            es_sub = self._make_ext_subnet('net%d' % x, '90.9%d.0.0/16' % x,
                dn='uni/tn-t1/out-l%d/instP-n%x' % (x, x))
            es = self.create_external_segment(
                name='seg%d' % x, subnet_id=es_sub['id'],
                external_routes=[{'destination': '12%d.0.0.0/24' % (8 + x),
                                  'nexthop': None}])['external_segment']
            ess.append(es)
            prs1 = self.create_policy_rule_set(name='prs1')['policy_rule_set']
            prs2 = self.create_policy_rule_set(name='prs2')['policy_rule_set']
            ep = self.create_external_policy(
                name='ep%d' % x,
                provided_policy_rule_sets={prs1['id']: 'scope'},
                consumed_policy_rule_sets={prs2['id']: 'scope'},
                external_segments=[es['id']])['external_policy']
            eps.append(ep)
            ext_nets.append(es_sub['network_id'])

        es_dict = {es['id']: [] for es in ess}
        l3p = self.create_l3_policy(name='l3p1',
            external_segments=es_dict)['l3_policy']
        self._check_routers_connections(l3p, ext_nets, eps, [])

        es_dict.pop(ess[0]['id'])
        l3p = self.update_l3_policy(l3p['id'],
                                    external_segments=es_dict)['l3_policy']
        self._check_routers_connections(l3p, ext_nets[1:], eps[1:], [])

        es_dict = {ess[0]['id']: ['']}
        l3p = self.update_l3_policy(l3p['id'],
                                    external_segments=es_dict)['l3_policy']
        self._check_routers_connections(l3p, ext_nets[0:1], eps[0:1], [])

        self.delete_l3_policy(l3p['id'])
        for r in l3p['routers']:
            self._show('routers', r, expected_code=404)

    def test_external_segment_l2p_subnets(self):
        ess = []
        ext_nets = []
        for x in range(0, 2):
            es_sub = self._make_ext_subnet('net%d' % x, '90.9%d.0.0/16' % x,
                dn='uni/tn-t1/out-l%d/instP-n%x' % (x, x))
            es = self.create_external_segment(
                name='seg%d' % x, subnet_id=es_sub['id'],
                external_routes=[{'destination': '12%d.0.0.0/24' % (8 + x),
                                  'nexthop': None}])['external_segment']
            ess.append(es)
            ext_nets.append(es_sub['network_id'])

        l3p = self.create_l3_policy(name='l3p1',
            external_segments={ess[0]['id']: []})['l3_policy']

        all_subnets = []
        ptgs = []
        for x in range(0, 2):
            l2p = self.create_l2_policy(name='l2p%d' % x,
                                        l3_policy_id=l3p['id'])['l2_policy']
            ptg = self.create_policy_target_group(name='ptg%d' % x,
                l2_policy_id=l2p['id'])['policy_target_group']
            ptgs.append(ptg)
            all_subnets.extend(ptg['subnets'])
            self._check_routers_connections(l3p, ext_nets[0:1], [],
                                            all_subnets)

        l3p = self.update_l3_policy(l3p['id'],
            external_segments={ess[1]['id']: []})['l3_policy']
        self._check_routers_connections(l3p, ext_nets[1:], [], all_subnets)

        for ptg in ptgs:
            self.delete_policy_target_group(ptg['id'])
            # verify subnets were deleted
            for s in ptg['subnets']:
                self._show('subnets', s, expected_code=404)

    def test_external_address(self):
        es_sub = self._make_ext_subnet('net1', '90.90.0.0/16',
                                       dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            subnet_id=es_sub['id'])['external_segment']
        l3p = self.create_l3_policy(
            external_segments={es['id']: ['90.90.0.10']})['l3_policy']
        routers = self._show_all('router', l3p['routers'])
        routers = [r for r in routers if self._router_gw(r)]
        self.assertEqual(1, len(routers))
        ext_ip = routers[0]['external_gateway_info']['external_fixed_ips']
        self.assertEqual([{'ip_address': '90.90.0.10',
                           'subnet_id': es_sub['id']}],
                         ext_ip)

    def test_one_l3_policy_ip_on_es(self):
        # Verify L3P created with more than 1 IP on ES fails
        es_sub = self._make_ext_subnet('net1', '90.90.0.0/16',
                                       dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            subnet_id=es_sub['id'])['external_segment']
        res = self.create_l3_policy(
            external_segments={es['id']: ['90.90.0.2', '90.90.0.3']},
            expected_res_status=400)
        self.assertEqual('OnlyOneAddressIsAllowedPerExternalSegment',
                         res['NeutronError']['type'])
        # Verify L3P updated to more than 1 IP on ES fails
        sneaky_l3p = self.create_l3_policy(
            external_segments={es['id']: ['90.90.0.2']},
            expected_res_status=201)['l3_policy']
        res = self.update_l3_policy(
            sneaky_l3p['id'], expected_res_status=400,
            external_segments={es['id']: ['90.90.0.2', '90.90.0.3']})
        self.assertEqual('OnlyOneAddressIsAllowedPerExternalSegment',
                         res['NeutronError']['type'])

    def test_one_l3_policy_per_es_with_no_nat(self):
        # Verify only one L3P can connect to ES with no-NAT
        es_sub = self._make_ext_subnet('net1', '90.90.0.0/16',
                                       dn='uni/tn-t1/out-l1/instP-n1',
                                       nat_type='')
        es = self.create_external_segment(
            subnet_id=es_sub['id'])['external_segment']
        self.create_l3_policy(external_segments={es['id']: []})
        res = self.create_l3_policy(
            external_segments={es['id']: []},
            expected_res_status=400)
        self.assertEqual('OnlyOneL3PolicyIsAllowedPerExternalSegment',
                         res['NeutronError']['type'])

    def test_l3_policy_with_multiple_routers(self):
        with self.router() as r1, self.router() as r2:
            res = self.create_l3_policy(
                routers=[r1['router']['id'], r2['router']['id']],
                expected_res_status=400)
            self.assertEqual('L3PolicyMultipleRoutersNotSupported',
                             res['NeutronError']['type'])


class TestLegacyL3Policy(TestL3Policy):

    def setUp(self, **kwargs):
        orig_create_per_l3p_implicit_contracts = (
                aimd.AIMMappingDriver._create_per_l3p_implicit_contracts)

        def _create_per_l3p_implicit_contracts(self):
            session = nctx.get_admin_context().session
            with session.begin(subtransactions=True):
                l3p_db = group_policy_mapping_db.L3PolicyMapping(
                        id='1234', tenant_id='some_tenant',
                        name='test-l3p', description='test-desc',
                        ip_version=4, ip_pool='10.0.0.0/8',
                        subnet_prefix_length=24, shared=False)
                session.add(l3p_db)
                session.flush()
            orig_create_per_l3p_implicit_contracts(self)
            aimd.AIMMappingDriver._create_per_l3p_implicit_contracts = (
                    orig_create_per_l3p_implicit_contracts)

        aimd.AIMMappingDriver._create_per_l3p_implicit_contracts = (
                _create_per_l3p_implicit_contracts)

        super(TestLegacyL3Policy, self).setUp(**kwargs)

    def test_create_implicit_contracts(self):
        self._validate_implicit_contracts_created('1234')
        l3p = self.create_l3_policy()['l3_policy']
        context = type('', (object,), {})()
        context._plugin_context = self._context
        self.driver._delete_implicit_contracts(context, l3p)
        self._validate_implicit_contracts_deleted(l3p['id'])
        self.driver._create_per_l3p_implicit_contracts()
        self._validate_implicit_contracts_created(l3p['id'])


class TestL3PolicyRollback(AIMBaseTestCase):

    def test_l3_policy_create_fail(self):
        orig_func = self.dummy.create_l3_policy_precommit
        self.dummy.create_l3_policy_precommit = mock.Mock(
            side_effect=Exception)
        self.create_l3_policy(name="l3p1", expected_res_status=500)
        self.assertEqual([], self._plugin.get_address_scopes(self._context))
        self.assertEqual([], self._plugin.get_subnetpools(self._context,
                                                          filters={}))
        self.assertEqual([], self._l3_plugin.get_routers(self._context))
        self.assertEqual([], self._gbp_plugin.get_l3_policies(self._context))
        # restore mock
        self.dummy.create_l3_policy_precommit = orig_func

    def test_l3_policy_update_fail(self):
        orig_func = self.dummy.update_l3_policy_precommit
        self.dummy.update_l3_policy_precommit = mock.Mock(
            side_effect=Exception)
        l3p = self.create_l3_policy(name="l3p1")['l3_policy']
        l3p_id = l3p['id']
        self.update_l3_policy(l3p_id, expected_res_status=500,
                              name="new name")
        new_l3p = self.show_l3_policy(l3p_id, expected_res_status=200)
        self.assertEqual(l3p['name'],
                         new_l3p['l3_policy']['name'])
        # restore mock
        self.dummy.update_l3_policy_precommit = orig_func

    def test_l3_policy_delete_fail(self):
        orig_func = self.dummy.delete_l3_policy_precommit
        self.dummy.delete_l3_policy_precommit = mock.Mock(
            side_effect=Exception)
        l3p = self.create_l3_policy(name="l3p1")['l3_policy']
        l3p_id = l3p['id']
        self.delete_l3_policy(l3p_id, expected_res_status=500)
        self.show_l3_policy(l3p_id, expected_res_status=200)
        self.assertEqual(
            1, len(self._plugin.get_address_scopes(self._context)))
        self.assertEqual(1, len(self._plugin.get_subnetpools(self._context,
                                                             filters={})))
        self.assertEqual(1, len(self._l3_plugin.get_routers(self._context)))
        # restore mock
        self.dummy.delete_l3_policy_precommit = orig_func


class TestL2PolicyBase(test_nr_base.TestL2Policy, AIMBaseTestCase):

    def _validate_default_epg_implicit_contracts(self, l2p):
        self._validate_implicit_contracts_created(
            l2p['l3_policy_id'], l2p=l2p)

    def _validate_bd_tenant(self, l2p, expected_tenant):
        network_id = l2p['network_id']
        self.assertIsNotNone(network_id)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        net = self.deserialize(self.fmt, req.get_response(self.api))['network']
        self.assertIsNotNone(net['id'])
        self.assertEqual(l2p['shared'], net['shared'])
        bd = self.driver._get_bd_by_dn(
            self._context, net[DN][BD])
        self.assertEqual(
            self.name_mapper.project(None, expected_tenant), bd.tenant_name)

    def _validate_epg_tenant(self, ptg, expected_tenant):
        epg = self.driver._get_epg_by_dn(
            self._context, ptg[DN][EPG])
        self.assertEqual(
            self.name_mapper.project(None, expected_tenant), epg.tenant_name)


class TestL2Policy(TestL2PolicyBase):

    def _test_l2_policy_lifecycle_implicit_l3p(self,
                                               shared=False):
        self.assertEqual(0, len(self.aim_mgr.find(
            self._aim_context, aim_resource.Contract)))
        self.assertEqual(1, len(self.aim_mgr.find(
            self._aim_context, aim_resource.Filter)))
        self.assertEqual(1, len(self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry)))
        l2p0 = self.create_l2_policy(name="l2p0",
                                     shared=shared)['l2_policy']
        # This validates that the infra and implicit Contracts, etc.
        # are created after the first L2P creation
        self._validate_default_epg_implicit_contracts(l2p0)
        l2p = self.create_l2_policy(name="l2p1",
                                    shared=shared)['l2_policy']
        self.assertEqual(gp_const.STATUS_BUILD, l2p['status'])
        # This validates that the infra and implicit Contracts, etc.
        # are not created after the second L2P creation
        self._validate_default_epg_implicit_contracts(l2p)
        l2p_id = l2p['id']
        network_id = l2p['network_id']
        l3p_id = l2p['l3_policy_id']
        self.assertIsNotNone(network_id)
        self.assertIsNotNone(l3p_id)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        net = self.deserialize(self.fmt, req.get_response(self.api))['network']
        self.assertIsNotNone(net['id'])
        self.assertEqual(l2p['shared'], net['shared'])
        self.show_l3_policy(l3p_id, expected_res_status=200)
        self.show_l2_policy(l2p_id, expected_res_status=200)

        self._validate_status('show_l2_policy', l2p_id)

        self.update_l2_policy(l2p_id, expected_res_status=200,
                              name="new name")

        self._switch_to_tenant2()
        # Create l2p in a different tenant, check infra and implicit contracts
        # created for that tenant
        l2p_tenant2 = self.create_l2_policy(
            name='l2p-alternate-tenant', shared=shared)['l2_policy']
        self._validate_default_epg_implicit_contracts(l2p_tenant2)
        self._switch_to_tenant1()
        self._validate_l2_policy_deleted(l2p)
        self._validate_l2_policy_deleted(l2p0)
        # Validate that the Contracts still exist in the other tenant
        self._switch_to_tenant2()
        self._validate_default_epg_implicit_contracts(l2p_tenant2)
        self._validate_l2_policy_deleted(l2p_tenant2)
        self._switch_to_tenant1()

    def test_unshared_l2_policy_lifecycle_implicit_l3p(self):
        self._test_l2_policy_lifecycle_implicit_l3p()

    def test_shared_l2_policy_lifecycle_implicit_l3p(self):
        self._test_l2_policy_lifecycle_implicit_l3p(shared=True)

    def _test_l2_policy_lifecycle_explicit_l3p(self, shared=False):
        l3p = self.create_l3_policy(name="l3p1",
                                    shared=shared)['l3_policy']
        l2p = self.create_l2_policy(name="l2p1",
                                    shared=shared,
                                    l3_policy_id=l3p['id'])['l2_policy']
        self.assertEqual(gp_const.STATUS_BUILD, l2p['status'])
        self._validate_default_epg_implicit_contracts(l2p)
        self.assertEqual(l2p['shared'], l3p['shared'])
        network_id = l2p['network_id']
        l3p_id = l2p['l3_policy_id']
        self.assertIsNotNone(network_id)
        self.assertIsNotNone(l3p_id)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        net = self.deserialize(self.fmt, req.get_response(self.api))['network']
        self.assertIsNotNone(net['id'])
        self.assertEqual(l2p['shared'], net['shared'])
        self._validate_l2_policy_deleted(l2p, implicit_l3p=False)
        self.delete_l3_policy(l3p_id)

    def test_unshared_l2_policy_lifecycle_explicit_l3p(self):
        self._test_l2_policy_lifecycle_explicit_l3p()

    def test_shared_l2_policy_lifecycle_explicit_l3p(self):
        self._test_l2_policy_lifecycle_explicit_l3p(shared=True)

    def test_unshared_l2_policy_shared_l3p_cross_tenant(self):
        l3p = self.create_l3_policy(name="l3p1",
                                    shared=True)['l3_policy']
        self._switch_to_tenant2()
        l2p = self.create_l2_policy(name="l2p1",
                                    shared=False,
                                    l3_policy_id=l3p['id'])['l2_policy']
        self.assertEqual(gp_const.STATUS_BUILD, l2p['status'])
        self._validate_default_epg_implicit_contracts(l2p)
        l3p_id = l2p['l3_policy_id']
        self.assertIsNotNone(l3p_id)
        self.assertEqual(l2p['shared'], not l3p['shared'])

        # BD is in tenant2 since there is no PTG yet in the L2P
        self._validate_bd_tenant(l2p, l2p['tenant_id'])

        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        # After creation of first PTG, BD is now in L3P's tenant
        self._validate_bd_tenant(l2p, l3p['tenant_id'])

        # EPG is now in L3P's tenant
        self._validate_epg_tenant(ptg, l3p['tenant_id'])

        self.delete_policy_target_group(ptg['id'], expected_res_status=204)
        self._validate_l2_policy_deleted(l2p, implicit_l3p=False)
        self._switch_to_tenant1()
        self.delete_l3_policy(l3p_id)


class TestL2PolicyWithAutoPTG(TestL2PolicyBase):

    def setUp(self, **kwargs):
        super(TestL2PolicyWithAutoPTG, self).setUp(**kwargs)
        self.driver.create_auto_ptg = True

    def tearDown(self):
        super(TestL2PolicyWithAutoPTG, self).tearDown()
        self.driver.create_auto_ptg = False

    def _get_auto_ptg(self, l2p):
        ptg = self._gbp_plugin.get_policy_target_groups(
            self._neutron_context)[0]
        l2p_id = ptg['l2_policy_id']
        auto_ptg_id = amap.AUTO_PTG_ID_PREFIX % hashlib.md5(l2p_id).hexdigest()
        self.assertEqual(auto_ptg_id, ptg['id'])
        self.assertEqual(aimd.AUTO_PTG_NAME_PREFIX % l2p_id, str(ptg['name']))
        return ptg

    def _test_auto_ptg(self, l2p, shared=False):
        ptg = self._get_auto_ptg(l2p)
        self.assertEqual(shared, ptg['shared'])
        prs_lists = self._get_provided_consumed_prs_lists(shared)
        # the test policy.json restricts auto-ptg access to admin
        ptg = self.update_policy_target_group(
            ptg['id'], is_admin_context=True,
            expected_res_status=webob.exc.HTTPOk.code,
            name='new name', description='something-else',
            provided_policy_rule_sets={prs_lists['provided']['id']:
                                       'scope'},
            consumed_policy_rule_sets={prs_lists['consumed']['id']:
                                       'scope'})['policy_target_group']
        self._test_policy_target_group_aim_mappings(
            ptg, prs_lists, l2p)
        # the test policy.json restricts auto-ptg access to admin
        self.update_policy_target_group(
            ptg['id'], is_admin_context=True, shared=(not shared),
            expected_res_status=webob.exc.HTTPBadRequest.code)
        # Auto PTG cannot be deleted by user
        res = self.delete_policy_target_group(
            ptg['id'], expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('AutoPTGDeleteNotSupported',
                         res['NeutronError']['type'])
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'])
        aim_epg = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup,
            name=aim_epg_name)[0]
        aim_epg_display_name = aim_epg.display_name
        ptg = self.update_policy_target_group(
            ptg['id'], expected_res_status=webob.exc.HTTPOk.code,
            is_admin_context=True,
            name='new name', description='something-else',
            provided_policy_rule_sets={},
            consumed_policy_rule_sets={})['policy_target_group']
        self._test_policy_target_group_aim_mappings(
            ptg, {'provided': None, 'consumed': None}, l2p)
        aim_epg = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup,
            name=aim_epg_name)[0]
        self.assertEqual(aim_epg_display_name, aim_epg.display_name)
        self._delete_prs_dicts_and_rules(prs_lists)
        self._validate_l2_policy_deleted(l2p)
        self.show_policy_target_group(ptg['id'], expected_res_status=404)

    def _test_multiple_l2p_post_create(self, shared=False):
        l2p = self.create_l2_policy(name="l2p0", shared=shared)['l2_policy']
        self._test_auto_ptg(l2p, shared=shared)
        # At this time first l2p and auto-ptg for that l2p are deleted
        self.create_l2_policy(name="l2p1", shared=shared)['l2_policy']
        self.create_l2_policy(name="l2p2", shared=shared)['l2_policy']
        # Two new l2ps are created, and each one should have their own auto-ptg
        ptgs = self._gbp_plugin.get_policy_target_groups(self._neutron_context)
        self.assertEqual(2, len(ptgs))

    def test_auto_ptg_lifecycle_shared(self):
        self._test_multiple_l2p_post_create(shared=True)

    def test_auto_ptg_lifecycle_unshared(self):
        self._test_multiple_l2p_post_create()

    def _test_epg_policy_enforcement_attr(self, ptg):
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            db_api.get_session(), ptg['id'])
        aim_epg = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup,
            name=aim_epg_name)[0]
        if aim_epg.policy_enforcement_pref == (
            aim_resource.EndpointGroup.POLICY_UNENFORCED):
            self.assertTrue(ptg['intra_ptg_allow'])
        elif aim_epg.policy_enforcement_pref == (
            aim_resource.EndpointGroup.POLICY_ENFORCED):
            self.assertFalse(ptg['intra_ptg_allow'])

    def _test_application_profile(self, apg, exists=True):
        ap_name = self.driver.apic_ap_name_for_application_policy_group(
            self._neutron_context.session, apg['id'])
        aim_ap_list = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            name=ap_name)
        if exists:
            self.assertEqual(1, len(aim_ap_list))
            self.assertEqual(ap_name, aim_ap_list[0].name)
            apg = self.show_application_policy_group(
                apg['id'], expected_res_status=200)['application_policy_group']
            ap = self.aim_mgr.get(
                self._aim_context, aim_resource.ApplicationProfile.from_dn(
                    apg[DN][AP][0]))
            self.assertEqual(aim_ap_list[0].name, ap.name)
        else:
            self.assertEqual(0, len(aim_ap_list))

    def test_ptg_lifecycle(self):
        # Once the testing strategy evolves to always assuming auto_ptg
        # being present, this UT can be removed/merged with the UTs in the
        # TestPolicyTargetGroup class
        apg = self.create_application_policy_group()[
            'application_policy_group']
        apg_id = apg['id']
        self.show_application_policy_group(apg_id, expected_res_status=200)
        ptg = self.create_policy_target_group(application_policy_group_id=
                                              apg['id'])['policy_target_group']
        self.assertEqual(apg_id, ptg['application_policy_group_id'])
        self._test_application_profile(apg)
        self._test_epg_policy_enforcement_attr(ptg)
        ptg_id = ptg['id']
        l2p = self.show_l2_policy(ptg['l2_policy_id'],
                                  expected_res_status=200)['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'],
                                  expected_res_status=200)['l3_policy']
        ascopes = self._plugin.get_address_scopes(self._context)
        self.assertEqual(l3p['address_scope_v4_id'], ascopes[0]['id'])
        subpools = self._plugin.get_subnetpools(self._context, filters={})
        self.assertEqual(l3p['subnetpools_v4'], [subpools[0]['id']])
        self.assertEqual(l3p['address_scope_v4_id'],
                         subpools[0]['address_scope_id'])
        routers = self._l3_plugin.get_routers(self._context)
        self.assertEqual(l3p['routers'], [routers[0]['id']])
        req = self.new_show_request('subnets', ptg['subnets'][0], fmt=self.fmt)
        subnet = self.deserialize(self.fmt,
                                  req.get_response(self.api))['subnet']
        self.assertIsNotNone(subnet['id'])
        self.assertEqual(l3p['subnetpools_v4'][0],
                         subnet['subnetpool_id'])

        new_apg = self.create_application_policy_group()[
            'application_policy_group']
        prs_lists = self._get_provided_consumed_prs_lists()
        ptg = self.update_policy_target_group(
            ptg_id, expected_res_status=200,
            provided_policy_rule_sets={prs_lists['provided']['id']:
                                       'scope'},
            consumed_policy_rule_sets={prs_lists['consumed']['id']:
                                       'scope'},
            application_policy_group_id=new_apg['id'])['policy_target_group']
        self._test_application_profile(new_apg)
        self._test_application_profile(apg, exists=False)
        self._test_epg_policy_enforcement_attr(ptg)

        ptg = self.update_policy_target_group(
            ptg_id, expected_res_status=200,
            application_policy_group_id=None)['policy_target_group']
        self._test_application_profile(new_apg, exists=False)

        ptg = self.update_policy_target_group(
            ptg_id, expected_res_status=200,
            application_policy_group_id=new_apg['id'])['policy_target_group']
        self._test_application_profile(new_apg)

        auto_ptg_id = self.driver._get_auto_ptg_id(ptg['l2_policy_id'])
        # the test policy.json restricts auto-ptg access to admin
        auto_ptg = self.show_policy_target_group(
            auto_ptg_id, is_admin_context=True,
            expected_res_status=200)['policy_target_group']
        self._test_epg_policy_enforcement_attr(auto_ptg)

        res = self.update_policy_target_group(
            auto_ptg_id, expected_res_status=webob.exc.HTTPBadRequest.code,
            is_admin_context=True, application_policy_group_id=new_apg['id'])
        self.assertEqual('ExplicitAPGAssociationNotSupportedForAutoPTG',
                         res['NeutronError']['type'])

        ptg2 = self.create_policy_target_group(
            application_policy_group_id=new_apg['id'])['policy_target_group']

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self._test_application_profile(new_apg)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        self.delete_policy_target_group(ptg2['id'], expected_res_status=204)
        self._test_application_profile(new_apg, exists=False)
        self.show_policy_target_group(ptg2['id'], expected_res_status=404)

        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=404)
        self.delete_application_policy_group(apg_id, expected_res_status=204)
        self.show_application_policy_group(apg_id, expected_res_status=404)
        self.assertEqual([], self._plugin.get_ports(self._context))
        self.assertEqual([], self._plugin.get_subnets(self._context))
        self.assertEqual([], self._plugin.get_networks(self._context))
        self.assertEqual([], self._plugin.get_address_scopes(self._context))
        self.assertEqual([], self._plugin.get_subnetpools(self._context,
                                                          filters={}))
        self.assertEqual([], self._l3_plugin.get_routers(self._context))

    def test_auto_ptg_rbac(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        # non-admin can create pt on non-auto-ptg
        self.create_policy_target(policy_target_group_id=ptg['id'],
                                  expected_res_status=201)
        # admin can create pt on non-auto-ptg
        self.create_policy_target(policy_target_group_id=ptg['id'],
                                  is_admin_context=True,
                                  expected_res_status=201)
        # non-admin can retrieve and update non-auto-ptg
        self.show_policy_target_group(ptg['id'], expected_res_status=200)
        self.update_policy_target_group(
            ptg['id'], expected_res_status=200, name='new_name')
        # admin can retrieve and update non-auto-ptg
        self.show_policy_target_group(ptg['id'], is_admin_context=True,
                                      expected_res_status=200)
        self.update_policy_target_group(
            ptg['id'], is_admin_context=True, expected_res_status=200,
            name='new_name')

        auto_ptg_id = self.driver._get_auto_ptg_id(ptg['l2_policy_id'])
        # non-admin cannot retrieve or update auto-ptg
        self.show_policy_target_group(auto_ptg_id, expected_res_status=404)
        self.update_policy_target_group(
            auto_ptg_id, expected_res_status=403, name='new_name')
        # admin can retrieve and update auto-ptg
        self.show_policy_target_group(auto_ptg_id, is_admin_context=True,
                                      expected_res_status=200)
        self.update_policy_target_group(
            auto_ptg_id, is_admin_context=True, expected_res_status=200,
            name='new_name')
        # admin can create pt on auto-ptg
        self.create_policy_target(
            policy_target_group_id=auto_ptg_id, is_admin_context=True,
            expected_res_status=201)
        # non-admin cannot create pt on auto-ptg
        self.create_policy_target(policy_target_group_id=auto_ptg_id,
                                  expected_res_status=403)

    def test_auto_ptg_tenant_unshared_l2_policy_shared_l3p(self):
        l3p = self.create_l3_policy(name="l3p1",
                                    shared=True)['l3_policy']
        self._switch_to_tenant2()
        l2p = self.create_l2_policy(name="l2p1",
                                    shared=False,
                                    l3_policy_id=l3p['id'])['l2_policy']
        self.assertEqual(gp_const.STATUS_BUILD, l2p['status'])
        self.assertEqual(l2p['shared'], not l3p['shared'])
        self._validate_default_epg_implicit_contracts(l2p)

        # After creation of auto-ptg, BD is now in L3P's tenant
        self._validate_bd_tenant(l2p, l3p['tenant_id'])

        ptg = self._get_auto_ptg(l2p)
        # Default EPG is in L3P's tenant
        self._validate_epg_tenant(ptg, l3p['tenant_id'])

        self._validate_l2_policy_deleted(l2p, implicit_l3p=False)
        self._switch_to_tenant1()
        self.delete_l3_policy(l3p['id'])

    def test_unshared_l2_policy_shared_l3p_get_gbp_details(self):
        l3p = self.create_l3_policy(name="l3p1",
                                    shared=True)['l3_policy']
        self._switch_to_tenant2()
        l2p = self.create_l2_policy(name="l2p1",
                                    shared=False,
                                    l3_policy_id=l3p['id'])['l2_policy']
        self.assertEqual(gp_const.STATUS_BUILD, l2p['status'])
        self.assertEqual(l2p['shared'], not l3p['shared'])
        self._validate_default_epg_implicit_contracts(l2p)

        # After creation of auto-ptg, BD is now in L3P's tenant
        self._validate_bd_tenant(l2p, l3p['tenant_id'])

        ptg = self._get_auto_ptg(l2p)
        # Default EPG is in L3P's tenant
        self._validate_epg_tenant(ptg, l3p['tenant_id'])

        subnet_id = ptg['subnets'][0]
        req = self.new_show_request('subnets', subnet_id)
        subnet = self.deserialize(self.fmt, req.get_response(self.api))

        with self.port(subnet=subnet) as port:
            port_id = port['port']['id']
            self._bind_port_to_host(port_id, 'h1')
            mapping = self.driver.get_gbp_details(
                self._neutron_admin_context, device='tap%s' % port_id,
                host='h1')
            self.assertEqual(
                self.name_mapper.network(None, l2p['network_id']),
                mapping['endpoint_group_name'])
            self.assertEqual(
                self.name_mapper.project(None, l3p['tenant_id']),
                mapping['ptg_tenant'])
            self.assertNotEqual(ptg['tenant_id'], mapping['ptg_tenant'])
            req = self.new_delete_request('ports', port_id)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)

        self._validate_l2_policy_deleted(l2p, implicit_l3p=False)
        self._switch_to_tenant1()
        self.delete_l3_policy(l3p['id'])

    def test_ep_notification_on_apg_update(self):
        # Once the testing strategy evolves to always assuming auto_ptg
        # being present, this UT can be removed/merged with the UTs in the
        # TestPolicyTargetGroup class
        mock_notif = mock.Mock()
        self.driver.aim_mech_driver.notifier.port_update = mock_notif
        apg = self.create_application_policy_group()[
            'application_policy_group']
        apg_id = apg['id']
        self.show_application_policy_group(apg_id, expected_res_status=200)
        ptg = self.create_policy_target_group(application_policy_group_id=
                                              apg_id)['policy_target_group']
        self.assertEqual(apg_id, ptg['application_policy_group_id'])
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt['port_id'], 'h1')
        port = self._plugin.get_port(self._context, pt['port_id'])
        mapping = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % pt['port_id'],
            host='h1')
        ap_name = self.driver.apic_ap_name_for_application_policy_group(
            self._neutron_context.session, apg_id)
        self.assertEqual(ap_name, mapping['app_profile_name'])
        new_apg = self.create_application_policy_group()[
            'application_policy_group']
        ptg = self.update_policy_target_group(
            ptg['id'], expected_res_status=200,
            application_policy_group_id=new_apg['id'])['policy_target_group']
        mapping = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % pt['port_id'],
            host='h1')
        ap_name = self.driver.apic_ap_name_for_application_policy_group(
            self._neutron_context.session, new_apg['id'])
        self.assertEqual(ap_name, mapping['app_profile_name'])
        mock_notif.assert_called_once_with(mock.ANY, port)


class TestL2PolicyRollback(TestL2PolicyBase):

    def test_l2_policy_create_fail(self):
        orig_func = self.dummy.create_l2_policy_precommit
        self.dummy.create_l2_policy_precommit = mock.Mock(
            side_effect=Exception)
        self.create_l2_policy(name="l2p1", expected_res_status=500)
        self.assertEqual([], self._plugin.get_networks(self._context))
        self.assertEqual([], self._gbp_plugin.get_l2_policies(self._context))
        self.assertEqual([], self._gbp_plugin.get_l3_policies(self._context))

        aim_tenant_name = md.COMMON_TENANT_NAME

        aim_contracts = self.aim_mgr.find(
            self._aim_context, aim_resource.Contract,
            tenant_name=aim_tenant_name)
        self.assertEqual(0, len(aim_contracts))
        aim_contract_subjects = self.aim_mgr.find(
            self._aim_context, aim_resource.ContractSubject,
            tenant_name=aim_tenant_name)
        self.assertEqual(0, len(aim_contract_subjects))

        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter,
            tenant_name=aim_tenant_name)
        self.assertEqual(1, len(aim_filters))
        aim_filter_entries = self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry,
            tenant_name=aim_tenant_name)
        self.assertEqual(1, len(aim_filter_entries))
        # restore mock
        self.dummy.create_l2_policy_precommit = orig_func

    def test_l2_policy_update_fail(self):
        orig_func = self.dummy.update_l2_policy_precommit
        self.dummy.update_l2_policy_precommit = mock.Mock(
            side_effect=Exception)
        l2p = self.create_l2_policy(name="l2p1")['l2_policy']
        l2p_id = l2p['id']
        self.update_l2_policy(l2p_id, expected_res_status=500,
                              name="new name")
        new_l2p = self.show_l2_policy(l2p_id, expected_res_status=200)
        self.assertEqual(l2p['name'],
                         new_l2p['l2_policy']['name'])
        self._validate_default_epg_implicit_contracts(l2p)
        # restore mock
        self.dummy.update_l2_policy_precommit = orig_func

    def test_l2_policy_delete_fail(self):
        orig_func = self.dummy.delete_l2_policy_precommit
        self.dummy.delete_l2_policy_precommit = mock.Mock(
            side_effect=Exception)
        l2p = self.create_l2_policy(name="l2p1")['l2_policy']
        l2p_id = l2p['id']
        network_id = l2p['network_id']
        l3p_id = l2p['l3_policy_id']
        self.delete_l2_policy(l2p_id, expected_res_status=500)
        req = self.new_show_request('networks', network_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertIsNotNone(res['network']['id'])
        self.show_l3_policy(l3p_id, expected_res_status=200)
        self.show_l2_policy(l2p_id, expected_res_status=200)
        self._validate_default_epg_implicit_contracts(l2p)
        # restore mock
        self.dummy.delete_l2_policy_precommit = orig_func


class TestPolicyTargetGroupVmmDomains(AIMBaseTestCase):

    def test_policy_target_group_aim_domains(self):
        self.aim_mgr.create(self._aim_context,
                            aim_resource.VMMDomain(type='OpenStack',
                                                   name='vm1'),
                            overwrite=True)
        self.aim_mgr.create(self._aim_context,
                            aim_resource.VMMDomain(type='OpenStack',
                                                   name='vm2'),
                            overwrite=True)
        self.aim_mgr.create(self._aim_context,
                            aim_resource.VMMDomain(type='VMware',
                                                   name='vm3'),
                            overwrite=True)
        self.aim_mgr.create(self._aim_context,
                            aim_resource.PhysicalDomain(name='ph1'),
                            overwrite=True)
        self.aim_mgr.create(self._aim_context,
                            aim_resource.PhysicalDomain(name='ph2'),
                            overwrite=True)
        ptg = self.create_policy_target_group(name="ptg1")[
            'policy_target_group']

        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'])
        aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
        aim_app_profile_name = self.driver.aim_mech_driver.ap_name
        aim_app_profiles = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        aim_epg = self.aim_mgr.get(
            self._aim_context, aim_resource.EndpointGroup(
                tenant_name=aim_tenant_name,
                app_profile_name=aim_app_profile_name, name=aim_epg_name))
        self.assertEqual(set([]),
                         set([vmm['name'] for vmm in aim_epg.vmm_domains]))
        self.assertEqual(set([]),
                         set([phys['name']
                              for phys in aim_epg.physical_domains]))


class TestPolicyTargetGroupIpv4(AIMBaseTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTargetGroupIpv4, self).setUp(*args, **kwargs)

        self.ip_dict = {4: {'address_scope_id_key': 'address_scope_v4_id',
                            'subnetpools_id_key': 'subnetpools_v4',
                            'cidrs': [('192.168.0.0/24', 24),
                                      ('10.0.0.0/16', 26)],
                            'address_scope': None,
                            'subnetpools': []}}

    def _family_specific_subnet_validation(self, subnet):
        pass

    def _verify_implicit_subnets_in_ptg(self, ptg, l3p=None):
        # Verify that implicit subnetpools exist for each address family,
        # and that the PTG was allocated a subnet with a prefix from
        # each address family
        for ip_version in self.ip_dict.keys():
            family_subnets = []
            for subnet_id in ptg['subnets']:
                req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
                subnet = self.deserialize(self.fmt,
                                          req.get_response(self.api))['subnet']
                self.assertIsNotNone(subnet['id'])
                if netaddr.IPNetwork(subnet['cidr']).version == ip_version:
                    family_subnets.append(subnet)
            self.assertNotEqual(family_subnets, [])
            cidrlist = [cidr for cidr, _ in self.ip_dict[ip_version]['cidrs']]
            for subnet in family_subnets:
                ip_ver = subnet['ip_version']
                check = IPSet(cidrlist).issuperset(
                    IPSet([subnet['cidr']]))
                self.assertTrue(check)
                if l3p:
                    self.assertIn(subnet['subnetpool_id'],
                        l3p[self.ip_dict[ip_ver]['subnetpools_id_key']])
                self._family_specific_subnet_validation(subnet)

    def test_policy_target_group_lifecycle_implicit_l2p(self):
        prs_lists = self._get_provided_consumed_prs_lists()
        ptg = self.create_policy_target_group(
            name="ptg1",
            provided_policy_rule_sets={prs_lists['provided']['id']: 'scope'},
            consumed_policy_rule_sets={prs_lists['consumed']['id']: 'scope'})[
                'policy_target_group']
        ptg_id = ptg['id']

        l2p = self.show_l2_policy(ptg['l2_policy_id'],
                                  expected_res_status=200)['l2_policy']
        l3p = self.show_l3_policy(l2p['l3_policy_id'],
                                  expected_res_status=200)['l3_policy']

        self._verify_implicit_subnets_in_ptg(ptg, l3p)
        self._test_policy_target_group_aim_mappings(ptg, prs_lists, l2p,
            num_address_families=len(self.ip_dict.keys()))

        new_name = 'new name'
        new_prs_lists = self._get_provided_consumed_prs_lists()
        ptg = self.update_policy_target_group(
            ptg_id, expected_res_status=200, name=new_name,
            provided_policy_rule_sets={new_prs_lists['provided']['id']:
                                       'scope'},
            consumed_policy_rule_sets={new_prs_lists['consumed']['id']:
                                       'scope'})['policy_target_group']

        self._test_policy_target_group_aim_mappings(ptg, new_prs_lists, l2p,
            num_address_families=len(self.ip_dict.keys()))

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        for subnet_id in ptg['subnets']:
            req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # check router ports are deleted too
        self.assertEqual([], self._plugin.get_ports(self._context))
        # Implicitly created L2P should be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=404)

        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup)
        self.assertEqual(0, len(aim_epgs))

    def test_policy_target_group_lifecycle_explicit_l2p(self):
        # TODO(Sumit): Refactor the common parts of this and the implicit test
        l2p = self.create_l2_policy(name="l2p1")['l2_policy']
        l2p_id = l2p['id']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_id)['policy_target_group']
        ptg_id = ptg['id']
        ptg_show = self.show_policy_target_group(
            ptg_id, expected_res_status=200)['policy_target_group']
        self.assertEqual(l2p_id, ptg['l2_policy_id'])
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        self._verify_implicit_subnets_in_ptg(ptg)
        self._validate_router_interface_created(
            num_address_families=len(self.ip_dict.keys()))

        ptg_name = ptg['name']
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg_id, ptg_name)
        aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
        aim_app_profile_name = self.driver.aim_mech_driver.ap_name
        aim_app_profiles = self.aim_mgr.find(
            self._aim_context, aim_resource.ApplicationProfile,
            tenant_name=aim_tenant_name, name=aim_app_profile_name)
        self.assertEqual(1, len(aim_app_profiles))
        req = self.new_show_request('networks', l2p['network_id'],
                                    fmt=self.fmt)
        net = self.deserialize(self.fmt,
                               req.get_response(self.api))['network']
        bd = self.aim_mgr.get(
            self._aim_context, aim_resource.BridgeDomain.from_dn(
                net[DN][BD]))
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self.assertEqual(aim_tenant_name, aim_epgs[0].tenant_name)
        self.assertEqual(bd.name, aim_epgs[0].bd_name)

        self.assertEqual(aim_epgs[0].dn,
                         ptg[DN][EPG])
        self._test_aim_resource_status(aim_epgs[0], ptg)
        self.assertEqual(aim_epgs[0].dn, ptg_show[DN][EPG])

        new_name = 'new name'
        new_prs_lists = self._get_provided_consumed_prs_lists()
        self.update_policy_target_group(
            ptg_id, expected_res_status=200, name=new_name,
            provided_policy_rule_sets={new_prs_lists['provided']['id']:
                                       'scope'},
            consumed_policy_rule_sets={new_prs_lists['consumed']['id']:
                                       'scope'})['policy_target_group']
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg_id, new_name)
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_epg_name, aim_epgs[0].name)
        self._validate_contracts(ptg, aim_epgs[0], new_prs_lists, l2p)
        self.assertEqual(bd.name, aim_epgs[0].bd_name)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        for subnet_id in ptg['subnets']:
            req = self.new_show_request('subnets', subnet_id, fmt=self.fmt)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        # Explicitly created L2P should not be deleted
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)

        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(0, len(aim_epgs))

    def _create_explicit_subnetpools(self):
        vrf_dn = None
        for ip_version in self.ip_dict.keys():
            ascp = self._make_address_scope_for_vrf(vrf_dn,
                ip_version, name='as1v' + str(ip_version))
            ascp = ascp['address_scope']
            vrf_dn = ascp[DN][VRF]
            self.ip_dict[ip_version]['address_scope'] = ascp
            count = 0
            for cidr, prefixlen in self.ip_dict[ip_version]['cidrs']:
                with self.subnetpool(
                        name='spv%s%s' % (str(ip_version), count),
                        prefixes=[cidr],
                        tenant_id=ascp['tenant_id'],
                        default_prefixlen=prefixlen,
                        address_scope_id=ascp['id']) as sp:
                    sp = sp['subnetpool']
                    self.ip_dict[ip_version]['subnetpools'].append(sp)
                    self.assertEqual(ascp['id'], sp['address_scope_id'])

    def test_create_ptg_explicit_subnetpools(self):
        self._create_explicit_subnetpools()
        kwargs = {'name': "l3p1", 'ip_pool': None}
        for ip_version in self.ip_dict.keys():
            kwargs[self.ip_dict[ip_version]['subnetpools_id_key']] = [sp['id']
                for sp in self.ip_dict[ip_version]['subnetpools']]
        if len(self.ip_dict.keys()) == 1:
            kwargs['ip_version'] = self.ip_dict.keys()[0]
        else:
            kwargs['ip_version'] = 46
        l3p = self.create_l3_policy(**kwargs)['l3_policy']
        for ip_version in self.ip_dict.keys():
            self.assertEqual(self.ip_dict[ip_version]['address_scope']['id'],
                l3p[self.ip_dict[ip_version]['address_scope_id_key']])
        subnetpool_prefixes = []
        for ip_version in self.ip_dict.keys():
            cidrlist = self.ip_dict[ip_version]['cidrs']
            subnetpool_prefixes.extend([cidr for cidr, _ in cidrlist])
        self._validate_create_l3_policy(
            l3p, subnetpool_prefixes=subnetpool_prefixes)
        for ip_version in self.ip_dict.keys():
            sp_key = self.ip_dict[ip_version]['subnetpools_id_key']
            self.assertEqual(len(self.ip_dict[ip_version]['subnetpools']),
                             len(l3p[sp_key]))
        l2p = self.create_l2_policy(
            name='l2p', l3_policy_id=l3p['id'])['l2_policy']
        l2p_id = l2p['id']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p_id)['policy_target_group']
        ptg_id = ptg['id']
        self.show_policy_target_group(
            ptg_id, expected_res_status=200)['policy_target_group']
        for subnet_id in ptg['subnets']:
            req = self.new_show_request(
                'subnets', subnet_id, fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.api))
            subnet = res['subnet']
            cidrlist = [cidr for cidr, _ in
                        self.ip_dict[subnet['ip_version']]['cidrs']]
            check = IPSet(cidrlist).issuperset(
                IPSet([subnet['cidr']]))
            self.assertTrue(check)
        self.delete_policy_target_group(
            ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should be deleted
        req = self.new_show_request(
            'subnets', ptg['subnets'][0], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)
        self.delete_l2_policy(l2p_id, expected_res_status=204)

        self._validate_delete_l3_policy(
            l3p, explicit_address_scope=True, explicit_subnetpool=True)

    def test_ptg_delete_no_subnet_delete(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        ptg2 = self.create_policy_target_group(
            name="ptg2", l2_policy_id=ptg['l2_policy_id'])[
                'policy_target_group']
        self.assertEqual(ptg['subnets'], ptg2['subnets'])
        self.show_l2_policy(ptg['l2_policy_id'], expected_res_status=200)
        self._verify_implicit_subnets_in_ptg(ptg)

        self.delete_policy_target_group(ptg_id, expected_res_status=204)
        self.show_policy_target_group(ptg_id, expected_res_status=404)
        # Implicitly created subnet should not be deleted
        self._verify_implicit_subnets_in_ptg(ptg)
        self._validate_router_interface_created(
            num_address_families=len(self.ip_dict.keys()))

    def test_delete_ptg_after_router_interface_delete(self):
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        ptg_id = ptg['id']
        self._validate_router_interface_created(
            num_address_families=len(self.ip_dict.keys()))

        router_id = self._l3_plugin.get_routers(self._context)[0]['id']
        subnet_id = self._plugin.get_subnets(self._context)[0]['id']
        info = self._l3_plugin.remove_router_interface(
            self._context, router_id, {'subnet_id': subnet_id})
        self.assertIn(subnet_id, info['subnet_ids'])
        self.delete_policy_target_group(ptg_id, expected_res_status=204)

    def test_policy_target_group_intra_ptg_allow(self):
        ptg = self.create_policy_target_group(
            intra_ptg_allow=False)['policy_target_group']
        self.assertFalse(ptg['intra_ptg_allow'])
        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'])
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(1, len(aim_epgs))
        self.assertEqual(aim_resource.EndpointGroup.POLICY_ENFORCED,
                         aim_epgs[0].policy_enforcement_pref)
        ptg = self.update_policy_target_group(
            ptg['id'], intra_ptg_allow=True)['policy_target_group']
        self.assertTrue(ptg['intra_ptg_allow'])
        aim_epgs = self.aim_mgr.find(
            self._aim_context, aim_resource.EndpointGroup, name=aim_epg_name)
        self.assertEqual(aim_resource.EndpointGroup.POLICY_UNENFORCED,
                         aim_epgs[0].policy_enforcement_pref)


class TestPolicyTargetGroupIpv6(TestPolicyTargetGroupIpv4):

    def setUp(self, *args, **kwargs):
        cfg.CONF.set_override(
            'default_ip_version', 6,
            group='group_policy_implicit_policy')
        cfg.CONF.set_override(
            'default_ip_pool', '2001:db8:1::/64',
            group='group_policy_implicit_policy')
        cfg.CONF.set_override(
            'default_ipv6_ra_mode', 'slaac',
            group='resource_mapping')
        cfg.CONF.set_override(
            'default_ipv6_address_mode', 'slaac',
            group='resource_mapping')
        super(TestPolicyTargetGroupIpv6, self).setUp(*args, **kwargs)

        self.ip_dict = {6: {'address_scope_id_key': 'address_scope_v6_id',
                            'subnetpools_id_key': 'subnetpools_v6',
                            'cidrs': [('2001:db8:1::/64', 65),
                                      ('2001:db8:2::/64', 66)],
                            'address_scope': None,
                            'subnetpools': []}}

    def _family_specific_subnet_validation(self, subnet):
        if subnet['ip_version'] is 6:
            self.assertEqual(subnet['ipv6_ra_mode'], 'slaac')
            self.assertEqual(subnet['ipv6_address_mode'], 'slaac')


class TestPolicyTargetGroupDualStack(TestPolicyTargetGroupIpv4):

    def setUp(self, *args, **kwargs):
        cfg.CONF.set_override(
            'default_ip_pool', '10.0.0.0/8,2001:db8:1::/64',
            group='group_policy_implicit_policy')
        cfg.CONF.set_override(
            'default_ip_version', 46,
            group='group_policy_implicit_policy')
        super(TestPolicyTargetGroupDualStack, self).setUp(*args, **kwargs)
        self.ip_dict = {4: {'address_scope_id_key': 'address_scope_v4_id',
                            'subnetpools_id_key': 'subnetpools_v4',
                            'cidrs': [('192.168.0.0/24', 24),
                                      ('10.0.0.0/16', 26)],
                            'address_scope': None,
                            'subnetpools': []},
                        6: {'address_scope_id_key': 'address_scope_v6_id',
                            'subnetpools_id_key': 'subnetpools_v6',
                            'cidrs': [('2001:db8:1::/64', 65),
                                      ('2001:db8:2::/64', 66)],
                            'address_scope': None,
                            'subnetpools': []}}


# TODO(Sumit): Add tests here which tests different scenarios for subnet
# allocation for PTGs
# 1. Multiple PTGs share the subnets associated with the l2_policy
# 2. Associated subnets are correctly used for IP address allocation
# 3. New subnets are created when the last available is exhausted
# 4. If multiple subnets are present, all are deleted at the time of
#    l2_policy deletion
# 5. 'prefixlen', 'cidr', and 'subnetpool_id' overrides as a part of
#    the subnet_specifics dictionary


class TestPolicyTargetGroupRollback(AIMBaseTestCase):

    def test_policy_target_group_create_fail(self):
        orig_func = self.dummy.create_policy_target_group_precommit
        self.dummy.create_policy_target_group_precommit = mock.Mock(
            side_effect=Exception)
        self.create_policy_target_group(name="ptg1", expected_res_status=500)
        self.assertEqual([], self._plugin.get_ports(self._context))
        self.assertEqual([], self._plugin.get_subnets(self._context))
        self.assertEqual([], self._plugin.get_networks(self._context))
        self.assertEqual([], self._gbp_plugin.get_policy_target_groups(
            self._context))
        self.assertEqual([], self._gbp_plugin.get_l2_policies(self._context))
        self.assertEqual([], self._gbp_plugin.get_l3_policies(self._context))
        # restore mock
        self.dummy.create_policy_target_group_precommit = orig_func

    def test_policy_target_group_update_fail(self):
        orig_func = self.dummy.update_policy_target_group_precommit
        self.dummy.update_policy_target_group_precommit = mock.Mock(
            side_effect=Exception)
        ptg = self.create_policy_target_group(name="ptg1")
        ptg_id = ptg['policy_target_group']['id']
        self.update_policy_target_group(ptg_id, expected_res_status=500,
                                        name="new name")
        new_ptg = self.show_policy_target_group(ptg_id,
                                                expected_res_status=200)
        self.assertEqual(ptg['policy_target_group']['name'],
                         new_ptg['policy_target_group']['name'])
        # restore mock
        self.dummy.update_policy_target_group_precommit = orig_func

    def test_policy_target_group_delete_fail(self):
        orig_func = self.dummy.delete_l3_policy_precommit
        self.dummy.delete_policy_target_group_precommit = mock.Mock(
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
        # restore mock
        self.dummy.delete_l3_policy_precommit = orig_func


class TestPolicyTarget(AIMBaseTestCase,
                       test_securitygroup.SecurityGroupsTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTarget, self).setUp(*args, **kwargs)
        cfg.CONF.set_override('path_mtu', 1000, group='ml2')
        cfg.CONF.set_override('global_physnet_mtu', 1000, None)
        cfg.CONF.set_override('advertise_mtu', True, None)

    def _doms(self, domains, with_type=True):
        if with_type:
            return [(str(dom['name']), str(dom['type']))
                    for dom in domains]
        else:
            return [str(dom['name']) for dom in domains]

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
        self.assertEqual(1, len(res['port']['security_groups']))

        self.update_policy_target(pt_id, expected_res_status=200,
                                  name="new name")
        new_pt = self.show_policy_target(pt_id, expected_res_status=200)
        self.assertEqual('new name', new_pt['policy_target']['name'])

        self.delete_policy_target(pt_id, expected_res_status=204)
        self.show_policy_target(pt_id, expected_res_status=404)
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_policy_target_segmentation_label_update(self):
        if not 'apic_segmentation_label' in self._extension_drivers:
            self.skipTest("apic_segmentation_label ED not configured")
        mock_notif = mock.Mock()
        self.driver.aim_mech_driver.notifier.port_update = mock_notif
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self.assertItemsEqual([], pt['segmentation_labels'])
        segmentation_labels = ['a=b', 'c=d']
        self._bind_port_to_host(pt['port_id'], 'h1')
        pt = self.update_policy_target(
            pt['id'], expected_res_status=200,
            segmentation_labels=segmentation_labels)['policy_target']
        self.assertItemsEqual(segmentation_labels, pt['segmentation_labels'])
        port = self._plugin.get_port(self._context, pt['port_id'])
        mock_notif.assert_called_once_with(mock.ANY, port)
        mock_notif.reset_mock()
        pt = self.update_policy_target(
            pt['id'], name='updated-pt',
            expected_res_status=200)['policy_target']
        self.assertItemsEqual(segmentation_labels, pt['segmentation_labels'])
        mock_notif.assert_not_called()

    def test_policy_target_with_default_domains(self):
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
                            aim_resource.VMMDomain(type='VMware',
                                                   name='vm3'),
                            overwrite=True)
        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt['port_id'], 'h1')

        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'])
        aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
        aim_app_profile_name = self.driver.aim_mech_driver.ap_name
        aim_epg = self.aim_mgr.get(
            self._aim_context, aim_resource.EndpointGroup(
                tenant_name=aim_tenant_name,
                app_profile_name=aim_app_profile_name, name=aim_epg_name))
        self.assertEqual(set([('vm1', 'OpenStack'),
                              ('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # move port to another host
        self._bind_port_to_host(pt['port_id'], 'h2')
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([('vm1', 'OpenStack'),
                              ('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # delete port
        self.delete_policy_target(pt['id'], expected_res_status=204)
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([('vm1', 'OpenStack'),
                              ('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))

    def test_policy_target_with_default_domains_explicit_port(self):
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
                            aim_resource.VMMDomain(type='VMware',
                                                   name='vm3'),
                            overwrite=True)
        with self.port() as port:
            port_id = port['port']['id']
            self._bind_port_to_host(port_id, 'h1')
            ptg = self.create_policy_target_group(
                name="ptg1")['policy_target_group']
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'],
                port_id=port_id)['policy_target']

            aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
                self._neutron_context.session, ptg['id'])
            aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
            aim_app_profile_name = self.driver.aim_mech_driver.ap_name
            aim_epg = self.aim_mgr.get(
                self._aim_context, aim_resource.EndpointGroup(
                    tenant_name=aim_tenant_name,
                    app_profile_name=aim_app_profile_name, name=aim_epg_name))
            self.assertEqual(set([('vm1', 'OpenStack'),
                                  ('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
            # move port to another host
            self._bind_port_to_host(pt['port_id'], 'h2')
            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([('vm1', 'OpenStack'),
                                  ('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
            # delete port
            self.delete_policy_target(pt['id'], expected_res_status=204)
            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([('vm1', 'OpenStack'),
                                  ('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))

    def test_policy_target_with_specific_domains(self):
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
                                                   domain_name='phys1',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='opflex-1',
                                                   domain_name='phys2',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)

        ptg = self.create_policy_target_group(
            name="ptg1")['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt['port_id'], 'opflex-1')

        aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'])
        aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
        aim_app_profile_name = self.driver.aim_mech_driver.ap_name
        aim_epg = self.aim_mgr.get(
            self._aim_context, aim_resource.EndpointGroup(
                tenant_name=aim_tenant_name,
                app_profile_name=aim_app_profile_name, name=aim_epg_name))
        self.assertEqual(set([('vm1', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # move port to another host
        self._bind_port_to_host(pt['port_id'], 'opflex-2')
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # create another port on a host that belongs to the same domain
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'opflex-2a')
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # delete 1st port
        self.delete_policy_target(pt['id'], expected_res_status=204)
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([('vm2', 'OpenStack')]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains,
                                        with_type=False)))
        # delete the last port
        self.delete_policy_target(pt1['id'], expected_res_status=204)
        aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.vmm_domains)))
        self.assertEqual(set([]),
                         set(self._doms(aim_epg.physical_domains)))

    def test_policy_target_with_specific_domains_explicit_port(self):
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
                                                   domain_name='phys1',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        hd_mapping = aim_infra.HostDomainMappingV2(host_name='opflex-1',
                                                   domain_name='phys2',
                                                   domain_type='PhysDom')
        self.aim_mgr.create(aim_ctx, hd_mapping)
        with self.port() as port:
            port_id = port['port']['id']
            self._bind_port_to_host(port_id, 'opflex-1')
            ptg = self.create_policy_target_group(
                name="ptg1")['policy_target_group']
            pt = self.create_policy_target(
                policy_target_group_id=ptg['id'],
                port_id=port_id)['policy_target']

            aim_epg_name = self.driver.apic_epg_name_for_policy_target_group(
                self._neutron_context.session, ptg['id'])
            aim_tenant_name = self.name_mapper.project(None, self._tenant_id)
            aim_app_profile_name = self.driver.aim_mech_driver.ap_name
            aim_epg = self.aim_mgr.get(
                self._aim_context, aim_resource.EndpointGroup(
                    tenant_name=aim_tenant_name,
                    app_profile_name=aim_app_profile_name, name=aim_epg_name))
            self.assertEqual(set([('vm1', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
            # move port to another host
            self._bind_port_to_host(port_id, 'opflex-2')
            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
        with self.port() as port1:
            # create another port on a host that belongs to the same domain
            port_id1 = port1['port']['id']
            self._bind_port_to_host(port_id1, 'opflex-2a')
            pt1 = self.create_policy_target(
                policy_target_group_id=ptg['id'],
                port_id=port_id1)['policy_target']

            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
            # delete 1st pt
            self.delete_policy_target(pt['id'], expected_res_status=204)
            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([('vm2', 'OpenStack')]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains,
                                            with_type=False)))
            # delete the last pt
            self.delete_policy_target(pt1['id'], expected_res_status=204)
            aim_epg = self.aim_mgr.get(aim_ctx, aim_epg)
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.vmm_domains)))
            self.assertEqual(set([]),
                             set(self._doms(aim_epg.physical_domains)))

    def _verify_gbp_details_assertions(self, mapping, req_mapping, port_id,
                                       expected_epg_name, expected_epg_tenant,
                                       subnet, default_route=None,
                                       map_tenant_name=True):
        self.assertEqual(mapping, req_mapping['gbp_details'])
        self.assertEqual(port_id, mapping['port_id'])
        self.assertEqual(expected_epg_name, mapping['endpoint_group_name'])
        exp_tenant = (self.name_mapper.project(None, expected_epg_tenant)
                      if map_tenant_name else expected_epg_tenant)
        self.assertEqual(exp_tenant, mapping['ptg_tenant'])
        self.assertEqual('someid', mapping['vm-name'])
        self.assertTrue(mapping['enable_dhcp_optimization'])
        self.assertFalse(mapping['enable_metadata_optimization'])
        self.assertEqual(1, len(mapping['subnets']))
        self.assertEqual(subnet['subnet']['cidr'],
                         mapping['subnets'][0]['cidr'])
        if default_route:
            self.assertTrue(
                {'destination': '0.0.0.0/0', 'nexthop': default_route} in
                mapping['subnets'][0]['host_routes'],
                "Default route missing in %s" % mapping['subnets'][0])
        # Verify Neutron details
        self.assertEqual(port_id, req_mapping['neutron_details']['port_id'])

    def _verify_vrf_details_assertions(self, vrf_mapping, expected_vrf_name,
                                       expected_l3p_id, expected_subnets,
                                       expected_vrf_tenant):
        self.assertEqual(expected_vrf_name, vrf_mapping['vrf_name'])
        self.assertEqual(expected_vrf_tenant, vrf_mapping['vrf_tenant'])
        self.assertEqual(set(expected_subnets),
                         set(vrf_mapping['vrf_subnets']))
        self.assertEqual(expected_l3p_id,
                         vrf_mapping['l3_policy_id'])

    def _setup_external_segment(self, name, dn=None):
        kwargs = {'router:external': True}
        if dn:
            kwargs[DN] = {EXTERNAL_NETWORK: dn}
        extn_attr = ('router:external', DN)

        net = self._make_network(self.fmt, name, True,
                                 arg_list=extn_attr,
                                 **kwargs)['network']
        subnet = self._make_subnet(
            self.fmt, {'network': net}, '100.100.0.1',
            '100.100.0.0/16')['subnet']
        ext_seg = self.create_external_segment(name=name,
            subnet_id=subnet['id'])['external_segment']
        return ext_seg, subnet

    def _verify_fip_details(self, mapping, fip, ext_epg_tenant,
                            ext_epg_name, ext_epg_app_profile='OpenStack'):
        self.assertEqual(1, len(mapping['floating_ip']))
        fip = copy.deepcopy(fip)
        fip['nat_epg_name'] = ext_epg_name
        fip['nat_epg_tenant'] = ext_epg_tenant
        fip['nat_epg_app_profile'] = ext_epg_app_profile
        self.assertEqual(fip, mapping['floating_ip'][0])

    def _verify_ip_mapping_details(self, mapping, ext_segment_name,
                                   ext_epg_tenant, ext_epg_name,
                                   ext_epg_app_profile='OpenStack'):
        self.assertTrue({'external_segment_name': ext_segment_name,
                         'nat_epg_name': ext_epg_name,
                         'nat_epg_app_profile': ext_epg_app_profile,
                         'nat_epg_tenant': ext_epg_tenant}
                        in mapping['ip_mapping'])

    def _verify_host_snat_ip_details(self, mapping, ext_segment_name,
                                     snat_ip, subnet_cidr):
        gw, prefix = subnet_cidr.split('/')
        self._check_ip_in_cidr(snat_ip, subnet_cidr)
        mapping['host_snat_ips'][0].pop('host_snat_ip', None)
        self.assertEqual({'external_segment_name': ext_segment_name,
                          'gateway_ip': gw,
                          'prefixlen': int(prefix)},
                         mapping['host_snat_ips'][0])

    # TODO(Kent): we should also add the ML2 related UTs for
    # get_gbp_details(). Its missing completely....
    def _do_test_get_gbp_details(self, pre_vrf=None):
        self.driver.aim_mech_driver.apic_optimized_dhcp_lease_time = 100
        es1, es1_sub = self._setup_external_segment(
            'es1', dn='uni/tn-t1/out-l1/instP-n1')
        es2, es2_sub1 = self._setup_external_segment(
            'es2', dn='uni/tn-t1/out-l2/instP-n2')
        es2_sub2 = self._make_subnet(
            self.fmt, {'network': {'id': es2_sub1['network_id'],
                                   'tenant_id': es2_sub1['tenant_id']}},
            '200.200.0.1', '200.200.0.0/16')['subnet']
        self._update('subnets', es2_sub2['id'],
                     {'subnet': {SNAT_HOST_POOL: True}})

        as_id = (self._make_address_scope_for_vrf(
            pre_vrf.dn, name='as1')['address_scope']['id']
            if pre_vrf else None)

        l3p = self.create_l3_policy(name='myl3',
            external_segments={es1['id']: [], es2['id']: []},
            address_scope_v4_id=as_id)['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        segmentation_labels = ['label1', 'label2']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'],
            segmentation_labels=segmentation_labels)['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        fip = self._make_floatingip(self.fmt, es1_sub['network_id'],
                                    port_id=pt1['port_id'])['floatingip']

        mapping = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % pt1['port_id'],
            host='h1')
        if 'apic_segmentation_label' in self._extension_drivers:
            self.assertItemsEqual(segmentation_labels,
                                  mapping['segmentation_labels'])
        req_mapping = self.driver.request_endpoint_details(
            nctx.get_admin_context(),
            request={'device': 'tap%s' % pt1['port_id'],
                     'timestamp': 0, 'request_id': 'request_id'},
            host='h1')
        epg_name = self.driver.apic_epg_name_for_policy_target_group(
            self._neutron_context.session, ptg['id'], ptg['name'])
        epg_tenant = ptg['tenant_id']
        subnet = self._get_object('subnets', ptg['subnets'][0], self.api)

        self._verify_gbp_details_assertions(
            mapping, req_mapping, pt1['port_id'], epg_name, epg_tenant, subnet)

        if pre_vrf:
            vrf_name = pre_vrf.name
            vrf_tenant = pre_vrf.tenant_name
        else:
            vrf_name = self.name_mapper.address_scope(
                None, l3p['address_scope_v4_id'])
            vrf_tenant = self.name_mapper.project(None,
                                                  self._tenant_id)
        vrf_id = '%s %s' % (vrf_tenant, vrf_name)
        prefixlist = [prefix.strip() for prefix in l3p['ip_pool'].split(',')]
        self._verify_vrf_details_assertions(
            mapping, vrf_name, vrf_id, prefixlist, vrf_tenant)

        self._verify_fip_details(mapping, fip, 't1', 'EXT-l1')
        self._verify_ip_mapping_details(mapping,
            'uni:tn-t1:out-l2:instP-n2', 't1', 'EXT-l2')
        self._verify_host_snat_ip_details(mapping,
            'uni:tn-t1:out-l2:instP-n2', '200.200.0.2', '200.200.0.1/16')

        # Create event on a second host to verify that the SNAT
        # port gets created for this second host
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt2['port_id'], 'h1')

        # As admin, create a SG in a different tenant then associate
        # with the same port
        sg = self._make_security_group(
            self.fmt, 'sg_1', 'test',
            tenant_id='test-tenant-2')['security_group']
        port = self._plugin.get_port(self._context, pt2['port_id'])
        port['security_groups'].append(sg['id'])
        port = self._plugin.update_port(
            self._context, port['id'], {'port': port})
        # Set the bad MTU through extra_dhcp_opts, it should fall back
        # to the network MTU
        data = {'port': {'extra_dhcp_opts': [{'opt_name': '26',
                                              'opt_value': 'garbage'}]}}
        port = self._update('ports', port['id'], data)['port']
        mapping = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % pt2['port_id'],
            host='h2')
        self.assertEqual(pt2['port_id'], mapping['port_id'])
        self._verify_ip_mapping_details(mapping,
            'uni:tn-t1:out-l1:instP-n1', 't1', 'EXT-l1')
        self._verify_ip_mapping_details(mapping,
            'uni:tn-t1:out-l2:instP-n2', 't1', 'EXT-l2')
        self._verify_host_snat_ip_details(mapping,
            'uni:tn-t1:out-l2:instP-n2', '200.200.0.3', '200.200.0.1/16')
        self.assertEqual(1000, mapping['interface_mtu'])
        self.assertEqual(100, mapping['dhcp_lease_time'])
        sg_list = []
        ctx = nctx.get_admin_context()
        port_sgs = (ctx.session.query(sg_models.SecurityGroup.id,
                                      sg_models.SecurityGroup.tenant_id).
                    filter(sg_models.SecurityGroup.id.
                           in_(port['security_groups'])).
                    all())
        for sg_id, tenant_id in port_sgs:
            sg_tenant = self.name_mapper.project(None, tenant_id)
            sg_list.append(
                {'policy-space': sg_tenant,
                 'name': sg_id})
        sg_list.append({'policy-space': 'common',
                        'name': self.driver.aim_mech_driver.apic_system_id +
                        '_DefaultSecurityGroup'})
        self.assertEqual(sg_list, mapping['security_group'])
        # Set the right MTU through extra_dhcp_opts
        data = {'port': {'extra_dhcp_opts': [{'opt_name': 'interface-mtu',
                                              'opt_value': '2000'}]}}
        port = self._update('ports', port['id'], data)['port']
        mapping = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % pt2['port_id'],
            host='h2')
        self.assertEqual(2000, mapping['interface_mtu'])

    def _do_test_gbp_details_no_pt(self, use_as=True, routed=True,
                                   pre_vrf=None):
        # Create port and bind it
        address_scope = self._make_address_scope_for_vrf(
            pre_vrf.dn if pre_vrf else None,
            name='as1')['address_scope']
        kargs = {}
        if use_as:
            kargs['address_scope_id'] = address_scope['id']
        subnetpool = self._make_subnetpool(
            self.fmt, ['10.10.0.0/26', '1.1.0.0/16'],
            name='as1', tenant_id=self._tenant_id, **kargs)['subnetpool']
        self._make_subnetpool(
            self.fmt, ['2.1.0.0/16'],
            name='as2', address_scope_id=address_scope['id'],
            tenant_id=self._tenant_id)

        ext_net1, router1, _ = self._setup_external_network(
            'l1', dn='uni/tn-t1/out-l1/instP-n1')
        ext_net2, router2, _ = self._setup_external_network(
            'l2', dn='uni/tn-t1/out-l2/instP-n2')
        ext_net2_sub2 = self._make_subnet(
            self.fmt, {'network': ext_net2}, '200.200.0.1',
            '200.200.0.0/16')['subnet']
        self._update('subnets', ext_net2_sub2['id'],
                     {'subnet': {SNAT_HOST_POOL: True}})
        self.assertTrue(
            n_utils.is_extension_supported(self._l3_plugin,
                                           dns.Dns.get_alias()))
        network = self._make_network(self.fmt, 'net1', True,
                                     arg_list=('dns_domain',),
                                     dns_domain='mydomain.')
        with self.subnet(network=network, cidr='1.1.2.0/24',
                         subnetpool_id=subnetpool['id']) as subnet:
            if routed:
                self.l3_plugin.add_router_interface(
                    nctx.get_admin_context(), router1['id'],
                    {'subnet_id': subnet['subnet']['id']})
            with self.port(subnet=subnet) as intf_port:
                if routed:
                    self.l3_plugin.add_router_interface(
                        nctx.get_admin_context(), router2['id'],
                        {'port_id': intf_port['port']['id']})
            with self.port(subnet=subnet) as port:
                port_id = port['port']['id']
                network = network['network']
                if routed:
                    fip = self.l3_plugin.create_floatingip(
                        nctx.get_admin_context(),
                        {'floatingip': {'floating_network_id':
                                        ext_net1['id'],
                                        'tenant_id': network['tenant_id'],
                                        'port_id': port_id}})

                self._bind_port_to_host(port_id, 'h1')
                mapping = self.driver.get_gbp_details(
                    self._neutron_admin_context, device='tap%s' % port_id,
                    host='h1')
                self.assertEqual('mydomain.', mapping['dns_domain'])
                req_mapping = self.driver.request_endpoint_details(
                    nctx.get_admin_context(),
                    request={'device': 'tap%s' % port_id,
                             'timestamp': 0, 'request_id': 'request_id'},
                    host='h1')
                if not routed:
                    vrf_name = ('%s_UnroutedVRF' %
                                self.driver.aim_mech_driver.apic_system_id)
                    vrf_tenant = 'common'
                elif use_as and pre_vrf:
                    vrf_name = pre_vrf.name
                    vrf_tenant = pre_vrf.tenant_name
                else:
                    vrf_name = (self.name_mapper.address_scope(
                                    None, address_scope['id'])
                                if use_as else 'DefaultVRF')
                    vrf_tenant = self.name_mapper.project(None,
                                                          self._tenant_id)
                vrf_id = '%s %s' % (vrf_tenant, vrf_name)
                vrf_mapping = self.driver.get_vrf_details(
                    self._neutron_admin_context, vrf_id=vrf_id)

                epg_name = self.name_mapper.network(
                    self._neutron_context.session, network['id'])
                epg_tenant = network['tenant_id']

                self._verify_gbp_details_assertions(
                    mapping, req_mapping, port_id, epg_name, epg_tenant,
                    subnet, default_route='1.1.2.1')
                supernet = ['1.1.2.0/24']
                if use_as:
                    supernet = ['10.10.0.0/26', '1.1.0.0/16', '2.1.0.0/16']
                self._verify_vrf_details_assertions(
                    mapping, vrf_name, vrf_id, supernet, vrf_tenant)
                self._verify_vrf_details_assertions(
                    vrf_mapping, vrf_name, vrf_id, supernet, vrf_tenant)
                if routed:
                    self._verify_fip_details(mapping, fip, 't1', 'EXT-l1')
                    self._verify_ip_mapping_details(mapping,
                        'uni:tn-t1:out-l2:instP-n2', 't1', 'EXT-l2')
                    self._verify_host_snat_ip_details(mapping,
                        'uni:tn-t1:out-l2:instP-n2', '200.200.0.2',
                        '200.200.0.1/16')
                else:
                    self.assertFalse(mapping['floating_ip'])
                    self.assertFalse(mapping['ip_mapping'])
                    self.assertFalse(mapping['host_snat_ips'])
                self.assertEqual(1000, mapping['interface_mtu'])
                # Set the right MTU through extra_dhcp_opts
                data = {'port': {'extra_dhcp_opts': [{'opt_name': '26',
                                                      'opt_value': '2100'}]}}
                port = self._update('ports', port_id, data)['port']
                mapping = self.driver.get_gbp_details(
                    self._neutron_admin_context, device='tap%s' % port_id,
                    host='h1')
                self.assertEqual(2100, mapping['interface_mtu'])

    def test_get_gbp_details(self):
        self._do_test_get_gbp_details()

    def test_get_gbp_details_pre_existing_vrf(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        vrf = self.aim_mgr.create(
            aim_ctx, aim_resource.VRF(tenant_name='common', name='ctx1',
                                      monitored=True))
        self._do_test_get_gbp_details(pre_vrf=vrf)

    def test_get_gbp_details_no_pt(self):
        # Test that traditional Neutron ports behave correctly from the
        # RPC perspective
        self._do_test_gbp_details_no_pt()

    def test_get_gbp_details_no_pt_pre_existing_vrf(self):
        aim_ctx = aim_context.AimContext(self.db_session)
        vrf = self.aim_mgr.create(
            aim_ctx, aim_resource.VRF(tenant_name='common', name='ctx1',
                                      monitored=True))
        self._do_test_gbp_details_no_pt(pre_vrf=vrf)

    def test_get_gbp_details_no_pt_no_as(self):
        self._do_test_gbp_details_no_pt(use_as=False)

    def test_get_gbp_details_no_pt_no_as_unrouted(self):
        self._do_test_gbp_details_no_pt(use_as=False, routed=False)

    def test_gbp_details_ext_net_no_pt(self):
        # Test ports created on Neutron external networks
        ext_net1, _, sn1 = self._setup_external_network(
            'l1', dn='uni/tn-common/out-l1/instP-n1')
        sn1 = {'subnet': sn1}
        ext_net2, _, sn2 = self._setup_external_network(
            'l2', dn='uni/tn-t1/out-l2/instP-n2')
        sn2 = {'subnet': sn2}
        # create unmanaged BDs in the VRF connected to L3outs
        aim_ctx = aim_context.AimContext(self.db_session)
        self.aim_mgr.create(
            aim_ctx, aim_resource.BridgeDomain(tenant_name='common',
                                               name='extra_bd_in_common-l1',
                                               vrf_name='EXT-l1'))
        self.aim_mgr.create(
            aim_ctx, aim_resource.BridgeDomain(tenant_name='t1',
                                               name='extra_bd_in_t1-l1',
                                               vrf_name='EXT-l1'))
        self.aim_mgr.create(
            aim_ctx, aim_resource.BridgeDomain(tenant_name='t1',
                                               name='extra_bd_in_t1-l2',
                                               vrf_name='EXT-l2'))

        with self.port(subnet=sn1) as port:
            port_id = port['port']['id']
            self._bind_port_to_host(port_id, 'h1')
            sn1_1 = self._make_subnet(self.fmt, {'network': ext_net1},
                                      '200.200.0.1', '200.200.0.0/16')

            mapping = self.driver.get_gbp_details(
                self._neutron_admin_context, device='tap%s' % port_id,
                host='h1')
            req_mapping = self.driver.request_endpoint_details(
                self._neutron_admin_context,
                request={'device': 'tap%s' % port_id,
                         'timestamp': 0, 'request_id': 'request_id'},
                host='h1')
            self._verify_gbp_details_assertions(
                mapping, req_mapping, port_id, "EXT-l1", "common", sn1,
                map_tenant_name=False)

            vrf_id = '%s %s' % ("common", "openstack_EXT-l1")
            vrf_mapping = self.driver.get_vrf_details(
                    self._neutron_admin_context, vrf_id=vrf_id)

            supernet = [sn1['subnet']['cidr'], sn1_1['subnet']['cidr']]
            self._verify_vrf_details_assertions(
                mapping, "openstack_EXT-l1", vrf_id, supernet, "common")
            self._verify_vrf_details_assertions(
                vrf_mapping, "openstack_EXT-l1", vrf_id, supernet, "common")

        with self.port(subnet=sn2) as port:
            port_id = port['port']['id']
            self._bind_port_to_host(port_id, 'h1')
            sn2_1 = self._make_subnet(self.fmt, {'network': ext_net2},
                                      '250.250.0.1', '250.250.0.0/16')

            mapping = self.driver.get_gbp_details(
                self._neutron_admin_context, device='tap%s' % port_id,
                host='h1')
            req_mapping = self.driver.request_endpoint_details(
                nctx.get_admin_context(),
                request={'device': 'tap%s' % port_id,
                         'timestamp': 0, 'request_id': 'request_id'},
                host='h1')
            self._verify_gbp_details_assertions(
                mapping, req_mapping, port_id, "EXT-l2", "t1", sn2,
                map_tenant_name=False)

            vrf_id = '%s %s' % ("t1", "EXT-l2")
            vrf_mapping = self.driver.get_vrf_details(
                self._neutron_admin_context, vrf_id=vrf_id)

            supernet = [sn2['subnet']['cidr'], sn2_1['subnet']['cidr']]
            self._verify_vrf_details_assertions(
                mapping, "EXT-l2", vrf_id, supernet, "t1")
            self._verify_vrf_details_assertions(
                vrf_mapping, "EXT-l2", vrf_id, supernet, "t1")

    def test_ip_address_owner_update(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(name='myl2',
                                    l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        net_id = l2p['network_id']

        pt1 = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg['id'])['policy_target']
        pt2 = self.create_policy_target(name="pt2",
            policy_target_group_id=ptg['id'])['policy_target']
        self._bind_port_to_host(pt1['port_id'], 'h1')
        self._bind_port_to_host(pt2['port_id'], 'h2')

        ip_owner_info = {'port': pt1['port_id'], 'ip_address_v4': '1.2.3.4'}
        self.driver.aim_mech_driver._notify_port_update = mock.Mock()

        # set new owner
        self.driver.ip_address_owner_update(self._context,
            ip_owner_info=ip_owner_info, host='h1')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', net_id)

        self.assertEqual(pt1['port_id'], obj['port_id'])
        self.driver.aim_mech_driver._notify_port_update.assert_called_with(
            mock.ANY, pt1['port_id'])

        # update existing owner
        self.driver.aim_mech_driver._notify_port_update.reset_mock()
        ip_owner_info['port'] = pt2['port_id']
        self.driver.ip_address_owner_update(self._context,
            ip_owner_info=ip_owner_info, host='h2')
        obj = self.driver.ha_ip_handler.get_port_for_ha_ipaddress(
            '1.2.3.4', net_id)
        self.assertEqual(pt2['port_id'], obj['port_id'])
        exp_calls = [
            mock.call(mock.ANY, pt1['port_id']),
            mock.call(mock.ANY, pt2['port_id'])]
        self._check_call_list(exp_calls,
            self.driver.aim_mech_driver._notify_port_update.call_args_list)

    def test_bind_port_with_allowed_vm_names(self):
        allowed_vm_names = ['safe_vm*', '^secure_vm*']
        l3p = self.create_l3_policy(name='myl3',
            allowed_vm_names=allowed_vm_names)['l3_policy']
        l2p = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']

        nova_client = mock.patch(
            'gbpservice.neutron.services.grouppolicy.drivers.cisco.'
            'apic.nova_client.NovaClient.get_server').start()
        vm = mock.Mock()
        vm.name = 'secure_vm1'
        nova_client.return_value = vm
        newp1 = self._bind_port_to_host(pt['port_id'], 'h1')
        self.assertEqual(newp1['port']['binding:vif_type'], 'ovs')

        # bind again
        vm.name = 'bad_vm1'
        newp1 = self._bind_port_to_host(pt['port_id'], 'h2')
        self.assertEqual(newp1['port']['binding:vif_type'], 'binding_failed')

        # update l3p with empty allowed_vm_names
        l3p = self.update_l3_policy(l3p['id'], tenant_id=l3p['tenant_id'],
                                    allowed_vm_names=[],
                                    expected_res_status=200)['l3_policy']
        newp1 = self._bind_port_to_host(pt['port_id'], 'h3')
        self.assertEqual(newp1['port']['binding:vif_type'], 'ovs')


class TestPolicyTargetDvs(AIMBaseTestCase):

    def setUp(self):
        super(TestPolicyTargetDvs, self).setUp()
        self.driver.aim_mech_driver._dvs_notifier = mock.MagicMock()
        self.driver.aim_mech_driver.dvs_notifier.bind_port_call = mock.Mock(
            return_value={'key': BOOKED_PORT_VALUE})

    def _verify_dvs_notifier(self, notifier, port, host):
            # can't use getattr() with mock, so use eval instead
            try:
                dvs_mock = eval('self.driver.aim_mech_driver.dvs_notifier.' +
                                notifier)
            except Exception:
                self.assertTrue(False,
                                "The method " + notifier + " was not called")
                return

            self.assertTrue(dvs_mock.called)
            a1, a2, a3, a4 = dvs_mock.call_args[0]
            self.assertEqual(a1['id'], port['id'])
            if notifier != 'delete_port_call':
                self.assertEqual(a2['id'], port['id'])
            self.assertEqual(a4, host)

    def _pg_name(self, project, profile, network):
        return ('prj_' + str(project) + '|' + str(profile) + '|' + network)

    def test_bind_port_dvs(self):
        self.agent_conf = AGENT_CONF_DVS
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp1 = self._bind_port_to_host(pt['port_id'], 'h1')
        vif_details = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_details.get('dvs_port_group_name'))
        pg = self._pg_name(ptg['tenant_id'],
                           self.driver.aim_mech_driver.ap_name, ptg['id'])
        self.assertEqual(pg, vif_details.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        self._verify_dvs_notifier('update_postcommit_port_call',
                                  newp1['port'], 'h1')
        self.delete_policy_target(pt['id'], expected_res_status=204)
        self._verify_dvs_notifier('delete_port_call', newp1['port'], 'h1')

    def test_bind_port_dvs_with_opflex_different_hosts(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        self.agent_conf = AGENT_CONF
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp2 = self._bind_port_to_host(pt2['port_id'], 'h2')
        vif_details = newp2['port']['binding:vif_details']
        self.assertIsNone(vif_details.get('dvs_port_group_name'))
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self.agent_conf = AGENT_CONF_DVS
        self.driver.aim_mech_driver.dvs_notifier.reset_mock()
        newp1 = self._bind_port_to_host(pt1['port_id'], 'h2')
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        vif_details = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_details.get('dvs_port_group_name'))
        pg = self._pg_name(ptg['tenant_id'],
                           self.driver.aim_mech_driver.ap_name, ptg['id'])
        self.assertEqual(pg, vif_details.get('dvs_port_group_name'))
        self._verify_dvs_notifier('update_postcommit_port_call',
                                  newp1['port'], 'h2')
        self.delete_policy_target(pt1['id'], expected_res_status=204)
        self._verify_dvs_notifier('delete_port_call', newp1['port'], 'h2')

    def test_bind_ports_opflex_same_host(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']

        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp1 = self._bind_port_to_host(pt1['port_id'], 'h1')
        vif_details = newp1['port']['binding:vif_details']
        self.assertIsNone(vif_details.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock = self.driver.aim_mech_driver.dvs_notifier
        dvs_mock.update_postcommit_port_call.assert_not_called()
        self.delete_policy_target(pt1['id'], expected_res_status=204)
        dvs_mock.delete_port_call.assert_not_called()
        self.driver.aim_mech_driver.dvs_notifier.reset_mock()

        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp2 = self._bind_port_to_host(pt2['port_id'], 'h1')
        vif_details = newp2['port']['binding:vif_details']
        self.assertIsNone(vif_details.get('dvs_port_group_name'))
        port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock.assert_not_called()
        self.delete_policy_target(pt2['id'], expected_res_status=204)
        dvs_mock.assert_not_called()

    def test_bind_ports_dvs_with_opflex_same_host(self):
        self.agent_conf = AGENT_CONF_DVS
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        l2p = self.create_l2_policy(
            name='myl2', l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            name="ptg1", l2_policy_id=l2p['id'])['policy_target_group']
        pt1 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp1 = self._bind_port_to_host(pt1['port_id'], 'h1')
        vif_details = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_details.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        self._verify_dvs_notifier('update_postcommit_port_call',
                                  newp1['port'], 'h1')
        self.delete_policy_target(pt1['id'], expected_res_status=204)
        self._verify_dvs_notifier('delete_port_call', newp1['port'], 'h1')
        self.driver.aim_mech_driver.dvs_notifier.reset_mock()

        self.agent_conf = AGENT_CONF
        pt2 = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp2 = self._bind_other_port_to_host(pt2['port_id'], 'h1')
        vif_details = newp2['port']['binding:vif_details']
        self.assertIsNone(vif_details.get('dvs_port_group_name'))
        port_key = newp2['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNone(port_key)
        dvs_mock = self.driver.aim_mech_driver.dvs_notifier
        dvs_mock.update_postcommit_port_call.assert_not_called()
        self.delete_policy_target(pt2['id'], expected_res_status=204)
        dvs_mock.delete_port_call.assert_not_called()

    def test_bind_port_dvs_shared(self):
        self.agent_conf = AGENT_CONF_DVS
        ptg = self.create_policy_target_group(shared=True,
            name="ptg1")['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        newp1 = self._bind_port_to_host(pt['port_id'], 'h1')
        vif_details = newp1['port']['binding:vif_details']
        self.assertIsNotNone(vif_details.get('dvs_port_group_name'))
        pg = self._pg_name(ptg['tenant_id'],
                           self.driver.aim_mech_driver.ap_name, ptg['id'])
        self.assertEqual(pg, vif_details.get('dvs_port_group_name'))
        port_key = newp1['port']['binding:vif_details'].get('dvs_port_key')
        self.assertIsNotNone(port_key)
        self.assertEqual(port_key, BOOKED_PORT_VALUE)
        self._verify_dvs_notifier('update_postcommit_port_call',
                                  newp1['port'], 'h1')
        self.delete_policy_target(pt['id'], expected_res_status=204)
        self._verify_dvs_notifier('delete_port_call', newp1['port'], 'h1')


class TestPolicyTargetRollback(AIMBaseTestCase):

    def test_policy_target_create_fail(self):
        orig_func = self.dummy.create_policy_target_precommit
        self.dummy.create_policy_target_precommit = mock.Mock(
            side_effect=Exception)
        ptg_id = self.create_policy_target_group(
            name="ptg1")['policy_target_group']['id']
        ports = self._plugin.get_ports(self._context)
        self.create_policy_target(name="pt1",
                                  policy_target_group_id=ptg_id,
                                  expected_res_status=500)
        self.assertEqual([],
                         self._gbp_plugin.get_policy_targets(self._context))
        new_ports = self._plugin.get_ports(self._context)
        self.assertItemsEqual(ports, new_ports)
        # restore mock
        self.dummy.create_policy_target_precommit = orig_func

    def test_policy_target_update_fail(self):
        orig_func = self.dummy.update_policy_target_precommit
        self.dummy.update_policy_target_precommit = mock.Mock(
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
        # restore mock
        self.dummy.update_policy_target_precommit = orig_func

    def test_policy_target_delete_fail(self):
        orig_func = self.dummy.delete_policy_target_precommit
        self.dummy.delete_policy_target_precommit = mock.Mock(
            side_effect=Exception)
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
        # restore mock
        self.dummy.delete_policy_target_precommit = orig_func


class TestPolicyRuleBase(AIMBaseTestCase):

    def _validate_filter_entry(self, policy_rule, afilter, filter_entry):
        filter_entry_name = 'os-entry-0'
        self.assertEqual(filter_entry_name, filter_entry.name)
        pc = self.show_policy_classifier(
            policy_rule['policy_classifier_id'])['policy_classifier']
        expected_entries = alib.get_filter_entries_for_policy_classifier(pc)
        if 'reverse' in afilter.name:
            del expected_entries['forward_rules']
        else:
            del expected_entries['reverse_rules']

        expected_filter_entry = self.driver._aim_filter_entry(
            self._neutron_context.session, afilter, filter_entry_name,
            alib.map_to_aim_filter_entry(
                expected_entries.items()[0][1].items()[0][1]))

        self.assertItemsEqual(
            aim_object_to_dict(expected_filter_entry),
            # special processing to convert unicode to str
            dict((str(k), str(v)) for k, v in aim_object_to_dict(
                                                    filter_entry).items()))

    def _validate_1_to_many_reverse_filter_entries(
            self, policy_rule, afilter, filter_entries):
        pc = self.show_policy_classifier(
            policy_rule['policy_classifier_id'])['policy_classifier']
        expected_entries = alib.get_filter_entries_for_policy_classifier(pc)

        for e_name, value in expected_entries['reverse_rules'].items():
            expected_filter_entry = self.driver._aim_filter_entry(
                    self._neutron_context.session, afilter, e_name,
                    alib.map_to_aim_filter_entry(value))
            filter_entry = (
                entry for entry in filter_entries if entry.name == e_name
                           ).next()
            self.assertItemsEqual(
                    aim_object_to_dict(expected_filter_entry),
                    # special processing to convert unicode to str
                    dict((str(k), str(v)) for k, v in aim_object_to_dict(
                        filter_entry).items()))

    def _test_policy_rule_aim_mapping(self, policy_rule):
        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, policy_rule['id']))
        filter_names = [aim_filter_name]
        protocol = self.show_policy_classifier(
            policy_rule['policy_classifier_id'])[
                'policy_classifier']['protocol']
        if protocol in alib.REVERSIBLE_PROTOCOLS:
            aim_reverse_filter_name = str(self.name_mapper.policy_rule(
                self._neutron_context.session, policy_rule['id'],
                prefix=alib.REVERSE_PREFIX))
            filter_names.append(aim_reverse_filter_name)
        aim_tenant_name = md.COMMON_TENANT_NAME
        filter_entries, aim_obj_list = [], []
        for filter_name in filter_names:
            aim_filters = self.aim_mgr.find(
                self._aim_context, aim_resource.Filter, name=filter_name)
            aim_obj_list.append(aim_filters[0])
            self.assertEqual(1, len(aim_filters))
            self.assertEqual(filter_name, aim_filters[0].name)
            self.assertEqual(aim_tenant_name, aim_filters[0].tenant_name)
            pr_display_name = policy_rule['name'].replace(' ', '_')
            self.assertEqual(pr_display_name, aim_filters[0].display_name)
            aim_filter_entries = self.aim_mgr.find(
                self._aim_context, aim_resource.FilterEntry,
                tenant_name=aim_filters[0].tenant_name,
                filter_name=aim_filters[0].name)
            if protocol == 'tcp' or protocol == 'udp' or not (
                    filter_name.startswith('reverse')):
                # this will also check the forward entries for
                # icmp and no protocol case
                self.assertEqual(1, len(aim_filter_entries))
                self._validate_filter_entry(policy_rule, aim_filters[0],
                                            aim_filter_entries[0])
            elif protocol == 'icmp':
                # this is only for reverse entries with ICMP
                self.assertEqual(4, len(aim_filter_entries))
                self._validate_1_to_many_reverse_filter_entries(
                        policy_rule, aim_filters[0], aim_filter_entries)
            else:
                # this is only for reverse entries when no protocol
                # is specified. One entry for TCP, one for UDP and
                # four entries for ICMP
                self.assertEqual(6, len(aim_filter_entries))
                self._validate_1_to_many_reverse_filter_entries(
                        policy_rule, aim_filters[0], aim_filter_entries)
            filter_entries.append(aim_filter_entries[0])
        aim_obj_list.extend(filter_entries)
        self.assertEqual(
            filter_entries[0].dn,
            policy_rule[DN]['Forward-FilterEntries'][0])
        if len(filter_names) > 1:
            self.assertEqual(
                filter_entries[1].dn, policy_rule[
                    DN]['Reverse-FilterEntries'][0])

        merged_status = self._gbp_plugin.policy_driver_manager.policy_drivers[
            'aim_mapping'].obj._merge_aim_status(self._neutron_context.session,
                                                 aim_obj_list)
        self.assertEqual(merged_status, policy_rule['status'])

    def _test_policy_rule_delete_aim_mapping(self, policy_rule):
        aim_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, policy_rule['id']))
        aim_reverse_filter_name = str(self.name_mapper.policy_rule(
            self._neutron_context.session, policy_rule['id'],
            prefix=alib.REVERSE_PREFIX))

        for filter_name in [aim_filter_name, aim_reverse_filter_name]:
            aim_filters = self.aim_mgr.find(
                self._aim_context, aim_resource.Filter, name=filter_name)
            self.assertEqual(0, len(aim_filters))


class TestPolicyRule(TestPolicyRuleBase):

    def _test_policy_classifier_update(self, pr):
        orig_pc_id = pr['policy_classifier_id']
        pc = self.create_policy_classifier(
            direction='in', protocol='tcp', port_range=80)['policy_classifier']
        new_pr = self.update_policy_rule(
            pr['id'], expected_res_status=200,
            policy_classifier_id=pc['id'])['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        prs = self.create_policy_rule_set(
            name="ctr", policy_rules=[new_pr['id']])[
                'policy_rule_set']
        self._validate_policy_rule_set_aim_mapping(prs, [new_pr])

        # Remove Classifier port
        self.update_policy_classifier(pc['id'], port_range=None)
        new_pr = self.update_policy_rule(
            pr['id'], expected_res_status=200,
            policy_classifier_id=pc['id'])['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        # Change direction
        self.update_policy_classifier(pc['id'], direction='out')
        new_pr = self.update_policy_rule(
            pr['id'], expected_res_status=200,
            policy_classifier_id=pc['id'])['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        # Check with protocol that does not require reverse filter
        self.update_policy_classifier(pc['id'], protocol=None)
        new_pr = self.update_policy_rule(
            pr['id'], expected_res_status=200,
            policy_classifier_id=pc['id'])['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        self.delete_policy_rule_set(prs['id'], expected_res_status=204)

        new_pr = self.update_policy_rule(
            pr['id'], expected_res_status=200,
            policy_classifier_id=orig_pc_id)['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        self.delete_policy_classifier(pc['id'], expected_res_status=204)

    def _test_policy_rule_lifecycle(self, protocol, direction):
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        if protocol == 'ANY':
            classifier = self.create_policy_classifier(
                direction=direction)['policy_classifier']
        elif protocol in ['TCP', 'UDP']:
            classifier = self.create_policy_classifier(
                protocol=protocol, port_range="22",
                direction=direction)['policy_classifier']
        else:
            classifier = self.create_policy_classifier(
                protocol='ICMP',
                direction=direction)['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']
        pr_name = pr['name']
        self.show_policy_rule(pr_id, expected_res_status=200)

        self._test_policy_rule_aim_mapping(pr)

        pr_name = 'new name'
        new_pr = self.update_policy_rule(pr_id, expected_res_status=200,
                                         name=pr_name)['policy_rule']
        self._test_policy_rule_aim_mapping(new_pr)

        self._test_policy_classifier_update(new_pr)

        self.delete_policy_rule(pr_id, expected_res_status=204)
        self.show_policy_rule(pr_id, expected_res_status=404)

        self._test_policy_rule_delete_aim_mapping(new_pr)

    def test_policy_rule_lifecycle_tcp_in(self):
        self._test_policy_rule_lifecycle(protocol='TCP', direction='in')

    def test_policy_rule_lifecycle_tcp_out(self):
        self._test_policy_rule_lifecycle(protocol='TCP', direction='out')

    def test_policy_rule_lifecycle_tcp_bi(self):
        self._test_policy_rule_lifecycle(protocol='TCP', direction='bi')

    def test_policy_rule_lifecycle_icmp_in(self):
        self._test_policy_rule_lifecycle(protocol='ICMP', direction='in')

    def test_policy_rule_lifecycle_icmp_out(self):
        self._test_policy_rule_lifecycle(protocol='ICMP', direction='out')

    def test_policy_rule_lifecycle_icmp_bi(self):
        self._test_policy_rule_lifecycle(protocol='ICMP', direction='bi')

    def test_policy_rule_lifecycle_udp_in(self):
        self._test_policy_rule_lifecycle(protocol='UDP', direction='in')

    def test_policy_rule_lifecycle_udp_out(self):
        self._test_policy_rule_lifecycle(protocol='UDP', direction='out')

    def test_policy_rule_lifecycle_udp_bi(self):
        self._test_policy_rule_lifecycle(protocol='UDP', direction='bi')

    def test_policy_rule_lifecycle_any_in(self):
        self._test_policy_rule_lifecycle(protocol='ANY', direction='in')

    def test_policy_rule_lifecycle_any_out(self):
        self._test_policy_rule_lifecycle(protocol='ANY', direction='out')

    def test_policy_rule_lifecycle_any_bi(self):
        self._test_policy_rule_lifecycle(protocol='ANY', direction='bi')


class TestPolicyRuleRollback(TestPolicyRuleBase):

    def test_policy_rule_create_fail(self):
        orig_func = self.dummy.create_policy_rule_precommit
        self.dummy.create_policy_rule_precommit = mock.Mock(
            side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']], expected_res_status=500)

        self.assertEqual([],
                         self._gbp_plugin.get_policy_rules(self._context))
        aim_filters = self.aim_mgr.find(
            self._aim_context, aim_resource.Filter)
        self.assertEqual(1, len(aim_filters))
        aim_filter_entries = self.aim_mgr.find(
            self._aim_context, aim_resource.FilterEntry)
        self.assertEqual(1, len(aim_filter_entries))
        # restore mock
        self.dummy.create_policy_rule_precommit = orig_func

    def test_policy_rule_update_fail(self):
        orig_func = self.dummy.update_policy_rule_precommit
        self.dummy.update_policy_rule_precommit = mock.Mock(
            side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        self._test_policy_rule_aim_mapping(pr)

        self.update_policy_rule(pr['id'], expected_res_status=500,
                                name='new name')
        self._test_policy_rule_aim_mapping(pr)

        # restore mock
        self.dummy.update_policy_rule_precommit = orig_func

    def test_policy_rule_delete_fail(self):
        orig_func = self.dummy.delete_policy_rule_precommit
        self.dummy.delete_policy_rule_precommit = mock.Mock(
            side_effect=Exception)
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']

        self.delete_policy_rule(pr_id, expected_res_status=500)
        self._test_policy_rule_aim_mapping(pr)

        # restore mock
        self.dummy.delete_policy_rule_precommit = orig_func


class TestPolicyRuleSet(AIMBaseTestCase):

    def test_policy_rule_set_lifecycle(self):
        rules = self._create_3_direction_rules()
        prs = self.create_policy_rule_set(
            name="ctr", policy_rules=[x['id'] for x in rules])[
                'policy_rule_set']
        self._validate_policy_rule_set_aim_mapping(prs, rules)

        # update directions of policy classifiers
        for r in rules:
            pc = self.show_policy_classifier(
                    r['policy_classifier_id'])['policy_classifier']
            if pc['direction'] == 'in':
                new_direction = 'bi'
            elif pc['direction'] == 'out':
                new_direction = 'in'
            else:
                new_direction = 'out'
            self.update_policy_classifier(pc['id'],
                                          direction=new_direction)
        self._validate_policy_rule_set_aim_mapping(prs, rules)

        new_rules = self._create_3_direction_rules()
        prs = self.update_policy_rule_set(
            prs['id'], policy_rules=[x['id'] for x in new_rules],
            expected_res_status=200)['policy_rule_set']
        self._validate_policy_rule_set_aim_mapping(prs, new_rules)

        self.delete_policy_rule_set(prs['id'], expected_res_status=204)


class TestPolicyRuleSetRollback(AIMBaseTestCase):

    def test_policy_rule_set_create_fail(self):
        orig_func = self.dummy.create_policy_rule_set_precommit
        self.dummy.create_policy_rule_set_precommit = mock.Mock(
            side_effect=Exception)
        rules = self._create_3_direction_rules()
        self.create_policy_rule_set(
            name="ctr", policy_rules=[x['id'] for x in rules],
            expected_res_status=500)

        self.assertEqual(
            [], self._gbp_plugin.get_policy_rule_sets(self._context))
        aim_contracts = self.aim_mgr.find(
            self._aim_context, aim_resource.Contract)
        self.assertEqual(0, len(aim_contracts))
        aim_contract_subjects = self.aim_mgr.find(
            self._aim_context, aim_resource.ContractSubject)
        self.assertEqual(0, len(aim_contract_subjects))
        # restore mock
        self.dummy.create_policy_rule_set_precommit = orig_func

    def test_policy_rule_set_update_fail(self):
        orig_func = self.dummy.update_policy_rule_set_precommit
        self.dummy.update_policy_rule_set_precommit = mock.Mock(
            side_effect=Exception)
        rules = self._create_3_direction_rules()
        prs = self.create_policy_rule_set(
            name="ctr", policy_rules=[x['id'] for x in rules])[
                'policy_rule_set']

        self.update_policy_rule_set(
            prs['id'], expected_res_status=500, name='new name')

        self._validate_policy_rule_set_aim_mapping(prs, rules)

        # restore mock
        self.dummy.update_policy_rule_set_precommit = orig_func

    def test_policy_rule_set_delete_fail(self):
        orig_func = self.dummy.delete_policy_rule_set_precommit
        self.dummy.delete_policy_rule_set_precommit = mock.Mock(
            side_effect=Exception)
        rules = self._create_3_direction_rules()
        prs = self.create_policy_rule_set(
            name="ctr", policy_rules=[x['id'] for x in rules])[
                'policy_rule_set']

        self.delete_policy_rule_set(prs['id'], expected_res_status=500)

        self._validate_policy_rule_set_aim_mapping(prs, rules)

        # restore mock
        self.dummy.delete_policy_rule_set_precommit = orig_func


class NotificationTest(AIMBaseTestCase):

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              l3_plugin=None, sc_plugin=None, **kwargs):
        self.fake_uuid = 0
        self.mac_prefix = '12:34:56:78:5d:'
        self.queue_notification_call_count = 0
        self.max_notification_queue_length = 0
        self.notification_queue = None
        self.post_notifications_from_queue_call_count = 0
        self.orig_generate_uuid = uuidutils.generate_uuid
        self.orig_is_uuid_like = uuidutils.is_uuid_like

        # The following three functions are patched so that
        # the same worflow can be run more than once in a single
        # test and will result in objects created that are
        # identical in all their attribute values.
        # The workflow is exercised once with batching turned
        # OFF, and once with batching turned ON.
        def generate_uuid():
            self.fake_uuid += 1
            return str(self.fake_uuid)

        def is_uuid_like(val):
            return True

        def _generate_mac():
            lsb = 10 + self.fake_uuid
            return self.mac_prefix + str(lsb)

        uuidutils.generate_uuid = generate_uuid
        uuidutils.is_uuid_like = is_uuid_like

        super(NotificationTest, self).setUp(
            policy_drivers=policy_drivers, core_plugin=core_plugin,
            ml2_options=ml2_options, l3_plugin=l3_plugin,
            sc_plugin=sc_plugin, **kwargs)
        self.orig_generate_mac = self._plugin._generate_mac
        self._plugin._generate_mac = _generate_mac

        self.orig_enqueue = local_api._enqueue

        # The functions are patched below to instrument how
        # many times the functions are called and also to track
        # the queue length.
        def _enqueue(session, transaction_key, entry):
            self.queue_notification_call_count += 1
            self.orig_enqueue(session, transaction_key, entry)
            if session.notification_queue:
                key = session.notification_queue.keys()[0]
                length = len(session.notification_queue[key])
                if length > self.max_notification_queue_length:
                    self.max_notification_queue_length = length
            self.notification_queue = session.notification_queue

        local_api._enqueue = _enqueue

        self.orig_send_or_queue_notification = (
            local_api.send_or_queue_notification)

        def send_or_queue_notification(
            session, transaction_key, notifier_obj, notifier_method, args):
            self.orig_send_or_queue_notification(session,
                transaction_key, notifier_obj, notifier_method, args)
            self.notification_queue = session.notification_queue

        local_api.send_or_queue_notification = send_or_queue_notification

        self.orig_send_or_queue_registry_notification = (
            local_api.send_or_queue_registry_notification)

        def send_or_queue_registry_notification(
            session, transaction_key, resource, event, trigger, **kwargs):
            self.orig_send_or_queue_registry_notification(session,
                transaction_key, resource, event, trigger, **kwargs)
            self.notification_queue = session.notification_queue

        local_api.send_or_queue_registry_notification = (
            send_or_queue_registry_notification)

        self.orig_post_notifications_from_queue = (
            local_api.post_notifications_from_queue)

        def post_notifications_from_queue(session, transaction_key):
            self.post_notifications_from_queue_call_count += 1
            self.orig_post_notifications_from_queue(session, transaction_key)
            self.notification_queue = session.notification_queue

        local_api.post_notifications_from_queue = (
            post_notifications_from_queue)

        self.orig_discard_notifications_after_rollback = (
            local_api.discard_notifications_after_rollback)

        def discard_notifications_after_rollback(session):
            self.orig_discard_notifications_after_rollback(session)
            self.notification_queue = session.notification_queue

        local_api.discard_notifications_after_rollback = (
            discard_notifications_after_rollback)

    def tearDown(self):
        super(NotificationTest, self).tearDown()
        self._plugin._generate_mac = self.orig_generate_mac
        uuidutils.generate_uuid = self.orig_generate_uuid
        uuidutils.is_uuid_like = self.orig_is_uuid_like
        local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = False
        local_api._enqueue = self.orig_enqueue
        local_api.send_or_queue_notification = (
            self.orig_send_or_queue_notification)
        local_api.post_notifications_from_queue = (
            self.orig_post_notifications_from_queue)
        local_api.discard_notifications_after_rollback = (
            self.orig_discard_notifications_after_rollback)

    def _expected_dhcp_agent_call_list(self):
        # This testing strategy assumes the sequence of notifications
        # that result from the sequence of operations currently
        # performed. If the internal orchestration logic changes resulting
        # in a change in the sequence of operations, the following
        # list should be updated accordingly.
        # The 2nd argument is the resource object that is created,
        # and can be potentially verified for further detail
        calls = [
            mock.call().notify(mock.ANY, mock.ANY, "network.create.end"),
            mock.call().notify(mock.ANY, mock.ANY, "subnet.create.end"),
            mock.call().notify(mock.ANY, mock.ANY, "port.create.end"),
            mock.call().notify(mock.ANY, mock.ANY, "port.create.end"),
            mock.call().notify(mock.ANY, mock.ANY, "port.delete.end"),
            mock.call().notify(mock.ANY, mock.ANY, "port.delete.end"),
            mock.call().notify(mock.ANY, mock.ANY, "subnet.delete.end"),
            mock.call().notify(mock.ANY, mock.ANY, "network.delete.end")]
        return calls

    def _test_notifier(self, notifier, expected_calls,
                       batch_notifications=False):
            local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = batch_notifications
            ptg = self.create_policy_target_group(name="ptg1")
            ptg_id = ptg['policy_target_group']['id']
            pt = self.create_policy_target(
                name="pt1", policy_target_group_id=ptg_id)['policy_target']
            self.assertEqual(pt['policy_target_group_id'], ptg_id)
            self.new_delete_request(
                'policy_targets', pt['id']).get_response(self.ext_api)
            self.new_delete_request(
                'policy_target_groups', ptg_id).get_response(self.ext_api)
            sg_rules = self._plugin.get_security_group_rules(
                self._neutron_context)
            sg_ids = set([x['security_group_id'] for x in sg_rules])
            for sg_id in sg_ids:
                self.new_delete_request(
                    'security-groups', sg_id).get_response(self.ext_api)
            # Remove any port update calls for port-binding
            new_mock = mock.MagicMock()
            call_list = []
            for call in notifier.mock_calls:
                if call[1][-1] != 'port.update.end':
                    call_list.append(call)
            new_mock.mock_calls = call_list
            new_mock.assert_has_calls(expected_calls(), any_order=False)
            # test that no notifications have been left out
            self.assertEqual({}, self.notification_queue)
            return new_mock

    def _test_notifications(self, no_batch, with_batch):
        for n1, n2 in zip(no_batch, with_batch):
            # temporary workaround
            if 'port' in n1[0][1]:
                # ip address assignment is random, hence do not compare
                n1[0][1]['port']['fixed_ips'][0]['ip_address'] = ''
                n2[0][1]['port']['fixed_ips'][0]['ip_address'] = ''
            # test the resource objects are identical with and without batch
            self.assertEqual(n1[0][1], n2[0][1])
            # test that all the same events are pushed with and without batch
            self.assertEqual(n1[0][2], n2[0][2])

    def test_dhcp_notifier(self):
        with mock.patch.object(dhcp_rpc_agent_api.DhcpAgentNotifyAPI,
                               'notify') as dhcp_notifier_no_batch:
            no_batch = self._test_notifier(dhcp_notifier_no_batch,
                self._expected_dhcp_agent_call_list, False)

        self.assertEqual(0, self.queue_notification_call_count)
        self.assertEqual(0, self.max_notification_queue_length)
        self.assertEqual(0, self.post_notifications_from_queue_call_count)
        self.fake_uuid = 0

        with mock.patch.object(dhcp_rpc_agent_api.DhcpAgentNotifyAPI,
                               'notify') as dhcp_notifier_with_batch:
            batch = self._test_notifier(dhcp_notifier_with_batch,
                self._expected_dhcp_agent_call_list, True)

        self.assertLess(0, self.queue_notification_call_count)
        self.assertLess(0, self.max_notification_queue_length)
        # There are 4 transactions - one for create PTG,
        # one for create PT, one for delete PT, and one for
        # delete PTG. Delete PT notification is sent without queueing,
        # which leaves us with 3 sets of queued notifications.
        self.assertEqual(3, self.post_notifications_from_queue_call_count)

        self._test_notifications(no_batch.call_args_list, batch.call_args_list)

    def test_notifiers_with_transaction_rollback(self):
        # No notifications should get pushed in this case
        orig_func = self.dummy.create_policy_target_group_precommit
        self.dummy.create_policy_target_group_precommit = mock.Mock(
            side_effect=Exception)
        local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = True
        with mock.patch.object(dhcp_rpc_agent_api.DhcpAgentNotifyAPI,
                               'notify') as dhcp_notifier:
            with mock.patch.object(nova.Notifier,
                                   'send_network_change') as nova_notifier:
                self.create_policy_target_group(name="ptg1",
                                                expected_res_status=500)
                # Remove any port updates, as those don't count
                args_list = []
                new_dhcp = mock.MagicMock()
                for call_args in dhcp_notifier.call_args_list:
                    if call_args[0][-1] != 'port.update.end':
                        args_list.append(call_args)
                new_dhcp.call_args_list = args_list
                # test that notifier was not called
                self.assertEqual([], new_dhcp.call_args_list)
                self.assertEqual([], nova_notifier.call_args_list)
                # test that notification queue has been flushed
                self.assertEqual({}, self.notification_queue)
                # test that the push notifications func itself was not called
                self.assertEqual(
                    0, self.post_notifications_from_queue_call_count)
        # restore mock
        self.dummy.create_policy_target_group_precommit = orig_func


class TestImplicitExternalSegment(AIMBaseTestCase):

    def setUp(self):
        self._default_es_name = 'default'
        super(TestImplicitExternalSegment, self).setUp()
        cfg.CONF.set_override(
            'default_external_segment_name', self._default_es_name,
            group='group_policy_implicit_policy')

    def _create_external_segment(self, **kwargs):
        es_sub = self._make_ext_subnet(
            'net', '100.90.0.0/16',
            tenant_id=(kwargs.get('tenant_id') or self._tenant_id),
            dn='uni/tn-t1/out-l0/instP-n')
        return self.create_external_segment(subnet_id=es_sub['id'],
                                            **kwargs)

    def _create_default_es(self, **kwargs):
        es_sub = self._make_ext_subnet(
            'net1', kwargs.pop('subnet_cidr', '90.90.0.0/16'),
            tenant_id=(kwargs.get('tenant_id') or self._tenant_id),
            dn=self._dn_t1_l1_n1)
        return self.create_external_segment(name=self._default_es_name,
                                            subnet_id=es_sub['id'],
                                            **kwargs)

    def _test_implicit_lifecycle(self, shared=False):
        # Create default ES
        es = self._create_default_es(shared=shared)['external_segment']
        # Create non-default ES
        ndes = self._create_external_segment(
            name='non-default-name')['external_segment']

        # Create EP without ES set
        ep = self.create_external_policy()['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])
        # Verify persisted
        req = self.new_show_request('external_policies', ep['id'],
                                    fmt=self.fmt)
        ep = self.deserialize(
            self.fmt, req.get_response(self.ext_api))['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])

        # Verify update
        ep = self.update_external_policy(
            ep['id'], expected_res_status=200,
            external_segments=[ndes['id']])['external_policy']
        self.assertEqual(ndes['id'], ep['external_segments'][0])
        self.assertEqual(1, len(ep['external_segments']))

        # Create L3P without ES set
        l3p = self.create_l3_policy()['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
        # Verify persisted
        req = self.new_show_request('l3_policies', l3p['id'],
                                    fmt=self.fmt)
        l3p = self.deserialize(
            self.fmt, req.get_response(self.ext_api))['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])

        # Verify update
        l3p = self.update_l3_policy(
            l3p['id'], expected_res_status=200,
            external_segments={ndes['id']: []})['l3_policy']
        self.assertEqual(ndes['id'], l3p['external_segments'].keys()[0])
        self.assertEqual(1, len(l3p['external_segments']))

        # Verify only one visible ES can exist
        res = self._create_default_es(expected_res_status=400,
                                      subnet_cidr='10.10.0.0/28')
        self.assertEqual('DefaultExternalSegmentAlreadyExists',
                         res['NeutronError']['type'])

    def test_implicit_lifecycle(self):
        self._test_implicit_lifecycle()

    def test_implicit_lifecycle_shared(self):
        self._test_implicit_lifecycle(True)

    def test_implicit_shared_visibility(self):
        es = self._create_default_es(shared=True,
                                     tenant_id='onetenant')['external_segment']
        ep = self.create_external_policy(
            tenant_id='anothertenant')['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])
        self.assertEqual(1, len(ep['external_segments']))

        l3p = self.create_l3_policy(
            tenant_id='anothertenant')['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
        self.assertEqual(1, len(ep['external_segments']))

        res = self._create_default_es(expected_res_status=400,
                                      tenant_id='anothertenant',
                                      subnet_cidr='10.10.0.0/28')
        self.assertEqual('DefaultExternalSegmentAlreadyExists',
                         res['NeutronError']['type'])


class TestExternalSegment(AIMBaseTestCase):

    def test_external_segment_lifecycle(self):
        es_sub = self._make_ext_subnet('net1', '90.90.0.0/16',
                                       dn=self._dn_t1_l1_n1)
        es = self.create_external_segment(
            name='seg1', subnet_id=es_sub['id'],
            external_routes=[{'destination': '129.0.0.0/24',
                              'nexthop': None},
                             {'destination': '128.0.0.0/16',
                              'nexthop': None}])['external_segment']
        self.assertEqual('90.90.0.0/16', es['cidr'])
        self.assertEqual(4, es['ip_version'])
        es_net = self._show('networks', es_sub['network_id'])['network']
        self.assertEqual(['128.0.0.0/16', '129.0.0.0/24'],
                         sorted(es_net[CIDR]))

        es = self.update_external_segment(es['id'],
            external_routes=[{'destination': '129.0.0.0/24',
                              'nexthop': None}])['external_segment']
        es_net = self._show('networks', es_sub['network_id'])['network']
        self.assertEqual(['129.0.0.0/24'], sorted(es_net[CIDR]))

        self.delete_external_segment(es['id'])
        es_net = self._show('networks', es_sub['network_id'])['network']
        self.assertEqual(['0.0.0.0/0'], es_net[CIDR])

    def test_implicit_subnet(self):
        res = self.create_external_segment(name='seg1',
                                           expected_res_status=400)
        self.assertEqual('ImplicitSubnetNotSupported',
                         res['NeutronError']['type'])

    def test_invalid_subnet(self):
        with self.network() as net:
            with self.subnet(network=net) as sub:
                res = self.create_external_segment(
                    name='seg1', subnet_id=sub['subnet']['id'],
                    expected_res_status=400)
                self.assertEqual('InvalidSubnetForES',
                                 res['NeutronError']['type'])


class TestExternalPolicy(AIMBaseTestCase):

    def _check_router_contracts(self, routers, prov_prs, cons_prs):
        session = self._neutron_context.session
        prov = sorted([str(self.name_mapper.policy_rule_set(session, c))
                       for c in prov_prs])
        cons = sorted([str(self.name_mapper.policy_rule_set(session, c))
                       for c in cons_prs])
        for router in self._show_all('router', routers):
            self.assertEqual(prov, sorted(router[PROV]),
                             'Router %s' % router)
            self.assertEqual(cons, sorted(router[CONS]),
                             'Router %s' % router)

    def test_external_policy_lifecycle(self):
        ess = []
        es_nets = {}
        for x in range(0, 3):
            es_sub = self._make_ext_subnet('net%d' % x, '90.9%d.0.0/16' % x,
                dn='uni/tn-t1/out-l%d/instP-n%x' % (x, x))
            es = self.create_external_segment(
                name='seg%d' % x, subnet_id=es_sub['id'],
                external_routes=[{'destination': '13%d.0.0.0/24' % x,
                                  'nexthop': None}])['external_segment']
            ess.append(es['id'])
            es_nets[es_sub['network_id']] = es['id']

        routers = {}
        for x in range(0, 3):
            l3p = self.create_l3_policy(name='l3p%d' % x,
                external_segments={ess[x]: [''],
                                   ess[(x + 1) % len(ess)]: ['']}
            )['l3_policy']
            l3p_routers = self._show_all('router', l3p['routers'])
            for r in l3p_routers:
                net = self._router_gw(r)
                if net:
                    routers.setdefault(es_nets[net], []).append(r['id'])

        self._check_router_contracts(routers[ess[0]] +
                                     routers[ess[1]] +
                                     routers[ess[2]], [], [])

        prss = []
        rules = self._create_3_direction_rules()
        for x in range(0, 4):
            prs = self.create_policy_rule_set(name='prs%d' % x,
                policy_rules=[x['id'] for x in rules])['policy_rule_set']
            prss.append(prs['id'])

        ep1 = self.create_external_policy(name='ep1',
            external_segments=[ess[0], ess[1]],
            provided_policy_rule_sets={p: 'scope' for p in prss[0:2]},
            consumed_policy_rule_sets={p: 'scope' for p in prss[2:4]}
        )['external_policy']
        self._check_router_contracts(routers[ess[0]] + routers[ess[1]],
                                     prss[0:2], prss[2:4])
        self._check_router_contracts(routers[ess[2]], [], [])

        ep1 = self.update_external_policy(ep1['id'],
            provided_policy_rule_sets={p: 'scope' for p in prss[1:4]},
            consumed_policy_rule_sets={p: 'scope' for p in prss[0:3]}
        )['external_policy']
        self._check_router_contracts(routers[ess[0]] + routers[ess[1]],
                                     prss[1:4], prss[0:3])
        self._check_router_contracts(routers[ess[2]], [], [])

        ep1 = self.update_external_policy(ep1['id'],
            external_segments=[ess[1], ess[2]],
            provided_policy_rule_sets={p: 'scope' for p in prss[0:2]},
            consumed_policy_rule_sets={p: 'scope' for p in prss[2:4]}
        )['external_policy']
        self._check_router_contracts(routers[ess[1]] + routers[ess[2]],
                                     prss[0:2], prss[2:4])
        self._check_router_contracts(routers[ess[0]], [], [])

        self.delete_external_policy(ep1['id'])
        self._check_router_contracts(routers[ess[0]] + routers[ess[1]] +
                                     routers[ess[2]], [], [])

    def test_shared_external_policy(self):
        res = self.create_external_policy(shared=True,
                                          expected_res_status=400)
        self.assertEqual('SharedExternalPolicyUnsupported',
                         res['NeutronError']['type'])

    def test_multiple_external_policy_for_es(self):
        es_sub = self._make_ext_subnet('net1', '90.90.0.0/16',
                                       dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name='seg1', subnet_id=es_sub['id'])['external_segment']

        self.create_external_policy(external_segments=[es['id']])
        res = self.create_external_policy(external_segments=[es['id']],
                                          expected_res_status=400)
        self.assertEqual('MultipleExternalPoliciesForL3Policy',
                         res['NeutronError']['type'])

        ep2 = self.create_external_policy()['external_policy']
        res = self.update_external_policy(ep2['id'],
                                          external_segments=[es['id']],
                                          expected_res_status=400)
        self.assertEqual('MultipleExternalPoliciesForL3Policy',
                         res['NeutronError']['type'])


class TestNatPool(AIMBaseTestCase):

    def _test_overlapping_peer_rejected(self, shared1=False, shared2=False):
        shared_net = shared1 or shared2
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    shared_net=shared_net,
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'],
            external_routes=routes, shared=shared_net,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        # Allowed
        self.create_nat_pool(external_segment_id=es['id'], ip_version=4,
                             ip_pool='192.168.1.0/24', shared=shared1,
                             expected_res_status=webob.exc.HTTPCreated.code)

        # Fails
        res = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24', shared=shared2,
            expected_res_status=webob.exc.HTTPBadRequest.code)

        self.assertEqual('OverlappingNATPoolInES', res['NeutronError']['type'])

    def test_overlapping_peer_rejected1(self):
        self._test_overlapping_peer_rejected(False, False)

    def test_overlapping_peer_rejected2(self):
        self._test_overlapping_peer_rejected(True, False)

    def test_overlapping_peer_rejected3(self):
        self._test_overlapping_peer_rejected(True, True)

    def test_overlapping_peer_rejected4(self):
        self._test_overlapping_peer_rejected(False, True)

    def _test_implicit_subnet_created(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    shared_net=shared,
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'],
            external_routes=routes, shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        self.assertIsNotNone(nat_pool['subnet_id'])
        subnet = self._get_object('subnets', nat_pool['subnet_id'],
                                  self.api)['subnet']
        self.assertEqual('192.168.1.0/24', subnet['cidr'])

    def test_implicit_subnet_created(self):
        self._test_implicit_subnet_created()

    def test_implicit_subnet_created_shared(self):
        self._test_implicit_subnet_created(True)

    def _test_partially_overlapping_subnets_rejected(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    shared_net=shared,
                                    dn='uni/tn-t1/out-l1/instP-n1')
        gw = str(netaddr.IPAddress(
            netaddr.IPNetwork('192.168.1.0/28').first + 1))
        net = self._get_object('networks', sub['network_id'], self.api)
        self._make_subnet(self.fmt, net, gw, '192.168.1.0/28')['subnet']
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'],
            external_routes=routes, shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        # Disallowed because they partially overlaps
        res = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('OverlappingSubnetForNATPoolInES',
                         res['NeutronError']['type'])

    def test_partially_overlapping_subnets_rejected(self):
        self._test_partially_overlapping_subnets_rejected()

    def test_partially_overlapping_subnets_rejected_shared(self):
        self._test_partially_overlapping_subnets_rejected(True)

    def _test_overlapping_subnets(self, shared=False):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    shared_net=shared,
                                    dn='uni/tn-t1/out-l1/instP-n1')
        gw = str(netaddr.IPAddress(
            netaddr.IPNetwork('192.168.1.0/24').first + 1))
        net = self._get_object('networks', sub['network_id'], self.api)
        sub2 = self._make_subnet(self.fmt, net, gw, '192.168.1.0/24')['subnet']
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'],
            external_routes=routes, shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']

        # Sub2 associated with the newly created NAT pool
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24', shared=shared,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        self.assertEqual(sub2['id'], nat_pool['subnet_id'])

    def test_overlapping_subnets(self):
        self._test_overlapping_subnets()

    def test_overlapping_subnets_shared(self):
        self._test_overlapping_subnets(True)

    def _test_subnet_swap(self, owned=True):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        # Use same IP pool as ES sub_id if we don't have to own
        # the subnet.
        ip_pool = '192.168.1.0/24' if owned else '192.168.0.0/24'

        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4, ip_pool=ip_pool,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']

        # Subnet deleted on 'delete'
        sub_id = nat_pool['subnet_id']
        self.delete_nat_pool(
            nat_pool['id'], expected_res_status=webob.exc.HTTPNoContent.code)
        self._get_object('subnets', sub_id, self.api,
                         expected_res_status=404 if owned else 200)

        # Subnet deleted on 'update'
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4, ip_pool=ip_pool,
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        sub_id = nat_pool['subnet_id']

        sub2 = self._make_ext_subnet('net1', '192.167.0.0/24',
                                     dn='uni/tn-t1/out-l2/instP-n2')
        es2 = self.create_external_segment(
            name="nondefault", subnet_id=sub2['id'],
            external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']

        # Update External Segment
        nat_pool = self.update_nat_pool(
            nat_pool['id'], external_segment_id=es2['id'])['nat_pool']
        self.assertNotEqual(nat_pool['subnet_id'], sub_id)
        self.assertIsNotNone(nat_pool['subnet_id'])

        # Verify subnet deleted
        self._get_object('subnets', sub_id, self.api,
                         expected_res_status=404 if owned else 200)

    def test_owned_subnet_deleted(self):
        self._test_subnet_swap(True)

    def test_not_owned_subnet_not_deleted(self):
        self._test_subnet_swap(False)

    def test_delete_with_fip_allocated(self):
        sub = self._make_ext_subnet('net1', '192.168.0.0/30',
                                    enable_dhcp=False,
                                    dn='uni/tn-t1/out-l1/instP-n1')
        net = self._get_object('networks', sub['network_id'], self.api)
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'])['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24')['nat_pool']
        fip_data = {'floatingip': {
            'tenant_id': net['network']['tenant_id'],
            'floating_network_id': net['network']['id'],
            'subnet_id': nat_pool['subnet_id']}}
        for i in range(3):
            self._l3_plugin.create_floatingip(
                nctx.get_admin_context(), fip_data)
        res = self.delete_nat_pool(nat_pool['id'], expected_res_status=409)
        self.assertEqual('NatPoolInUseByPort', res['NeutronError']['type'])


class TestNetworkServicePolicy(AIMBaseTestCase):

    def test_create_nsp_multiple_ptgs(self):
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
        # Create two PTGs that use this NSP
        ptg1 = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg2 = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        # Update the PTGs and unset the NSP used
        self.update_policy_target_group(
                    ptg1['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)
        self.update_policy_target_group(
                    ptg2['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)

        self.update_policy_target_group(
                    ptg1['id'],
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPOk.code)

        self.delete_policy_target_group(
                    ptg1['id'],
                    expected_res_status=204)

    def test_unsupported_nsp_parameters_rejected(self):
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "self_subnet", "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "external_subnet",
                 "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_single", "value": "self_subnet", "name": "vip"},
                {"type": "ip_single", "value": "self_subnet", "name": "vip"}],
            expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_nsp_cleanup_on_unset(self):
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg_subnet_id = ptg['subnets'][0]
        subnet = self._show_subnet(ptg_subnet_id)
        initial_allocation_pool = subnet['allocation_pools']
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        # Update PTG, associating a NSP with it and verify that an IP is
        # reserved from the PTG subnet allocation pool
        self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)
        allocation_pool_after_nsp = subnet['allocation_pools']
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('start')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('start')))
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('end')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('end')) + 1)

        # Update the PTGs and unset the NSP used and verify that the IP is
        # restored to the PTG subnet allocation pool
        self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=None,
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)
        allocation_pool_after_nsp_cleanup = subnet['allocation_pools']
        self.assertEqual(
                initial_allocation_pool, allocation_pool_after_nsp_cleanup)

    def test_create_nsp_ip_pool_multiple_ptgs(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        # Create two PTGs that use this NSP
        ptg1 = self.create_policy_target_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']
        ptg2 = self.create_policy_target_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg1['id'])
        port_id = pt['policy_target']['port_id']
        req = self.new_show_request('ports', port_id, fmt=self.fmt)
        port = self.deserialize(self.fmt,
                                req.get_response(self.api))['port']

        res = self._list('floatingips')['floatingips']
        self.assertEqual(1, len(res))
        self.assertEqual(res[0]['fixed_ip_address'],
                         port['fixed_ips'][0]['ip_address'])

        pt2 = self.create_policy_target(
            name="pt2", policy_target_group_id=ptg1['id'])
        port2_id = pt2['policy_target']['port_id']
        req = self.new_show_request('ports', port2_id, fmt=self.fmt)
        port = self.deserialize(self.fmt,
                                req.get_response(self.api))['port']

        res = self._list('floatingips')['floatingips']
        self.assertEqual(2, len(res))

        # Update the PTGs and unset the NSP used
        # TODO(Sumit): Remove the floating IPs here
        self.update_policy_target_group(
            ptg1['id'], network_service_policy_id=None,
            expected_res_status=webob.exc.HTTPOk.code)

        self.update_policy_target_group(
            ptg2['id'], network_service_policy_id=None,
            expected_res_status=webob.exc.HTTPOk.code)

        self.delete_policy_target_group(
            ptg1['id'], expected_res_status=204)

        self.delete_policy_target_group(
            ptg2['id'], expected_res_status=204)

    def test_nsp_fip_single(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_single", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']

        # Update PTG, associating a NSP with it and verify that a FIP
        # is allocated
        self.update_policy_target_group(
            ptg['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPOk.code)
        mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
        self.assertNotEqual([], mapping)
        self.assertEqual(mapping[0].service_policy_id, nsp['id'])
        self.assertIsNotNone(mapping[0].floatingip_id)

        # Update the PTGs and unset the NSP used and verify that the IP
        # is restored to the PTG subnet allocation pool
        self.update_policy_target_group(
            ptg['id'], network_service_policy_id=None,
            expected_res_status=webob.exc.HTTPOk.code)
        mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
        self.assertEqual([], mapping)

        self.delete_policy_target_group(
            ptg['id'], expected_res_status=204)

    def test_nsp_fip_single_different_pool(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.1.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_single", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']

        # Update PTG, associating a NSP with it and verify that a FIP
        # is allocated
        self.update_policy_target_group(
            ptg['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPOk.code)
        mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
        self.assertNotEqual([], mapping)
        self.assertEqual(mapping[0].service_policy_id, nsp['id'])
        self.assertIsNotNone(mapping[0].floatingip_id)

        fip = self._get_object(
            'floatingips', mapping[0].floatingip_id, self.ext_api)[
                'floatingip']

        # Verify FIP is in the new subnet
        self.assertTrue(
            netaddr.IPAddress(fip['floating_ip_address']) in
            netaddr.IPNetwork('192.168.1.0/24'),
            "IP %s not in pool %s" % (fip['floating_ip_address'],
                                      '192.168.1.0/24'))

        # Update the PTGs and unset the NSP used and verify that the IP
        # is restored to the PTG subnet allocation pool
        self.update_policy_target_group(
            ptg['id'], network_service_policy_id=None,
            expected_res_status=webob.exc.HTTPOk.code)
        mapping = self._get_nsp_ptg_fip_mapping(ptg['id'])
        self.assertEqual([], mapping)

        self.delete_policy_target_group(
            ptg['id'], expected_res_status=204)

    def test_nsp_rejected_without_nat_pool(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_single", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']

        data = self.create_policy_target_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NSPRequiresNatPool', data['NeutronError']['type'])

        self.update_policy_target_group(
            ptg['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPBadRequest.code)

        self.assertEqual('NSPRequiresNatPool', data['NeutronError']['type'])

    def test_reject_nsp_without_es(self):
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_pool", "value": "nat_pool",
                             "name": "test"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']
        # create PTG with NSP fails when ES is not present
        data = self.create_policy_target_group(
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NSPRequiresES',
                         data['NeutronError']['type'])
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        # update PTG with NSP fails when ES is not present
        data = self.update_policy_target_group(
                    ptg['id'],
                    network_service_policy_id=nsp['id'],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NSPRequiresES',
                         data['NeutronError']['type'])

    def test_reject_l3p_update_with_es(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub1 = self._make_ext_subnet('net1', '192.168.0.0/24',
                                     dn='uni/tn-t1/out-l1/instP-n1')
        es1 = self.create_external_segment(
            name="default", subnet_id=sub1['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        self.create_nat_pool(
            external_segment_id=es1['id'], ip_version=4,
            ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es1['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']
        self.create_policy_target_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']

        req = self.new_list_request('l3_policies', fmt=self.fmt)

        l3ps = self.deserialize(self.fmt, req.get_response(self.ext_api))[
            'l3_policies']

        sub2 = self._make_ext_subnet('net2', '192.167.0.0/24',
                                     dn='uni/tn-t1/out-l2/instP-n2')
        es2 = self.create_external_segment(
            name='nondefault', subnet_id=sub2['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        res = self.update_l3_policy(
            l3ps[0]['id'], expected_res_status=409,
            external_segments={es2['id']: []})
        self.assertEqual('L3PEsinUseByNSP', res['NeutronError']['type'])

    def test_nsp_delete_nat_pool_rejected(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        nat_pool = self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        self.create_policy_target_group(
            l2_policy_id=l2p['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']

        res = self.delete_nat_pool(nat_pool['id'], expected_res_status=409)
        self.assertEqual('NatPoolinUseByNSP', res['NeutronError']['type'])

    def test_update_nsp_nat_pool_after_pt_create(self):
        routes = [{'destination': '0.0.0.0/0', 'nexthop': None}]
        sub = self._make_ext_subnet('net1', '192.168.0.0/24',
                                    dn='uni/tn-t1/out-l1/instP-n1')
        es = self.create_external_segment(
            name="default", subnet_id=sub['id'], external_routes=routes,
            expected_res_status=webob.exc.HTTPCreated.code)['external_segment']
        self.create_nat_pool(
            external_segment_id=es['id'], ip_version=4,
            ip_pool='192.168.0.0/24',
            expected_res_status=webob.exc.HTTPCreated.code)['nat_pool']
        nsp = self.create_network_service_policy(
            network_service_params=[
                {"type": "ip_pool", "value": "nat_pool",
                 "name": "external_access"}],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'network_service_policy']
        l3p = self.create_l3_policy(name='l3p1',
            external_segments={es['id']: []})['l3_policy']

        l2p = self.create_l2_policy(name='l2p1',
                                    l3_policy_id=l3p['id'])['l2_policy']

        # Create a PTG and PTs and then associate the NSP
        ptg1 = self.create_policy_target_group(
            l2_policy_id=l2p['id'],
            expected_res_status=webob.exc.HTTPCreated.code)[
                'policy_target_group']
        pt = self.create_policy_target(
            name="pt1", policy_target_group_id=ptg1['id'])
        port_id = pt['policy_target']['port_id']

        pt2 = self.create_policy_target(
            name="pt2", policy_target_group_id=ptg1['id'])
        port2_id = pt2['policy_target']['port_id']

        res = self._list('floatingips')['floatingips']
        self.assertEqual(0, len(res))

        self.update_policy_target_group(
            ptg1['id'], network_service_policy_id=nsp['id'],
            expected_res_status=webob.exc.HTTPOk.code)

        res = self._list('floatingips')['floatingips']
        self.assertEqual(2, len(res))
        req = self.new_show_request('ports', port_id, fmt=self.fmt)
        port1 = self.deserialize(self.fmt, req.get_response(self.api))['port']
        req = self.new_show_request('ports', port2_id, fmt=self.fmt)
        port2 = self.deserialize(self.fmt, req.get_response(self.api))['port']
        port_fixed_ips = [port1['fixed_ips'][0]['ip_address'],
                          port2['fixed_ips'][0]['ip_address']]
        fip_fixed_ips = [res[0]['fixed_ip_address'],
                         res[1]['fixed_ip_address']]
        self.assertEqual(set(port_fixed_ips), set(fip_fixed_ips))
        self.update_policy_target_group(
            ptg1['id'], network_service_policy_id=None,
            expected_res_status=webob.exc.HTTPOk.code)
        res = self._list('floatingips')['floatingips']
        self.assertEqual(0, len(res))

    def test_nsp_cleanup_multiple_on_unset(self):
        ptg = self.create_policy_target_group(
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                        'policy_target_group']
        ptg_subnet_id = ptg['subnets'][0]
        subnet = self._show_subnet(ptg_subnet_id)
        nsp = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        nsp2 = self.create_network_service_policy(
                    network_service_params=[
                            {"type": "ip_single", "value": "self_subnet",
                             "name": "vip"}],
                    expected_res_status=webob.exc.HTTPCreated.code)[
                                                    'network_service_policy']

        # Update PTG, associating an NSP with it and verify that an IP is
        # reserved from the PTG subnet allocation pool. Also test updating
        # the PTG with a different NSP and then resetting it back to the
        # initially set NSP
        self._verify_update_ptg_with_nsp(ptg['id'], nsp['id'], subnet)
        self._verify_update_ptg_with_nsp(ptg['id'], nsp2['id'], subnet)
        self._verify_update_ptg_with_nsp(ptg['id'], nsp['id'], subnet)

    def _verify_update_ptg_with_nsp(self, ptg_id, nsp_id, ptg_subnet_no_nsp):
        ptg_subnet_id = ptg_subnet_no_nsp['id']
        initial_allocation_pool = ptg_subnet_no_nsp['allocation_pools']
        self.update_policy_target_group(
                    ptg_id,
                    network_service_policy_id=nsp_id,
                    expected_res_status=webob.exc.HTTPOk.code)
        subnet = self._show_subnet(ptg_subnet_id)
        allocation_pool_after_nsp = subnet['allocation_pools']
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('start')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('start')))
        self.assertEqual(
                netaddr.IPAddress(initial_allocation_pool[0].get('end')),
                netaddr.IPAddress(allocation_pool_after_nsp[0].get('end')) + 1)


class TestNeutronPortOperation(AIMBaseTestCase):

    def setUp(self, **kwargs):
        super(TestNeutronPortOperation, self).setUp(**kwargs)
        # Doing the following assignment since the call to _register_agent
        # needs self.plugin to point to the neutron core plugin.
        # TODO(Sumit): Ideally, the self.plugin of the GBP test cases should be
        # consistent with the neutron test setup and point to the neutron
        # core plugin. The self._gbp_plugin already points to the GBP service
        # plugin and should be used instead.
        self.plugin = self._plugin

    def test_port_security_port(self):
        self._register_agent('host1', test_aim_md.AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')

        # test compute port
        p1 = self._make_port(self.fmt, net['network']['id'],
                             device_owner='compute:')['port']
        p1 = self._bind_port_to_host(p1['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertFalse(details['promiscuous_mode'])

        p2 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('port_security_enabled',),
                             device_owner='compute:',
                             port_security_enabled=True)['port']
        p2 = self._bind_port_to_host(p2['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p2['id'],
            host='h1')
        self.assertFalse(details['promiscuous_mode'])

        p3 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('port_security_enabled',),
                             device_owner='compute:',
                             port_security_enabled=False)['port']
        p3 = self._bind_port_to_host(p3['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p3['id'],
            host='h1')
        self.assertTrue(details['promiscuous_mode'])

        # test DHCP port
        p1_dhcp = self._make_port(self.fmt, net['network']['id'],
            device_owner=n_constants.DEVICE_OWNER_DHCP)['port']
        p1_dhcp = self._bind_port_to_host(p1_dhcp['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1_dhcp['id'],
            host='h1')
        self.assertTrue(details['promiscuous_mode'])

        p2_dhcp = self._make_port(self.fmt, net['network']['id'],
            arg_list=('port_security_enabled',), port_security_enabled=True,
            device_owner=n_constants.DEVICE_OWNER_DHCP)['port']
        p2_dhcp = self._bind_port_to_host(p2_dhcp['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p2_dhcp['id'],
            host='h1')
        self.assertTrue(details['promiscuous_mode'])

        p3_dhcp = self._make_port(self.fmt, net['network']['id'],
            arg_list=('port_security_enabled',), port_security_enabled=False,
            device_owner=n_constants.DEVICE_OWNER_DHCP)['port']
        p3_dhcp = self._bind_port_to_host(p3_dhcp['id'], 'host1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p3_dhcp['id'],
            host='h1')
        self.assertTrue(details['promiscuous_mode'])

    def test_gbp_details_for_allowed_address_pair(self):
        self._register_agent('h1', test_aim_md.AGENT_CONF_OPFLEX)
        self._register_agent('h2', test_aim_md.AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        sub1 = self._make_subnet(self.fmt, net, '10.0.0.1', '10.0.0.0/24')[
            'subnet']
        sub2 = self._make_subnet(self.fmt, net, '1.2.3.1', '1.2.3.0/24')[
            'subnet']
        allow_addr = [{'ip_address': '1.2.3.250',
                       'mac_address': '00:00:00:AA:AA:AA'},
                      {'ip_address': '1.2.3.251',
                       'mac_address': '00:00:00:BB:BB:BB'}]

        # create 2 ports with same allowed-addresses
        p1 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('allowed_address_pairs',),
                             device_owner='compute:',
                             fixed_ips=[{'subnet_id': sub1['id']}],
                             allowed_address_pairs=allow_addr)['port']
        p2 = self._make_port(self.fmt, net['network']['id'],
                             arg_list=('allowed_address_pairs',),
                             device_owner='compute:',
                             fixed_ips=[{'subnet_id': sub1['id']}],
                             allowed_address_pairs=allow_addr)['port']
        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h2')
        self.driver.ha_ip_handler.set_port_id_for_ha_ipaddress(
            p1['id'], '1.2.3.250')
        self.driver.ha_ip_handler.set_port_id_for_ha_ipaddress(
            p2['id'], '1.2.3.251')
        allow_addr[0]['active'] = True
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertEqual(allow_addr, details['allowed_address_pairs'])
        del allow_addr[0]['active']
        allow_addr[1]['active'] = True
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p2['id'],
            host='h2')
        self.assertEqual(allow_addr, details['allowed_address_pairs'])

        # set allowed-address as fixed-IP of ports p3 and p4, which also have
        # floating-IPs. Verify that FIP is "stolen" by p1 and p2
        net_ext, rtr, _ = self._setup_external_network(
            'l1', dn='uni/tn-t1/out-l1/instP-n1')
        p3 = self._make_port(self.fmt, net['network']['id'],
                             device_owner='compute:',
                             fixed_ips=[{'subnet_id': sub2['id'],
                                         'ip_address': '1.2.3.250'}])['port']
        p4 = self._make_port(self.fmt, net['network']['id'],
                             device_owner='compute:',
                             fixed_ips=[{'subnet_id': sub2['id'],
                                         'ip_address': '1.2.3.251'}])['port']
        self.l3_plugin.add_router_interface(
            self._neutron_admin_context, rtr['id'], {'subnet_id': sub1['id']})
        self.l3_plugin.add_router_interface(
            self._neutron_admin_context, rtr['id'], {'subnet_id': sub2['id']})
        fip1 = self._make_floatingip(self.fmt, net_ext['id'],
                                     port_id=p3['id'])['floatingip']
        fip2 = self._make_floatingip(self.fmt, net_ext['id'],
                                     port_id=p4['id'])['floatingip']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertEqual(1, len(details['floating_ip']))
        self.assertEqual(
            fip1['floating_ip_address'],
            details['floating_ip'][0]['floating_ip_address'])
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p2['id'],
            host='h2')
        self.assertEqual(1, len(details['floating_ip']))
        self.assertEqual(
            fip2['floating_ip_address'],
            details['floating_ip'][0]['floating_ip_address'])

        # verify FIP updates: update to p3, p4 should also update p1 and p2
        self.driver.aim_mech_driver._notify_port_update = mock.Mock()
        self.driver.aim_mech_driver._notify_port_update_for_fip(
            self._neutron_admin_context, p3['id'])
        expected_calls = [
            mock.call(mock.ANY, p)
            for p in sorted([p1['id'], p2['id'], p3['id']])]
        self._check_call_list(
            expected_calls,
            self.driver.aim_mech_driver._notify_port_update.call_args_list)

        self.driver.aim_mech_driver._notify_port_update.reset_mock()
        self.driver.aim_mech_driver._notify_port_update_for_fip(
            self._neutron_admin_context, p4['id'])
        expected_calls = [
            mock.call(mock.ANY, p)
            for p in sorted([p1['id'], p2['id'], p4['id']])]
        self._check_call_list(
            expected_calls,
            self.driver.aim_mech_driver._notify_port_update.call_args_list)

    def test_port_bound_other_agent(self):
        self._register_agent('h1', test_aim_md.AGENT_CONF_OPFLEX)
        self._register_agent('h2', test_aim_md.AGENT_CONF_OPFLEX)
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '10.0.1.1', '10.0.1.0/24')

        # First test an unbound port
        p1 = self._make_port(self.fmt, net['network']['id'],
                             device_owner='compute:')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertEqual('', details['host'])
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h2')
        self.assertEqual('', details['host'])

        # Test port bound to h1, queries from h1 and h2
        p1 = self._bind_port_to_host(p1['id'], 'h2')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertEqual('h2', details['host'])
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h2')
        self.assertEqual('h2', details['host'])

        # Test rebind of port to h2, queries from h1 and h2
        p1 = self._bind_port_to_host(p1['id'], 'h1')['port']
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h1')
        self.assertEqual('h1', details['host'])
        details = self.driver.get_gbp_details(
            self._neutron_admin_context, device='tap%s' % p1['id'],
            host='h2')
        self.assertEqual('h1', details['host'])


class TestPerL3PImplicitContractsConfig(TestL2PolicyWithAutoPTG):

    def setUp(self, **kwargs):
        aimd.cfg.CONF.set_override('create_per_l3p_implicit_contracts',
                False, "aim_mapping")
        self.mock_create = mock.Mock()
        aimd.AIMMappingDriver._create_per_l3p_implicit_contracts = (
                self.mock_create)
        super(TestPerL3PImplicitContractsConfig, self).setUp(**kwargs)

    def tearDown(self):
        super(TestPerL3PImplicitContractsConfig, self).tearDown()
        aimd.cfg.CONF.set_override('create_per_l3p_implicit_contracts',
                True, group='aim_mapping')
        self.driver.create_per_l3p_implicit_contracts = True

    def test_create_not_called(self):
        self.mock_create.assert_not_called()


class TestVlanAwareVM(AIMBaseTestCase):

    def setUp(self, *args, **kwargs):
        super(TestVlanAwareVM, self).setUp(trunk_plugin='trunk', **kwargs)

    def _do_test_gbp_details_no_pt(self):
        network = self._make_network(self.fmt, 'net1', True)
        with self.subnet(network=network, cidr='1.1.2.0/24') as subnet:
            with self.port(subnet=subnet) as port:
                with self.port(subnet=subnet) as subp:
                    port_id = port['port']['id']
                    subp_id = subp['port']['id']
                    trunk = self._create_resource('trunk', port_id=port_id)
                    self.driver._trunk_plugin.add_subports(
                        nctx.get_admin_context(), trunk['trunk']['id'],
                        {'sub_ports': [{'port_id': subp_id,
                                        'segmentation_type': 'vlan',
                                        'segmentation_id': 100}]})
                    self._bind_port_to_host(port_id, 'h1')
                    req_mapping = self.driver.request_endpoint_details(
                        nctx.get_admin_context(),
                        request={'device': 'tap%s' % port_id,
                                 'timestamp': 0, 'request_id': 'request_id'},
                        host='h1')
                    self.assertEqual(req_mapping['trunk_details']['trunk_id'],
                                     trunk['trunk']['id'])
                    self.assertEqual(
                        req_mapping['trunk_details']['master_port_id'],
                        trunk['trunk']['port_id'])
                    self.assertEqual(
                        req_mapping['trunk_details']['subports'],
                        [{'port_id': subp_id,
                          'segmentation_type': 'vlan',
                          'segmentation_id': 100}])
                    # Retrieve the subport
                    self._bind_port_to_host(subp_id, 'h1')
                    req_mapping = self.driver.request_endpoint_details(
                        nctx.get_admin_context(),
                        request={'device': 'tap%s' % subp_id,
                                 'timestamp': 0, 'request_id': 'request_id'},
                        host='h1')
                    self.assertEqual(req_mapping['trunk_details']['trunk_id'],
                                     trunk['trunk']['id'])
                    self.assertEqual(
                        req_mapping['trunk_details']['master_port_id'],
                        port_id)
                    self.assertEqual(
                        req_mapping['trunk_details']['subports'],
                        [{'port_id': subp_id,
                          'segmentation_type': 'vlan',
                          'segmentation_id': 100}])

    def test_trunk_master_port(self):
        self._do_test_gbp_details_no_pt()
