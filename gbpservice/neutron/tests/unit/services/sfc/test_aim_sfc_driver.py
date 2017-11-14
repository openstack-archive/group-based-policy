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

from aim.api import infra as aim_infra
from aim.api import resource as aim_res
from aim.api import service_graph as aim_sg
import mock
from networking_sfc.extensions import flowclassifier as flowc_ext
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.services.flowclassifier.common import config as flc_cfg
from networking_sfc.services.flowclassifier import driver_manager as fc_driverm
from networking_sfc.services.sfc.common import config as sfc_cfg
from networking_sfc.services.sfc import driver_manager as sfc_driverm
from neutron.callbacks import exceptions as c_exc
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_log import log as logging

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.db.grouppolicy import test_group_policy_db
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver as test_aim_base)

LOG = logging.getLogger(__name__)


class Rollback(Exception):
    pass


class TestAIMServiceFunctionChainingBase(test_aim_base.AIMBaseTestCase):

    def setUp(self, *args, **kwargs):
        sfc_cfg.cfg.CONF.set_override('drivers', ['aim'], group='sfc')
        flc_cfg.cfg.CONF.set_override('drivers', ['aim'],
                                      group='flowclassifier')
        config.cfg.CONF.set_override(
            'network_vlan_ranges', ['physnet1:100:200'], group='ml2_type_vlan')
        ml2_options = {'mechanism_drivers': ['apic_aim', 'openvswitch'],
                       'extension_drivers': ['apic_aim', 'port_security',
                                             'dns'],
                       'type_drivers': ['opflex', 'local', 'vlan'],
                       'tenant_network_types': ['vlan']}
        # NOTE(ivar): the SFC and FLC driver managers load the driver names in
        # the default parameters of their INIT functions. In Python, default
        # params are evaluated only once when the module is loaded hence
        # causing issues in the tests if those modules ever get loaded before
        # the aim override happens. We need to reload the modules at this point
        # to fix the issue.
        reload(fc_driverm)
        reload(sfc_driverm)
        super(TestAIMServiceFunctionChainingBase, self).setUp(
            *args, ml2_options=ml2_options, trunk_plugin='trunk', **kwargs)
        self.agent_conf = test_group_policy_db.AGENT_CONF
        self._sfc_driver = None
        self._flowc_driver = None
        self._sfc_plugin = None
        self._flowc_plugin = None
        self._aim_mech_driver = None
        self.hlink1 = aim_infra.HostLink(host_name='h1', interface_name='eth0',
                           path='topology/pod-1/paths-101/pathep-[eth1/1]')
        self.hlink2 = aim_infra.HostLink(host_name='h2', interface_name='eth0',
                           path='topology/pod-1/paths-102/pathep-[eth1/1]')
        self.path_by_host = {'h1': 'topology/pod-1/paths-101/pathep-[eth1/1]',
                             'h2': 'topology/pod-1/paths-102/pathep-[eth1/1]'}
        self.physdom = aim_res.PhysicalDomain(name='sfc-phys', monitored=True)

        self.aim_mgr.create(self._aim_context, self.hlink1)
        self.aim_mgr.create(self._aim_context, self.hlink2)
        self.aim_mgr.create(self._aim_context, self.physdom)
        self.aim_mgr.create(self._aim_context,
                            aim_infra.HostDomainMappingV2(
                                host_name='h1', domain_name=self.physdom.name,
                                domain_type='PhysDom'))
        self.aim_mgr.create(self._aim_context,
                            aim_infra.HostDomainMappingV2(
                                host_name='h2', domain_name=self.physdom.name,
                                domain_type='PhysDom'))
        self._plugin = directory.get_plugin()
        self._plugin.remove_networks_from_down_agents = mock.Mock()
        self._plugin.is_agent_down = mock.Mock(return_value=False)
        self._ctx = context.get_admin_context()

    def tearDown(self):
        LOG.warning("SFCDs used in this test: %s",
                    self.sfc_plugin.driver_manager.drivers.keys())
        LOG.warning("FLCDs used in this test: %s",
                    self.flowc_plugin.driver_manager.drivers.keys())
        # Always reset configuration to dummy driver. Any
        # test which requires to configure a different
        # policy driver would have done so in it's setup
        # (and should have ideally reset it too).
        config.cfg.CONF.set_override('drivers', ['dummy'], group='sfc')
        config.cfg.CONF.set_override('drivers', ['dummy'],
                                     group='flowclassifier')
        super(TestAIMServiceFunctionChainingBase, self).tearDown()

    @property
    def sfc_plugin(self):
        if not self._sfc_plugin:
            self._sfc_plugin = directory.get_plugin(sfc_ext.SFC_EXT)
        return self._sfc_plugin

    @property
    def flowc_plugin(self):
        if not self._flowc_plugin:
            self._flowc_plugin = directory.get_plugin(
                flowc_ext.FLOW_CLASSIFIER_EXT)
        return self._flowc_plugin

    @property
    def sfc_driver(self):
        # aim_mapping policy driver reference
        if not self._sfc_driver:
            self._sfc_driver = (
                self.sfc_plugin.driver_manager.drivers['aim'].obj)
        return self._sfc_driver

    @property
    def flowc_driver(self):
        # aim_mapping policy driver reference
        if not self._flowc_driver:
            self._flowc_driver = (
                self.flowc_plugin.driver_manager.drivers['aim'].obj)
        return self._flowc_driver

    @property
    def aim_mech(self):
        if not self._aim_mech_driver:
            self._aim_mech_driver = (
                self._plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
        return self._aim_mech_driver

    def _create_simple_ppg(self, pairs=2, leftn_id=None, rightn_id=None):
        nets = []
        # Pairs go in 2 networks
        if not leftn_id or not rightn_id:
            for i in range(2):
                net = self._make_network(self.fmt, 'net1', True)
                self._make_subnet(self.fmt, net, '192.168.%s.1' % i,
                                  '192.168.%s.0/24' % i)
                nets.append(net['network']['id'])
        else:
            nets = [leftn_id, rightn_id]

        port_pairs = []
        for i in range(pairs):
            p1 = self._make_port(self.fmt, nets[0])['port']
            self._bind_port_to_host(p1['id'], 'h%s' % ((i % 2) + 1))
            p2 = self._make_port(self.fmt, nets[1])['port']
            self._bind_port_to_host(p2['id'], 'h%s' % ((i % 2) + 1))
            pp = self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                                       expected_res_status=201)['port_pair']
            port_pairs.append(pp)
        # This goes through
        return self.create_port_pair_group(
            port_pairs=[pp['id'] for pp in port_pairs],
            expected_res_status=201)['port_pair_group']

    def _create_simple_flowc(self, src_svi=False, dst_svi=False):
        kwargs = {}

        def get_svi_kwargs():
            return {'apic:svi': True}

        if src_svi:
            # We need to create the L3Out and the External network
            kwargs = get_svi_kwargs()
        net1 = self._make_network(self.fmt, 'net1', True,
                                  arg_list=self.extension_attributes,
                                  **kwargs)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        kwargs = {}
        if dst_svi:
            kwargs = get_svi_kwargs()
        net2 = self._make_network(self.fmt, 'net2', True,
                                  arg_list=self.extension_attributes,
                                  **kwargs)
        self._make_subnet(self.fmt, net2, '192.168.1.1', '192.168.1.0/24')
        return self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net2['network']['id']},
            source_ip_prefix='192.168.0.0/24',
            destination_ip_prefix='192.168.1.0/24',
            expected_res_status=201)['flow_classifier']

    def _create_simple_port_chain(self, flowcs=1, ppgs=2, flowcs_args=None,
                                  ppg_args=None):
        flowc_ids = []
        ppg_args = ppg_args or []
        flowcs_args = flowcs_args or []
        for i in range(flowcs):
            try:
                flowc_ids.append(
                    self._create_simple_flowc(**flowcs_args[i])['id'])
            except IndexError:
                flowc_ids.append(self._create_simple_flowc()['id'])
        ppg_ids = []
        for i in range(ppgs):
            try:
                ppg_ids.append(self._create_simple_ppg(**ppg_args[i])['id'])
            except IndexError:
                ppg_ids.append(self._create_simple_ppg()['id'])
        return self.create_port_chain(port_pair_groups=ppg_ids,
                                      flow_classifiers=flowc_ids,
                                      expected_res_status=201)['port_chain']

    def _verify_ppg_mapping(self, ppg, tenant):
        apic_tn = tenant
        # Verify expected AIM model
        ctx = self._aim_context
        # DeviceCluster. Only one created
        dc = self.aim_mgr.get(ctx, aim_sg.DeviceCluster(
            tenant_name=apic_tn, name='ppg_' + ppg['id']))
        self.assertIsNotNone(dc)
        self.assertEqual(self.physdom.name, dc.physical_domain_name)
        pps = [self.show_port_pair(x)['port_pair'] for x in ppg['port_pairs']]

        for pp in pps:
            self.assertIsNotNone(self.aim_mgr.get(
                ctx, aim_sg.ConcreteDevice(tenant_name=apic_tn,
                                           device_cluster_name=dc.name,
                                           name='pp_' + pp['id'])))

        for pp in pps:
            # Each of these CD have 2 CDIs
            iprt = self._show_port(pp['ingress'])
            eprt = self._show_port(pp['egress'])
            pp_dcis = self.aim_mgr.find(
                ctx, aim_sg.ConcreteDeviceInterface, tenant_name=apic_tn,
                device_cluster_name=dc.name, device_name='pp_' + pp['id'])
            self.assertEqual(self.path_by_host[iprt['binding:host_id']],
                             pp_dcis[0].path)
            self.assertEqual(self.path_by_host[eprt['binding:host_id']],
                             pp_dcis[1].path)
            iepg = self.aim_mech._get_epg_by_network_id(self._ctx.session,
                                                        iprt['network_id'])
            eepg = self.aim_mech._get_epg_by_network_id(self._ctx.session,
                                                        eprt['network_id'])
            self.assertFalse(self.aim_mgr.get(ctx, iepg).sync)
            self.assertFalse(self.aim_mgr.get(ctx, eepg).sync)

        # 1 PPG means 1 service, which has 2 DeviceClusterInterfaces
        # comprehensive of all the above ConcreteDeviceInterfaces
        idci = self.aim_mgr.get(ctx, aim_sg.DeviceClusterInterface(
            tenant_name=dc.tenant_name, device_cluster_name=dc.name,
            name='ingress'))
        edci = self.aim_mgr.get(ctx, aim_sg.DeviceClusterInterface(
            tenant_name=dc.tenant_name, device_cluster_name=dc.name,
            name='egress'))
        self.assertIsNotNone(idci)
        self.assertIsNotNone(edci)

        # Ingress CDIs
        ingr_cdis = [
            self.aim_mgr.get(
                ctx, aim_sg.ConcreteDeviceInterface(
                    tenant_name=apic_tn, device_cluster_name=dc.name,
                    device_name='pp_' + pp['id'], name='prt_' + pp['ingress']))
            for pp in pps]

        self.assertEqual({ingr.dn for ingr in ingr_cdis},
                         set(idci.concrete_interfaces))

        # Egress CDIs
        egr_cdis = [
            self.aim_mgr.get(
                ctx, aim_sg.ConcreteDeviceInterface(
                    tenant_name=apic_tn, device_cluster_name=dc.name,
                    device_name='pp_' + pp['id'], name='prt_' + pp['egress']))
            for pp in pps]

        self.assertEqual({egr.dn for egr in egr_cdis},
                         set(edci.concrete_interfaces))

        # Redirect Policy Ingress
        irp = self.aim_mgr.get(ctx, aim_sg.ServiceRedirectPolicy(
            tenant_name=dc.tenant_name, name='ingr_ppg_' + ppg['id']))
        erp = self.aim_mgr.get(ctx, aim_sg.ServiceRedirectPolicy(
            tenant_name=dc.tenant_name, name='egr_ppg_' + ppg['id']))
        self.assertIsNotNone(irp)
        self.assertIsNotNone(erp)

        # Ingress Ports
        iprts = [self._show_port(pp['ingress']) for pp in pps]
        self.assertEqual(
            sorted([{'ip': iprt['fixed_ips'][0]['ip_address'],
                     'mac': iprt['mac_address']} for iprt in iprts]),
            irp.destinations)
        eprts = [self._show_port(pp['egress']) for pp in pps]
        self.assertEqual(
            sorted([{'ip': eprt['fixed_ips'][0]['ip_address'],
                     'mac': eprt['mac_address']} for eprt in eprts]),
            erp.destinations)

    def _verify_pc_mapping(self, pc):
        ctx = self._aim_context
        flowcs = [self.show_flow_classifier(x)['flow_classifier'] for x in
                  pc['flow_classifiers']]
        flowc_tenants = set([self._show_network(
            flowc['l7_parameters']['logical_destination_network'])['tenant_id']
            for flowc in flowcs])
        ppgs = [self.show_port_pair_group(x)['port_pair_group'] for x in
                pc['port_pair_groups']]
        self.assertEqual(
            len(flowcs), len(self.aim_mgr.find(ctx, aim_res.Contract)))
        self.assertEqual(
            len(flowcs), len(self.aim_mgr.find(ctx, aim_res.ContractSubject)))
        self.assertEqual(
            len(flowc_tenants) * len(ppgs),
            len(self.aim_mgr.find(ctx, aim_sg.DeviceClusterContext)))
        self.assertEqual(
            len(flowc_tenants) * len(ppgs) * 2,
            len(self.aim_mgr.find(ctx, aim_sg.DeviceClusterInterfaceContext)))
        self.assertEqual(
            len(flowc_tenants),
            len(self.aim_mgr.find(ctx, aim_sg.ServiceGraph)))
        for flowc in flowcs:
            src_net = self._show_network(
                flowc['l7_parameters']['logical_source_network'])
            dst_net = self._show_network(
                flowc['l7_parameters']['logical_destination_network'])
            apic_tn = 'prj_' + dst_net['tenant_id']
            device_clusters = []
            sg = self.aim_mgr.get(ctx, aim_sg.ServiceGraph(
                tenant_name=apic_tn, name='ptc_' + pc['id']))
            self.assertIsNotNone(sg)
            # Verify Flow Classifier mapping
            contract = self.aim_mgr.get(
                ctx, aim_res.Contract(tenant_name=apic_tn,
                                      name='flc_' + flowc['id']))
            self.assertIsNotNone(contract)
            subject = self.aim_mgr.get(
                ctx, aim_res.ContractSubject(
                    tenant_name=apic_tn, contract_name='flc_' + flowc['id'],
                    name='ptc_' + pc['id']))
            self.assertIsNotNone(subject)
            self.assertEqual(['openstack_AnyFilter'], subject.bi_filters)
            src_cidr = flowc['source_ip_prefix']
            dst_cird = flowc['destination_ip_prefix']
            for net, pref, cidr in [(src_net, 'src_', src_cidr),
                                    (dst_net, 'dst_', dst_cird)]:
                if net['apic:svi']:
                    # TODO(ivar): this will not work, there's no L3Outside
                    # DN extension for external networks.
                    ext = aim_res.ExternalNetwork.from_dn(
                        net['apic:distinguished_names']['ExternalNetwork'])
                    if cidr in ['0.0.0.0/0', '::/0']:
                        # use default external EPG
                        ext_net = self.aim_mgr.get(ctx, ext)
                    else:
                        ext_net = self.aim_mgr.get(
                            ctx, aim_res.ExternalNetwork(
                                tenant_name=ext.tenant_name,
                                l3out_name=ext.l3out_name,
                                name=cidr.replace(
                                    '/', '_') + '_' + 'net_' + net['id']))
                    ext_sub = self.aim_mgr.get(ctx, aim_res.ExternalSubnet(
                        tenant_name=ext.tenant_name, l3out_name=ext.l3out_name,
                        external_network_name=ext_net.name, cidr=cidr))
                    self.assertIsNotNone(ext_net)
                    self.assertIsNotNone(ext_sub)
                    self.assertTrue(
                        contract.name in (ext_net.consumed_contract_names if
                                          pref == 'src_' else
                                          ext_net.provided_contract_names))
                else:
                    epg = self.aim_mgr.get(
                        ctx, aim_res.EndpointGroup.from_dn(
                            net['apic:distinguished_names']['EndpointGroup']))
                    self.assertTrue(
                        contract.name in (epg.consumed_contract_names if
                                          pref == 'src_' else
                                          epg.provided_contract_names))
            for ppg in ppgs:
                self._verify_ppg_mapping(ppg, apic_tn)
                device_cluster = self.aim_mgr.get(
                    ctx, aim_sg.DeviceCluster(tenant_name=apic_tn,
                                              name='ppg_' + ppg['id']))
                device_clusters.append(device_cluster)
                dcc = self.aim_mgr.get(
                    ctx, aim_sg.DeviceClusterContext(
                        tenant_name=sg.tenant_name,
                        contract_name="any",
                        service_graph_name=sg.name,
                        node_name=device_cluster.name))
                self.assertIsNotNone(dcc)
                self.assertEqual(device_cluster.name, dcc.device_cluster_name)
                self.assertEqual(apic_tn, dcc.device_cluster_tenant_name)
                # Get ingress/egress BD
                pp = self.show_port_pair(ppg['port_pairs'][0])['port_pair']
                ingress_net = self._get_port_network(pp['ingress'])
                egress_net = self._get_port_network(pp['egress'])
                ingress_bd = ingress_net[
                    'apic:distinguished_names']['BridgeDomain']
                egress_bd = egress_net[
                    'apic:distinguished_names']['BridgeDomain']

                dci = aim_sg.DeviceClusterInterface(
                    tenant_name=device_cluster.tenant_name,
                    device_cluster_name=device_cluster.name, name='ingress')
                dcic = aim_sg.DeviceClusterInterfaceContext(
                    tenant_name=apic_tn, contract_name="any",
                    service_graph_name=sg.name, node_name=device_cluster.name,
                    connector_name='consumer')
                dcic = self.aim_mgr.get(ctx, dcic)
                self.assertIsNotNone(dcic)
                self.assertEqual(ingress_bd, dcic.bridge_domain_dn)
                self.assertEqual(dci.dn, dcic.device_cluster_interface_dn)
                self.assertNotEqual('', dcic.service_redirect_policy_dn)

                dci = aim_sg.DeviceClusterInterface(
                    tenant_name=device_cluster.tenant_name,
                    device_cluster_name=device_cluster.name, name='egress')
                dcic = aim_sg.DeviceClusterInterfaceContext(
                    tenant_name=apic_tn, contract_name="any",
                    service_graph_name=sg.name, node_name=device_cluster.name,
                    connector_name='provider')
                dcic = self.aim_mgr.get(ctx, dcic)
                self.assertIsNotNone(dcic)
                self.assertEqual(egress_bd, dcic.bridge_domain_dn)
                self.assertEqual(dci.dn, dcic.device_cluster_interface_dn)
                self.assertNotEqual('', dcic.service_redirect_policy_dn)
            self.assertEqual(
                sorted({'name': x.name, 'device_cluster_name': x.name,
                        'device_cluster_tenant_name': x.tenant_name}
                       for x in device_clusters),
                sorted(sg.linear_chain_nodes))

    def _verify_pc_delete(self, pc):
        ctx = self._aim_context
        self.delete_port_chain(pc['id'])
        # PC and Flowc unmapped
        self.assertEqual([], self.aim_mgr.find(ctx, aim_res.Contract))
        self.assertEqual([], self.aim_mgr.find(ctx, aim_res.ContractSubject))
        self.assertEqual(
            [], self.aim_mgr.find(ctx, aim_sg.DeviceClusterContext))
        self.assertEqual(
            [], self.aim_mgr.find(ctx, aim_sg.DeviceClusterInterfaceContext))
        self.assertEqual([], self.aim_mgr.find(ctx, aim_sg.ServiceGraph))
        # PPGs unmapped
        self.assertEqual(
            0, len(self.aim_mgr.find(ctx, aim_sg.ServiceRedirectPolicy)))
        self.assertEqual(
            0, len(self.aim_mgr.find(ctx, aim_sg.ConcreteDeviceInterface)))
        self.assertEqual(
            0, len(self.aim_mgr.find(ctx, aim_sg.ConcreteDevice)))
        self.assertEqual(
            0, len(self.aim_mgr.find(ctx, aim_sg.DeviceCluster)))
        self.assertEqual(
            0, len(self.aim_mgr.find(ctx, aim_sg.DeviceClusterInterface)))
        ppgs = [self.show_port_pair_group(x)['port_pair_group'] for x in
                pc['port_pair_groups']]
        for ppg in ppgs:
            pps = [self.show_port_pair(x)['port_pair'] for x in
                   ppg['port_pairs']]
            for pp in pps:
                iprt = self._show_port(pp['ingress'])
                eprt = self._show_port(pp['egress'])
                iepg = self.aim_mech._get_epg_by_network_id(self._ctx.session,
                                                            iprt['network_id'])
                eepg = self.aim_mech._get_epg_by_network_id(self._ctx.session,
                                                            eprt['network_id'])
                self.assertTrue(self.aim_mgr.get(ctx, iepg).sync)
                self.assertTrue(self.aim_mgr.get(ctx, eepg).sync)

    def _delete_network(self, network_id):
        req = self.new_delete_request('networks', network_id)
        return req.get_response(self.api)


class TestPortPair(TestAIMServiceFunctionChainingBase):

    def test_port_pair_validation(self):
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        p1 = self._make_port(self.fmt, net1['network']['id'])['port']

        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net1, '192.168.1.1', '192.168.1.0/24')
        p2 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h2')
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=201)
        # Same network ports
        p3 = self._make_port(self.fmt, net2['network']['id'])['port']
        p4 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p3['id'], 'h1')
        self._bind_port_to_host(p4['id'], 'h2')
        self.create_port_pair(ingress=p3['id'], egress=p4['id'],
                              expected_res_status=500)
        # Also unbound ports can be used
        p5 = self._make_port(self.fmt, net1['network']['id'])['port']
        self.create_port_pair(ingress=p3['id'], egress=p5['id'],
                              expected_res_status=400)
        # Ports with no domain

    def test_port_pair_validation_no_domain(self):
        self.aim_mgr.delete(self._aim_context, self.physdom)
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net1, '192.168.1.1', '192.168.1.0/24')
        p1 = self._make_port(self.fmt, net1['network']['id'])['port']
        p2 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p1['id'], 'h1')
        # H3 has no domain specified
        self._bind_port_to_host(p2['id'], 'h3')
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=500)
        # Both ports no domain
        p3 = self._make_port(self.fmt, net1['network']['id'])['port']
        self._bind_port_to_host(p3['id'], 'h4')
        self.create_port_pair(ingress=p3['id'], egress=p2['id'],
                              expected_res_status=500)
        # Add domain, but different than H1
        pd = self.aim_mgr.create(
            self._aim_context, aim_infra.HostDomainMappingV2(
                host_name='h3', domain_name='diff-name',
                domain_type='PhysDom'))
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=500)
        # Multi domain per host
        self.aim_mgr.create(self._aim_context, aim_infra.HostDomainMappingV2(
            host_name='h3', domain_name=self.physdom.name,
            domain_type='PhysDom'))
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=500)
        # Delete extra domain
        self.aim_mgr.delete(self._aim_context, pd)
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=201)

    def test_port_pair_validation_trunk(self):
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        snet1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.167.0.1', '192.167.0.0/24')
        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net1, '192.168.1.1', '192.168.1.0/24')
        snet2 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.167.1.1', '192.167.1.0/24')
        p1 = self._make_port(self.fmt, net1['network']['id'])['port']
        p2 = self._make_port(self.fmt, net2['network']['id'])['port']
        sp1 = self._make_port(self.fmt, snet1['network']['id'])['port']
        sp2 = self._make_port(self.fmt, snet2['network']['id'])['port']
        trunk1 = self._create_resource('trunk', port_id=p1['id'])
        trunk2 = self._create_resource('trunk', port_id=p2['id'])
        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h2')
        self._bind_subport(self._ctx, trunk1, sp1)
        self._bind_subport(self._ctx, trunk2, sp2)
        self.driver._trunk_plugin.add_subports(
            self._ctx, trunk1['trunk']['id'],
            {'sub_ports': [{'port_id': sp1['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 100}]})
        self.driver._trunk_plugin.add_subports(
            self._ctx, trunk2['trunk']['id'],
            {'sub_ports': [{'port_id': sp2['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 100}]})
        self.create_port_pair(ingress=sp1['id'], egress=sp2['id'],
                              expected_res_status=201)


class TestPortPairGroup(TestAIMServiceFunctionChainingBase):

    def test_ppg_validation(self):
        # Correct creation
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net2, '192.168.1.1', '192.168.1.0/24')

        # Service 1
        p11 = self._make_port(self.fmt, net1['network']['id'])['port']
        self._bind_port_to_host(p11['id'], 'h1')
        p12 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p12['id'], 'h1')
        pp1 = self.create_port_pair(ingress=p11['id'], egress=p12['id'],
                                    expected_res_status=201)['port_pair']
        # Service 2
        p21 = self._make_port(self.fmt, net1['network']['id'])['port']
        self._bind_port_to_host(p21['id'], 'h2')
        p22 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p22['id'], 'h2')
        pp2 = self.create_port_pair(ingress=p21['id'], egress=p22['id'],
                                    expected_res_status=201)['port_pair']
        # This goes through
        ppg1 = self.create_port_pair_group(
            port_pairs=[pp1['id'], pp2['id']],
            expected_res_status=201)['port_pair_group']
        # Use invalid pairs
        net3 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net3, '192.168.0.1', '192.168.0.0/24')
        p31 = self._make_port(self.fmt, net3['network']['id'])['port']
        self._bind_port_to_host(p31['id'], 'h1')
        pp3 = self.create_port_pair(ingress=p21['id'], egress=p31['id'],
                                    expected_res_status=201)['port_pair']
        self.delete_port_pair_group(ppg1['id'])
        self.create_port_pair_group(port_pairs=[pp1['id'], pp3['id']],
                                    expected_res_status=500)
        # Works with only one PP
        ppg2 = self.create_port_pair_group(
            port_pairs=[pp3['id']],
            expected_res_status=201)['port_pair_group']
        # But update fails
        self.update_port_pair_group(
            ppg2['id'], port_pairs=[pp3['id'], pp1['id']],
            expected_res_status=500)


class TestFlowClassifier(TestAIMServiceFunctionChainingBase):

    def test_fc_validation(self):
        # Correct classifier
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')

        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net1, '192.168.1.1', '192.168.1.0/24')
        fc = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net2['network']['id']},
            source_ip_prefix='192.168.0.0/24',
            destination_ip_prefix='192.168.1.0/24',
            expected_res_status=201)['flow_classifier']
        self.delete_flow_classifier(fc['id'], expected_res_status=204)
        # Wrong FCs
        self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net2['network']['id']},
            source_ip_prefix='192.168.0.0/24', expected_res_status=400)
        self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net2['network']['id']},
            destination_ip_prefix='192.168.1.0/24',
            expected_res_status=400)
        self.create_flow_classifier(
            l7_parameters={'logical_source_network': net1['network']['id']},
            source_ip_prefix='192.168.0.0/24',
            destination_ip_prefix='192.168.1.0/24', expected_res_status=400)
        self.create_flow_classifier(
            l7_parameters={
                'logical_destination_network': net2['network']['id']},
            source_ip_prefix='192.168.0.0/24',
            destination_ip_prefix='192.168.1.0/24', expected_res_status=400)
        self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net1['network']['id']},
            source_ip_prefix='192.168.0.0/24', expected_res_status=400)
        self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': ''},
            source_ip_prefix='192.168.0.0/24', expected_res_status=400)
        self._delete_network(net2['network']['id'])
        self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': net1['network']['id'],
                'logical_destination_network': net2['network']['id']},
            source_ip_prefix='192.168.0.0/24', expected_res_status=404)


class TestPortChain(TestAIMServiceFunctionChainingBase):

    def setUp(self, *args, **kwargs):
        super(TestPortChain, self).setUp()
        self.src_svi = False
        self.dst_svi = False

    def _get_port_network(self, port_id):
        port = self._show_port(port_id)
        return self._show_network(port['network_id'])

    def test_pc_validation(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2)
        ppg2 = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=201)['port_chain']
        # Same classifier is not allowed.
        self.create_port_chain(port_pair_groups=[ppg2['id']],
                               flow_classifiers=[fc['id']],
                               expected_res_status=409)
        self.update_port_chain(
            pc['id'], port_pair_groups=[ppg['id'], ppg2['id']],
            expected_res_status=200)

    def test_pc_validation_network_conflict(self):
        nets = []
        for i in range(3):
            net = self._make_network(self.fmt, 'net1', True)
            self._make_subnet(self.fmt, net, '192.168.%s.1' % i,
                              '192.168.%s.0/24' % i)
            nets.append(net['network']['id'])
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2, leftn_id=nets[0],
                                      rightn_id=nets[1])
        ppg2 = self._create_simple_ppg(pairs=2, leftn_id=nets[0],
                                       rightn_id=nets[1])
        # Conflict with only one network
        ppg3 = self._create_simple_ppg(pairs=2, leftn_id=nets[0],
                                       rightn_id=nets[2])
        self.create_port_chain(port_pair_groups=[ppg['id'], ppg2['id']],
                               flow_classifiers=[fc['id']],
                               expected_res_status=400)
        self.create_port_chain(port_pair_groups=[ppg['id'], ppg3['id']],
                               flow_classifiers=[fc['id']],
                               expected_res_status=400)

    def test_pc_mapping(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_pc_mapping_two_flowcs(self):
        pc = self._create_simple_port_chain(
            flowcs=2, ppgs=3, ppg_args=[{'pairs': 1}, {'pairs': 2},
                                        {'pairs': 3}])
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_pc_mapping_no_flowcs(self):
        pc = self._create_simple_port_chain(
            flowcs=0, ppgs=3, ppg_args=[{'pairs': 1}, {'pairs': 2},
                                        {'pairs': 3}])
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_ppg_update(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=201)['port_chain']
        pps = ppg['port_pairs']
        # remove one pp
        ppg = self.update_port_pair_group(
            ppg['id'], port_pairs=[pps[0]])['port_pair_group']
        self._verify_pc_mapping(pc)
        # Replace pp
        ppg = self.update_port_pair_group(
            ppg['id'], port_pairs=[pps[1]])['port_pair_group']
        self._verify_pc_mapping(pc)
        # Add pp
        ppg = self.update_port_pair_group(
            ppg['id'], port_pairs=pps)['port_pair_group']
        self._verify_pc_mapping(pc)

    def test_flowc_update(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=1)
        self.create_port_chain(port_pair_groups=[ppg['id']],
                               flow_classifiers=[fc['id']],
                               expected_res_status=201)
        res = self._delete_network(
            fc['l7_parameters']['logical_source_network'])
        self.assertEqual(400, res.status_int)
        res = self._delete_network(
            fc['l7_parameters']['logical_destination_network'])
        self.assertEqual(400, res.status_int)

    def test_vrf_update(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2)
        self.create_port_chain(port_pair_groups=[ppg['id']],
                               flow_classifiers=[fc['id']],
                               expected_res_status=201)
        self.aim_mgr.create(
            self._aim_context, aim_res.EndpointGroup(
                tenant_name='new', app_profile_name='new', name='new'))
        net_db = self._plugin._get_network(
            self._ctx, fc['l7_parameters']['logical_source_network'])
        self.assertRaises(c_exc.CallbackFailure,
                          self.aim_mech._set_network_vrf_and_notify,
                          self._ctx, net_db.aim_mapping,
                          aim_res.VRF(tenant_name='new', name='new'))
        net_db = self._plugin._get_network(
            self._ctx, fc['l7_parameters']['logical_destination_network'])
        self.assertRaises(c_exc.CallbackFailure,
                          self.aim_mech._set_network_vrf_and_notify,
                          self._ctx, net_db.aim_mapping,
                          aim_res.VRF(tenant_name='new', name='new'))
        # Also changing EPG affects PC if tenant changes
        self.assertRaises(c_exc.CallbackFailure,
                          self.aim_mech._set_network_epg_and_notify,
                          self._ctx, net_db.aim_mapping,
                          aim_res.EndpointGroup(tenant_name='new',
                                                app_profile_name='new',
                                                name='new'))
        # But it doesn't if tenant stays the same
        self.aim_mgr.create(
            self._aim_context, aim_res.EndpointGroup(
                tenant_name=net_db.aim_mapping.epg_tenant_name,
                app_profile_name='new', name='new'))
        self.aim_mech._set_network_epg_and_notify(
            self._ctx, net_db.aim_mapping, aim_res.EndpointGroup(
                tenant_name=net_db.aim_mapping.epg_tenant_name,
                app_profile_name='new', name='new'))

        pp = self.show_port_pair(ppg['port_pairs'][0])['port_pair']
        net = self._get_port_network(pp['ingress'])
        net_db = self._plugin._get_network(self._ctx, net['id'])
        # Modifying EPG in service nets has no effect
        self.aim_mech._set_network_epg_and_notify(
            self._ctx, net_db.aim_mapping,
            aim_res.EndpointGroup(tenant_name='new', app_profile_name='new',
                                  name='new'))
        # But it fails when VRF is changed
        self.assertRaises(c_exc.CallbackFailure,
                          self.aim_mech._set_network_vrf_and_notify,
                          self._ctx, net_db.aim_mapping,
                          aim_res.VRF(tenant_name='new', name='new'))

    def test_pc_mapping_no_host_mapping(self):
        ctx = self._aim_context
        self.aim_mgr.delete_all(ctx, aim_infra.HostDomainMappingV2)
        # Since one physdom exists, everything works just fine
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)
        # If I also delete the physdom, everything fails
        self.aim_mgr.delete(ctx, self.physdom)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=400)

    def test_pc_mapping_same_provider_diff_consumer(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        # New classifier with only one change in subnet
        fc2 = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': fc[
                    'l7_parameters']['logical_source_network'],
                'logical_destination_network': fc[
                    'l7_parameters']['logical_destination_network']},
            source_ip_prefix='192.168.3.0/24',
            destination_ip_prefix=fc['destination_ip_prefix'],
            expected_res_status=201)['flow_classifier']

        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc['id']],
                                    expected_res_status=201)['port_chain']
        pc = self.update_port_chain(pc['id'],
                                    flow_classifiers=[fc['id'], fc2['id']],
                                    expected_res_status=200)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_pc_mapping_default_sub_dst(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        # New classifier with only one change in subnet
        fc2 = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': fc[
                    'l7_parameters']['logical_source_network'],
                'logical_destination_network': fc[
                    'l7_parameters']['logical_destination_network']},
            source_ip_prefix=fc['source_ip_prefix'],
            destination_ip_prefix='0.0.0.0/0',
            expected_res_status=201)['flow_classifier']

        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc2['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_pc_mapping_default_sub_src(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        # New classifier with only one change in subnet
        fc2 = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': fc[
                    'l7_parameters']['logical_source_network'],
                'logical_destination_network': fc[
                    'l7_parameters']['logical_destination_network']},
            source_ip_prefix='0.0.0.0/0',
            destination_ip_prefix=fc['destination_ip_prefix'],
            expected_res_status=201)['flow_classifier']

        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc2['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    def test_pc_mapping_default_sub_both(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        # New classifier with only one change in subnet
        fc2 = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': fc[
                    'l7_parameters']['logical_source_network'],
                'logical_destination_network': fc[
                    'l7_parameters']['logical_destination_network']},
            source_ip_prefix='0.0.0.0/0',
            destination_ip_prefix='0.0.0.0/0',
            expected_res_status=201)['flow_classifier']

        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc2['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)

    # Enable once fixed on the SVI side.
    def _test_pc_mapping_default_sub_ipv6(self):
        fc = self._create_simple_flowc(src_svi=self.src_svi,
                                       dst_svi=self.dst_svi)
        # New classifier with only one change in subnet
        fc2 = self.create_flow_classifier(
            l7_parameters={
                'logical_source_network': fc[
                    'l7_parameters']['logical_source_network'],
                'logical_destination_network': fc[
                    'l7_parameters']['logical_destination_network']},
            source_ip_prefix='::/0', destination_ip_prefix='::/0',
            expected_res_status=201, ethertype='IPv6')['flow_classifier']

        ppg = self._create_simple_ppg(pairs=2)
        pc = self.create_port_chain(port_pair_groups=[ppg['id']],
                                    flow_classifiers=[fc2['id']],
                                    expected_res_status=201)['port_chain']
        self._verify_pc_mapping(pc)
        self._verify_pc_delete(pc)


class TestPortChainSVI(TestPortChain):

    def setUp(self, *args, **kwargs):
        super(TestPortChainSVI, self).setUp()
        self.src_svi = True
        self.dst_svi = True

    def test_vrf_update(self):
        # TODO(ivar): VRF is not in mapping, can't be updated
        pass
