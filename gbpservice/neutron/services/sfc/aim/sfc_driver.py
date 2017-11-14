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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim.api import service_graph as aim_sg
from aim import context as aim_context
from aim import utils as aim_utils
from networking_sfc.db import sfc_db
from networking_sfc.extensions import flowclassifier as flowc_ext
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.drivers import base
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron import manager
from neutron_lib import constants as n_constants
from oslo_log import log as logging

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions

PBR_INGR_PREFIX = 'ingr_'
PBR_EGR_PREFIX = 'egr_'
INGRESS = 'ingress'
EGRESS = 'egress'
FLOWC_SRC_PREFIX = 'src_'
FLOWC_DST_PREFIX = 'dst_'
LOG = logging.getLogger(__name__)
PHYSDOM_TYPE = 'PhysDom'
SUPPORTED_DOM_TYPES = [PHYSDOM_TYPE]


class SfcAIMDriverBase(base.SfcDriverBase):
    def delete_port_pair_group(self, context):
        pass

    def create_port_chain(self, context):
        pass

    def create_port_pair(self, context):
        pass

    def create_port_pair_group(self, context):
        pass

    def delete_port_pair(self, context):
        pass

    def delete_port_chain(self, context):
        pass

    def update_port_pair_group(self, context):
        pass

    def update_port_chain(self, context):
        pass

    def update_port_pair(self, context):
        pass


class SfcAIMDriver(SfcAIMDriverBase):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        # TODO(ivar): SFC resource mapping to APIC DNs
        self._core_plugin = None
        self._flowc_plugin = None
        self._l3_plugin = None
        self._sfc_plugin = None
        self._aim_mech_driver = None
        self.name_mapper = apic_mapper.APICNameMapper()
        self.aim = aim_manager.AimManager()
        # We don't care about deletion, that is managed by the database layer
        # (can't delete a flowclassifier if in use.
        for event in [events.PRECOMMIT_UPDATE, events.PRECOMMIT_CREATE]:
            registry.subscribe(self._handle_flow_classifier,
                               sfc_cts.GBP_FLOW_CLASSIFIER, event)
        registry.subscribe(self._handle_port_bound, sfc_cts.GBP_PORT,
                           events.PRECOMMIT_UPDATE)

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = manager.NeutronManager.get_plugin()
            if not self._core_plugin:
                LOG.error(_("No Core plugin found."))
                raise exc.GroupPolicyDeploymentError()
        return self._core_plugin

    @property
    def flowc_plugin(self):
        if not self._flowc_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._flowc_plugin = plugins.get(flowc_ext.FLOW_CLASSIFIER_EXT)
            if not self._flowc_plugin:
                LOG.error(_("No FlowClassifier service plugin found."))
                raise exc.GroupPolicyDeploymentError()
        return self._flowc_plugin

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._l3_plugin = plugins.get(n_constants.L3)
            if not self._l3_plugin:
                LOG.error(_("No L3 service plugin found."))
                raise exc.GroupPolicyDeploymentError()
        return self._l3_plugin

    @property
    def sfc_plugin(self):
        if not self._sfc_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._sfc_plugin = plugins.get(sfc_ext.SFC_EXT)
            if not self._sfc_plugin:
                LOG.error(_("No SFC service plugin found."))
                raise exc.GroupPolicyDeploymentError()
        return self._sfc_plugin

    @property
    def aim_mech(self):
        if not self._aim_mech_driver:
            try:
                self._aim_mech_driver = (
                    self.plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
            except (KeyError, AttributeError):
                LOG.error(_("No AIM driver found"))
                raise exc.GroupPolicyDeploymentError()
        return self._aim_mech_driver

    def create_port_pair_precommit(self, context):
        """Map Port Pair to AIM model

        A Port Pair by itself doesn't need to generate AIM model at least
        until added to a Port Pair Group.
        :param context:
        :return:
        """
        self._validate_port_pair(context)

    def update_port_pair_precommit(self, context, remap=False):
        self._validate_port_pair(context)
        p_ctx = context._plugin_context
        # Remap the affected groups if needed.
        if remap or self._should_regenerate_pp(context):
            for group in self._get_groups_by_pair_id(p_ctx,
                                                     context.current['id']):
                # Curr and original are identical, so the same object gets
                # remapped.
                g_ctx = sfc_ctx.PortPairGroupContext(context._plugin, p_ctx,
                                                     group, group)
                self.update_port_pair_group_precommit(g_ctx, remap=True)

    def delete_port_pair_precommit(self, context):
        # NOTE(ivar): DB layer prevents port pair deletion when in use by a
        # port pair group.
        pass

    def create_port_pair_group_precommit(self, context):
        """Map port pair group to AIM model

        A Port Pair Group is the equivalent of a Logical Device in AIM.
        :param context:
        :return:
        """
        self._validate_port_pair_group(context)

    def update_port_pair_group_precommit(self, context, remap=False):
        self._validate_port_pair_group(context)
        # Remap Port Chain if needed
        if remap or self._should_regenerate_ppg(context):
            for chain in self._get_chains_by_ppg_id(context._plugin_context,
                                                    context.current['id']):
                c_ctx = sfc_ctx.PortChainContext(
                    context._plugin, context._plugin_context, chain, chain)
                self.update_port_chain_precommit(c_ctx, remap=True)

    def delete_port_pair_group_precommit(self, context):
        # NOTE(ivar): DB layer prevents deletion when used by port chains
        pass

    def create_port_chain_precommit(self, context):
        pc = context.current
        p_ctx = context._plugin_context
        flowcs, ppgs = self._get_pc_flowcs_and_ppgs(p_ctx, pc)
        self._validate_port_chain(context, flowcs, ppgs)
        self._map_port_chain(p_ctx, pc, flowcs, ppgs)

    def update_port_chain_precommit(self, context, remap=False):
        p_ctx = context._plugin_context
        flowcs, ppgs = self._get_pc_flowcs_and_ppgs(p_ctx, context.current)
        self._validate_port_chain(context, flowcs, ppgs)
        # Regenerate Port Chain Model
        if remap or self._should_regenerate_pc(context):
            o_flowcs, o_ppgs = self._get_pc_flowcs_and_ppgs(p_ctx,
                                                            context.original)
            self._delete_port_chain_mapping(p_ctx, context.original, o_flowcs,
                                            o_ppgs)
            self._map_port_chain(p_ctx, context.current, flowcs, ppgs)

    def delete_port_chain_precommit(self, context):
        p_ctx = context._plugin_context
        flowcs, ppgs = self._get_pc_flowcs_and_ppgs(p_ctx, context.current)
        self._delete_port_chain_mapping(p_ctx, context.current, flowcs, ppgs)

    def _validate_port_pair(self, context):
        # Ports need to belong to distinct networks
        p_ctx = context._plugin_context
        ingress_port = self.plugin.get_port(p_ctx, context.current['ingress'])
        egress_port = self.plugin.get_port(p_ctx, context.current['egress'])
        ingress_net = ingress_port['network_id']
        egress_net = egress_port['network_id']
        if ingress_net == egress_net:
            raise exceptions.PortPairsSameNetwork(id=context.current['id'])
        igress_dom = self.aim_mech._get_port_unique_domain(p_ctx, ingress_port)
        egress_dom = self.aim_mech._get_port_unique_domain(p_ctx, egress_port)
        if igress_dom != egress_dom:
            raise exceptions.PortPairsDifferentDomain(id=context.current['id'])
        if any(x for x in [igress_dom, egress_dom] if x == (None, None)):
            raise exceptions.PortPairsNoUniqueDomain(id=context.current['id'])
        # Ensure  domain types supported
        if igress_dom[0] not in SUPPORTED_DOM_TYPES:
            raise exceptions.PortPairsUnsupportedDomain(
                id=context.current['id'], doms=SUPPORTED_DOM_TYPES)

    def _validate_port_pair_group(self, context):
        # Verify all ports are in the same network for each side of the
        # connection
        p_ctx = context._plugin_context
        port_pairs = context._plugin.get_port_pairs(
            p_ctx, filters={'id': context.current['port_pairs']})
        domains = set()
        net_pairs = set()
        for port_pair in port_pairs:
            ingress_port = self.plugin.get_port(p_ctx, port_pair['ingress'])
            egress_port = self.plugin.get_port(p_ctx, port_pair['egress'])
            domains.add(self.aim_mech._get_port_unique_domain(p_ctx,
                                                              ingress_port))
            if len(domains) > 1:
                raise exceptions.PortPairsInPortPairGroupDifferentDomain(
                    id=context.current['id'])
            net_pairs.add((ingress_port['network_id'],
                           egress_port['network_id']))
            if len(net_pairs) > 1:
                raise exceptions.PortPairsDifferentNetworkInGroup(
                    id=context.current['id'])

    def _validate_port_chain(self, context, flowcs, ppgs):
        # TODO(ivar): validate the followings:
        # - All networks in play (prov, cons, services) are in the same VRF,
        #   also listen to events to prevent VRF to change after the fact
        #   alternatively, and ERROR status can be raised
        # - TEMPORARY: provider and consumer EPGs are in the same tenant, this
        #   can be removed once contract export is implemented.
        pass

    def _map_port_pair_group(self, plugin_context, ppg, tenant):
        session = plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        # Create Logical device model, container for all the PPG port pairs.
        dc = self._get_ppg_device_cluster(session, ppg, tenant)
        type, domain = self._get_ppg_domain(plugin_context, ppg)
        if type == PHYSDOM_TYPE:
            dc.device_type = 'PHYSICAL'
            dc.physical_domain_name = domain
        else:
            dc.device_type = 'VIRTUAL'
            dc.vmm_domain = [{'type': type, 'name': domain}]
        self.aim.create(aim_ctx, dc)
        # For each port pair, create the corresponding Concrete Devices
        # (represented by the static path of each interface)
        ingress_cdis = []
        egress_cdis = []
        port_pairs = self.sfc_plugin.get_port_pairs(
            plugin_context, filters={'id': ppg['port_pairs']})
        for pp in port_pairs:
            ingress_port = self.plugin.get_port(plugin_context, pp['ingress'])
            egress_port = self.plugin.get_port(plugin_context, pp['egress'])
            pp_id = self.name_mapper.port_pair(session, pp['id'])
            pp_name = aim_utils.sanitize_display_name(ppg['name'])
            cd = aim_sg.ConcreteDevice(
                tenant_name=dc.tenant_name, device_cluster_name=dc.name,
                name=pp_id, display_name=pp_name)
            # Create ConcreteDevice
            self.aim.create(aim_ctx, cd)
            for p, store in [(ingress_port, ingress_cdis),
                             (egress_port, egress_cdis)]:
                p_id = self.name_mapper.port(session, p['id'])
                p_name = aim_utils.sanitize_display_name(p['name'])
                path, encap = self.aim_mech._get_port_static_path_and_encap(
                    plugin_context, p)
                if path is None:
                    LOG.warning("Path not found for Port Pair %s member %s ",
                                "Port might be unbound.", pp['id'], p['id'])
                    continue
                # TODO(ivar): what if encap is None? is that a Opflex port?
                # Create Concrete Device Interface
                cdi = aim_sg.ConcreteDeviceInterface(
                    tenant_name=cd.tenant_name,
                    device_cluster_name=cd.device_cluster_name,
                    device_name=cd.name, name=p_id, display_name=p_name,
                    path=path)
                cdi = self.aim.create(aim_ctx, cdi)
                store.append((cdi, encap, p))
        # Ingress and Egress CDIs have the same length.
        # All the ingress devices must be load balances, and so the egress
        # (for reverse path). Create the proper PBR policies as well as
        # the Logical Interfaces (which see all the physical interfaces of a
        # specific direction as they were one).
        internal_dci = aim_sg.DeviceClusterInterface(
            tenant_name=dc.tenant_name, device_cluster_name=dc.name,
            name=INGRESS, display_name=INGRESS)
        external_dci = aim_sg.DeviceClusterInterface(
            tenant_name=dc.tenant_name, device_cluster_name=dc.name,
            name=EGRESS, display_name=EGRESS)
        # Create 2 PBR rules per PPG, one per direction.
        ipbr = self._get_ppg_service_redirect_policy(session, ppg, INGRESS,
                                                     tenant)
        epbr = self._get_ppg_service_redirect_policy(session, ppg, EGRESS,
                                                     tenant)

        for i in range(len(ingress_cdis)):
            icdi, iencap, iport = ingress_cdis[i]
            ecdi, eencap, eport = egress_cdis[i]
            internal_dci.encap = iencap
            external_dci.encap = eencap
            internal_dci.concrete_interfaces.append(icdi.dn)
            external_dci.concrete_interfaces.append(ecdi.dn)
            if iport['fixed_ips']:
                ipbr.destinations.append(
                    {'ip': iport['fixed_ips'][0]['ip_address'],
                     'mac': iport['mac_address']})
            if eport['fixed_ips']:
                epbr.destinations.append(
                    {'ip': eport['fixed_ips'][0]['ip_address'],
                     'mac': eport['mac_address']})

        self.aim.create(aim_ctx, internal_dci)
        self.aim.create(aim_ctx, external_dci)
        self.aim.create(aim_ctx, ipbr)
        self.aim.create(aim_ctx, epbr)

    def _delete_port_pair_group_mapping(self, plugin_context, ppg, tenant):
        # Just delete cascade the DeviceCluster and PBR policies
        session = plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        dc = self._get_ppg_device_cluster(session, ppg, tenant)
        self.aim.delete(aim_ctx, dc, cascade=True)
        for prefix in [PBR_INGR_PREFIX, PBR_EGR_PREFIX]:
            pbr_id = self.name_mapper.port_pair_group(session, ppg['id'],
                                                      prefix=prefix)
            self.aim.delete(
                aim_ctx, aim_sg.ServiceRedirectPolicy(
                    tenant_name=dc.tenant_name, name=pbr_id), cascade=True)

    def _map_port_chain(self, plugin_context, pc, flowcs, ppgs):
        # Create one DeviceClusterContext per PPG
        p_ctx = plugin_context
        aim_ctx = aim_context.AimContext(p_ctx.session)
        # For each flow classifier, there are as many DeviceClusterContext as
        # the number of nodes in the chain.
        mapped_ppgs = set()
        for flc in flowcs:
            p_tenant = self._get_flowc_provider_group(
                plugin_context, flc).tenant_name
            sg = self._get_pc_service_graph(p_ctx.session, pc, flc, p_tenant)
            self._map_flow_classifier(p_ctx, flc, p_tenant)
            contract = self._get_flc_contract(p_ctx.session, flc, p_tenant)
            subject = aim_resource.ContractSubject(
                tenant_name=contract.tenant_name,
                contract_name=contract.name, name=sg.name,
                service_graph_name=sg.name,
                bi_filters=[self.aim_mech._any_filter_name])
            self.aim.create(aim_ctx, contract)
            self.aim.create(aim_ctx, subject)
            for ppg in ppgs:
                dc = self._get_ppg_device_cluster(p_ctx.session, ppg, p_tenant)
                # Map device clusters for each flow tenant
                if dc.dn not in mapped_ppgs:
                    self._map_port_pair_group(plugin_context, ppg, p_tenant)
                    mapped_ppgs.add(dc.dn)
                dcc = aim_sg.DeviceClusterContext(
                    tenant_name=sg.tenant_name, contract_name=contract.name,
                    service_graph_name=sg.name, node_name=dc.name,
                    display_name=dc.display_name, device_cluster_name=dc.name,
                    device_cluster_tenant_name=dc.tenant_name)
                dcc = self.aim.create(aim_ctx, dcc)
                # Create device context interfaces.
                left_bd, right_bd = self._get_ppg_left_right_bds(p_ctx, ppg)
                for conn_name, direction, bd in [
                        ('provider', EGRESS, right_bd),
                        ('consumer', INGRESS, left_bd)]:
                    dci = aim_sg.DeviceClusterInterface(
                        tenant_name=dc.tenant_name,
                        device_cluster_name=dc.name, name=direction)
                    pbr = self._get_ppg_service_redirect_policy(
                        p_ctx.session, ppg, direction, p_tenant)
                    dcic = aim_sg.DeviceClusterInterfaceContext(
                        tenant_name=dcc.tenant_name,
                        contract_name=dcc.contract_name,
                        service_graph_name=dcc.service_graph_name,
                        node_name=dcc.node_name, connector_name=conn_name,
                        display_name=dcc.display_name, bridge_domain_dn=bd.dn,
                        device_cluster_interface_dn=dci.dn,
                        service_redirect_policy_dn=pbr.dn)
                    self.aim.create(aim_ctx, dcic)
                sg.linear_chain_nodes.append(
                    {'name': dc.name, 'device_cluster_name': dc.name,
                     'device_cluster_tenant_name': dc.tenant_name})
            self.aim.create(aim_ctx, sg)

    def _delete_port_chain_mapping(self, plugin_context, pc, flowcs, ppgs):
        p_ctx = plugin_context
        session = p_ctx.session
        aim_ctx = aim_context.AimContext(session)
        deleted_ppgs = set()
        for flc in flowcs:
            tenant = self._get_flowc_provider_group(plugin_context,
                                                    flc).tenant_name
            for ppg in ppgs:
                key = (tenant, ppg['id'])
                if key not in deleted_ppgs:
                    self._delete_port_pair_group_mapping(p_ctx, ppg, tenant)
                    deleted_ppgs.add(key)
            flc_aid = self.name_mapper.flow_classifier(session, flc['id'])
            self._delete_flow_classifier_mapping(p_ctx, flc, tenant)
            contract = self._get_flc_contract(p_ctx.session, flc, tenant)
            sg = aim_sg.ServiceGraph(tenant_name=tenant, name=flc_aid)
            self.aim.delete(aim_ctx, contract, cascade=True)
            self.aim.delete(aim_ctx, sg, cascade=True)
            for ppg_id in pc['port_pair_groups']:
                ppg_aid = self.name_mapper.port_pair_group(session, ppg_id)
                dcc = aim_sg.DeviceClusterContext(
                    tenant_name=tenant, contract_name=contract.name,
                    service_graph_name=sg.name, node_name=ppg_aid)
                self.aim.delete(aim_ctx, dcc, cascade=True)

    def _map_flow_classifier(self, plugin_context, flowc, tenant):
        """Map flowclassifier to AIM model

        If source/destination ports are plugged to external networks, create
        AIM external EPGs in the proper L3Outs and set the corresponding
        source/destination ip prefix.

        :param context:
        :return:
        """
        aim_ctx = aim_context.AimContext(plugin_context.session)
        cons_group = self._get_flowc_consumer_group(plugin_context, flowc)
        prov_group = self._get_flowc_provider_group(plugin_context, flowc)
        contract = self._get_flc_contract(plugin_context.session, flowc,
                                          tenant)
        # TODO(ivar): if provider/consumer are in different tenant, export
        cons_group.consumed_contract_names.append(contract.name)
        prov_group.provided_contract_names.append(contract.name)
        self.aim.create(aim_ctx, cons_group, overwrite=True)
        self.aim.create(aim_ctx, prov_group, overwrite=True)

    def _map_flowc_network_group(self, plugin_context, net, cidr, flowc,
                                 prefix):
        flc_aid = self.name_mapper.flow_classifier(plugin_context.session,
                                                   flowc['id'], prefix=prefix)
        flc_aname = aim_utils.sanitize_display_name(flowc['name'])
        aim_ctx = aim_context.AimContext(plugin_context.session)
        l3out = self.aim_mech._get_net_l3out(net)
        if l3out:
            # Create ExternalNetwork and ExternalSubnet on the proper
            # L3Out. Return the External network
            ext_net = aim_resource.ExternalNetwork(
                tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                name=flc_aid, display_name=flc_aname)
            ext_sub = aim_resource.ExternalSubnet(
                tenant_name=ext_net.tenant_name, l3out_name=ext_net.l3out_name,
                external_network_name=ext_net.name, cidr=cidr,
                display_name=cidr)
            ext_net = self.aim.create(aim_ctx, ext_net)
            self.aim.create(aim_ctx, ext_sub)
            return ext_net
        else:
            return self.aim_mech._get_epg_by_network_id(plugin_context.session,
                                                        net['id'])

    def _delete_flow_classifier_mapping(self, plugin_context, flowc, tenant):
        source_net = self.aim_mech._get_network_by_port_id(
            plugin_context, flowc['logical_source_port'])
        dest_net = self.aim_mech._get_network_by_port_id(
            plugin_context, flowc['logical_destination_port'])
        self._delete_flowc_network_group_mapping(plugin_context, source_net,
                                                 flowc, tenant,
                                                 FLOWC_SRC_PREFIX)
        self._delete_flowc_network_group_mapping(plugin_context, dest_net,
                                                 flowc, tenant,
                                                 FLOWC_DST_PREFIX)

    def _delete_flowc_network_group_mapping(self, plugin_context, net, flowc,
                                            tenant, prefix=''):
        flc_aid = self.name_mapper.flow_classifier(
            plugin_context.session, flowc['id'], prefix=prefix)
        flc_aname = aim_utils.sanitize_display_name(flowc['name'])
        aim_ctx = aim_context.AimContext(plugin_context.session)
        l3out = self.aim_mech._get_net_l3out(net)
        if l3out:
            ext_net = aim_resource.ExternalNetwork(
                tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                name=flc_aid, display_name=flc_aname)
            self.aim.delete(aim_ctx, ext_net, cascade=True)
        else:
            epg = self.aim.get(
                aim_ctx, self.aim_mech._get_epg_by_network_id(
                    plugin_context.session, net['id']))
            contract = self._get_flc_contract(plugin_context.session, flowc,
                                              tenant)
            try:
                if prefix == FLOWC_SRC_PREFIX:
                    epg.consumed_contract_names.remove(contract.name)
                else:
                    epg.provided_contract_names.remove(contract.name)
                self.aim.create(aim_ctx, epg, overwrite=True)
            except ValueError:
                pass

    def _get_chains_by_classifier_id(self, plugin_context, flowc_id):
        context = plugin_context
        with context.session.begin(subtransactions=True):
            chain_ids = [x.portchain_id for x in context.session.query(
                sfc_db.ChainClassifierAssoc).filter_by(
                flowclassifier_id=flowc_id).all()]
            return self.sfc_plugin.get_port_chains(plugin_context,
                                                   filters={'id': chain_ids})

    def _get_chains_by_ppg_id(self, plugin_context, ppg_id):
        context = plugin_context
        with context.session.begin(subtransactions=True):
            chain_ids = [x.portchain_id for x in context.session.query(
                sfc_db.ChainGroupAssoc).filter_by(
                portpairgroup_id=ppg_id).all()]
            return self.sfc_plugin.get_port_chains(plugin_context,
                                                   filters={'id': chain_ids})

    def _get_groups_by_pair_id(self, plugin_context, pp_id):
        # NOTE(ivar): today, port pair can be associated only to one PPG
        context = plugin_context
        with context.session.begin(subtransactions=True):
            pp_db = self.sfc_plugin._get_port_pair(plugin_context, pp_id)
            if pp_db and pp_db.portpairgroup_id:
                return self.sfc_plugin.get_port_pair_groups(
                    plugin_context, filters={'id': [pp_db.portpairgroup_id]})
        return []

    def _should_regenerate_pp(self, context):
        attrs = [INGRESS, EGRESS, 'name']
        return any(context.current[a] != context.original[a] for a in attrs)

    def _should_regenerate_ppg(self, context):
        attrs = ['port_pairs', 'name']
        return any(context.current[a] != context.original[a] for a in attrs)

    def _should_regenerate_pc(self, context):
        attrs = ['flow_classifiers', 'port_pair_groups', 'name']
        return any(context.current[a] != context.original[a] for a in attrs)

    def _get_ppg_device_cluster(self, session, ppg, tenant):
        tenant_aid = tenant
        ppg_aid = self.name_mapper.port_pair_group(session, ppg['id'])
        ppg_aname = aim_utils.sanitize_display_name(ppg['name'])
        return aim_sg.DeviceCluster(tenant_name=tenant_aid, name=ppg_aid,
                                    display_name=ppg_aname, managed=False)

    def _get_ppg_domain(self, plugin_context, ppg):
        pp = self.sfc_plugin.get_port_pair(plugin_context,
                                           ppg['port_pairs'][0])
        ingress_port = self.plugin.get_port(plugin_context, pp['ingress'])
        return self.aim_mech._get_port_unique_domain(plugin_context,
                                                     ingress_port)

    def _get_pc_service_graph(self, session, pc, flowc, tenant):
        tenant_aid = tenant
        flowc_aid = self.name_mapper.flow_classifier(session, flowc['id'])
        pc_aname = aim_utils.sanitize_display_name(pc['name'])
        return aim_sg.ServiceGraph(tenant_name=tenant_aid,
                                   name=flowc_aid, display_name=pc_aname)

    def _get_flc_contract(self, session, flc, tenant):
        tenant_id = tenant
        flc_aid = self.name_mapper.flow_classifier(session, flc['id'])
        flc_aname = aim_utils.sanitize_display_name(flc['name'])
        return aim_resource.Contract(tenant_name=tenant_id, name=flc_aid,
                                     display_name=flc_aname)

    def _get_ppg_service_redirect_policy(self, session, ppg, direction,
                                         tenant):
        if direction == INGRESS:
            prfx = PBR_INGR_PREFIX
        elif direction == EGRESS:
            prfx = PBR_EGR_PREFIX
        dc = self._get_ppg_device_cluster(session, ppg, tenant)
        pbr_id = self.name_mapper.port_pair_group(session, ppg['id'],
                                                  prefix=prfx)
        return aim_sg.ServiceRedirectPolicy(tenant_name=dc.tenant_name,
                                            name=pbr_id)

    def _get_ppg_left_right_bds(self, plugin_context, ppg):
        pps = self.sfc_plugin.get_port_pairs(plugin_context,
                                             filters={'id': ppg['port_pairs']})
        for pp in pps:
            ingress = self.plugin.get_port(plugin_context, pp['ingress'])
            egress = self.plugin.get_port(plugin_context, pp['egress'])
            ingress_bd = self.aim_mech._get_port_bd(plugin_context.session,
                                                    ingress)
            egress_bd = self.aim_mech._get_port_bd(plugin_context.session,
                                                   egress)
            # Every port pair will return the same result
            return ingress_bd, egress_bd

    def _handle_flow_classifier(self, rtype, event, trigger, driver_context,
                                **kwargs):
        if event == events.PRECOMMIT_UPDATE:
            current = driver_context.current
            original = driver_context.original
            pctx = driver_context._plugin_context
            if any(current[x] != original[x] for x in
                   sfc_cts.SUPPORTED_FC_PARAMS):
                # reject if in use
                for chain in self._get_chains_by_classifier_id(pctx,
                                                               current['id']):
                    raise exceptions.FlowClassifierInUseByAChain(
                        fields=sfc_cts.SUPPORTED_FC_PARAMS, pc_id=chain['id'])

    def _handle_port_bound(self, rtype, event, trigger, driver_context,
                           **kwargs):
        if event == events.PRECOMMIT_UPDATE:
            context = driver_context
            p_ctx = driver_context._plugin_context
            c_host = context.host
            o_host = context.original_host
            if (c_host or o_host) and (c_host != o_host):
                pps = self.sfc_plugin.get_port_pairs(
                    p_ctx, filters={'ingress': [driver_context.current['id']]})
                pps.extend(self.sfc_plugin.get_port_pairs(
                    p_ctx, filters={'egress': [driver_context.current['id']]}))
                for pp in pps:
                    d_ctx = sfc_ctx.PortPairContext(context._plugin, p_ctx, pp,
                                                    pp)
                    self.update_port_pair_precommit(d_ctx, remap=True)

    def _get_pc_flowcs_and_ppgs(self, plugin_context, pc):
        flowcs = self.flowc_plugin.get_flow_classifiers(
            plugin_context, filters={'id': pc['flow_classifiers']})
        ppgs = self.sfc_plugin.get_port_pair_groups(
            plugin_context, filters={'id': pc['port_pair_groups']})
        return flowcs, ppgs

    def _get_flowc_provider_group(self, plugin_context, flowc):
        aim_ctx = aim_context.AimContext(plugin_context.session)
        net = self.aim_mech._get_network_by_port_id(
            plugin_context, flowc['logical_destination_port'])
        return self.aim.get(aim_ctx, self._map_flowc_network_group(
            plugin_context, net, flowc['destination_ip_prefix'], flowc,
            FLOWC_DST_PREFIX))

    def _get_flowc_consumer_group(self, plugin_context, flowc):
        aim_ctx = aim_context.AimContext(plugin_context.session)
        net = self.aim_mech._get_network_by_port_id(
            plugin_context, flowc['logical_source_port'])
        return self.aim.get(aim_ctx, self._map_flowc_network_group(
            plugin_context, net, flowc['source_ip_prefix'], flowc,
            FLOWC_SRC_PREFIX))
