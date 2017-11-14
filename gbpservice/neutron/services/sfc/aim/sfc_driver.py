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
from aim.api import infra as aim_infra
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
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context as ml2_context
from neutron_lib import constants as n_constants
from oslo_log import log as logging

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions

COMMON_TENANT_NAME = 'common'
PBR_INGR_PREFIX = 'ingr'
PBR_EGR_PREFIX = 'egr'
INGRESS = 'ingress'
EGRESS = 'egress'
LOG = logging.getLogger(__name__)


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


class SfcAIMDriver(SfcAIMDriverBase, db.DbMixin):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        self._core_plugin = None
        self._flowc_plugin = None
        self._l3_plugin = None
        self._sfc_plugin = None
        self.name_mapper = apic_mapper.APICNameMapper()
        self.aim = aim_manager.AimManager()
        # We don't care about deletion, that is managed by the database layer
        # (can't delete a flowclassifier if in use.
        for event in [events.PRECOMMIT_UPDATE, events.PRECOMMIT_CREATE]:
            registry.subscribe(self._handle_flow_classifier,
                               sfc_cts.GBP_FLOW_CLASSIFIER, event)


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

    def create_port_pair_precommit(self, context):
        """Map Port Pair to AIM model

        A Port Pair by itself doesn't need to generate AIM model at least
        until added to a Port Pair Group.
        :param context:
        :return:
        """
        self._validate_port_pair(context)

    def update_port_pair_precommit(self, context):
        self._validate_port_pair(context)
        p_ctx = context._plugin_context
        curr = context.current
        orig = context.original
        # If the port pair is using different services, remap the affected
        # groups.
        if (curr[INGRESS], curr[EGRESS]) != (orig[INGRESS], orig[EGRESS]):
            for group in self._get_groups_by_pair_id(p_ctx,
                                                     context.current['id']):
                # Curr and original are identical, so the same object gets
                # remapped.
                g_ctx = sfc_ctx.PortPairGroupContext(context._plugin, p_ctx,
                                                     group, group)
                self.update_port_pair_group_precommit(g_ctx, remap=True)

    def delete_port_pair_precommit(self, context):
        # NOTE(ivar): The SFC plugin prevents port pair deletion when
        # belonging to a port pair group.
        pass

    def create_port_pair_group_precommit(self, context):
        """Map port pair group to AIM model

        A Port Pair Group is the equivalent of a Logical Device in AIM.
        :param context:
        :return:
        """
        # TODO(ivar): Some ports in the port pair group might not be bound.
        # we need to intercept binding events and modify the AIM model
        # accordingly
        self._validate_port_pair_group(context)
        self._map_port_pair_group(context._plugin_context, context.current)

    def update_port_pair_group_precommit(self, context, remap=False):
        self._validate_port_pair_group(context)
        # Regenerate Port Pair Group Model
        # NOTE(ivar): this doesn't imply any datapth disruption if not
        # needed. By regenerating the AIM model in a single transaction,
        # we modify the hashtree by the same much as we would by only
        # adding the configuration difference. This is certainly slower though,
        # as we need to run more queries and compute more events on the
        # hashtree, so it should be improved to regenerate the model only
        # when necessary
        if remap or self._should_regenerate_ppg(context):
            self._delete_port_pair_group_mapping(context._plugin_context,
                                                 context.original)
            self._map_port_pair_group(context._plugin_context, context.current)
            for chain in self._get_chains_by_ppg_id(context._plugin_context,
                                                    context.current['id']):
                c_ctx = sfc_ctx.PortChainContext(
                    context._plugin, context._plugin_context, chain, chain)
                self.update_port_chain_precommit(c_ctx, remap=True)

    def delete_port_pair_group_precommit(self, context):
        # NOTE(ivar): DB layer prevents deletion when used by port chains
        self._delete_port_pair_group_mapping(context._plugin_context,
                                             context.current)

    def create_port_chain_precommit(self, context):
        self._validate_port_chain(context)
        self._map_port_chain(context._plugin_context, context.current)

    def update_port_chain_precommit(self, context, remap=False):
        self._validate_port_chain(context)
        # Regenerate Port Chain Model
        if remap or self._should_regenerate_pc(context):
            self._delete_port_chain_mapping(context._plugin_context,
                                            context.original)
            self._map_port_chain(context._plugin_context, context.current)

    def delete_port_chain_precommit(self, context):
        self._delete_port_chain_mapping(context._plugin_context,
                                        context.current)

    def _validate_port_pair(self, context):
        # Disallow service_function_parameters
        if context.current['service_function_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='service_function_parameters', type='port_pair')
        # Ports need to belong to distinct networks
        ingress_net = self._get_port_network_id(context._plugin_context,
                                                context.current[0]['ingress'])
        egress_net = self._get_port_network_id(context._plugin_context,
                                               context.current[0]['egress'])
        if ingress_net == egress_net:
            raise exceptions.PortPairsSameNetwork(id=context.current['id'])

    def _validate_port_pair_group(self, context):
        # Disallow port_pair_group_parameters
        if context.current['port_pair_group_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='port_pair_group_parameters', type='port_pair_group')
        # Verify all ports are in the same network for each side of the
        # connection
        port_pairs = context._plugin.get_port_pairs(
            context._plugin_context,
            filters={'id': context.current['port_pairs']})
        if port_pairs:
            ingress_net = self._get_port_network_id(
                context._plugin_context, port_pairs[0]['ingress'])
            egress_net = self._get_port_network_id(
                context._plugin_context, port_pairs[0]['egress'])
            if any(x for x in port_pairs[1:] if ((ingress_net, egress_net) != (
                    self._get_port_network_id(context._plugin_context, y)
                    for y in [x['ingress'], x['egress']]))):
                raise exceptions.PortPairsDifferentNetworkInGroup(
                    id=context.current['id'])

    def _validate_port_chain(self, context):
        # Disallow service_function_parameters
        if context.current['chain_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='chain_parameters', type='port_chain')
        # Disallow multiple chains with same flow classifier.
        for flowc_id in context.current['flow_classifiers']:
            for chain in self._get_chains_by_classifier_id(
                    context._plugin_context, flowc_id):
                if chain['id'] != context.current['id']:
                    raise exceptions.OnlyOneChainPerFlowClassifierAllowed(
                        current=context.current['id'], conflicting=chain['id'])

    def _map_port_pair_group(self, plugin_context, ppg):
        session = plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        # Create Logical device model, container for all the PPG port pairs.
        dc = self._get_ppg_device_cluster(session, ppg)
        self.aim.create(aim_ctx, dc)
        # For each port pair, create the corresponding Concrete Devices
        # (represented by the static path of each interface)
        ingress_cdis = egress_cdis = []
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
                path, encap = self._get_port_static_path_and_encap(
                    plugin_context, p)
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
        ipbr = self._get_ppg_service_redirect_policy(session, ppg, INGRESS)
        epbr = self._get_ppg_service_redirect_policy(session, ppg, EGRESS)

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

    def _delete_port_pair_group_mapping(self, plugin_context, ppg):
        # Just delete cascade the DeviceCluster and PBR policies
        session = plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        tenant_id = self.name_mapper.project(session, ppg['tenant_id'])
        ppg_id = self.name_mapper.port_pair_group(session, ppg['id'])
        self.aim.delete(
            aim_ctx, aim_sg.DeviceCluster(tenant_name=tenant_id, name=ppg_id),
            cascade=True)
        for prefix in [PBR_INGR_PREFIX, PBR_EGR_PREFIX]:
            pbr_id = self.name_mapper.port_pair_group(session, ppg['id'],
                                                      prefix=prefix)
            self.aim.delete(
                aim_ctx, aim_sg.ServiceRedirectPolicy(tenant_name=tenant_id,
                                                      name=pbr_id),
                cascade=True)

    def _map_port_chain(self, plugin_context, pc):
        # Create one DeviceClusterContext per PPG
        p_ctx = plugin_context
        aim_ctx = aim_context.AimContext(p_ctx.session)
        # TODO(ivar): figure out the right tenant
        tenant_aid = self.name_mapper.project(p_ctx.session, pc['tenant_id'])
        pc_aid = self.name_mapper.port_chain(p_ctx.session, pc['id'])
        pc_aname = aim_utils.sanitize_display_name(pc['name'])
        # For each flow classifier, there are as many DeviceClusterContext as
        # the number of nodes in the chain.
        for flc in self.flowc_plugin.get_flow_classifiers(
                p_ctx, filters={'id': pc['flow_classifiers']}):
            self._map_flow_classifier(p_ctx, flc)
            contract = self._get_flc_contract(p_ctx.session, flc)
            sg = aim_sg.ServiceGraph(tenant_name=COMMON_TENANT_NAME,
                                     name=pc_aid)
            subject = aim_resource.ContractSubject(
                tenant_name=contract.tenant_name, name=sg.name,
                service_graph_name=sg.name)
            self.aim.create(aim_ctx, contract)
            self.aim.create(aim_ctx, subject)
            for ppg in self.sfc_plugin.get_port_pair_groups(
                    p_ctx, filters={'id': pc['port_pair_groups']}):
                dc = self._get_ppg_device_cluster(p_ctx.session, ppg)
                dcc = aim_sg.DeviceClusterContext(
                    tenant_name=tenant_aid, contract_name=contract.name,
                    service_graph_name=sg.name, node_name=dc.name,
                    display_name=pc_aname, device_cluster_name=dc.name,
                    device_cluster_tenant_name=dc.tenant_name)
                dcc = self.aim.create(aim_ctx, dcc)
                # Create device context interfaces.
                prov_bd, cons_bd = self._get_ppg_provider_consumer_bds(p_ctx,
                                                                       ppg)
                for conn_name, direction, bd in [
                        ('provider', INGRESS, prov_bd),
                        ('consumer', EGRESS, cons_bd)]:
                    dci = aim_sg.DeviceClusterInterface(
                        tenant_name=dc.tenant_name,
                        device_cluster_name=dc.name, name=direction)
                    pbr = self._get_ppg_service_redirect_policy(
                        p_ctx.session, ppg, direction)
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

    def _delete_port_chain_mapping(self, plugin_context, pc):
        p_ctx = plugin_context
        session = p_ctx.session
        aim_ctx = aim_context.AimContext(session)
        # TODO(ivar): figure out the right tenant
        tenant_aid = self.name_mapper.project(session, pc['tenant_id'])
        pc_aid = self.name_mapper.port_chain(session, pc['id'])
        for flc in self.flowc_plugin.get_flow_classifiers(
                p_ctx, filters={'id': pc['flow_classifiers']}):
            self._delete_flow_classifier_mapping(p_ctx, flc)
            contract = self._get_flc_contract(p_ctx.session, flc)
            sg = aim_sg.ServiceGraph(tenant_name=COMMON_TENANT_NAME,
                                     name=pc_aid)
            self.aim.delete(aim_ctx, contract, cascade=True)
            self.aim.delete(aim_ctx, sg, cascade=True)
            for ppg_id in pc['port_pair_groups']:
                ppg_aid = self.name_mapper.port_pair_group(session, ppg_id)
                dcc = aim_sg.DeviceClusterContext(
                    tenant_name=tenant_aid, contract_name=contract.name,
                    service_graph_name=sg.name, node_name=ppg_aid)
                self.aim.delete(aim_ctx, dcc, cascade=True)

    def _map_flow_classifier(self, plugin_context, flowc):
        """Map flowclassifier to AIM model

        If source/destination ports are plugged to an external network, create
        AIM external EPGs in the proper L3Outs and set the corresponding
        source/destination ip prefix.

        :param context:
        :return:
        """

    def _delete_flow_classifier_mapping(self, plugin_context, flowc):
        pass

    def _get_port_network_id(self, plugin_context, port_id):
        # TODO(ivar): this should be shared with the AIM mechanism driver.
        port = self.plugin.get_port(plugin_context, port_id)
        return port['network_id']

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

    def _should_regenerate_ppg(self, context):
        attrs = ['port_pairs']
        return any(sorted(context.current[a]) != sorted(context.original[a])
                   for a in attrs)

    def _should_regenerate_pc(self, context):
        attrs = ['flow_classifiers', 'port_pair_groups']
        return any(sorted(context.current[a]) != sorted(context.original[a])
                   for a in attrs)

    def _get_port_static_path_and_encap(self, plugin_context, port):
        # TODO(ivar): this should be shared with the AIM mechanism driver.
        port_id = port['id']
        path = encap = None
        if self._is_port_bound(port):
            session = plugin_context.session
            aim_ctx = aim_context.AimContext(db_session=session)
            _, binding = db.get_locked_port_and_binding(session, port_id)
            levels = db.get_binding_levels(session, port_id, binding.host)
            network = self.plugin.get_network(
                plugin_context, port['network_id'])
            port_context = ml2_context.PortContext(
                self, plugin_context, port, network, binding, levels)
            host = port_context.host
            segment = port_context.bottom_bound_segment
            host_link_net_labels = self.aim.find(
                aim_ctx, aim_infra.HostLinkNetworkLabel, host_name=host,
                network_label=segment[api.PHYSICAL_NETWORK])
            if host_link_net_labels:
                for hl_net_label in host_link_net_labels:
                    interface = hl_net_label.interface_name
                    host_link = self.aim.find(
                        aim_ctx, aim_infra.HostLink, host_name=host,
                        interface_name=interface)
                    if not host_link or not host_link[0].path:
                        LOG.warning(
                            _('No host link information found for host: '
                                '%(host)s, interface: %(interface)s'),
                            {'host': host, 'interface': interface})
                        continue
                    path = host_link[0].path
            if not path:
                host_link = self.aim.find(aim_ctx, aim_infra.HostLink,
                                          host_name=host)
                if not host_link or not host_link[0].path:
                    LOG.warning(
                        _('No host link information found for host %s'),
                        host)
                    return
                path = host_link[0].path
            if segment:
                if segment.get(api.NETWORK_TYPE) in [pconst.TYPE_VLAN]:
                    encap = 'vlan-%s' % segment[api.SEGMENTATION_ID]
                else:
                    LOG.debug('Unsupported segmentation type for static path '
                              'binding: %s',
                              segment.get(api.NETWORK_TYPE))
                    return None, None
        return path, encap

    def _is_port_bound(self, port):
        # TODO(ivar): this should be shared with the AIM mechanism driver.
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _get_ppg_device_cluster(self, session, ppg):
        # TODO(ivar): figure out the best APIC tenant to use
        tenant_aid = self.name_mapper.project(session, ppg['tenant_id'])
        ppg_aid = self.name_mapper.port_pair_group(session, ppg['id'])
        ppg_aname = aim_utils.sanitize_display_name(ppg['name'])
        # TODO(ivar): specify physical_domain_name
        return aim_sg.DeviceCluster(tenant_name=tenant_aid, name=ppg_aid,
                                    display_name=ppg_aname, managed=False)

    def _get_flc_contract(self, session, flc):
        # TODO(ivar): figure out the best APIC tenant to use
        tenant_id = COMMON_TENANT_NAME
        flc_aid = self.name_mapper.flow_classifier(session, flc['id'])
        flc_aname = aim_utils.sanitize_display_name(flc['name'])
        # TODO(ivar): specify physical_domain_name
        return aim_resource.Contract(tenant_name=tenant_id, name=flc_aid,
                                     display_name=flc_aname)

    def _get_ppg_service_redirect_policy(self, session, ppg, direction):
        if direction == INGRESS:
            prfx = PBR_INGR_PREFIX
        elif direction == EGRESS:
            prfx = PBR_EGR_PREFIX
        dc = self._get_ppg_device_cluster(session, ppg)
        pbr_id = self.name_mapper.port_pair_group(session, ppg['id'],
                                                  prefix=prfx)
        return aim_sg.ServiceRedirectPolicy(tenant_name=dc.tenant_name,
                                            name=pbr_id)

    def _get_ppg_provider_consumer_bds(self, plugin_context, ppg):
        pps = self.sfc_plugin.get_port_pairs(plugin_context,
                                             filters={'id': ppg['port_pairs']})
        for pp in pps:
            ingress = self.plugin.get_ports(plugin_context,
                                            filters={'id': [pp['ingress']]})
            egress = self.plugin.get_ports(plugin_context,
                                           filters={'id': [pp['egress']]})
            if ingress and egress:
                ingress_bd = self._get_port_bd(plugin_context.session, ingress)
                egress_bd = self._get_port_bd(plugin_context.session, egress)
                # Every port pair will return the same result
                return ingress_bd, egress_bd

    def _get_port_bd(self, session, port):
        # TODO(ivar): this should be shared with the AIM mechanism driver.
        net_mapping = self._get_network_mapping(session, port['network_id'])
        return self._get_network_bd(net_mapping)

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
