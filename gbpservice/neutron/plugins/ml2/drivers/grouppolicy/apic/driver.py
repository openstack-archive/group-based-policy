# Copyright (c) 2014 Cisco Systems Inc.
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

from neutron import context as nctx
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from opflexagent import constants as ofcst
from oslo_log import log
from oslo_utils import importutils

from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)


LOG = log.getLogger(__name__)

# TODO(tbachman) Find a good home for these
AGENT_TYPE_DVS = 'DVS agent'
VIF_TYPE_DVS = 'dvs'
DVS_AGENT_KLASS = 'vmware_dvs.api.dvs_agent_rpc_api.DVSClientAPI'


class APICMechanismGBPDriver(api.MechanismDriver):

    def __init__(self):
        super(APICMechanismGBPDriver, self).__init__()
        self._dvs_notifier = None

    def _agent_bind_port(self, context, agent_list, bind_strategy):
        """Attempt port binding per agent.

           Perform the port binding for a given agent.
           Returns True if bound successfully.
        """
        for agent in agent_list:
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if bind_strategy(context, segment, agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return True
            else:
                LOG.warning(_("Refusing to bind port %(pid)s to dead agent: "
                              "%(agent)s"),
                            {'pid': context.current['id'], 'agent': agent})
        return False

    def bind_port(self, context):
        """Get port binding per host.

           This is similar to the one defined in the
           AgentMechanismDriverBase class, but is modified
           to support multiple L2 agent types (DVS and OpFlex).
        """
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in [portbindings.VNIC_NORMAL]:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        # Attempt to bind ports for DVS agents for nova-compute daemons
        # first. This allows having network agents (dhcp, metadata)
        # that typically run on a network node using an OpFlex agent to
        # co-exist with nova-compute daemons for ESX, which host DVS agents.
        if context.current['device_owner'].startswith('compute:'):
            agent_list = context.host_agents(AGENT_TYPE_DVS)
            if self._agent_bind_port(context, agent_list, self._bind_dvs_port):
                return

        # It either wasn't a DVS binding, or there wasn't a DVS
        # agent on the binding host (could be the case in a hybrid
        # environment supporting KVM and ESX compute). Go try for
        # OpFlex agents.
        agent_list = context.host_agents(ofcst.AGENT_TYPE_OPFLEX_OVS)
        self._agent_bind_port(context, agent_list, self._bind_opflex_port)

    def _bind_dvs_port(self, context, segment, agent):
        """Populate VIF type and details for DVS VIFs.

           For DVS VIFs, provide the portgroup along
           with the security groups setting
        """
        if self._check_segment_for_agent(segment, agent):
            port = context.current
            # We only handle details for ports that are PTs in PTGs
            ptg, pt = self.apic_gbp._port_id_to_ptg(context._plugin_context,
                                                    port['id'])
            if ptg is None:
                LOG.warning(_("PTG for port %s does not exist"), port['id'])
                return False
            mapper = self.apic_gbp.name_mapper.name_mapper
            ptg_name = mapper.policy_target_group(context, ptg['name'])
            network_id = port.get('network_id')
            network = self.apic_gbp._get_network(context._plugin_context,
                                                 network_id)
            project_name = self.apic_gbp._tenant_by_sharing_policy(network)
            profile = self.apic_gbp.apic_manager.app_profile_name
            # Use default security groups from MD
            vif_details = {portbindings.CAP_PORT_FILTER: False}
            vif_details['dvs_port_group_name'] = (str(project_name) +
                                             '|' + str(profile) +
                                             '|' + str(ptg_name))
            booked_port_key = None
            if self.dvs_notifier:
                booked_port_key = self.dvs_notifier.bind_port_call(
                    context.current,
                    context.network.network_segments,
                    context.network.current,
                    context.host
                )
            if booked_port_key:
                vif_details['dvs_port_key'] = booked_port_key
            context.set_binding(segment[api.ID],
                                VIF_TYPE_DVS, vif_details)
            return True
        else:
            return False

    def _bind_opflex_port(self, context, segment, agent):
        """Populate VIF type and details for OpFlex VIFs.

           For OpFlex VIFs, we just report the OVS VIF type,
           along with security groups setting, which were
           set when this mechanism driver was instantiated.
        """
        if self._check_segment_for_agent(segment, agent):
            context.set_binding(segment[api.ID],
                                portbindings.VIF_TYPE_OVS,
                                {portbindings.CAP_PORT_FILTER: False,
                                 portbindings.OVS_HYBRID_PLUG: False})
            return True
        else:
            return False

    def _check_segment_for_agent(self, segment, agent):
        """Check support for OpFlex type segments.

           The agent has the ability to limit the segments in OpFlex
           networks by specifying the mappings in their config. If no
           mapping is specifified, then all OpFlex segments are
           supported.
        """
        network_type = segment[api.NETWORK_TYPE]
        if network_type == ofcst.TYPE_OPFLEX:
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug("Checking segment: %(segment)s "
                      "for physical network: %(mappings)s ",
                      {'segment': segment, 'mappings': opflex_mappings})
            return (opflex_mappings is None or
                    segment[api.PHYSICAL_NETWORK] in opflex_mappings)
        elif network_type == 'local':
            return True
        else:
            return False

    def initialize(self):
        super(APICMechanismGBPDriver, self).initialize()
        self._apic_gbp = None

    @property
    def apic_gbp(self):
        if not self._apic_gbp:
            self._apic_gbp = manager.NeutronManager.get_service_plugins()[
                'GROUP_POLICY'].policy_driver_manager.policy_drivers[
                'apic'].obj
        return self._apic_gbp

    @property
    def dvs_notifier(self):
        if not self._dvs_notifier:
            try:
                self._dvs_notifier = importutils.import_object(
                    DVS_AGENT_KLASS,
                    nctx.get_admin_context_without_session()
                )
            except ImportError:
                self._dvs_notifier = None
        return self._dvs_notifier

    def create_port_postcommit(self, context):
        self.apic_gbp.process_port_added(context)

    def update_port_postcommit(self, context):
        self.apic_gbp.process_port_changed(context)
        port = context.current
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.update_postcommit_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host
            )

    def delete_port_precommit(self, context):
        self.apic_gbp.process_pre_port_deleted(context)

    def delete_port_postcommit(self, context):
        self.apic_gbp.process_port_deleted(context)
        port = context.current
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.delete_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host
            )

    def update_subnet_postcommit(self, context):
        self.apic_gbp.process_subnet_changed(context._plugin_context,
                                             context.original, context.current)

    def create_subnet_postcommit(self, context):
        if not context.current['name'].startswith(amap.APIC_OWNED):
            self.apic_gbp.process_subnet_added(context._plugin_context,
                                               context.current)

    def delete_subnet_postcommit(self, context):
        self.apic_gbp.process_subnet_deleted(context._plugin_context,
                                             context.current)
