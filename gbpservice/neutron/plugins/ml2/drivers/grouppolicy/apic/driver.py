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

from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from opflexagent import constants as ofcst
from oslo_log import log

from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)


LOG = log.getLogger(__name__)

# TODO(tbachman) Find a good home for these
VIF_TYPE_DVS = 'dvs'
AGENT_TYPE_DVS = 'DVS agent'
HYPERVISOR_VCENTER = 'VMware vCenter'


class APICMechanismGBPDriver(mech_agent.AgentMechanismDriverBase):

    def __init__(self):
        self.vif_details = {portbindings.CAP_PORT_FILTER: False,
                            portbindings.OVS_HYBRID_PLUG: False}
        self.vif_type = portbindings.VIF_TYPE_OVS
        super(APICMechanismGBPDriver, self).__init__(
            ofcst.AGENT_TYPE_OPFLEX_OVS)

    def _is_dvs_vif_type(self, context, agent):
        """Return if this port is a DVS vif

           We need to bind the port as a DVS VIF type
           when the port belongs to nova, and when there's
           an OpFlex agent on that (compute) host that's told
           us it's supporting a VMware hypervisor.
        """
        port = context.current
        if port['device_owner'] == 'compute:nova':
            hv_type = agent['configurations'].get('hypervisor_type', None)
            if hv_type and hv_type == HYPERVISOR_VCENTER:
                return True
        return False

    def _get_dvs_vif_details(self, context):
        """Populate VIF details for DVS VIFs.

           For DVS VIFs, provide the portgroup along
           with the security groups setting
        """

        port = context.current
        network_id = port.get('network_id')
        # Use default security groups from MD
        vif_details = ({portbindings.CAP_PORT_FILTER:
                        self.vif_details[portbindings.CAP_PORT_FILTER]})
        if port.get('tenant_id') and network_id:
            network = self.apic_gbp._get_network(context._plugin_context,
                                                 network_id)
            project_name = self.apic_gbp.name_mapper.tenant(port)
            if network.get('shared'):
                project_name = amap.apic_manager.TENANT_COMMON
            profile = self.apic_gbp.get_apic_manager().app_profile_name
            # networks are named using the name of the Policy Target
            # Group prepended iwth "l2p_". However, the portgroup just
            # uses the Policy Target Group name
            network_name = (network['name'][4:]
                if network['name'].startswith('l2p_') else network['name'])
            vif_details['dvs_port_group'] = (str(project_name) +
                                             '|' + str(profile) +
                                             '|' + network_name)
        return vif_details

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self._check_segment_for_agent(segment, agent):
            vif_type = self.vif_type
            vif_details = self.vif_details
            if self._is_dvs_vif_type(context, agent):
                vif_type = VIF_TYPE_DVS
                vif_details = self._get_dvs_vif_details(context)
            context.set_binding(segment[api.ID], vif_type, vif_details)
            return True
        else:
            return False

    def _check_segment_for_agent(self, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == ofcst.TYPE_OPFLEX:
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug(_("Checking segment: %(segment)s "
                        "for mappings: %(mappings)s "),
                      {'segment': segment, 'mappings': opflex_mappings})
            return ((opflex_mappings is None) or
                    (segment[api.PHYSICAL_NETWORK] in opflex_mappings))
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

    def create_port_postcommit(self, context):
        self.apic_gbp.process_port_added(
            context._plugin_context, context.current)

    def update_port_postcommit(self, context):
        self.apic_gbp.process_port_changed(context._plugin_context,
                                           context.original, context.current)

    def delete_port_precommit(self, context):
        self.apic_gbp.process_pre_port_deleted(context._plugin_context,
                                               context.current)

    def delete_port_postcommit(self, context):
        self.apic_gbp.process_port_deleted(context._plugin_context,
                                           context.current)

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
