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

from neutron.agent import securitygroups_rpc
from neutron.common import constants as n_constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

from gbpservice.common import constants as gbpcst
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)

LOG = log.getLogger(__name__)


class APICMechanismGBPDriver(mech_agent.AgentMechanismDriverBase):

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                            portbindings.OVS_HYBRID_PLUG: sg_enabled}
        self.apic_vif_details = {portbindings.CAP_PORT_FILTER: False,
                                 portbindings.OVS_HYBRID_PLUG: False}
        self.vif_type = portbindings.VIF_TYPE_OVS
        super(APICMechanismGBPDriver, self).__init__(
            gbpcst.AGENT_TYPE_APIC_OVS)

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            context.set_binding(
                segment[api.ID], self.vif_type,
                (self.apic_vif_details if
                 segment[api.NETWORK_TYPE] == gbpcst.TYPE_APIC else
                 self.vif_details))
            return True
        else:
            return False

    def check_segment_for_agent(self, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == gbpcst.TYPE_APIC:
            apic_mappings = agent['configurations'].get('apic_networks', [])
            LOG.debug(_("Checking segment: %(segment)s "
                        "for physical network: %(mappings)s "),
                      {'segment': segment, 'mappings': apic_mappings})
            return (apic_mappings is None or
                    segment[api.PHYSICAL_NETWORK] in apic_mappings)
        else:
            mappings = agent['configurations'].get('bridge_mappings', {})
            tunnel_types = agent['configurations'].get('tunnel_types', [])
            LOG.debug(_("Checking segment: %(segment)s "
                        "for mappings: %(mappings)s "
                        "with tunnel_types: %(tunnel_types)s"),
                      {'segment': segment, 'mappings': mappings,
                       'tunnel_types': tunnel_types})
            if network_type == 'local':
                return True
            elif network_type in tunnel_types:
                return True
            elif network_type in ['flat', 'vlan']:
                return segment[api.PHYSICAL_NETWORK] in mappings
            else:
                return False

    def initialize(self):
        super(APICMechanismGBPDriver, self).initialize()
        self._apic_gbp = None

    @property
    def apic_gbp(self):
        if not self._apic_gbp:
            self._apic_gbp = (amap.ApicMappingDriver.
                              get_initialized_instance())
        return self._apic_gbp

    def create_port_postcommit(self, context):
        # DHCP Ports are created implicitly by Neutron, need to inform GBP
        if (context.current.get('device_owner') ==
                n_constants.DEVICE_OWNER_DHCP):
            self.apic_gbp.create_dhcp_policy_target_if_needed(
                context._plugin_context, context.current)

    def update_port_postcommit(self, context):
        self.apic_gbp.process_port_changed(context._plugin_context,
                                           context.original, context.current)

    def update_subnet_postcommit(self, context):
        self.apic_gbp.process_subnet_changed(context._plugin_context,
                                             context.original, context.current)

    def bind_port(self, context):
        super(APICMechanismGBPDriver, self).bind_port(context)
        context._plugin._update_port_dict_binding(context.current,
                                                  context._binding)
        self.apic_gbp.process_port_bound(context._plugin_context,
                                         context.current)
