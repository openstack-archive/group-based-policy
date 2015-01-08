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

from neutron.common import constants as n_constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

from gbpservice.common import constants as gbpcst
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)

LOG = log.getLogger(__name__)


class APICMechanismGBPDriver(mech_agent.SimpleAgentMechanismDriverBase):

    def __init__(self):
        vif_details = {portbindings.CAP_PORT_FILTER: False,
                       portbindings.OVS_HYBRID_PLUG: False}
        super(APICMechanismGBPDriver, self).__init__(
            gbpcst.AGENT_TYPE_APIC_OVS,
            portbindings.VIF_TYPE_OVS,
            vif_details)

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('apic_networks', [])
        LOG.debug(_("Checking segment: %(segment)s "
                    "for physical network: %(mappings)s "),
                  {'segment': segment, 'mappings': mappings})
        network_type = segment[api.NETWORK_TYPE]
        if network_type == gbpcst.TYPE_APIC:
            return (mappings is None or
                    segment[api.PHYSICAL_NETWORK] in mappings)
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
