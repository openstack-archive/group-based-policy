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
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from opflexagent import constants as ofcst

from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping as amap)


LOG = log.getLogger(__name__)


class APICMechanismGBPDriver(mech_agent.AgentMechanismDriverBase):

    def __init__(self):
        self.vif_details = {portbindings.CAP_PORT_FILTER: False,
                            portbindings.OVS_HYBRID_PLUG: False}
        self.vif_type = portbindings.VIF_TYPE_OVS
        super(APICMechanismGBPDriver, self).__init__(
            ofcst.AGENT_TYPE_OPFLEX_OVS)

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            context.set_binding(
                segment[api.ID], self.vif_type, self.vif_details)
            return True
        else:
            return False

    def check_segment_for_agent(self, segment, agent):
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
