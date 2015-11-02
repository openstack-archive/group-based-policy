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
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.openvswitch.mech_driver import (
        mech_openvswitch as base)
from oslo_log import log

from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base

LOG = log.getLogger(__name__)


class TrafficStitchingMechanismGBPDriver(base.OpenvswitchMechanismDriver):
    """Traffic Stitching Mechanism Driver for GBP.

    This driver makes sure that service targets are bound with port_filter and
    hybrid_mode set to false. This should disable port security and anti
    spoofing rules for these special ports.
    """

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        vif_details = self.vif_details
        if self.check_segment_for_agent(segment, agent):
            if context.current['name'].startswith(
                    'pt_' + plumber_base.SERVICE_TARGET_NAME_PREFIX):
                vif_details = {portbindings.CAP_PORT_FILTER: False,
                               portbindings.OVS_HYBRID_PLUG: False}
            context.set_binding(
                segment[api.ID], self.vif_type, vif_details)
            return True
        else:
            return False
