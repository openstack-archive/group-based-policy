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
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from oslo_log import log as log

from gbpservice.neutron.services.grouppolicy.drivers.odl import odl_mapping


LOG = log.getLogger(__name__)


class OdlMechanismGBPDriver(api.MechanismDriver):

    def initialize(self):
        self._odl_gbp = None
        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}

    @property
    def odl_gbp(self):
        if not self._odl_gbp:
            self._odl_gbp = (odl_mapping.OdlMappingDriver.
                             get_initialized_instance())
        return self._odl_gbp

    def create_port_postcommit(self, context):
        # DHCP Ports are created implicitly by Neutron, need to inform GBP
        if (context.current.get('device_owner') ==
                n_constants.DEVICE_OWNER_DHCP):
            self.odl_gbp.create_dhcp_policy_target_if_needed(
                context._plugin_context, context.current
            )

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.network.network_segments:
            if self._check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_constants.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    def _check_segment(self, segment):
        """Verify a segment is valid for the OpenDaylight MechanismDriver.

        Verify the requested segment is supported by ODL and return True or
        False to indicate this to callers.
        """
        network_type = segment[api.NETWORK_TYPE]
        return network_type in [constants.TYPE_VXLAN, ]
