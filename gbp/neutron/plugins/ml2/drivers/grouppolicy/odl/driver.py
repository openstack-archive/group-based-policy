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
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

from gbp.neutron.services.grouppolicy.drivers.odl import odl_mapping

LOG = log.getLogger(__name__)


class OdlMechanismGBPDriver(api.MechanismDriver):

    def initialize(self):
        self._odl_gbp = None

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
                context._plugin_context, context.current)

    def update_port_postcommit(self, context):
        self.odl_gbp.process_port_changed(context._plugin_context,
                                           context.original, context.current)

    def update_subnet_postcommit(self, context):
        self.odl_gbp.process_subnet_changed(context._plugin_context,
                                             context.original, context.current)
