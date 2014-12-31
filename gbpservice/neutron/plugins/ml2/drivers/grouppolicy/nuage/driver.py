# Copyright 2014 Alcatel-Lucent USA Inc.
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


from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.nuage.common import constants as nuage_const

from gbpservice.neutron.services.grouppolicy.drivers.nuage import driver


class NuageMechanismGBPDriver(api.MechanismDriver):

    def initialize(self):
        self._nuage_gbp = None

    @property
    def nuage_gbp(self):
        if not self._nuage_gbp:
            self._nuage_gbp = (driver.NuageGBPDriver.
                               get_initialized_instance())
        return self._nuage_gbp

    def update_port_postcommit(self, context):
        port = context.current
        port_prefix = nuage_const.NOVA_PORT_OWNER_PREF
        # Check two things prior to proceeding with
        # talking to backend.
        # 1) binding has happened successfully.
        # 2) Its a VM port.
        if ((not context.original_bound_segment and
            context.bound_segment) and
            port['device_owner'].startswith(port_prefix)):
            self.nuage_gbp.create_nuage_policy_target(
                context._plugin_context, context.current)
