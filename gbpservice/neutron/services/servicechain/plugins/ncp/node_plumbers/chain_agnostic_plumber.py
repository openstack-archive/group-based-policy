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

from neutron.common import log

from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base


class ChainAgnosticPlumber(plumber_base.NodePlumberBase):
    """ Chain Agnostic Plumber.

    This plumber simply provides node drivers with the Service Targets
    they requested for, without making any modification depending on the
    rest of the chain.
    """

    @log.log
    def initialize(self):
        pass

    @log.log
    def plug_services(self, context, deployment):
        for part in deployment:
            self._create_service_targets(context, part)

    @log.log
    def unplug_services(self, context, deployment):
        for part in deployment:
            self._delete_service_targets(context, part)
