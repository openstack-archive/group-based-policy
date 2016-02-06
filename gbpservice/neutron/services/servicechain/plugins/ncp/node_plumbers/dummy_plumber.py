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

from oslo_log import helpers as log

from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base


class NoopPlumber(plumber_base.NodePlumberBase):

    initialized = False

    @log.log_method_call
    def initialize(self):
        self.initialized = True

    @log.log_method_call
    def plug_services(self, context, deployment):
        self._sort_deployment(deployment)

    @log.log_method_call
    def unplug_services(self, context, deployment):
        self._sort_deployment(deployment)
