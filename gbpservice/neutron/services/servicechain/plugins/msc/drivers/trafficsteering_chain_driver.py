# Copyright 2015, Instituto de Telecomunicacoes - Polo de Aveiro - ATNoG.
# All rights reserved.
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


from neutron.common import log
from neutron import manager
from neutron.plugins.common import constants as pconst
from oslo_log import log as logging

from gbpservice.neutron.services.servicechain.common import exceptions as exc


LOG = logging.getLogger(__name__)

sc_supported_type = [pconst.DUMMY]


class TrafficSteeringChainDriver(object):

    @log.log
    def initialize(self):
        pass

    @log.log
    def create_servicechain_node_precommit(self, context):
        pass

    @log.log
    def create_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_node_precommit(self, context):
        pass

    @log.log
    def update_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def delete_servicechain_node_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def create_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def create_servicechain_spec_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def update_servicechain_spec_postcommit(self, context):
        pass

    @log.log
    def delete_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_spec_postcommit(self, context):
        pass

    @log.log
    def create_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def create_servicechain_instance_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def update_servicechain_instance_postcommit(self, context):
        pass

    @log.log
    def delete_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_instance_postcommit(self, context):
        pass

    @property
    def _core_plugin(self):
        # REVISIT(Magesh): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _grouppolicy_plugin(self):
        # REVISIT(Magesh): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        grouppolicy_plugin = plugins.get(pconst.GROUP_POLICY)
        if not grouppolicy_plugin:
            LOG.error(_("No Grouppolicy service plugin found."))
            raise exc.ServiceChainDeploymentError()
        return grouppolicy_plugin