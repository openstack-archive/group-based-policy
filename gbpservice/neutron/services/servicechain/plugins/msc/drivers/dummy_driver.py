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


class NoopDriver(object):

    @log.log_method_call
    def initialize(self):
        pass

    @log.log_method_call
    def create_servicechain_node_precommit(self, context):
        pass

    @log.log_method_call
    def create_servicechain_node_postcommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_node_precommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_node_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_node_precommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_node_postcommit(self, context):
        pass

    @log.log_method_call
    def create_servicechain_spec_precommit(self, context):
        pass

    @log.log_method_call
    def create_servicechain_spec_postcommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_spec_precommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_spec_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_spec_precommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_spec_postcommit(self, context):
        pass

    @log.log_method_call
    def create_servicechain_instance_precommit(self, context):
        pass

    @log.log_method_call
    def create_servicechain_instance_postcommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_instance_precommit(self, context):
        pass

    @log.log_method_call
    def update_servicechain_instance_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_instance_precommit(self, context):
        pass

    @log.log_method_call
    def delete_servicechain_instance_postcommit(self, context):
        pass

    @log.log_method_call
    def create_service_profile_precommit(self, context):
        pass

    @log.log_method_call
    def create_service_profile_postcommit(self, context):
        pass

    @log.log_method_call
    def update_service_profile_precommit(self, context):
        pass

    @log.log_method_call
    def update_service_profile_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_service_profile_precommit(self, context):
        pass

    @log.log_method_call
    def delete_service_profile_postcommit(self, context):
        pass
