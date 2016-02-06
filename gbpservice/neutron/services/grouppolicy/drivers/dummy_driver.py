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

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)


class NoopDriver(api.PolicyDriver):

    @log.log_method_call
    def initialize(self):
        pass

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_target_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_target_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_target_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_target_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_target_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_target_group_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_target_group_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_target_group_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_target_group_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_target_group_postcommit(self, context):
        pass

    @log.log_method_call
    def create_l2_policy_precommit(self, context):
        pass

    @log.log_method_call
    def create_l2_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def update_l2_policy_precommit(self, context):
        pass

    @log.log_method_call
    def update_l2_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_l2_policy_precommit(self, context):
        pass

    @log.log_method_call
    def delete_l2_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def create_l3_policy_precommit(self, context):
        pass

    @log.log_method_call
    def create_l3_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def update_l3_policy_precommit(self, context):
        pass

    @log.log_method_call
    def update_l3_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_l3_policy_precommit(self, context):
        pass

    @log.log_method_call
    def delete_l3_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def create_network_service_policy_precommit(self, context):
        pass

    @log.log_method_call
    def create_network_service_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def update_network_service_policy_precommit(self, context):
        pass

    @log.log_method_call
    def update_network_service_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_network_service_policy_precommit(self, context):
        pass

    @log.log_method_call
    def delete_network_service_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_classifier_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_classifier_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_classifier_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_rule_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_set_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_set_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_set_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_set_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_rule_set_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_rule_set_postcommit(self, context):
        pass
