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

from gbpservice.neutron.services.servicechain.plugins.ncp import driver_base


class NoopNodeDriver(driver_base.NodeDriverBase):

    initialized = False

    @log.log_method_call
    def initialize(self, name):
        self.initialized = True
        self._name = name

    @log.log_method_call
    def get_plumbing_info(self, context):
        pass

    @log.log_method_call
    def validate_create(self, context):
        pass

    @log.log_method_call
    def validate_update(self, context):
        pass

    @log.log_method_call
    def create(self, context):
        pass

    @log.log_method_call
    def delete(self, context):
        pass

    @log.log_method_call
    def update(self, context):
        pass

    @log.log_method_call
    def update_policy_target_added(self, context, policy_target):
        pass

    @log.log_method_call
    def update_policy_target_removed(self, context, policy_target):
        pass

    @log.log_method_call
    def update_node_consumer_ptg_added(self, context, policy_target_group):
        pass

    @log.log_method_call
    def update_node_consumer_ptg_removed(self, context, policy_target_group):
        pass

    @log.log_method_call
    def notify_chain_parameters_updated(self, context):
        pass

    @log.log_method_call
    def policy_target_group_updated(self, context, old_policy_target_group,
                                    current_policy_target_group):
        pass

    @property
    def name(self):
        return self._name

    @log.log_method_call
    def get_status(self, context):
        pass
