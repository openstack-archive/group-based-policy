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


class HeatDriver(object):

    def __init__(self, config):
        pass

    def apply_config(self, network_function_details):
        pass

    def is_config_complete(self, stack_id, tenant_id):
        pass

    def check_config_complete(self, event):
        pass

    def is_config_delete_complete(self, stack_id, tenant_id):
        pass

    def delete_config(self, stack_id, tenant_id):
        pass

    def update_config(self, network_function_details, stack_id):
        pass

    def handle_policy_target_added(self, network_function_details,
                                   policy_target):
        pass

    def handle_policy_target_removed(self, network_function_details,
                                     policy_target):
        pass

    def notify_chain_parameters_updated(self, network_function_details):
        pass

    def handle_consumer_ptg_added(self, network_function_details,
                                  policy_target_group):
        pass

    def handle_consumer_ptg_removed(self, network_function_details,
                                    policy_target_group):
        pass

    def handle_policy_target_operations(self, network_function_details,
                                     policy_target):
        pass

    def handle_consumer_ptg_operations(self, network_function_details,
                                    policy_target_group):
        pass

    def parse_template_config_string(self, config_str):
        pass
