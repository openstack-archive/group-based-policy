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


class ServiceChainNotificationsMixin(object):

    def _notify_sc_plugin_pt_added(self, context, policy_target, instance_id):
        if self._servicechain_plugin:
            self._servicechain_plugin.update_chains_pt_added(
                context, policy_target, instance_id)

    def _notify_sc_plugin_pt_removed(self, context, policy_target,
                                     instance_id):
        if self._servicechain_plugin:
            self._servicechain_plugin.update_chains_pt_removed(
                context, policy_target, instance_id)

    def _notify_sc_consumer_added(self, context, policy_target_group,
                                  instance_id):
        if self._servicechain_plugin:
            self._servicechain_plugin.update_chains_consumer_added(
                context, policy_target_group, instance_id)

    def _notify_sc_consumer_removed(self, context, policy_target_group,
                                    instance_id):
        if self._servicechain_plugin:
            self._servicechain_plugin.update_chains_consumer_removed(
                context, policy_target_group, instance_id)

    def _notify_ptg_updated(self, context, old, current, instance_id):
        if self._servicechain_plugin:
            self._servicechain_plugin.policy_target_group_updated(
                    context, old, current, instance_id)
