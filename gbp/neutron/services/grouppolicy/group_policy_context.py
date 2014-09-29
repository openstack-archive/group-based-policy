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

from gbp.neutron.services.grouppolicy import group_policy_driver_api as api


class GroupPolicyContext(object):
    """GroupPolicy context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class EndpointContext(GroupPolicyContext, api.EndpointContext):

    def __init__(self, plugin, plugin_context, endpoint,
                 original_endpoint=None):
        super(EndpointContext, self).__init__(plugin, plugin_context)
        self._endpoint = endpoint
        self._original_endpoint = original_endpoint

    @property
    def current(self):
        return self._endpoint

    @property
    def original(self):
        return self._original_endpoint


class EndpointGroupContext(GroupPolicyContext, api.EndpointGroupContext):

    def __init__(self, plugin, plugin_context, endpoint_group,
                 original_endpoint_group=None):
        super(EndpointGroupContext, self).__init__(plugin, plugin_context)
        self._endpoint_group = endpoint_group
        self._original_endpoint_group = original_endpoint_group

    @property
    def current(self):
        return self._endpoint_group

    @property
    def original(self):
        return self._original_endpoint_group

    def set_l2_policy_id(self, l2_policy_id):
        self._plugin._set_l2_policy_for_endpoint_group(
            self._plugin_context, self._endpoint_group['id'], l2_policy_id)
        self._endpoint_group['l2_policy_id'] = l2_policy_id


class L2PolicyContext(GroupPolicyContext, api.L2PolicyContext):

    def __init__(self, plugin, plugin_context, l2_policy,
                 original_l2_policy=None):
        super(L2PolicyContext, self).__init__(plugin, plugin_context)
        self._l2_policy = l2_policy
        self._original_l2_policy = original_l2_policy

    @property
    def current(self):
        return self._l2_policy

    @property
    def original(self):
        return self._original_l2_policy

    def set_l3_policy_id(self, l3_policy_id):
        self._plugin._set_l3_policy_for_l2_policy(
            self._plugin_context, self._l2_policy['id'], l3_policy_id)
        self._l2_policy['l3_policy_id'] = l3_policy_id


class L3PolicyContext(GroupPolicyContext, api.L3PolicyContext):

    def __init__(self, plugin, plugin_context, l3_policy,
                 original_l3_policy=None):
        super(L3PolicyContext, self).__init__(plugin, plugin_context)
        self._l3_policy = l3_policy
        self._original_l3_policy = original_l3_policy

    @property
    def current(self):
        return self._l3_policy

    @property
    def original(self):
        return self._original_l3_policy
