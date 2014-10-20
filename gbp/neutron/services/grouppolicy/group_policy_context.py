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

    def set_port_id(self, port_id):
        self._plugin._set_port_for_endpoint(
            self._plugin_context, self._endpoint['id'], port_id)
        self._endpoint['port_id'] = port_id


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

    def set_network_service_policy_id(self, network_service_policy_id):
        nsp_id = network_service_policy_id
        self._plugin._set_network_service_policy_for_endpoint_group(
            self._plugin_context, self._endpoint_group['id'], nsp_id)
        self._endpoint_group['network_service_policy_id'] = nsp_id

    def add_subnet(self, subnet_id):
        subnets = self._plugin._add_subnet_to_endpoint_group(
            self._plugin_context, self._endpoint_group['id'], subnet_id)
        self._endpoint_group['subnets'] = subnets


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

    def set_network_id(self, network_id):
        self._plugin._set_network_for_l2_policy(
            self._plugin_context, self._l2_policy['id'], network_id)
        self._l2_policy['network_id'] = network_id


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

    def add_router(self, router_id):
        routers = self._plugin._add_router_to_l3_policy(
            self._plugin_context, self._l3_policy['id'], router_id)
        self._l3_policy['routers'] = routers


class NetworkServicePolicyContext(
    GroupPolicyContext, api.NetworkServicePolicyContext):

    def __init__(self, plugin, plugin_context, network_service_policy,
                 original_network_service_policy=None):
        super(NetworkServicePolicyContext, self).__init__(
            plugin, plugin_context)
        self._network_service_policy = network_service_policy
        self._original_network_service_policy = original_network_service_policy

    @property
    def current(self):
        return self._network_service_policy

    @property
    def original(self):
        return self._original_network_service_policy


class PolicyClassifierContext(GroupPolicyContext, api.PolicyClassifierContext):

    def __init__(self, plugin, plugin_context, policy_classifier,
                 original_policy_classifier=None):
        super(PolicyClassifierContext, self).__init__(plugin, plugin_context)
        self._policy_classifier = policy_classifier
        self._original_policy_classifier = original_policy_classifier

    @property
    def current(self):
        return self._policy_classifier

    @property
    def original(self):
        return self._original_policy_classifier


class PolicyActionContext(GroupPolicyContext, api.PolicyActionContext):

    def __init__(self, plugin, plugin_context, policy_action,
                 original_policy_action=None):
        super(PolicyActionContext, self).__init__(plugin, plugin_context)
        self._policy_action = policy_action
        self._original_policy_action = original_policy_action

    @property
    def current(self):
        return self._policy_action

    @property
    def original(self):
        return self._original_policy_action


class PolicyRuleContext(GroupPolicyContext, api.PolicyRuleContext):

    def __init__(self, plugin, plugin_context, policy_rule,
                 original_policy_rule=None):
        super(PolicyRuleContext, self).__init__(plugin, plugin_context)
        self._policy_rule = policy_rule
        self._original_policy_rule = original_policy_rule

    @property
    def current(self):
        return self._policy_rule

    @property
    def original(self):
        return self._original_policy_rule


class ContractContext(GroupPolicyContext, api.ContractContext):

    def __init__(self, plugin, plugin_context, contract,
                 original_contract=None):
        super(ContractContext, self).__init__(plugin, plugin_context)
        self._contract = contract
        self._original_contract = original_contract

    @property
    def current(self):
        return self._contract

    @property
    def original(self):
        return self._original_contract
