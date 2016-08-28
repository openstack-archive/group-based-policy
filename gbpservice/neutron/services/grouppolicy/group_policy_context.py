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

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)


class GroupPolicyContext(object):
    """GroupPolicy context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class PolicyTargetContext(GroupPolicyContext, api.PolicyTargetContext):

    def __init__(self, plugin, plugin_context, policy_target,
                 original_policy_target=None):
        super(PolicyTargetContext, self).__init__(plugin, plugin_context)
        self._policy_target = policy_target
        self._original_policy_target = original_policy_target

    @property
    def current(self):
        return self._policy_target

    @property
    def original(self):
        return self._original_policy_target

    def set_port_id(self, port_id):
        self._plugin._set_port_for_policy_target(
            self._plugin_context, self._policy_target['id'], port_id)
        self._policy_target['port_id'] = port_id


class PolicyTargetGroupContext(GroupPolicyContext,
                               api.PolicyTargetGroupContext):

    def __init__(self, plugin, plugin_context, policy_target_group,
                 original_policy_target_group=None):
        super(PolicyTargetGroupContext, self).__init__(plugin, plugin_context)
        self._policy_target_group = policy_target_group
        self._original_policy_target_group = original_policy_target_group

    @property
    def current(self):
        return self._policy_target_group

    @property
    def original(self):
        return self._original_policy_target_group

    def set_l2_policy_id(self, l2_policy_id):
        self._plugin._validate_shared_create(
            self._plugin, self._plugin_context, self._policy_target_group,
            'policy_target_group')
        self._plugin._set_l2_policy_for_policy_target_group(
            self._plugin_context, self._policy_target_group['id'],
            l2_policy_id)
        self._policy_target_group['l2_policy_id'] = l2_policy_id

    def set_network_service_policy_id(self, network_service_policy_id):
        nsp_id = network_service_policy_id
        self._plugin._set_network_service_policy_for_policy_target_group(
            self._plugin_context, self._policy_target_group['id'], nsp_id)
        self._policy_target_group['network_service_policy_id'] = nsp_id

    def add_subnet(self, subnet_id):
        subnets = self._plugin._add_subnet_to_policy_target_group(
            self._plugin_context, self._policy_target_group['id'], subnet_id)
        self._policy_target_group['subnets'] = subnets

    def add_subnets(self, subnet_ids):
        for subnet_id in subnet_ids:
            self.add_subnet(subnet_id)


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
        self._plugin._validate_shared_create(
            self._plugin, self._plugin_context, self._l2_policy, 'l2_policy')
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

    def set_address_scope_id(self, address_scope_id, version=4):
        self._plugin._set_address_scope_for_l3_policy(
            self._plugin_context, self._l3_policy['id'], address_scope_id,
            ip_version=version)
        if version == 4:
            self._l3_policy['address_scope_v4_id'] = address_scope_id
        else:
            self._l3_policy['address_scope_v6_id'] = address_scope_id

    def add_subnetpool(self, subnetpool_id, ip_version=4):
        subnetpools = self._plugin._add_subnetpool_to_l3_policy(
            self._plugin_context, self._l3_policy['id'], subnetpool_id,
            ip_version=ip_version)
        self._l3_policy['subnetpools_v4'] = subnetpools[4]
        self._l3_policy['subnetpools_v6'] = subnetpools[6]

    def remove_subnetpool(self, subnetpool_id, ip_version=4):
        subnetpools = self._plugin._remove_subnetpool_to_l3_policy(
            self._plugin_context, self._l3_policy['id'], subnetpool_id,
            ip_version=ip_version)
        self._l3_policy['subnetpools_v4'] = subnetpools[4]
        self._l3_policy['subnetpools_v6'] = subnetpools[6]

    def add_router(self, router_id):
        routers = self._plugin._add_router_to_l3_policy(
            self._plugin_context, self._l3_policy['id'], router_id)
        self._l3_policy['routers'] = routers

    def remove_router(self, router_id):
        routers = self._plugin._remove_router_from_l3_policy(
            self._plugin_context, self._l3_policy['id'], router_id)
        self._l3_policy['routers'] = routers

    def set_external_fixed_ips(self, external_segment_id, ips):
        self._l3_policy['external_segments'][external_segment_id] = ips
        self._plugin._update_ess_for_l3p(self._plugin_context,
                                         self._l3_policy['id'],
                                         self._l3_policy['external_segments'])

    def set_external_segment(self, external_segment_id):
        external_segments = {external_segment_id: []}
        self.current['external_segments'] = external_segments
        plugin_context = self._plugin_context
        with plugin_context.session.begin(subtransactions=True):
            l3p_db = self._plugin._get_l3_policy(plugin_context,
                                                 self._l3_policy['id'])
            self._plugin._set_ess_for_l3p(plugin_context, l3p_db,
                                          self.current['external_segments'])


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


class PolicyRuleSetContext(GroupPolicyContext, api.PolicyRuleSetContext):

    def __init__(self, plugin, plugin_context, policy_rule_set,
                 original_policy_rule_set=None):
        super(PolicyRuleSetContext, self).__init__(plugin, plugin_context)
        self._policy_rule_set = policy_rule_set
        self._original_policy_rule_set = original_policy_rule_set

    @property
    def current(self):
        return self._policy_rule_set

    @property
    def original(self):
        return self._original_policy_rule_set


class ExternalSegmentContext(GroupPolicyContext, api.ExternalSegmentContext):

    def __init__(self, plugin, plugin_context, external_segment,
                 original_external_segment=None):
        super(ExternalSegmentContext, self).__init__(plugin, plugin_context)
        self._external_segment = external_segment
        self._original_external_segment = original_external_segment

    @property
    def current(self):
        return self._external_segment

    @property
    def original(self):
        return self._original_external_segment

    def add_subnet(self, subnet_id):
        self._plugin._set_subnet_to_es(self._plugin_context,
                                       self.current['id'], subnet_id)
        self.current['subnet_id'] = subnet_id


class ExternalPolicyContext(GroupPolicyContext, api.ExternalPolicyContext):

    def __init__(self, plugin, plugin_context, external_policy,
                 original_external_policy=None):
        super(ExternalPolicyContext, self).__init__(plugin, plugin_context)
        self._external_policy = external_policy
        self._original_external_policy = original_external_policy

    @property
    def current(self):
        return self._external_policy

    @property
    def original(self):
        return self._original_external_policy

    def set_external_segment(self, external_segment_id):
        external_segmets = [external_segment_id]
        self.current['external_segments'] = external_segmets
        self._plugin.update_external_policy(
            self._plugin_context, self.current['id'],
            {'external_policy': {'external_segments': external_segmets}})


class NatPoolContext(GroupPolicyContext, api.NatPoolContext):

    def __init__(self, plugin, plugin_context, nat_pool,
                 original_nat_pool=None):
        super(NatPoolContext, self).__init__(plugin, plugin_context)
        self._nat_pool = nat_pool
        self._original_nat_pool = original_nat_pool

    @property
    def current(self):
        return self._nat_pool

    @property
    def original(self):
        return self._original_nat_pool
