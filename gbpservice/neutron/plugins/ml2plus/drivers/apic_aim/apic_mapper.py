# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
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

from neutron.common import exceptions

NAME_TYPE_TENANT = 'tenant'
NAME_TYPE_NETWORK = 'network'
NAME_TYPE_ADDRESS_SCOPE = 'address_scope'
NAME_TYPE_ROUTER = 'router'
NAME_TYPE_POLICY_TARGET_GROUP = 'policy_target_group'
NAME_TYPE_L3_POLICY = 'l3_policy'
NAME_TYPE_L2_POLICY = 'l2_policy'
NAME_TYPE_POLICY_RULE_SET = 'policy_rule_set'
NAME_TYPE_POLICY_RULE = 'policy_rule'
NAME_TYPE_EXTERNAL_SEGMENT = 'external_segment'
NAME_TYPE_EXTERNAL_POLICY = 'external_policy'
NAME_TYPE_NAT_POOL = 'nat_pool'


class InvalidResourceId(exceptions.BadRequest):
    message = _("The %(type)s ID '%(id)s' is invalid.")


class APICNameMapper(object):
    def mapper(name_type):
        """Wrapper to land all the common operations between mappers."""
        def wrap(func):
            def inner(inst, session, resource_id, resource_name=None,
                      prefix=None):
                if not resource_id:
                    raise InvalidResourceId(type=name_type, id=resource_id)
                result = resource_id
                if prefix:
                    result = prefix + result
                return result
            return inner
        return wrap

    @mapper(NAME_TYPE_TENANT)
    def tenant(self, session, tenant_id, tenant_name=None):
        return tenant_name

    @mapper(NAME_TYPE_NETWORK)
    def network(self, session, network_id, network_name=None):
        return network_name

    @mapper(NAME_TYPE_ADDRESS_SCOPE)
    def address_scope(self, session, address_scope_id,
                      address_scope_name=None):
        return address_scope_name

    @mapper(NAME_TYPE_ROUTER)
    def router(self, session, router_id, router_name=None):
        return router_name

    @mapper(NAME_TYPE_POLICY_TARGET_GROUP)
    def policy_target_group(self, session, policy_target_group_id,
                            policy_target_group_name=None):
        return policy_target_group_name

    @mapper(NAME_TYPE_L3_POLICY)
    def l3_policy(self, context, l3_policy_id):
        l3_policy = context._plugin.get_l3_policy(context._plugin_context,
                                                  l3_policy_id)
        return l3_policy['name']

    @mapper(NAME_TYPE_L2_POLICY)
    def l2_policy(self, context, l2_policy_id, l2_policy_name=None):
        return l2_policy_name

    @mapper(NAME_TYPE_POLICY_RULE_SET)
    def policy_rule_set(self, context, policy_rule_set_id,
                        policy_rule_set_name=None):
        return policy_rule_set_name

    @mapper(NAME_TYPE_POLICY_RULE)
    def policy_rule(self, context, policy_rule_id,
                    policy_rule_name=None):
        return policy_rule_name

    @mapper(NAME_TYPE_EXTERNAL_SEGMENT)
    def external_segment(self, context, external_segment_id):
        external_segment = context._plugin.get_external_segment(
            context._plugin_context, external_segment_id)
        return external_segment['name']

    @mapper(NAME_TYPE_EXTERNAL_POLICY)
    def external_policy(self, context, external_policy_id):
        external_policy = context._plugin.get_external_policy(
            context._plugin_context, external_policy_id)
        return external_policy['name']

    @mapper(NAME_TYPE_NAT_POOL)
    def nat_pool(self, context, nat_pool_id):
        nat_pool = context._plugin.get_nat_pool(context._plugin_context,
                                                nat_pool_id)
        return nat_pool['name']

    def delete_apic_name(self, session, object_id):
        pass
