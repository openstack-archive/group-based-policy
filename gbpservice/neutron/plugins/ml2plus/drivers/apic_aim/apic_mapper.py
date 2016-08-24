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

import re

from neutron._i18n import _LI

LOG = None


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

MAX_APIC_NAME_LENGTH = 46


# TODO(rkukura): This is name mapper is copied from the apicapi repo,
# and modified to pass in resource names rather than calling the core
# plugin to get them, and to use the existing DB session. We need
# decide whether to make these changes in apicapi (maybe on a branch),
# move this some other repo, or keep it here. The changes are not
# backwards compatible. The implementation should also be cleaned up
# and simplified. For example, sessions should be passed in place of
# contexts, and the core plugin calls eliminated.


def truncate(string, max_length):
    if max_length < 0:
        return ''
    return string[:max_length] if len(string) > max_length else string


class APICNameMapper(object):
    def __init__(self, db, log):
        self.db = db
        self.min_suffix = 5
        global LOG
        LOG = log.getLogger(__name__)

    def mapper(name_type):
        """Wrapper to land all the common operations between mappers."""
        def wrap(func):
            def inner(inst, session, resource_id, resource_name=None,
                      prefix=None):
                # REVISIT(Bob): Optional argument for reserving characters in
                # the prefix?
                saved_name = inst.db.get_apic_name(session,
                                                   resource_id,
                                                   name_type)
                if saved_name:
                    result = saved_name[0]
                    # REVISIT(Sumit): Should this name mapper be aware of
                    # this prefixing logic, or should we instead prepend
                    # the prefix at the point from where this is being
                    # invoked. The latter approach has the disadvantage
                    # of having to replicate the logic in many places.
                    if prefix:
                        result = prefix + result
                        result = truncate(result, MAX_APIC_NAME_LENGTH)
                    return result
                name = ''
                try:
                    name = func(inst, session, resource_id, resource_name)
                except Exception as e:
                    LOG.warn(("Exception in looking up name %s"), name_type)
                    LOG.error(e.message)

                purged_id = re.sub(r"-+", "-", resource_id)
                result = purged_id[:inst.min_suffix]
                if name:
                    name = re.sub(r"-+", "-", name)
                    # Keep as many uuid chars as possible
                    id_suffix = "_" + result
                    max_name_length = MAX_APIC_NAME_LENGTH - len(id_suffix)
                    result = truncate(name, max_name_length) + id_suffix

                    result = truncate(result, MAX_APIC_NAME_LENGTH)
                    # Remove forbidden whitespaces
                    result = result.replace(' ', '')
                    result = inst._grow_id_if_needed(
                        session, purged_id, name_type, result,
                        start=inst.min_suffix)
                else:
                    result = purged_id

                inst.db.add_apic_name(session, resource_id,
                                      name_type, result)
                if prefix:
                    result = prefix + result
                    result = truncate(result, MAX_APIC_NAME_LENGTH)
                return result
            return inner
        return wrap

    def _grow_id_if_needed(self, session, resource_id, name_type,
                           current_result, start=0):
        result = current_result
        if result.endswith('_'):
            result = result[:-1]
        try:
            x = 0
            while True:
                if self.db.get_filtered_apic_names(session,
                                                   neutron_type=name_type,
                                                   apic_name=result):
                    if x == 0 and start == 0:
                        result += '_'
                    # This name overlaps, add more ID characters
                    result += resource_id[start + x]
                    x += 1
                else:
                    break
        except AttributeError:
            LOG.info(_LI("Current DB API doesn't support "
                         "get_filtered_apic_names."))
        except IndexError:
            LOG.debug("Ran out of ID characters.")
        return result

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
        self.db.delete_apic_name(session, object_id)
