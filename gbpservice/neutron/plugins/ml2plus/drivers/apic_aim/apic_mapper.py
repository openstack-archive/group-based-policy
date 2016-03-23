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
NAME_TYPE_POLICY_TARGET_GROUP = 'policy_target_group'

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
            def inner(inst, session, resource_id, resource_name=None):
                saved_name = inst.db.get_apic_name(session,
                                                   resource_id,
                                                   name_type)
                if saved_name:
                    result = saved_name[0]
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

    @mapper(NAME_TYPE_POLICY_TARGET_GROUP)
    def policy_target_group(self, session, policy_target_group_id,
                            policy_target_group_name=None):
        return policy_target_group_name

    def delete_apic_name(self, session, object_id):
        self.db.delete_apic_name(session, object_id)
