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

PROJECT_TYPE_TAG = 'prj'
NETWORK_TYPE_TAG = 'net'
ADDRESS_SCOPE_TYPE_TAG = 'as'
ROUTER_TYPE_TAG = 'rtr'
POLICY_RULE_SET_TYPE_TAG = 'prs'
POLICY_RULE_TYPE_TAG = 'pr'


class APICNameMapper(object):
    # This class may be overriden to customize the mapping from
    # OpenStack resource IDs to APIC resource names. Certain resource
    # mappings support prefixes in order to allow mapping a single
    # OpenStack resource to multiple APIC resources of the same type,
    # and there are reverse mapping methods for resources that need
    # them. Note that there is no reverse_project method, since there
    # are potential use cases for mapping multiple OpenStack project
    # IDs to the same APIC Tenant.

    def project(self, session, id):
        # REVISIT: The external connectiviy unit tests pass "common"
        # as a project_id, and expect this to be mapped to the AIM
        # common Tenant. Its not clear how a real deployment using
        # Keystone would arrange to have "common" as a valid
        # project_id, so maybe this special handling is not really
        # needed.
        return (id if id == "common" else
                self._map(session, id, PROJECT_TYPE_TAG))

    def network(self, session, id):
        return self._map(session, id, NETWORK_TYPE_TAG)

    def reverse_network(self, session, name):
        return self._unmap(session, name)

    def address_scope(self, session, id):
        return self._map(session, id, ADDRESS_SCOPE_TYPE_TAG)

    def reverse_address_scope(self, session, name):
        return self._unmap(session, name)

    def router(self, session, id):
        return self._map(session, id, ROUTER_TYPE_TAG)

    def policy_rule_set(self, session, id, prefix=""):
        return self._map(session, id, POLICY_RULE_SET_TYPE_TAG, prefix)

    def policy_rule(self, session, id, prefix=""):
        return self._map(session, id, POLICY_RULE_TYPE_TAG, prefix)

    def _map(self, session, id, type_tag, prefix=""):
        return ("%(prefix)s%(type_tag)s_%(id)s" %
                {'prefix': prefix, 'type_tag': type_tag, 'id': id})

    def _unmap(self, session, name):
        return name.split('_', 1)[-1]
