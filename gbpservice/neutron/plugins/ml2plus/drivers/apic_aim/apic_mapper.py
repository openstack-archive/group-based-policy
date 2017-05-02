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

from oslo_log import log

from gbpservice._i18n import _LE
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import exceptions

LOG = log.getLogger(__name__)

PROJECT_TYPE_TAG = 'prj'
NETWORK_TYPE_TAG = 'net'
ADDRESS_SCOPE_TYPE_TAG = 'as'
ROUTER_TYPE_TAG = 'rtr'
L3_POLICY_TYPE_TAG = 'l3p'
POLICY_RULE_SET_TYPE_TAG = 'prs'
POLICY_RULE_TYPE_TAG = 'pr'
APPLICATION_POLICY_GROUP_TYPE_TAG = 'apg'


class APICNameMapper(object):
    # This class may be overriden to customize the mapping from
    # OpenStack resource IDs to APIC resource names. Prefixes can be
    # supplied in order to allow mapping a single OpenStack resource
    # to multiple APIC resources of the same type. There are reverse
    # mapping methods for most resources, but there is no
    # reverse_project method because of potential use cases for
    # mapping multiple OpenStack project IDs to the same APIC Tenant.

    def project(self, session, id, prefix=""):
        # REVISIT: The external connectiviy unit tests pass "common"
        # as a project_id, and expect this to be mapped to the AIM
        # common Tenant. Its not clear how a real deployment using
        # Keystone would arrange to have "common" as a valid
        # project_id, so maybe this special handling is not really
        # needed.
        return (id if id == "common" else
                self._map(session, id, PROJECT_TYPE_TAG, prefix))

    def network(self, session, id, prefix=""):
        return self._map(session, id, NETWORK_TYPE_TAG, prefix)

    def reverse_network(self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, NETWORK_TYPE_TAG, prefix, enforce)

    def address_scope(self, session, id, prefix=""):
        return self._map(session, id, ADDRESS_SCOPE_TYPE_TAG, prefix)

    def reverse_address_scope(self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, ADDRESS_SCOPE_TYPE_TAG, prefix, enforce)

    def router(self, session, id, prefix=""):
        return self._map(session, id, ROUTER_TYPE_TAG, prefix)

    def reverse_router(self, session, name, prefix="", enforce=True):
        return self._unmap(session, name, ROUTER_TYPE_TAG, prefix, enforce)

    def l3_policy(self, session, id, prefix=""):
        return self._map(session, id, L3_POLICY_TYPE_TAG, prefix)

    def reverse_l3_policy(self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, L3_POLICY_TYPE_TAG, prefix, enforce)

    def policy_rule_set(self, session, id, prefix=""):
        return self._map(session, id, POLICY_RULE_SET_TYPE_TAG, prefix)

    def reverse_policy_rule_set(self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, POLICY_RULE_SET_TYPE_TAG, prefix, enforce)

    def policy_rule(self, session, id, prefix=""):
        return self._map(session, id, POLICY_RULE_TYPE_TAG, prefix)

    def reverse_policy_rule(self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, POLICY_RULE_TYPE_TAG, prefix, enforce)

    def application_policy_group(self, session, id, prefix=""):
        return self._map(
            session, id, APPLICATION_POLICY_GROUP_TYPE_TAG, prefix)

    def reverse_application_policy_group(
        self, session, name, prefix="", enforce=True):
        return self._unmap(
            session, name, APPLICATION_POLICY_GROUP_TYPE_TAG, prefix, enforce)

    def _map(self, session, id, type_tag, prefix):
        return ("%(prefix)s%(type_tag)s_%(id)s" %
                {'prefix': prefix, 'type_tag': type_tag, 'id': id})

    def _unmap(self, session, name, type_tag, prefix, enforce):
        pos = len(prefix) + len(type_tag) + 1
        if self._map(session, "", type_tag, prefix) == name[:pos]:
            return name[pos:]
        elif enforce:
            LOG.error(_LE("Attempted to reverse-map invalid APIC name '%s'"),
                      name)
            raise exceptions.InternalError()
