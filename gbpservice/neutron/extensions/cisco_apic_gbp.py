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

from neutron.api import extensions

from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import group_policy as gp

ALIAS = 'cisco-apic-gbp'

FORWARD_FILTER_ENTRIES = 'Forward-FilterEntries'
REVERSE_FILTER_ENTRIES = 'Reverse-FilterEntries'
CONTRACT = 'Contract'
CONTRACT_SUBJECT = 'ContractSubject'

EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGET_GROUPS: {
        cisco_apic.DIST_NAMES: {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
    },
    gp.POLICY_RULES: {
        cisco_apic.DIST_NAMES: {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
    },
    gp.POLICY_RULE_SETS: {
        cisco_apic.DIST_NAMES: {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
    },
}


class Cisco_apic_gbp(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco APIC GBP"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return _("Extension exposing mapping of GBP resources to Cisco "
                 "APIC constructs")

    @classmethod
    def get_updated(cls):
        return "2016-07-11T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
