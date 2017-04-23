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
from neutron_lib.api import converters

from gbpservice.neutron.extensions import group_policy as gp


CISCO_APIC_GBP_ALLOWED_VM_NAME_EXT = 'cisco_apic_gbp_allowed_vm_name'

EXTENDED_ATTRIBUTES_2_0 = {
    gp.L3_POLICIES: {
        'allowed_vm_names': {
            'allow_post': True, 'allow_put': True, 'default': None,
            'validate': {'type:list_of_unique_strings': None},
            'convert_to': converters.convert_none_to_empty_list,
            'is_visible': True},
    },
}


class Apic_allowed_vm_name(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "APIC GBP Allowed VM Name Extension"

    @classmethod
    def get_alias(cls):
        return CISCO_APIC_GBP_ALLOWED_VM_NAME_EXT

    @classmethod
    def get_description(cls):
        return _("This extension supports a list of allowed VM name regexes "
                 "that can be applied to the L3 policy resource.")

    @classmethod
    def get_updated(cls):
        return "2016-10-10T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
