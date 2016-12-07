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
from neutron.api.v2 import attributes as attr

from gbpservice.neutron.extensions import group_policy as gp


CISCO_APIC_GBP_INTRA_PTG_EXT = 'cisco_apic_gbp_intra_ptg_allow'

EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGET_GROUPS: {
        'intra_ptg_allow': {
            'allow_post': True, 'allow_put': True, 'default': True,
            'convert_to': attr.convert_to_boolean, 'is_visible': True},
    },
}


class Apic_intra_ptg(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "APIC GBP Intra PTG Traffic Allow/Disallow Extension"

    @classmethod
    def get_alias(cls):
        return CISCO_APIC_GBP_INTRA_PTG_EXT

    @classmethod
    def get_description(cls):
        return _("This extension enables disallowing communication "
                 "between Policy Targets in a PTG by setting the "
                 "policy enforcement attribute of the APIC EPG "
                 "that maps to the PTG.")

    @classmethod
    def get_updated(cls):
        return "2016-12-06T04:20:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
