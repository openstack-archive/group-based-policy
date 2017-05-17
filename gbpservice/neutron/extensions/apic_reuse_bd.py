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

from neutron_lib.api import extensions

from gbpservice.neutron.extensions import group_policy as gp


CISCO_APIC_GBP_REUSE_BD_EXT = 'cisco_apic_gbp_reuse_bd'

EXTENDED_ATTRIBUTES_2_0 = {
    gp.L2_POLICIES: {
        'reuse_bd': {
            'allow_post': True, 'allow_put': False, 'default': None,
            'validate': {'type:uuid_or_none': None},
            'is_visible': True},
    },
}


class Apic_reuse_bd(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "APIC GBP Reuse BD Extension"

    @classmethod
    def get_alias(cls):
        return CISCO_APIC_GBP_REUSE_BD_EXT

    @classmethod
    def get_description(cls):
        return _("This extension enables creating L2 policy objects that "
                 "use the same BridgeDomain on APIC")

    @classmethod
    def get_updated(cls):
        return "2016-11-11T04:20:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
