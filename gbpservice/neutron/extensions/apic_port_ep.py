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

from neutron.api import extensions
from neutron.api.v2 import attributes

ALIAS = 'apic-port-ep'

ENDPOINT_UP_TO_DATE = 'apic:endpoint_up_to_date'

APIC_ATTRIBUTES = {
    ENDPOINT_UP_TO_DATE: {'allow_post': False, 'allow_put': True,
                          'convert_to': attributes.convert_to_boolean,
                          'is_visible': True}
}

EXTENDED_ATTRIBUTES_2_0 = {
    attributes.PORTS: APIC_ATTRIBUTES,
}


class Apic_port_ep(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "APIC Port Endpoint"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Extension exposing whether the EP file for a specific port "
                "is up to date.")

    @classmethod
    def get_updated(cls):
        return "2016-10-19T12:00:00-00:00"

    @classmethod
    def get_namespace(self):
        pass

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
