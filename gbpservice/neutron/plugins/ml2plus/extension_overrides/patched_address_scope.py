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

from neutron.extensions import address_scope
from neutron_lib.api.definitions import address_scope as apidef


class Patched_address_scope(address_scope.Address_scope):
    def update_attributes_map(self, attributes):
        super(Patched_address_scope, self).update_attributes_map(
            attributes,
            extension_attrs_map=apidef.RESOURCE_ATTRIBUTE_MAP)
