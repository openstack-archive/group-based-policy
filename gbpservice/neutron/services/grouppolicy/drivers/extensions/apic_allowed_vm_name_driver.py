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

from oslo_log import log as logging
import re

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_allowed_vm_name_db as db)
from gbpservice.neutron.extensions import apic_allowed_vm_name as aavnext
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc

LOG = logging.getLogger(__name__)


class AllowedVMNameBadRegex(gpexc.GroupPolicyBadRequest):
    message = _("Bad regex: %(regex)s is defined for the allowed-vm-names "
                "attribute.")


class ApicAllowedVMNameExtensionDriver(api.ExtensionDriver,
                                       db.ApicAllowedVMNameDBMixin):
    _supported_extension_alias = aavnext.CISCO_APIC_GBP_ALLOWED_VM_NAME_EXT
    _extension_dict = aavnext.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.debug("APIC Allowed VM Name Extension Driver  __init__")
        self._policy_driver = None

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_l3_policy(self, session, data, result):
        l3p = data['l3_policy']
        if 'allowed_vm_names' in l3p:
            for vm_name in l3p['allowed_vm_names']:
                try:
                    re.compile(vm_name)
                except re.error:
                    raise AllowedVMNameBadRegex(regex=vm_name)
                self.add_l3_policy_allowed_vm_name(
                    session, l3_policy_id=result['id'],
                    allowed_vm_name=vm_name)

    def process_update_l3_policy(self, session, data, result):
        l3p = data['l3_policy']
        if not 'allowed_vm_names' in l3p:
            return
        rows = self.get_l3_policy_allowed_vm_names(
            session, l3_policy_id=result['id'])
        old_vm_names = [r.allowed_vm_name for r in rows]
        add_vm_names = list(set(l3p['allowed_vm_names']) - set(old_vm_names))
        for vm_name in add_vm_names:
            try:
                re.compile(vm_name)
            except re.error:
                raise AllowedVMNameBadRegex(regex=vm_name)
            self.add_l3_policy_allowed_vm_name(
                session, l3_policy_id=result['id'],
                allowed_vm_name=vm_name)
        rm_vm_names = list(set(old_vm_names) - set(l3p['allowed_vm_names']))
        for vm_name in rm_vm_names:
            self.delete_l3_policy_allowed_vm_name(
                session, l3_policy_id=result['id'],
                allowed_vm_name=vm_name)

    def extend_l3_policy_dict(self, session, result):
        rows = self.get_l3_policy_allowed_vm_names(
            session, l3_policy_id=result['id'])
        allowed_vm_names = [r.allowed_vm_name for r in rows]
        result['allowed_vm_names'] = allowed_vm_names
