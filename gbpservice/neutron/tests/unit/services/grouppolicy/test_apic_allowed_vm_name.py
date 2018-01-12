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

from neutron.db import api as db_api

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_allowed_vm_name_db as db)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)


class ExtensionDriverTestCase(test_ext_base.ExtensionDriverTestBase):
    _extension_drivers = ['apic_allowed_vm_name']
    _extension_path = None

    def test_l3p_lifecycle(self):
        l3p = self.create_l3_policy(name='myl3')['l3_policy']
        self.assertEqual([], l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertEqual([], l3p['allowed_vm_names'])
        self.delete_l3_policy(l3p['id'], tenant_id=l3p['tenant_id'],
                              expected_res_status=204)

        allowed_vm_names = []
        l3p = self.create_l3_policy(
            name='myl3',
            allowed_vm_names=allowed_vm_names)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertItemsEqual([], l3p['allowed_vm_names'])
        self.delete_l3_policy(l3p['id'], tenant_id=l3p['tenant_id'],
                              expected_res_status=204)

        allowed_vm_names = ['safe_vm*', '^secure_vm*']
        l3p = self.create_l3_policy(
            name='myl3',
            allowed_vm_names=allowed_vm_names)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])

        allowed_vm_names = ['good_vm*', '^ok_vm*', 'safe_vm*']
        l3p = self.update_l3_policy(
            l3p['id'], allowed_vm_names=allowed_vm_names,
            expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])

        allowed_vm_names = []
        l3p = self.update_l3_policy(
            l3p['id'], allowed_vm_names=allowed_vm_names,
            expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])

        allowed_vm_names = ['^ok_vm*']
        l3p = self.update_l3_policy(
            l3p['id'], allowed_vm_names=allowed_vm_names,
            expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])
        l3p = self.show_l3_policy(
            l3p['id'], expected_res_status=200)['l3_policy']
        self.assertItemsEqual(allowed_vm_names, l3p['allowed_vm_names'])

        self.delete_l3_policy(l3p['id'], tenant_id=l3p['tenant_id'],
                              expected_res_status=204)
        session = db_api.get_reader_session()
        rows = (session.query(db.ApicAllowedVMNameDB).filter_by(
                l3_policy_id=l3p['id']).all())
        self.assertEqual([], rows)
