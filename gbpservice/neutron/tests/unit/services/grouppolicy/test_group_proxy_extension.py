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

import os

from gbpservice.neutron.services.grouppolicy import extensions as ext
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)


class ExtensionDriverTestCase(test_ext_base.ExtensionDriverTestBase):

    _extension_drivers = ['proxy_group']
    _extension_path = os.path.dirname(os.path.abspath(ext.__file__))

    def test_proxy_group_extension(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        self.assertIsNone(ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])

        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'])['policy_target_group']
        self.assertIsNone(ptg_proxy['proxy_group_id'])
        self.assertEqual(ptg['id'], ptg_proxy['proxied_group_id'])

        # Verify relationship added
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg_proxy['id'], ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])
