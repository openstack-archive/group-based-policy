# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron.db import api as db_api
from neutron import manager
from neutron_lib.db import model_base
from oslo_config import cfg

from gbpservice.neutron.services.grouppolicy.\
     drivers.vmware.nsx_policy import nsx_policy_mapping as driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)


class NsxPolicyMappingTestCase(test_rmd.ResourceMappingTestCase):

    def setUp(self):
        self.set_up_config()
        self.set_up_mocks()

        super(NsxPolicyMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'nsx_policy'])
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

    def tearDown(self):
        super(NsxPolicyMappingTestCase, self).tearDown()

    def set_up_config(self):
        cfg.CONF.register_opts(driver.policy_opts, driver.DRIVER_OPT_GROUP)
        cfg.CONF.register_opts(driver.nsx_opts, driver.NSX_V3_GROUP)
        cfg.CONF.set_override('nsx_policy_manager', '1.1.1.1',
                              driver.DRIVER_OPT_GROUP)
        cfg.CONF.set_override('nsx_api_managers', '1.1.1.1',
                              driver.NSX_V3_GROUP)

    def set_up_mocks(self):
        mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()


class TestPolicyTargetGroup(NsxPolicyMappingTestCase):

    def test_policy_target_group_create(self):
        self.create_policy_target_group(name="ptg1")

        # TODO(annak): verify neutron objects and mock calls


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    def test_policy_rule_set_create(self):
        self.create_policy_rule_set(name="test")

        # TODO(annak): verify neutron objects and mock calls
