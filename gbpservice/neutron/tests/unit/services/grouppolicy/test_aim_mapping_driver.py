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

from aim.api import resource as aim_resource
from aim.db import model_base as aim_model_base
from aim import aim_manager
from neutron import context as nctx
from neutron.db import api as db_api

from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_mapping as aim_driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_neutron_resources_driver as test_nr_base)


class TestPolicyRule(test_nr_base.CommonNeutronBaseTestCase):

    def setUp(self, policy_drivers=None, core_plugin=None, ml2_options=None,
              sc_plugin=None):
        policy_drivers = policy_drivers or ['aim_driver']
        super(TestPolicyRule, self).setUp(
            policy_drivers=policy_drivers, core_plugin=core_plugin,
            ml2_options=ml2_options, sc_plugin=sc_plugin)
        engine = db_api.get_engine()
        aim_model_base.Base.metadata.create_all(engine)
        self._aim = aim_manager.AimManager()
        self._neutron_context = nctx.get_admin_context()
        self._aim_context = aim_manager.AimContext(
            self._neutron_context.session)
        self._aim_mapper = aim_driver.APICNameMapper()

    def test_policy_rule_lifecycle(self):
        action1 = self.create_policy_action(
            action_type='redirect')['policy_action']
        classifier = self.create_policy_classifier(
            protocol='TCP', port_range="22",
            direction='bi')['policy_classifier']

        pr = self.create_policy_rule(
            name="pr1", policy_classifier_id=classifier['id'],
            policy_actions=[action1['id']])['policy_rule']
        pr_id = pr['id']
        self.show_policy_rule(pr_id, expected_res_status=200)

        tenant = pr['tenant_id']
        pr_id = pr['id']
        pr_name = pr['name']
        rn = self._aim_mapper.tenant_filter(tenant, pr_id, name=pr_name)
        aim_pr = self._aim.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(1, len(aim_pr))
        self.assertEqual(rn, aim_pr[0].rn)
        self.assertEqual(tenant, aim_pr[0].tenant_rn)

        self.delete_policy_rule(pr_id, expected_res_status=204)
        self.show_policy_rule(pr_id, expected_res_status=404)

        aim_pr = self._aim.find(
            self._aim_context, aim_resource.TenantFilter, rn=rn)
        self.assertEqual(0, len(aim_pr))
