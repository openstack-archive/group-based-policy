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
from neutron import context
from oslo.config import cfg

import gbp.neutron.tests.unit.db.grouppolicy.test_group_policy_db as tdb


cfg.CONF.import_opt('policy_drivers',
                    'gbp.neutron.services.grouppolicy.config',
                    group='group_policy')
GP_PLUGIN_KLASS = (
    "gbp.neutron.services.grouppolicy.plugin.GroupPolicyPlugin"
)


class FakeDriver(object):

    def _fill_order(self, context):
        context.call_order.append(self)

    def __getattr__(self, item):
        return self._fill_order


class GroupPolicyPluginTestCase(tdb.GroupPolicyDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        super(GroupPolicyPluginTestCase, self).setUp(
            gp_plugin=GP_PLUGIN_KLASS
        )

    def test_reverse_on_delete(self):
        manager = self.plugin.policy_driver_manager
        ctx = context.get_admin_context()
        drivers = manager.ordered_policy_drivers
        first, second = mock.Mock(), mock.Mock()
        first.obj, second.obj = FakeDriver(), FakeDriver()
        try:
            manager.ordered_policy_drivers = [first, second]
            ordered_obj = [first.obj, second.obj]
            ctx.call_order = []
            manager._call_on_drivers('nodelete', ctx)
            self.assertEqual(ordered_obj, ctx.call_order)
            ctx.call_order = []
            manager._call_on_drivers('delete', ctx)
            self.assertEqual(ordered_obj[::-1], ctx.call_order)
        finally:
            manager.ordered_policy_drivers = drivers


class TestGroupPolicyPluginGroupResources(
    GroupPolicyPluginTestCase, tdb.TestGroupResources):

    pass
