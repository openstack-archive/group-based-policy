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

import gbp.neutron.tests.unit.db.grouppolicy.test_group_policy_db as tgpdb
import gbp.neutron.tests.unit.db.grouppolicy.test_group_policy_mapping_db as \
    tgpmdb


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


class GroupPolicyPluginTestCase(tgpmdb.GroupPolicyMappingDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None):
        if not gp_plugin:
            gp_plugin = GP_PLUGIN_KLASS
        super(GroupPolicyPluginTestCase, self).setUp(core_plugin=core_plugin,
                                                     gp_plugin=gp_plugin)

    def test_reverse_on_delete(self):
        manager = self.plugin.policy_driver_manager
        ctx = context.get_admin_context()
        drivers = manager.ordered_policy_drivers
        first, second = mock.Mock(), mock.Mock()
        first.obj, second.obj = FakeDriver(), FakeDriver()
        try:
            manager.ordered_policy_drivers = [first, second]
            manager.reverse_ordered_policy_drivers = [second, first]
            ordered_obj = [first.obj, second.obj]
            ctx.call_order = []
            manager._call_on_drivers('nodelete', ctx)
            self.assertEqual(ordered_obj, ctx.call_order)
            ctx.call_order = []
            manager._call_on_drivers('delete', ctx)
            self.assertEqual(ordered_obj[::-1], ctx.call_order)
        finally:
            manager.ordered_policy_drivers = drivers

    def test_delete_fails_on_used_epg(self):
        epg = self.create_endpoint_group()['endpoint_group']
        self.create_endpoint(endpoint_group_id=epg['id'])
        req = self.new_delete_request('endpoint_groups', epg['id'], self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)


class TestGroupPolicyPluginGroupResources(
    GroupPolicyPluginTestCase, tgpdb.TestGroupResources):

    pass


class TestGroupPolicyPluginMappedGroupResourceAttrs(
    GroupPolicyPluginTestCase, tgpmdb.TestMappedGroupResourceAttrs):

    pass
