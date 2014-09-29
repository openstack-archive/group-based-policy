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


class GroupPolicyPluginTestCase(tgpmdb.GroupPolicyMappingDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        super(GroupPolicyPluginTestCase, self).setUp(
            gp_plugin=GP_PLUGIN_KLASS
        )


class TestGroupPolicyPluginGroupResources(
    GroupPolicyPluginTestCase, tgpdb.TestGroupResources):

    pass


class TestGroupPolicyPluginMappedGroupResourceAttrs(
    GroupPolicyPluginTestCase, tgpmdb.TestMappedGroupResourceAttrs):

    pass
