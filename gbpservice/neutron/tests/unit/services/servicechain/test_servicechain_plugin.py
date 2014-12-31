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

from gbpservice.neutron.tests.unit.db.grouppolicy import (
    test_servicechain_db as test_servicechain_db)

cfg.CONF.import_opt('servicechain_drivers',
                    'gbpservice.neutron.services.servicechain.config',
                    group='servicechain')
SC_PLUGIN_KLASS = (
    "gbpservice.neutron.services.servicechain.servicechain_plugin."
    "ServiceChainPlugin"
)


class ServiceChainPluginTestCase(test_servicechain_db.ServiceChainDbTestCase):

    def setUp(self, core_plugin=None, sc_plugin=None):
        if not sc_plugin:
            sc_plugin = SC_PLUGIN_KLASS
        super(ServiceChainPluginTestCase, self).setUp(core_plugin=core_plugin,
                                                      sc_plugin=sc_plugin)


class TestGroupPolicyPluginGroupResources(
                    ServiceChainPluginTestCase,
                    test_servicechain_db.TestServiceChainResources):
    pass
