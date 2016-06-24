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

from neutron.tests import base

from gbpservice.contrib.nfp.configurator.drivers.nfp_service.heat.heat_driver \
                                                        import HeatDriver
from gbpservice.contrib.nfp.configurator.lib import (
                                            nfp_service_constants as const)
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                nfp_service_test_data as fo)


class NfpServiceHeatDriverTestCase(base.BaseTestCase):
    """ Implements test cases for driver methods
    of nfp service.

    """

    def __init__(self, *args, **kwargs):
        super(NfpServiceHeatDriverTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()

    def test_configure_interfaces(self):
        """ Implements test case for nfp service heat driver.

        Returns: none

        """

        driver = HeatDriver(self.fo.conf)
        actual_val = driver.run_heat(self.fo.context, self.fo.kwargs)

        expected_val = const.UNHANDLED_RESULT
        self.assertEqual(actual_val, expected_val)
