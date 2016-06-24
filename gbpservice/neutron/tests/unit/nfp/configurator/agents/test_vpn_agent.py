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


from gbpservice.neutron.tests.unit.nfp.configurator.test_data import \
                                                                vpn_test_data
from gbpservice.nfp.configurator.agents import vpn
from gbpservice.nfp.configurator.drivers.vpn.vyos import vyos_vpn_driver

import mock
import unittest

"""
Implements test cases for RPC manager methods of vpn agent
"""


class VPNaasEventHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(VPNaasEventHandlerTestCase, self).__init__(*args, **kwargs)
        self.conf = 'conf'
        self.dict_obj = vpn_test_data.VPNTestData()
        self.handler = vpn.VPNaasEventHandler(self.dict_obj.sc,
                                              self.dict_obj.drivers)
        self.ev = vpn_test_data.FakeEvent()
        self.driver = vyos_vpn_driver.VpnaasIpsecDriver(self.conf)

    def test_handle_event(self):
        '''
        Test to handle the vpn agent's vpnservice_updated method to
        handle various vpn operations

        '''
        with mock.patch.object(self.handler,
                               '_get_driver',
                               return_value=self.dict_obj.drivers),\
            mock.patch.object(self.driver, 'vpnservice_updated') as (
                                                    mock_vpnservice_updated):
            self.handler._vpnservice_updated(self.ev, self.driver)
            mock_vpnservice_updated.assert_called_with(self.ev.data['context'],
                                                       self.ev.data[
                                                           'resource_data'])

if __name__ == '__main__':
    unittest.main()
