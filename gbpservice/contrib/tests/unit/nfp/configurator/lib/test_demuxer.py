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

from gbpservice.contrib.nfp.configurator.lib import demuxer
from gbpservice.contrib.tests.unit.nfp.configurator.test_data import (
                                                        fw_test_data as fo)
from neutron.tests import base


class ServiceAgentDemuxerTestCase(base.BaseTestCase):
    """ Implements test cases for demuxer of configurator. """
    def __init__(self, *args, **kwargs):
        super(ServiceAgentDemuxerTestCase, self).__init__(*args, **kwargs)
        self.fo = fo.FakeObjects()
        self.demuxer = demuxer.ServiceAgentDemuxer()
        self.maxDiff = None

    def test_get_service_type(self):
        """ Tests that demuxer extracts the service type from
        request data.

        Returns: none

        """

        expected_val = 'firewall'

        request_data = self.fo.fake_request_data_generic_single(self)
        actual_val = self.demuxer.get_service_type(request_data)

        self.assertEqual(actual_val, expected_val)

    def test_get_service_agent_info_generic_config(self):
        """ Tests that demuxer extracts and prepares a list of configurations
        of generic config for each request inside the request_data.

        Returns: none

        """

        expected_val = self.fo.fake_sa_req_list()

        request_data = self.fo.fake_request_data_generic_bulk()
        actual_val, service_type = self.demuxer.get_service_agent_info(
                                'create', 'firewall', request_data, True)

        for agent_info in expected_val:
            agent_info['agent_info']['context']['nf_id'] = 'nf_id'
            agent_info['agent_info']['context']['nfi_id'] = 'nfi_id'
        self.assertEqual(actual_val, expected_val)

    def test_get_service_agent_info_firewall(self):
        """ Tests that demuxer extracts and prepares a list of configuration
        of firewall for each request inside the request_data.

        Returns: none

        """

        expected_val = self.fo.fake_sa_req_list_fw()

        request_data = self.fo.fake_request_data_fw()
        actual_val, service_type = self.demuxer.get_service_agent_info(
                                'create', 'firewall', request_data, False)

        self.assertEqual(actual_val, expected_val)
