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


import filter_base
from gbpservice.contrib.nfp.configurator.lib import data_filter


class FilterTest(filter_base.BaseTestCase):
    """Test class to test data_filter.py using unittest framework """
    def __init__(self, *args, **kwargs):
        super(FilterTest, self).__init__(*args, **kwargs)

    def setUp(self):
        """Prepare setup for every test case.
        """
        super(FilterTest, self).setUp()
        self.context = {}
        self.filter_obj = data_filter.Filter(None, None)

    def tearDown(self):
        """ Reset values after test case execution.
        """
        super(FilterTest, self).tearDown()
        self.context = {}

    def _make_test(self, context, method, **filters):
        """ To reduce the boilerplate. """
        retval = self.filter_obj.call(self.context,
                                      self.filter_obj.make_msg(method,
                                                               **filters))
        return retval

    def _make_vpn_service_context(self):
        """Make the context for the vpn service

        Returns: vpn service context

        """
        service_info = self._test_get_vpn_info()
        self.context['service_info'] = service_info
        return self.context

    def _make_fw_service_context(self):
        """Make the context for the fw service

        Returns: fw service context

        """
        service_info = self._test_get_fw_info()
        self.context['service_info'] = service_info
        return self.context

    def test_get_vpn_service_with_tenantid(self):
        """Test get_vpn_services() of data_filter.py by passing
           only tenant_id in filters
        """
        retval = self._make_test(self._make_vpn_service_context(),
                                 'get_vpn_services',
                                 filters=(
                            {'tenant_id': [self.vpnservices[0]['tenant_id']]}))

        self.assertEqual(retval, [self.vpnservices[0], self.vpnservices[1]])

    def test_get_vpn_service_with_ids(self):
        """Test get_vpn_services() of data_filter.py by passing
           vpn service ids in filters
        """
        retval = self._make_test(self._make_vpn_service_context(),
                                 'get_vpn_services',
                                 ids=[self.vpnservices[0]['id'],
                                      self.vpnservices[1]['id']])
        self.assertEqual(retval, [self.vpnservices[0], self.vpnservices[1]])

    def test_get_ipsec_conns(self):
        """Test get_ipsec_conns() of data_filter.py
        """
        retval = self._make_test(
                self._make_vpn_service_context(),
                'get_ipsec_conns',
                tenant_id=[self.ipsec_site_connections[0]['tenant_id']],
                peer_address=[self.ipsec_site_connections[0]['peer_address']])
        self.assertEqual(retval, self.ipsec_site_connections)

    def test_get_vpn_servicecontext_ipsec_service_type(self):
        """Test get_vpn_servicecontext() of data_filter.py
           based on ipsec service type
        """
        service_info = self._test_get_vpn_info()
        self.context['service_info'] = service_info
        retval = self.filter_obj._get_vpn_servicecontext(
                    self.context,
                    {'tenant_id': self.vpnservices[0]['tenant_id'],
                     'vpnservice_id': self.vpnservices[0]['id'],
                     'ipsec_site_connections':
                     self.ipsec_site_connections[0]['id']})

        expected = {'service': self.vpnservices[0],
                    'siteconns': [{'connection':
                                   self.ipsec_site_connections[0],
                                   'ikepolicy': self.ikepolicies[0],
                                   'ipsecpolicy': self.ipsecpolicies[0]
                                   }]}

        self.assertEqual(retval, [expected])

    def test_get_vpn_servicecontext_ipsec_service_type_with_tenantid(self):
        """Test get_vpn_servicecontext() of data_filter.py
           based on ipsec service type and tenant_id
        """
        service_info = self._test_get_vpn_info()
        self.context['service_info'] = service_info
        retval = self.filter_obj._get_vpn_servicecontext(
                    self.context,
                    {'tenant_id': self.vpnservices[0]['tenant_id'],
                     })

        expected = {'service': self.vpnservices[0],
                    'siteconns': [{'connection':
                                   self.ipsec_site_connections[0],
                                   'ikepolicy': self.ikepolicies[0],
                                   'ipsecpolicy': self.ipsecpolicies[0]
                                   }]}

        self.assertEqual(retval, [expected])
