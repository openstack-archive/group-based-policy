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

import mock
from neutron.common import config  # noqa

from gbpservice.neutron.services.servicechain.plugins.ncp.node_plumbers import(
    admin_owned_resources_apic_tscp as admin_tscp)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_tscp_apic_mapping as test_tscp_apic_mapping)


class AdminOwnedResourcesTscpTestCase(
        test_tscp_apic_mapping.ApicMappingStitchingPlumberGBPTestCase):

    def setUp(self):
        user = 'user'
        password = 'password'
        tenant_name = 'tenant_name',
        uri = 'http://127.0.0.1:35357/v2.0/'
        config.cfg.CONF.set_override('admin_user', user,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_password', password,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_tenant_name', tenant_name,
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_uri', uri,
                                     group='keystone_authtoken')
        super(AdminOwnedResourcesTscpTestCase, self).setUp(
            plumber='admin_owned_resources_apic_plumber')
        admin_tscp.keyclient = mock.Mock()
        res = mock.patch('gbpservice.neutron.services.servicechain.plugins.'
                         'ncp.node_plumbers.admin_owned_resources_apic_tscp.'
                         'AdminOwnedResourcesApicTSCP.'
                         '_get_resource_owner_tenant_id').start()
        res.return_value = "1234"


class TestApicChains(AdminOwnedResourcesTscpTestCase,
                     test_tscp_apic_mapping.TestApicChains):
    pass
