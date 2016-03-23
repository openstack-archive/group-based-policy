# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
#
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

from keystoneclient.v2_0 import client as keyclient
from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

PLUGIN_NAME = 'gbpservice.neutron.plugins.ml2plus.plugin.Ml2PlusPlugin'


# This is just a quick sanity test that basic ML2 plugin functionality
# is preserved.

# REVISIT(rkukura): Use mock for this instead?
class FakeTenant(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name


class FakeTenantManager(object):
    def list(self):
        return [FakeTenant('test-tenant', 'TestTenantName')]


class FakeKeystoneClient(object):
    def __init__(self, **kwargs):
        self.tenants = FakeTenantManager()


class ApicAimTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'apic_aim'],
                                     'ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')
        config.cfg.CONF.set_override('admin_user', 'user',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_password', 'password',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('admin_tenant_name', 'tenant_name',
                                     group='keystone_authtoken')
        config.cfg.CONF.set_override('auth_uri',
                                     'http://127.0.0.1:35357/v2.0/',
                                     group='keystone_authtoken')
        super(ApicAimTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'

        self.saved_keystone_client = keyclient.Client
        keyclient.Client = FakeKeystoneClient

        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()

    def tearDown(self):
        keyclient.Client = self.saved_keystone_client
        super(ApicAimTestCase, self).tearDown()


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      ApicAimTestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            ApicAimTestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2,
                     ApicAimTestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        ApicAimTestCase):
    pass


class TestMl2SubnetsV2(test_plugin.TestSubnetsV2,
                       ApicAimTestCase):
    pass


class TestMl2SubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                           ApicAimTestCase):
    pass
