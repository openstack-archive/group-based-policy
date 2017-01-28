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
from mock import patch
import unittest2

from oslo_config import cfg

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.orchestrator.drivers import (
    orchestration_driver
)

import uuid as pyuuid

cfg.CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')
OPENSTACK_DRIVER_CLASS_PATH = ('gbpservice.nfp.orchestrator'
                               '.openstack.openstack_driver')
NFP_GBP_NETWORK_DRIVER_CLASS_PATH = ('gbpservice.nfp.orchestrator'
                                     '.coal.networking'
                                     '.nfp_gbp_network_driver')
NFP_NEUTRON_NETWORK_DRIVER_CLASS_PATH = ('gbpservice.nfp.orchestrator'
                                         '.coal.networking'
                                         '.nfp_neutron_network_driver')


@patch(OPENSTACK_DRIVER_CLASS_PATH + '.KeystoneClient.__init__',
       mock.MagicMock(return_value=None))
@patch(OPENSTACK_DRIVER_CLASS_PATH + '.NovaClient.__init__',
       mock.MagicMock(return_value=None))
@patch(NFP_GBP_NETWORK_DRIVER_CLASS_PATH + '.NFPGBPNetworkDriver.__init__',
       mock.MagicMock(return_value=None))
@patch(NFP_NEUTRON_NETWORK_DRIVER_CLASS_PATH +
       '.NFPNeutronNetworkDriver.__init__',
       mock.MagicMock(return_value=None))
class OrchestrationDriverTestCase(unittest2.TestCase):

    def test_create_network_function_device(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=True,
            max_interfaces=8)
        driver.network_handler = driver.network_handlers['gbp']

        # Mock the client methods
        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.identity_handler.get_tenant_id = mock.MagicMock(
            return_value='8')
        driver.identity_handler.get_keystone_creds = mock.MagicMock(
            return_value=(None, None, 'admin', None))
        driver.network_handler.create_port = mock.MagicMock(
            return_value={'id': str(pyuuid.uuid4()),
                          'port_id': str(pyuuid.uuid4())})
        driver.network_handler.set_promiscuos_mode = mock.MagicMock(
            return_value=None)
        driver.network_handler.set_promiscuos_mode_fast = mock.MagicMock(
            return_value=None)
        driver.compute_handler_nova.get_image_id = mock.MagicMock(
            return_value='6')
        driver.compute_handler_nova.get_image_metadata = mock.MagicMock(
            return_value=[])
        driver.compute_handler_nova.create_instance = mock.MagicMock(
            return_value='8')
        driver.network_handler.delete_port = mock.MagicMock(
            return_value=None)
        driver.network_handler.get_port_id = mock.MagicMock(return_value='7')
        driver.network_handler.get_port_details = mock.MagicMock(
            return_value=('a.b.c.d',
                          'aa:bb:cc:dd:ee:ff',
                          'p.q.r.s/t',
                          'w.x.y.z'))
        driver.network_handler.get_neutron_port_details = mock.MagicMock(
            return_value=(1, 2, 3, 4,
                          {'port': {}},
                          {'subnet': {}}))

        # test for create device when interface hotplug is enabled
        device_data = {'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},
                       'name': 'FIREWALL.vyos.1.2',
                       'volume_support': None,
                       'volume_size': None,
                       'management_network_info': {'id': '2'},
                       'ports': [{'id': '3',
                                  'port_model': 'gbp',
                                  'port_classification': 'provider'},
                                 {'id': '4',
                                  'port_model': 'gbp',
                                  'port_classification': 'consumer'}],
                       'token': str(pyuuid.uuid4()),
                       'admin_tenant_id': str(pyuuid.uuid4())}
        self.assertRaises(exceptions.ComputePolicyNotSupported,
                          driver.create_network_function_device,
                          device_data)
        device_data['service_details']['device_type'] = 'nova'
        self.assertIsInstance(driver.create_network_function_device(
            device_data),
            dict,
            msg=('Return value from the'
                 ' create_network_function_device call'
                 ' is not a dictionary'))

        # test for create device along with provider port
        driver.supports_hotplug = False
        self.assertIsInstance(driver.create_network_function_device(
            device_data),
            dict,
            msg=('Return value from the'
                 ' create_network_function_device call'
                 ' is not a dictionary'))

    def test_delete_network_function_device(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=True,
            max_interfaces=8)
        driver.network_handler = driver.network_handlers['gbp']

        # Mock the client methods
        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.identity_handler.get_tenant_id = mock.MagicMock(
            return_value='8')
        driver.identity_handler.get_keystone_creds = mock.MagicMock(
            return_value=(None, None, 'admin', None))
        driver.compute_handler_nova.delete_instance = mock.MagicMock(
            return_value=None)
        driver.network_handler.delete_port = mock.MagicMock(return_value=None)

        device_data = {'id': '1',
                       'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},
                       'mgmt_port_id': {'id': '3',
                                        'port_model': 'gbp',
                                        'port_classification': 'mgmt'}}
        self.assertRaises(exceptions.ComputePolicyNotSupported,
                          driver.delete_network_function_device,
                          device_data)
        device_data['service_details']['device_type'] = 'nova'
        self.assertIsNone(driver.delete_network_function_device(device_data))

    def test_get_network_function_device_status(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=True,
            max_interfaces=8)

        # Mock the client methods
        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.identity_handler.get_tenant_id = mock.MagicMock(
            return_value='8')
        driver.identity_handler.get_keystone_creds = mock.MagicMock(
            return_value=(None, None, 'admin', None))
        driver.compute_handler_nova.get_instance = mock.MagicMock(
            return_value={'status': 'ACTIVE'})

        device_data = {'id': '1',
                       'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},
                       'token': str(pyuuid.uuid4()),
                       'tenant_id': str(pyuuid.uuid4())}

        self.assertRaises(exceptions.ComputePolicyNotSupported,
                          driver.get_network_function_device_status,
                          device_data)
        device_data['service_details']['device_type'] = 'nova'

        self.assertTrue(
            driver.get_network_function_device_status(device_data) ==
            'ACTIVE')

    def test_plug_network_function_device_interfaces(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=False,
            max_interfaces=8)
        driver.network_handler = driver.network_handlers['gbp']
        # Mock the client methods
        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.identity_handler.get_tenant_id = mock.MagicMock(
            return_value='8')
        driver.identity_handler.get_keystone_creds = mock.MagicMock(
            return_value=(None, None, 'admin', None))
        driver.network_handler.set_promiscuos_mode = mock.MagicMock(
            return_value=None)
        driver.network_handler.set_promiscuos_mode_fast = mock.MagicMock(
            return_value=None)
        driver.compute_handler_nova.attach_interface = mock.MagicMock(
            return_value=None)
        driver.compute_handler_nova.get_image_metadata = mock.MagicMock(
            return_value={})
        driver.network_handler.get_port_id = mock.MagicMock(return_value='7')

        device_data = {'id': '1',
                       'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},
                       'ports': [{'id': '3',
                                  'port_model': 'gbp',
                                  'port_classification': 'provider'},
                                 {'id': '4',
                                  'port_model': 'neutron',
                                  'port_classification': 'consumer'}],
                       'provider_metadata': {},
                       'token': str(pyuuid.uuid4()),
                       'tenant_id': str(pyuuid.uuid4())}

        device_data['service_details']['device_type'] = 'nova'

        self.assertTrue(driver.plug_network_function_device_interfaces(
            device_data),
            msg='')

    def test_unplug_network_function_device_interfaces(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=False,
            max_interfaces=8)
        driver.network_handler = driver.network_handlers['gbp']

        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.identity_handler.get_tenant_id = mock.MagicMock(
            return_value='8')
        driver.identity_handler.get_keystone_creds = mock.MagicMock(
            return_value=(None, None, 'admin', None))
        driver.compute_handler_nova.detach_interface = mock.MagicMock(
            return_value=None)
        driver.compute_handler_nova.get_image_metadata = mock.MagicMock(
            return_value={})
        driver.network_handler.get_port_id = mock.MagicMock(return_value='7')

        device_data = {'id': '1',
                       'tenant_id': 'tenant_id',
                       'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},
                       'provider_metadata': {},
                       'ports': [{'id': '3',
                                  'port_model': 'gbp',
                                  'port_classification': 'provider'},
                                 {'id': '4',
                                  'port_model': 'neutron',
                                  'port_classification': 'consumer'}]}

        device_data['service_details']['device_type'] = 'nova'

        self.assertTrue(driver.unplug_network_function_device_interfaces(
            device_data),
            msg='')

    def test_get_network_function_device_healthcheck_info(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=False,
            max_interfaces=8)

        device_data = {'id': '1',
                       'mgmt_ip_address': 'a.b.c.d'}

        self.assertIsInstance(
            driver.get_network_function_device_config(device_data,
                nfp_constants.HEALTHMONITOR_RESOURCE),
            dict, msg='')

    def test_get_network_function_device_config(self):
        driver = orchestration_driver.OrchestrationDriver(
            cfg.CONF,
            supports_device_sharing=True,
            supports_hotplug=False,
            max_interfaces=8)
        driver.network_handler = driver.network_handlers['gbp']

        driver.identity_handler.get_admin_token = mock.MagicMock(
            return_value='token')
        driver.network_handler.get_port_details = mock.MagicMock(
            return_value=('a.b.c.d',
                          'aa:bb:cc:dd:ee:ff',
                          'p.q.r.s/t',
                          'w.x.y.z'))

        device_data = {'service_details': {'device_type': 'xyz',
                                           'service_type': 'firewall',
                                           'service_vendor': 'vyos',
                                           'network_mode': 'gbp'},

                       'mgmt_ip_address': 'a.b.c.d',
                       'ports': [{'id': '3',
                                  'port_model': 'gbp',
                                  'port_classification': 'provider'}]}

        reply = driver.get_network_function_device_config(device_data,
                nfp_constants.GENERIC_CONFIG)
        self.assertIsInstance(reply, dict, msg='')
        self.assertTrue('config' in reply)
