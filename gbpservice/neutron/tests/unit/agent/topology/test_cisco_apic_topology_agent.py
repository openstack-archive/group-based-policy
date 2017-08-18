# Copyright (c) 2017 Cisco Systems
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

import mock

from oslo_config import cfg

from neutron.tests import base

from gbpservice.neutron.agent.topology import apic_topology


PERIODIC_TASK = 'oslo_service.periodic_task'
DEV_EXISTS = 'neutron.agent.linux.ip_lib.device_exists'
IP_DEVICE = 'neutron.agent.linux.ip_lib.IPDevice'
EXECUTE = 'neutron.agent.linux.utils.execute'

LLDP_CMD = ['lldpctl', '-f', 'keyvalue']

APIC_EXT_SWITCH = '203'
APIC_EXT_MODULE = '1'
APIC_EXT_PORT = '34'

APIC_UPLINK_PORTS = ['uplink_port']

SERVICE_HOST = 'host1'
SERVICE_HOST_IFACE = 'eth0'
SERVICE_HOST_MAC = 'aa:ee:ii:oo:uu:yy'

SERVICE_PEER_CHASSIS_NAME = 'leaf4'
SERVICE_PEER_CHASSIS = 'topology/pod-1/node-' + APIC_EXT_SWITCH
SERVICE_PEER_PORT_LOCAL = 'Eth%s/%s' % (APIC_EXT_MODULE, APIC_EXT_PORT)
SERVICE_PEER_PORT_DESC = ('topology/pod-1/paths-%s/pathep-[%s]' %
                          (APIC_EXT_SWITCH, SERVICE_PEER_PORT_LOCAL.lower()))
ETH0 = SERVICE_HOST_IFACE

LLDPCTL_RES = (
    'lldp.' + ETH0 + '.via=LLDP\n'
    'lldp.' + ETH0 + '.rid=1\n'
    'lldp.' + ETH0 + '.age=0 day, 20:55:54\n'
    'lldp.' + ETH0 + '.chassis.mac=' + SERVICE_HOST_MAC + '\n'
    'lldp.' + ETH0 + '.chassis.name=' + SERVICE_PEER_CHASSIS_NAME + '\n'
    'lldp.' + ETH0 + '.chassis.descr=' + SERVICE_PEER_CHASSIS + '\n'
    'lldp.' + ETH0 + '.chassis.Bridge.enabled=on\n'
    'lldp.' + ETH0 + '.chassis.Router.enabled=on\n'
    'lldp.' + ETH0 + '.port.local=' + SERVICE_PEER_PORT_LOCAL + '\n'
    'lldp.' + ETH0 + '.port.descr=' + SERVICE_PEER_PORT_DESC)


class TestCiscoApicTopologyAgent(base.BaseTestCase):

        def setUp(self):
            super(TestCiscoApicTopologyAgent, self).setUp()
            # Configure the Cisco APIC mechanism driver
            cfg.CONF.set_override('apic_host_uplink_ports',
                                  APIC_UPLINK_PORTS, 'ml2_cisco_apic')
            # Patch device_exists
            self.dev_exists = mock.patch(DEV_EXISTS).start()
            # Patch IPDevice
            ipdev_c = mock.patch(IP_DEVICE).start()
            self.ipdev = mock.Mock()
            ipdev_c.return_value = self.ipdev
            self.ipdev.link.address = SERVICE_HOST_MAC
            # Patch execute
            self.execute = mock.patch(EXECUTE).start()
            self.execute.return_value = LLDPCTL_RES
            # Patch tasks
            self.periodic_task = mock.patch(PERIODIC_TASK).start()
            self.agent = apic_topology.ApicTopologyAgent()
            self.agent.host = SERVICE_HOST
            self.agent.service_agent = mock.Mock()
            self.agent.lldpcmd = LLDP_CMD

        def test_init_host_device_exists(self):
            self.agent.lldpcmd = None
            self.dev_exists.return_value = True
            self.agent.init_host()
            self.assertEqual(LLDP_CMD + APIC_UPLINK_PORTS,
                             self.agent.lldpcmd)

        def test_init_host_device_not_exist(self):
            self.agent.lldpcmd = None
            self.dev_exists.return_value = False
            self.agent.init_host()
            self.assertEqual(LLDP_CMD, self.agent.lldpcmd)

        def test_get_peers(self):
            self.agent.peers = {}
            peers = self.agent._get_peers()
            expected = [(SERVICE_HOST, SERVICE_HOST_IFACE,
                         SERVICE_HOST_MAC, APIC_EXT_SWITCH,
                         APIC_EXT_MODULE, APIC_EXT_PORT,
                         SERVICE_PEER_PORT_DESC)]
            self.assertEqual(expected,
                             peers[SERVICE_HOST_IFACE])

        def test_check_for_new_peers_no_peers(self):
            self.agent.peers = {}
            expected = (SERVICE_HOST, SERVICE_HOST_IFACE,
                        SERVICE_HOST_MAC, APIC_EXT_SWITCH,
                        APIC_EXT_MODULE, APIC_EXT_PORT,
                        SERVICE_PEER_PORT_DESC)
            peers = {SERVICE_HOST_IFACE: [expected]}
            context = mock.Mock()
            with mock.patch.object(self.agent, '_get_peers',
                                   return_value=peers):
                self.agent._check_for_new_peers(context)
                self.assertEqual(expected,
                                 self.agent.peers[SERVICE_HOST_IFACE])
                self.agent.service_agent.update_link.assert_called_once_with(
                    context, *expected)

        def test_check_for_new_peers_with_peers(self):
            expected = (SERVICE_HOST, SERVICE_HOST_IFACE,
                        SERVICE_HOST_MAC, APIC_EXT_SWITCH,
                        APIC_EXT_MODULE, APIC_EXT_PORT,
                        SERVICE_PEER_PORT_DESC)
            peers = {SERVICE_HOST_IFACE: [expected]}
            self.agent.peers = {SERVICE_HOST_IFACE:
                                [tuple(x + '1' for x in expected)]}
            context = mock.Mock()
            with mock.patch.object(self.agent, '_get_peers',
                                   return_value=peers):
                self.agent._check_for_new_peers(context)
                self.agent.service_agent.update_link.assert_called_with(
                    context, *expected)
