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

import sys

import mock
sys.modules["apicapi"] = mock.Mock()

import contextlib
from gbpservice.neutron.plugins.ml2.drivers.grouppolicy.apic import \
    gbp_ovs_agent

from neutron.openstack.common import uuidutils
from neutron.tests import base
from oslo.config import cfg

_uuid = uuidutils.generate_uuid
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'


class TestGbpOvsAgent(base.BaseTestCase):

    def setUp(self):
        super(TestGbpOvsAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.agent = self._initialize_agent()
        self.agent.mapping_to_file = mock.Mock()
        self.agent.mapping_cleanup = mock.Mock()
        self.agent.apic_networks = ['phys_net']

    def _initialize_agent(self):
        kwargs = gbp_ovs_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('gbpservice.neutron.plugins.ml2.drivers.grouppolicy.'
                       'apic.gbp_ovs_agent.GBPOvsAgent.setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('gbpservice.neutron.plugins.ml2.drivers.grouppolicy.'
                       'apic.gbp_ovs_agent.GBPOvsAgent.'
                       'setup_ancillary_bridges',
                       return_value=[]),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_local_port_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.utils.get_interface_mac',
                       return_value='00:00:00:00:00:01'),
            mock.patch('neutron.agent.linux.ovs_lib.'
                       'get_bridges'),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            agent = gbp_ovs_agent.GBPOvsAgent(**kwargs)
            # set back to true because initial report state will succeed due
            # to mocked out RPC calls
            agent.use_call = True
            agent.tun_br = mock.Mock()
        agent.sg_agent = mock.Mock()
        return agent

    def _get_gbp_details(self, **kwargs):
        pattern = {'port_id': 'port_id',
                   'mac_address': 'aa:bb:cc:00:11:22',
                   'ptg_id': 'ptg_id',
                   'segmentation_id': None,
                   'network_type': None,
                   'l2_policy_id': 'l2p_id',
                   'tenant_id': 'tenant_id',
                   'host': 'host1',
                   'ptg_apic_tentant': 'apic_tenant',
                   'endpoint_group_name': 'epg_name',
                   'promiscuous_mode': False}
        pattern.update(**kwargs)
        return pattern

    def _port_bound_args(self, net_type='net_type'):
        return {'port': mock.Mock(),
                'net_uuid': 'net_id',
                'network_type': net_type,
                'physical_network': 'phys_net',
                'segmentation_id': 1000,
                'fixed_ips': [{'subnet_id': 'id1',
                               'ip_address': '192.168.0.2'},
                              {'subnet_id': 'id2',
                               'ip_address': '192.168.1.2'}],
                'device_owner': 'compute:',
                'ovs_restarted': True}

    def test_port_bound(self):
        self.agent.int_br = mock.Mock()
        self.agent.gbp_rpc.get_gbp_details = mock.Mock()
        mapping = self._get_gbp_details()
        self.agent.gbp_rpc.get_gbp_details.return_value = mapping
        self.agent.provision_local_vlan = mock.Mock()
        args = self._port_bound_args('apic')
        args['port'].gbp_details = mapping
        self.agent.port_bound(**args)
        self.agent.int_br.clear_db_attribute.assert_called_with(
            "Port", mock.ANY, "tag")
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.agent.mapping_to_file.assert_called_with(
            args['port'], mapping, ['192.168.0.2', '192.168.1.2'])

    def test_port_bound_no_mapping(self):
        self.agent.int_br = mock.Mock()
        self.agent.gbp_rpc.get_gbp_details = mock.Mock()
        self.agent.gbp_rpc.get_gbp_details.return_value = None
        self.agent.provision_local_vlan = mock.Mock()
        args = self._port_bound_args('apic')
        args['port'].gbp_details = None
        self.agent.port_bound(**args)
        self.assertFalse(self.agent.int_br.set_db_attribute.called)
        self.assertFalse(self.agent.provision_local_vlan.called)
        self.assertFalse(self.agent.mapping_to_file.called)
