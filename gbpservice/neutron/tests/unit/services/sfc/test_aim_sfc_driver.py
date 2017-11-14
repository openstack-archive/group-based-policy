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

from networking_sfc.extensions import flowclassifier as flowc_ext
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.services.flowclassifier.common import (
    config as flc_cfg)  # noqa
from networking_sfc.services.sfc.common import (
    config as sfc_cfg)  # noqa
from neutron import manager

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver as test_aim_base)


class TestAIMServiceFunctionChainingBase(test_aim_base.AIMBaseTestCase):

    def setUp(self, *args, **kwargs):
        config.cfg.CONF.set_override('drivers', ['aim'], group='sfc')
        config.cfg.CONF.set_override('drivers', ['aim'],
                                     group='flowclassifier')
        super(TestAIMServiceFunctionChainingBase, self).setUp(*args, **kwargs)
        self._sfc_driver = None
        self._flowc_driver = None
        self._sfc_plugin = None
        self._flowc_plugin = None

    @property
    def sfc_plugin(self):
        if not self._sfc_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._sfc_plugin = plugins.get(sfc_ext.SFC_EXT)
        return self._sfc_plugin

    @property
    def flowc_plugin(self):
        if not self._flowc_plugin:
            plugins = manager.NeutronManager.get_service_plugins()
            self._flowc_plugin = plugins.get(flowc_ext.FLOW_CLASSIFIER_EXT)
        return self._flowc_plugin

    @property
    def sfc_driver(self):
        # aim_mapping policy driver reference
        if not self._sfc_driver:
            self._sfc_driver = (
                self.sfc_plugin.driver_manager.drivers['aim'].obj)
        return self._sfc_driver

    @property
    def flowc_driver(self):
        # aim_mapping policy driver reference
        if not self._flowc_driver:
            self._flowc_driver = (
                self.flowc_plugin.driver_manager.drivers['aim'].obj)
        return self._flowc_driver


class TestPortPair(TestAIMServiceFunctionChainingBase):

    def test_port_pair_validation(self):
        net1 = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net1, '192.168.0.1', '192.168.0.0/24')
        p1 = self._make_port(self.fmt, net1['network']['id'])['port']

        net2 = self._make_network(self.fmt, 'net2', True)
        self._make_subnet(self.fmt, net1, '192.168.1.1', '192.168.1.0/24')
        p2 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p1['id'], 'h1')
        self._bind_port_to_host(p2['id'], 'h2')
        self.create_port_pair(ingress=p1['id'], egress=p2['id'],
                              expected_res_status=201)
        # Same network ports
        p3 = self._make_port(self.fmt, net2['network']['id'])['port']
        p4 = self._make_port(self.fmt, net2['network']['id'])['port']
        self._bind_port_to_host(p3['id'], 'h1')
        self._bind_port_to_host(p4['id'], 'h2')
        self.create_port_pair(ingress=p3['id'], egress=p4['id'],
                              expected_res_status=500)
        # Also unbound ports can be used
        p5 = self._make_port(self.fmt, net1['network']['id'])['port']
        self.create_port_pair(ingress=p3['id'], egress=p5['id'],
                              expected_res_status=400)
