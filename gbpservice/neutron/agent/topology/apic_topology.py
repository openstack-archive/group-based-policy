# Copyright (c) 2014 Cisco Systems Inc.
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

import re
import sys

import eventlet

eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import periodic_task
from oslo_service import service as svc

from neutron.agent.common import config
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import config as common_cfg
from neutron.common import utils as neutron_utils
from neutron import manager
from neutron import service

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice.neutron.agent.topology import rpc as arpc

ACI_CHASSIS_DESCR_FORMAT = 'topology/pod-1/node-(\d+)'
ACI_PORT_DESCR_FORMATS = [
    'topology/pod-1/node-(\d+)/sys/conng/path-\[eth(\d+)/(\d+(\/\d+)*)\]',
    'topology/pod-1/paths-(\d+)/pathep-\[eth(\d+)/(\d+(\/\d+)*)\]',
]
ACI_PORT_LOCAL_FORMAT = 'Eth(\d+)/(\d+(\/\d+)*)'
ACI_VPCPORT_DESCR_FORMAT = ('topology/pod-1/protpaths-(\d+)-(\d+)/pathep-'
                            '\[(.*)\]')

AGENT_FORCE_UPDATE_COUNT = 5
BINARY_APIC_HOST_AGENT = 'neutron-cisco-apic-host-agent'
TYPE_APIC_HOST_AGENT = 'cisco-apic-host-agent'
VPCMODULE_NAME = 'vpc-%s-%s'


LOG = logging.getLogger(__name__)

apic_opts = [
    cfg.ListOpt('apic_host_uplink_ports',
                default=[],
                help=_('The uplink ports to check for ACI connectivity')),
    cfg.FloatOpt('apic_agent_poll_interval',
                 default=60,
                 help=_('Interval between agent poll for topology (in sec)')),
    cfg.FloatOpt('apic_agent_report_interval',
                 default=60,
                 help=_('Interval between agent status updates (in sec)')),
]

cfg.CONF.register_opts(apic_opts, "ml2_cisco_apic")


class ApicTopologyAgent(manager.Manager):
    def __init__(self, host=None):
        if host is None:
            host = neutron_utils.get_hostname()
        super(ApicTopologyAgent, self).__init__(host=host)

        self.conf = cfg.CONF.ml2_cisco_apic
        self.count_current = 0
        self.count_force_send = AGENT_FORCE_UPDATE_COUNT
        self.interfaces = {}
        self.lldpcmd = None
        self.peers = {}
        self.port_desc_re = map(re.compile, ACI_PORT_DESCR_FORMATS)
        self.port_local_re = re.compile(ACI_PORT_LOCAL_FORMAT)
        self.vpcport_desc_re = re.compile(ACI_VPCPORT_DESCR_FORMAT)
        self.chassis_desc_re = re.compile(ACI_CHASSIS_DESCR_FORMAT)
        self.service_agent = arpc.ApicTopologyServiceNotifierApi()
        self.state = None
        self.state_agent = None
        self.topic = arpc.TOPIC_APIC_SERVICE
        self.uplink_ports = []
        self.invalid_peers = []

    def init_host(self):
        LOG.info(_LI("APIC host agent: agent starting on %s"), self.host)
        self.state = {
            'binary': BINARY_APIC_HOST_AGENT,
            'host': self.host,
            'topic': self.topic,
            'configurations': {},
            'start_flag': True,
            'agent_type': TYPE_APIC_HOST_AGENT,
        }

        self.uplink_ports = []
        for inf in self.conf.apic_host_uplink_ports:
            if ip_lib.device_exists(inf):
                self.uplink_ports.append(inf)
            else:
                # ignore unknown interfaces
                LOG.error(_LE("No such interface (ignored): %s"), inf)
        self.lldpcmd = ['lldpctl', '-f', 'keyvalue'] + self.uplink_ports

    def after_start(self):
        LOG.info(_LI("APIC host agent: started on %s"), self.host)

    @periodic_task.periodic_task(
        spacing=cfg.CONF.ml2_cisco_apic.apic_agent_poll_interval,
        run_immediately=True)
    def _check_for_new_peers(self, context):
        LOG.debug("APIC host agent: _check_for_new_peers")

        if not self.lldpcmd:
            return
        try:
            # Check if we must send update even if there is no change
            force_send = False
            self.count_current += 1
            if self.count_current >= self.count_force_send:
                force_send = True
                self.count_current = 0

            # Check for new peers
            new_peers = self._get_peers()
            new_peers = self._valid_peers(new_peers)

            # Make a copy of current interfaces
            curr_peers = {}
            for interface in self.peers:
                curr_peers[interface] = self.peers[interface]
            # Based curr -> new updates, add the new interfaces
            self.peers = {}
            for interface in new_peers:
                peer = new_peers[interface]
                self.peers[interface] = peer
                if (interface in curr_peers and
                        curr_peers[interface] != peer):
                    LOG.debug('reporting peer removal: %s', peer)
                    self.service_agent.update_link(
                        context, peer[0], peer[1], None, 0, 0, 0, '')
                if (interface not in curr_peers or
                        curr_peers[interface] != peer or
                        force_send):
                    LOG.debug('reporting new peer: %s', peer)
                    self.service_agent.update_link(context, *peer)
                if interface in curr_peers:
                    curr_peers.pop(interface)

            # Any interface still in curr_peers need to be deleted
            for peer in curr_peers.values():
                LOG.debug('reporting peer removal: %s', peer)
                self.service_agent.update_link(
                    context, peer[0], peer[1], None, 0, 0, 0, '')

        except Exception:
            LOG.exception(_LE("APIC service agent: exception in LLDP parsing"))

    def _get_peers(self):
        interfaces = {}
        peers = {}
        lldpkeys = utils.execute(self.lldpcmd, run_as_root=True)
        for line in lldpkeys.splitlines():
            if '=' not in line:
                continue
            fqkey, value = line.split('=', 1)
            lldp, interface, key = fqkey.split('.', 2)
            if lldp == 'lldp':
                if interface not in interfaces:
                    interfaces[interface] = {}
                interfaces[interface][key] = value

        for interface in interfaces:
            if 'port.descr' in interfaces[interface]:
                value = interfaces[interface]['port.descr']
                port_desc = value
                for regexp in self.port_desc_re:
                    match = regexp.match(value)
                    if match:
                        mac = self._get_mac(interface)
                        switch, module, port = match.group(1, 2, 3)
                        peer = (self.host, interface, mac,
                                switch, module, port, port_desc)
                        if interface not in peers:
                            peers[interface] = []
                        peers[interface].append(peer)
                match = self.vpcport_desc_re.match(value)
                if match:
                    mac = self._get_mac(interface)
                    switch1, switch2, bundle = match.group(1, 2, 3)
                    switch, module, port = None, None, None
                    if (bundle is not None and
                            'chassis.descr' in interfaces[interface]):
                        value = interfaces[interface]['chassis.descr']
                        match = self.chassis_desc_re.match(value)
                        if match:
                            switch = match.group(1)
                        if (switch is not None and
                                'port.local' in interfaces[interface]):
                            value = interfaces[interface]['port.local']
                            match = self.port_local_re.match(value)
                            if match:
                                module, port = match.group(1, 2)
                            if module is not None and port is not None:
                                vpcmodule = VPCMODULE_NAME % (module, port)
                                peer = (self.host, interface, mac,
                                        switch, vpcmodule, bundle, port_desc)
                                if interface not in peers:
                                    peers[interface] = []
                                peers[interface].append(peer)

        return peers

    def _valid_peers(self, peers):
        # Reduce the peers array to one valid peer per interface
        # NOTE:
        # There is a bug in lldpd daemon that it keeps reporting
        # old peers even after their updates have stopped
        # we keep track of that report remove them from peers

        valid_peers = {}
        invalid_peers = []
        for interface in peers:
            curr_peer = None
            for peer in peers[interface]:
                if peer in self.invalid_peers or curr_peer:
                    invalid_peers.append(peer)
                else:
                    curr_peer = peer
            if curr_peer is not None:
                valid_peers[interface] = curr_peer

        self.invalid_peers = invalid_peers
        return valid_peers

    def _get_mac(self, interface):
        if interface in self.interfaces:
            return self.interfaces[interface]
        try:
            mac = ip_lib.IPDevice(interface).link.address
            self.interfaces[interface] = mac
            return mac
        except Exception:
            # we can safely ignore it, it is only needed for debugging
            LOG.exception(
                _LE("APIC service agent: can not get MACaddr for %s"),
                interface)

    def report_send(self, context):
        if not self.state_agent:
            return
        LOG.debug("APIC host agent: sending report state")

        try:
            self.state_agent.report_state(context, self.state)
            self.state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            # ignore it
            return
        except Exception:
            LOG.exception(_LE("APIC host agent: failed in reporting state"))


def launch(binary, manager, topic=None):
    cfg.CONF(project='neutron')
    common_cfg.init(sys.argv[1:])
    config.setup_logging()
    report_period = cfg.CONF.ml2_cisco_apic.apic_agent_report_interval
    poll_period = cfg.CONF.ml2_cisco_apic.apic_agent_poll_interval
    server = service.Service.create(
        binary=binary, manager=manager, topic=topic,
        report_interval=report_period, periodic_interval=poll_period)
    svc.launch(cfg.CONF, server).wait()


def agent_main():
    launch(
        BINARY_APIC_HOST_AGENT,
        'gbpservice.neutron.agent.topology.' +
        'apic_topology.ApicTopologyAgent')
