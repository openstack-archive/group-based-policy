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

import os
import signal
import sys

from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common import utils as q_utils
from neutron.openstack.common import log as logging
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs
from neutron.plugins.openvswitch.common import config  # noqa
from neutron.plugins.openvswitch.common import constants
from oslo.config import cfg
from oslo.serialization import jsonutils

from gbpservice.common import constants as gbpcst
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import rpc

LOG = logging.getLogger(__name__)

gbp_opts = [
    cfg.BoolOpt('hybrid_mode',
                default=False,
                help=_("Whether Neutron's ports can coexist with GBP owned"
                       "ports.")),
    cfg.StrOpt('epg_mapping_dir',
               default='/var/lib/opflex-agent-ovs/endpoints/',
               help=_("Directory where the EPG port mappings will be "
                      "stored.")),
    cfg.ListOpt('apic_networks',
                default=[],
                help=_("List of the physical networks managed by this agent. "
                       "Use * for binding any apic network to this agent"))
]
cfg.CONF.register_opts(gbp_opts, "OPFLEX")

FILE_NAME_FORMAT = "%s.ep"


class GBPOvsPluginApi(rpc.GBPServerRpcApiMixin):
    pass


class GBPOvsAgent(ovs.OVSNeutronAgent):

    def __init__(self, **kwargs):
        self.hybrid_mode = kwargs['hybrid_mode']
        separator = (kwargs['epg_mapping_dir'][-1] if
                     kwargs['epg_mapping_dir'] else '')
        self.epg_mapping_file = (kwargs['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 FILE_NAME_FORMAT)
        self.apic_networks = kwargs['apic_networks']
        if self.apic_networks and self.apic_networks[0] == '*':
            self.apic_networks = None
        del kwargs['hybrid_mode']
        del kwargs['epg_mapping_dir']
        del kwargs['apic_networks']
        super(GBPOvsAgent, self).__init__(**kwargs)
        self.supported_pt_network_types = [gbpcst.TYPE_APIC]

    def setup_rpc(self):
        self.agent_state['agent_type'] = gbpcst.AGENT_TYPE_APIC_OVS
        self.agent_state['configurations']['apic_networks'] = (
            self.apic_networks)
        super(GBPOvsAgent, self).setup_rpc()
        # Set GBP rpc API
        self.gbp_rpc = GBPOvsPluginApi(rpc.TOPIC_GBP)

    def setup_integration_br(self):
        """Override parent setup integration bridge.

        The opflex agent controls all the flows in the integration bridge,
        therefore we have to make sure the parent doesn't reset them.
        """
        self.int_br.create()
        self.int_br.set_secure_mode()

        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        # The following is executed in the parent method:
        # self.int_br.remove_all_flows()

        if self.hybrid_mode:
            # switch all traffic using L2 learning
            self.int_br.add_flow(priority=1, actions="normal")
        # Add a canary flow to int_br to track OVS restarts
        self.int_br.add_flow(table=constants.CANARY_TABLE, priority=0,
                             actions="drop")

    def setup_physical_bridges(self, bridge_mappings):
        """Override parent setup physical bridges.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        if self.hybrid_mode:
            super(GBPOvsAgent, self).setup_physical_bridges(bridge_mappings)

    def reset_tunnel_br(self, tun_br_name=None):
        """Override parent reset tunnel br.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        if self.hybrid_mode:
            super(GBPOvsAgent, self).reset_tunnel_br(tun_br_name)

    def setup_tunnel_br(self, tun_br_name=None):
        """Override parent setup tunnel br.

        Only needs to be executed in hybrid mode. If not in hybrid mode, only
        the existence of the integration bridge is assumed.
        """
        if self.hybrid_mode:
            super(GBPOvsAgent, self).setup_tunnel_br(tun_br_name)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):

        mapping = port.gbp_details
        if not mapping:
            self.mapping_cleanup(port.vif_id)
            if self.hybrid_mode:
                super(GBPOvsAgent, self).port_bound(
                    port, net_uuid, network_type, physical_network,
                    segmentation_id, fixed_ips, device_owner, ovs_restarted)
        elif network_type in self.supported_pt_network_types:
            if ((self.apic_networks is None) or
                    (physical_network in self.apic_networks)):
                # Port has to be untagged due to a opflex agent requirement
                self.int_br.clear_db_attribute("Port", port.port_name, "tag")
                self.mapping_to_file(port, mapping, [x['ip_address'] for x in
                                                     fixed_ips])
            else:
                LOG.error(_("Cannot provision APIC network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        else:
            LOG.error(_("Network type %(net_type)s not supported for "
                        "Policy Target provisioning. Supported types: "
                        "%(supported)s"),
                      {'net_type': network_type,
                       'supported': self.supported_pt_network_types})

    def port_unbound(self, vif_id, net_uuid=None):
        super(GBPOvsAgent, self).port_unbound(vif_id, net_uuid)
        # Delete epg mapping file
        self.mapping_cleanup(vif_id)

    def mapping_to_file(self, port, mapping, ips):
        """Mapping to file.

        Converts the port mapping into file.
        """
        mapping_dict = {
            "policy-space-name": mapping['ptg_apic_tentant'],
            "endpoint-group-name": mapping['endpoint_group_name'],
            "interface-name": port.port_name,
            "ip": ips,
            "mac": port.vif_mac,
            "uuid": port.vif_id,
            "promiscuous-mode": mapping['promiscuous_mode']}
        filename = self.epg_mapping_file % port.vif_id
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'w') as f:
            jsonutils.dump(mapping_dict, f)

    def mapping_cleanup(self, vif_id):
        try:
            os.remove(self.epg_mapping_file % vif_id)
        except OSError:
            pass

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        # REVISIT(ivar): This method is copied from parent in order to inject
        # an efficient way to request GBP details. This is needed because today
        # ML2 RPC doesn't allow drivers to add custom information to the device
        # details list.

        skipped_devices = []
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                cfg.CONF.host)
            devices_gbp_details_list = self.gbp_rpc.get_gbp_details_list(
                self.context, self.agent_id, devices, cfg.CONF.host)
            # Correlate port details
            gbp_details_per_device = {x['device']: x for x in
                                      devices_gbp_details_list if x}
        except Exception as e:
            raise ovs.DeviceListRetrievalError(devices=devices, error=e)
        for details in devices_details_list:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                # Inject GBP details
                port.gbp_details = gbp_details_per_device.get(
                    details['device'], {})
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    details['fixed_ips'],
                                    details['device_owner'],
                                    ovs_restarted)
                # update plugin about port status
                # FIXME(salv-orlando): Failures while updating device status
                # must be handled appropriately. Otherwise this might prevent
                # neutron server from sending network-vif-* events to the nova
                # API server, thus possibly preventing instance spawn.
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices


def create_agent_config_map(conf):
    agent_config = ovs.create_agent_config_map(conf)
    agent_config['hybrid_mode'] = conf.OPFLEX.hybrid_mode
    agent_config['epg_mapping_dir'] = conf.OPFLEX.epg_mapping_dir
    agent_config['apic_networks'] = conf.OPFLEX.apic_networks
    # DVR not supported
    agent_config['enable_distributed_routing'] = False
    # ARP responder not supported
    agent_config['arp_responder'] = False
    return agent_config


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in agent_config['root_helper']
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)
    agent = GBPOvsAgent(**agent_config)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == "__main__":
    main()