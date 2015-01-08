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
from gbpservice.neutron.api.rpc.handlers import gbp_rpc

LOG = logging.getLogger(__name__)

gbp_opts = [
    cfg.BoolOpt('hybrid_mode',
                default=False,
                help=_("Whether Neutron's ports can coexist with GBP owned"
                       "ports.")),
    cfg.StrOpt('epg_mapping_dir',
               default='/var/lib/opflex-agent-ovs/endpoints/',
               help=_("Directory where the EPG port mappings will be stored"))
]
cfg.CONF.register_opts(gbp_opts, "OPFLEX")

FILE_NAME_FORMAT = "%s.ep"


class GBPOvsPluginApi(gbp_rpc.GBPServerRpcApiMixin):
    pass


class GBPOvsAgent(ovs.OVSNeutronAgent):

    def __init__(self, **kwargs):
        self.hybrid_mode = kwargs['hybrid_mode']
        separator = (kwargs['epg_mapping_dir'][-1] if
                     kwargs['epg_mapping_dir'] else '')
        self.epg_mapping_file = (kwargs['epg_mapping_dir'] +
                                 ('/' if separator != '/' else '') +
                                 FILE_NAME_FORMAT)
        del kwargs['hybrid_mode']
        del kwargs['epg_mapping_dir']
        super(GBPOvsAgent, self).__init__(**kwargs)

    def setup_rpc(self):
        self.agent_state['agent_type'] = gbpcst.AGENT_TYPE_APIC_OVS
        super(GBPOvsAgent, self).setup_rpc()
        # Set GBP rpc API
        self.gbp_rpc = GBPOvsPluginApi(gbp_rpc.TOPIC_GBP)

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
        # TODO(ivar): This approach requires a large number of rpc calls,
        # needs to be done more efficiently. One way could be to override the
        # agent RPC handler so that "get_devices_details_list" calls both the
        # core plugin and GBP's
        mapping = self.gbp_rpc.get_gbp_details(self.context,
                                               self.agent_id,
                                               device=port.vif_id,
                                               host=cfg.CONF.host)
        if not mapping:
            self.mapping_cleanup(port.vif_id)
            if self.hybrid_mode:
                super(GBPOvsAgent, self).port_bound(
                    port, net_uuid, network_type, physical_network,
                    segmentation_id, fixed_ips, device_owner, ovs_restarted)
        else:
            # Port has to be untagged due to a opflex agent requirement
            self.int_br.clear_db_attribute("Port", port.port_name, "tag")
            self.mapping_to_file(port, mapping, [x['ip_address'] for x in
                                                 fixed_ips])

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
        os.remove(self.epg_mapping_file % vif_id)

    # TODO(ivar): port update RPC call tells the agent that a specific port has
    # to be revisited. Useful for EPG changes!


def create_agent_config_map(conf):
    agent_config = ovs.create_agent_config_map(conf)
    agent_config['hybrid_mode'] = conf.OPFLEX.hybrid_mode
    agent_config['epg_mapping_dir'] = conf.OPFLEX.epg_mapping_dir
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