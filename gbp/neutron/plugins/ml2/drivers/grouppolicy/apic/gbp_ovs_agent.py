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

import signal
import sys

from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import utils as q_utils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs
from neutron.plugins.openvswitch.common import config  # noqa
from oslo.config import cfg

from gbp.neutron.api.rpc.handlers import gbp_rpc
from gbp.neutron.services.grouppolicy.common import constants as g_const

LOG = logging.getLogger(__name__)


class GBPOvsPluginApi(agent_rpc.PluginApi, gbp_rpc.GBPServerRpcApiMixin):
    pass


class GBPOvsAgent(ovs.OVSNeutronAgent):

    def setup_rpc(self):
        super(GBPOvsAgent, self).setup_rpc()
        # Set GBP rpc API
        self.gbp_rpc = GBPOvsPluginApi(gbp_rpc.TOPIC_GBP)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):
        # TODO(ivar): This approach requires a large number of rpc calls,
        # needs to be done more efficiently. One way could be to override the
        # agent RPC handler to that "get_devices_details_list" calls both the
        # core plugin and GBP's
        mapping = self.gbp_rpc.get_gbp_details(self.context,
                                               self.agent_id,
                                               device=port.vif_id,
                                               host=cfg.CONF.host)
        if mapping:
            # Bind using a "per port" local vlan
            mapping['ofport'] = port.ofport
            network_type = mapping.get('network_type') or network_type
            super(GBPOvsAgent, self).port_bound(
                port, mapping['port_id'], network_type, physical_network,
                mapping, fixed_ips, device_owner, ovs_restarted)
        else:
            # Use the old path
            super(GBPOvsAgent, self).port_bound(port, net_uuid,
                                                network_type, physical_network,
                                                segmentation_id, fixed_ips,
                                                device_owner, ovs_restarted)

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
        if isinstance(segmentation_id, dict) and segmentation_id.get(
                g_const.DEVICE_OWNER_GP_POLICY_TARGET):
            # This is a GBP mapping
            gbp_mapping = segmentation_id
            segmentation_id = gbp_mapping['segmentation_id']
            # First, provision local vlan by port_id
            super(GBPOvsAgent, self).provision_local_vlan(
                gbp_mapping['port_id'], p_const.TYPE_LOCAL, physical_network,
                segmentation_id)
            # Then, set flows appropriate for GBP
            local = self.local_vlan_map.get(gbp_mapping['port_id']).vlan
            if gbp_mapping['network_type'] in [p_const.TYPE_VLAN]:
                if physical_network in self.phys_brs:
                    # to the outside world
                    br = self.phys_brs[physical_network]
                    br.add_flow(priority=5,
                                in_port=self.phys_ofports[physical_network],
                                dl_vlan=local,
                                actions="mod_vlan_vid:%s,output:%s" %
                                        (segmentation_id, br.uplink))
                    br.add_flow(priority=4, in_port='*',
                                dl_vlan=segmentation_id,
                                actions="output:%s" %
                                        self.phys_ofports[physical_network])
                    # from the outside world. Priority set to 5 to avoid match
                    # with DHCP port rule
                    self.int_br.add_flow(
                        priority=4, in_port=self.int_ofports[physical_network],
                        dl_vlan=segmentation_id,
                        dl_dst=gbp_mapping['mac_address'],
                        actions="strip_vlan,output:%s" % gbp_mapping['ofport'])
                    self.int_br.add_flow(
                        priority=4, in_port=gbp_mapping['ofport'],
                        actions="output:%s" %
                                self.int_ofports[physical_network])
                    # TODO(ivar): Broadcast.
                else:
                    LOG.error(_("Cannot provision VLAN network for "
                                "port-id=%(port_id)s - no bridge for "
                                "physical_network %(physical_network)s"),
                              {'port_id': gbp_mapping['port_id'],
                               'physical_network': physical_network})
        else:
            super(GBPOvsAgent, self).provision_local_vlan(
                net_uuid, network_type, physical_network, segmentation_id)

    def setup_physical_bridges(self, bridge_mappings):
        super(GBPOvsAgent, self).setup_physical_bridges(bridge_mappings)
        for br in self.phys_brs.itervalues():
            for port in br.get_port_name_list():
                # TODO(ivar) has to be configurable! Test Only
                if port.startswith('eth'):
                    br.uplink = br.get_port_ofport(port)
                    return


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = ovs.create_agent_config_map(cfg.CONF)
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