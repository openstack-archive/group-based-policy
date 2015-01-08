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

from apicapi import apic_manager
from neutron.common import constants as n_constants
from neutron.common import log
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

TOPIC_GBP = 'gbp'


class AgentNotifierApi(n_rpc.RpcProxy):

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_port_update = topics.get_topic_name(topic, topics.PORT,
                                                       topics.UPDATE)

    def port_update(self, context, port):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port),
                         topic=self.topic_port_update)


class GBPServerRpcApiMixin(n_rpc.RpcProxy):
    """Agent-side RPC (stub) for agent-to-plugin interaction."""

    GBP_RPC_VERSION = "1.0"

    def __init__(self, topic):
        super(GBPServerRpcApiMixin, self).__init__(
            topic=topic, default_version=self.GBP_RPC_VERSION)

    @log.log
    def get_gbp_details(self, context, agent_id, device=None, host=None):
        return self.call(context,
                         self.make_msg('get_gbp_details',
                                       agent_id=agent_id,
                                       device=device,
                                       host=host),
                         version=self.GBP_RPC_VERSION)

    @log.log
    def get_gbp_details_list(self, context, agent_id, devices=None, host=None):
        return self.call(context,
                         self.make_msg('get_gbp_details_list',
                                       agent_id=agent_id,
                                       devices=devices,
                                       host=host),
                         version=self.GBP_RPC_VERSION)


class GBPServerRpcCallback(n_rpc.RpcCallback):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction."""

    # History
    #   1.0 Initial version

    RPC_API_VERSION = "1.0"

    def __init__(self, gbp_driver):
        super(GBPServerRpcCallback, self).__init__()
        self.gbp_driver = gbp_driver

    def get_gbp_details(self, context, **kwargs):
        port_id = self.gbp_driver._core_plugin._device_to_port_id(
            kwargs['device'])
        port_context = self.gbp_driver._core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return
        port = port_context.current
        # retrieve PTG from a given Port
        ptg = self.gbp_driver._port_id_to_ptg(context, port['id'])
        if not ptg:
            return

        context._plugin = self.gbp_driver.gbp_plugin
        context._plugin_context = context

        def is_port_promiscuous(port):
            return port['device_owner'] == n_constants.DEVICE_OWNER_DHCP

        segment = port_context.bound_segment or {}
        return {'device': kwargs.get('device'),
                'port_id': port_id,
                'mac_address': port['mac_address'],
                'ptg_id': ptg['id'],
                'segment': segment,
                'segmentation_id': segment.get('segmentation_id'),
                'network_type': segment.get('network_type'),
                'l2_policy_id': ptg['l2_policy_id'],
                'tenant_id': port['tenant_id'],
                'host': port[portbindings.HOST_ID],
                'ptg_apic_tentant': str(
                    self.gbp_driver.name_mapper.tenant(
                        context, ptg['tenant_id'])
                    if not ptg['shared'] else apic_manager.TENANT_COMMON),
                'endpoint_group_name': str(
                    self.gbp_driver.name_mapper.policy_target_group(
                        context, ptg['id'])),
                'promiscuous_mode': is_port_promiscuous(port)}

    def get_gbp_details_list(self, context, **kwargs):
        return [
            self.get_gbp_details(
                context,
                device=device,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]