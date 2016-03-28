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

from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.lib import transport as transport
from gbpservice.nfp.proxy_agent.lib import topics


from oslo_log import helpers as log_helpers
import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)


def rpc_init(config, sc):
    """Register agent with its handler."""
    rpcmgr = RpcHandler(config, sc)
    agent = RpcAgent(
        sc,
        host=config.host,
        topic=topics.PROXY_AGENT_TOPIC,
        manager=rpcmgr)
    sc.register_rpc_agents([agent])


def nfp_module_init(sc, conf):
    """Initialize module to register rpc & event handler"""
    rpc_init(conf, sc)


class RpcHandler(object):
    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(RpcHandler, self).__init__()
        self._conf = conf
        self._sc = sc

    @log_helpers.log_method_call
    def create_network_function_config(self, context, body):
        """Method of rpc handler for create_network_function_config.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "CREATE")

    @log_helpers.log_method_call
    def delete_network_function_config(self, context, body):
        """Method of rpc handler for delete_network_function_config.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "DELETE")

    @log_helpers.log_method_call
    def update_network_function_config(self, context, body):
        """Method of rpc handler for delete_network_function_config.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "UPDATE")

    @log_helpers.log_method_call
    def create_network_function_device_config(self, context, body):
        """Method of rpc handler for create_network_function_device_config.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "CREATE",
                                               device_config=True)

    @log_helpers.log_method_call
    def delete_network_function_device_config(self, context, body):
        """Method of rpc handler for delete_network_function_device_config.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "DELETE",
                                               device_config=True)

    @log_helpers.log_method_call
    def network_function_event(self, context, body):
        """Method of rpc handler for create_service.
        Return: Http Response.
        """
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               "CREATE",
                                               network_function_event=True)
