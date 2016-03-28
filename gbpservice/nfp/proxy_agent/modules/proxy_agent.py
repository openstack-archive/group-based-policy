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

from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.proxy_agent.lib import RestClientOverUnix as rc
from gbpservice.nfp.proxy_agent.lib import topics

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging

LOGGER = logging.getLogger(__name__)
LOG = nfp_common.log


def rpc_init(config, sc):
    """Register agent with its handler."""
    rpcmgr = RpcHandler(config, sc)
    agent = RpcAgent(
        sc,
        host=config.host,
        topic=topics.CONFIG_AGENT_PROXY,
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
        try:
            resp, content = rc.post(
                'create_network_function_config', body=body)
            LOG(LOGGER, 'INFO',
                "create_network_function_config ->"
                "POST response: (%s)" % (content))

        except rc.RestClientException as rce:
            LOG(LOGGER, 'ERROR',
                "create_firewall -> POST request failed.Reason: %s" % (
                    rce))

    @log_helpers.log_method_call
    def delete_network_function_config(self, context, body):
        """Method of rpc handler for delete_network_function_config.
        Return: Http Response.
        """
        try:
            resp, content = rc.post('delete_network_function_config',
                                    body=body, delete=True)
            LOG(LOGGER, 'INFO',
                "delete_network_function_config -> POST response: (%s)"
                % (content))

        except rc.RestClientException as rce:
            LOG(LOGGER, 'ERROR',
                "delete_firewall -> DELETE request failed.Reason: %s" % (
                    rce))

    @log_helpers.log_method_call
    def create_network_function_device_config(self, context, body):
        """Method of rpc handler for create_network_function_device_config.
        Return: Http Response.
        """
        try:
            resp, content = rc.post('create_network_function_device_config',
                                    body=body)
            LOG(LOGGER, 'INFO',
                "create_network_function_device_config ->"
                "POST response: (%s)" % (content))

        except rc.RestClientException as rce:
            LOG(LOGGER, 'ERROR',
                "create_network_function_device_config ->"
                "request failed . Reason %s " % (rce))

    @log_helpers.log_method_call
    def delete_network_function_device_config(self, context, body):
        """Method of rpc handler for delete_network_function_device_config.
        Return: Http Response.
        """
        try:
            resp, content = rc.post('delete_network_function_device_config',
                                    body=body, delete=True)
            LOG(LOGGER, 'INFO',
                "delete_network_function_device_config ->"
                "POST response: (%s)" % (content))

        except rc.RestClientException as rce:
            LOG(LOGGER, 'ERROR',
                "delete_network_function_device_config ->"
                "request failed.Reason %s " % (rce))
