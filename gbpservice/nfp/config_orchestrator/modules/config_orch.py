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

from gbpservice.nfp.config_orchestrator.common import topics as a_topics
from gbpservice.nfp.config_orchestrator.handlers.config import (
    firewall as fw)
from gbpservice.nfp.config_orchestrator.handlers.config import (
    loadbalancer as lb)
from gbpservice.nfp.config_orchestrator.handlers.config import vpn
from gbpservice.nfp.config_orchestrator.handlers.notification import (
    handler as notif_handler)

from gbpservice.nfp.core.rpc import RpcAgent
from gbpservice.nfp.lib import transport
from neutron import context as n_context
from oslo_config import cfg
import time


def rpc_init(sc, conf):
    fwrpcmgr = fw.FwAgent(conf, sc)
    fwagent = RpcAgent(
        sc,
        host=cfg.CONF.host,
        topic=a_topics.FW_NFP_CONFIGAGENT_TOPIC,
        manager=fwrpcmgr
    )

    lb_report_state = {
        'binary': 'NCO',
        'host': cfg.CONF.host,
        'topic': a_topics.LB_NFP_CONFIGAGENT_TOPIC,
        'plugin_topic': a_topics.LB_NFP_PLUGIN_TOPIC,
        'agent_type': 'NFP Loadbalancer agent',
        'configurations': {'device_drivers': ['loadbalancer']},
        'start_flag': True,
        'report_interval': 10
    }
    lbrpcmgr = lb.LbAgent(conf, sc)
    lbagent = RpcAgent(
        sc,
        host=cfg.CONF.host,
        topic=a_topics.LB_NFP_CONFIGAGENT_TOPIC,
        manager=lbrpcmgr,
        report_state=lb_report_state
    )

    vpn_report_state = {
        'binary': 'NCO',
        'host': cfg.CONF.host,
        'topic': a_topics.VPN_NFP_CONFIGAGENT_TOPIC,
        'plugin_topic': a_topics.VPN_NFP_PLUGIN_TOPIC,
        'agent_type': 'NFP Vpn agent',
        'configurations': {'device_drivers': ['vpn']},
        'start_flag': True,
        'report_interval': 10
    }
    vpnrpcmgr = vpn.VpnAgent(conf, sc)
    vpnagent = RpcAgent(
        sc,
        host=cfg.CONF.host,
        topic=a_topics.VPN_NFP_CONFIGAGENT_TOPIC,
        manager=vpnrpcmgr,
        report_state=vpn_report_state
    )

    rpchandler = notif_handler.RpcHandler(conf, sc)
    rpcagent = RpcAgent(
        sc,
        host=cfg.CONF.host,
        topic=a_topics.CONFIG_ORCH_TOPIC,
        manager=rpchandler,
    )

    sc.register_rpc_agents([fwagent, lbagent, vpnagent, rpcagent])


def nfp_module_init(sc, conf):
    rpc_init(sc, conf)


def nfp_module_post_init(sc, conf):
    uptime = time.strftime("%c")
    body = {'eventdata': {'uptime': uptime,
                          'module': 'config_orchestrator'},
            'eventid': 'NFP_UP_TIME',
            'eventtype': 'NFP_CONTROLLER'}
    context = n_context.Context('config_agent_user', 'config_agent_tenant')
    transport.send_request_to_configurator(conf,
                                           context,
                                           body,
                                           'CREATE',
                                           network_function_event=True,
                                           override_backend='tcp_rest')
