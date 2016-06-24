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
import traceback

from gbpservice.contrib.nfp.config_orchestrator.common import (
    lbv2_constants as lbv2_const)
from gbpservice.contrib.nfp.config_orchestrator.common import (
    topics as a_topics)
from gbpservice.nfp.common import constants as const
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import transport

import oslo_messaging as messaging


LOG = nfp_logging.getLogger(__name__)


class RpcHandler(object):
    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(RpcHandler, self).__init__()
        self.conf = conf
        self.sc = sc

    def network_function_notification(self, context, notification_data):
        try:
            if notification_data['info']['service_type'] is not None:
                handler = NaasNotificationHandler(self.conf, self.sc)
                handler.\
                    handle_notification(context, notification_data)
            else:
                # Handle Event
                request_data = {'context': context.to_dict(),
                                'notification_data': notification_data
                                }
                event = self.sc.new_event(id='OTC_EVENT',
                                          key='OTC_EVENT',
                                          data=request_data)
                self.sc.post_event(event)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            msg = ("Generic exception (%s) while handling message (%s) : %s"
                   % (e,
                      notification_data,
                      traceback.format_exception(exc_type,
                                                 exc_value,
                                                 exc_traceback)))
            LOG.info(msg)


class FirewallNotifier(object):

    def __init__(self, conf, sc):
        self._sc = sc
        self._conf = conf

    def set_firewall_status(self, context, notification_data):
        notification = notification_data['notification'][0]

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        resource_data = notification['data']
        firewall_id = resource_data['firewall_id']
        status = resource_data['status']

        msg = ("Config Orchestrator received "
               "firewall_configuration_create_complete API, making an "
               "set_firewall_status RPC call for firewall: %s & status "
               " %s" % (firewall_id, status))
        LOG.info(msg)

        # RPC call to plugin to set firewall status
        rpcClient = transport.RPCClient(a_topics.FW_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt.cast(context, 'set_firewall_status',
                             host=resource_data['host'],
                             firewall_id=firewall_id,
                             status=status)
        nfp_logging.clear_logging_context()

    def firewall_deleted(self, context, notification_data):
        notification = notification_data['notification'][0]

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        resource_data = notification['data']
        firewall_id = resource_data['firewall_id']

        msg = ("Config Orchestrator received "
               "firewall_configuration_delete_complete API, making an "
               "firewall_deleted RPC call for firewall: %s" % (firewall_id))
        LOG.info(msg)

        # RPC call to plugin to update firewall deleted
        rpcClient = transport.RPCClient(a_topics.FW_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt.cast(context, 'firewall_deleted',
                             host=resource_data['host'],
                             firewall_id=firewall_id)
        nfp_logging.clear_logging_context()


class LoadbalancerNotifier(object):

    def __init__(self, conf, sc):
        self._sc = sc
        self._conf = conf

    def update_status(self, context, notification_data):
        notification = notification_data['notification'][0]

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        resource_data = notification['data']
        obj_type = resource_data['obj_type']
        obj_id = resource_data['obj_id']
        status = resource_data['status']

        msg = ("NCO received LB's update_status API, making an update_status"
               "RPC call to plugin for %s: %s with status %s" % (
                   obj_type, obj_id, status))
        LOG.info(msg)
        nfp_logging.clear_logging_context()

        # RPC call to plugin to update status of the resource
        rpcClient = transport.RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(
            version=const.LOADBALANCER_RPC_API_VERSION)
        rpcClient.cctxt.cast(context, 'update_status',
                             obj_type=obj_type,
                             obj_id=obj_id,
                             status=status)

    def update_pool_stats(self, context, notification_data):
        notification = notification_data['notification'][0]

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        resource_data = notification['data']
        pool_id = resource_data['pool_id']
        stats = resource_data['stats']
        host = resource_data['host']

        msg = ("NCO received LB's update_pool_stats API, making an "
               "update_pool_stats RPC cast to plugin for updating"
               "pool: %s stats" % (pool_id))
        LOG.info(msg)

        # RPC cast to plugin to update stats of pool
        rpcClient = transport.RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(
            version=const.LOADBALANCER_RPC_API_VERSION)
        rpcClient.cctxt.cast(context, 'update_pool_stats',
                             pool_id=pool_id,
                             stats=stats,
                             host=host)
        nfp_logging.clear_logging_context()

    def vip_deleted(self, context, notification_data):
        pass


class LoadbalancerV2Notifier(object):

    def __init__(self, conf, sc):
        self._sc = sc
        self._conf = conf

    def update_status(self, context, notification_data):
        notification = notification_data['notification'][0]

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        resource_data = notification['data']
        obj_type = resource_data['obj_type']
        obj_id = resource_data['obj_id']

        rpcClient = transport.RPCClient(a_topics.LBV2_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(
            version=const.LOADBALANCERV2_RPC_API_VERSION)

        lb_p_status = const.ACTIVE
        lb_o_status = None
        obj_p_status = resource_data['provisioning_status']
        obj_o_status = resource_data['operating_status']

        msg = ("NCO received LB's update_status API, making an update_status "
               "RPC call to plugin for %s: %s with status %s" % (
                   obj_type, obj_id, obj_p_status))
        LOG.info(msg)

        if obj_type == 'healthmonitor':
                obj_o_status = None

        if obj_type != 'loadbalancer':
            rpcClient.cctxt.cast(context, 'update_status',
                                 obj_type=obj_type,
                                 obj_id=obj_id,
                                 provisioning_status=obj_p_status,
                                 operating_status=obj_o_status)
        else:
            lb_o_status = lbv2_const.ONLINE
            if obj_p_status == const.ERROR:
                lb_p_status = const.ERROR
                lb_o_status = lbv2_const.OFFLINE

        rpcClient.cctxt.cast(context, 'update_status',
                             obj_type='loadbalancer',
                             obj_id=resource_data['root_lb_id'],
                             provisioning_status=lb_p_status,
                             operating_status=lb_o_status)
        nfp_logging.clear_logging_context()

    # TODO(jiahao): implememnt later
    def update_loadbalancer_stats(self, context, loadbalancer_id, stats_data):
        pass


class VpnNotifier(object):

    def __init__(self, conf, sc):
        self._sc = sc
        self._conf = conf

    def update_status(self, context, notification_data):
        resource_data = notification_data['notification'][0]['data']

        request_info = notification_data.get('info')
        request_context = request_info.get('context')
        logging_context = request_context.get('logging_context')
        nfp_logging.store_logging_context(**logging_context)

        status = resource_data['status']
        msg = ("NCO received VPN's update_status API,"
               "making an update_status RPC cast to plugin for object"
               "with status %s" % (status))
        LOG.info(msg)
        rpcClient = transport.RPCClient(a_topics.VPN_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt.cast(context, 'update_status',
                             status=status)
        nfp_logging.clear_logging_context()

    def ipsec_site_conn_deleted(self, context, notification_data):
        pass


ServicetypeToHandlerMap = {'firewall': FirewallNotifier,
                           'loadbalancer': LoadbalancerNotifier,
                           'loadbalancerv2': LoadbalancerV2Notifier,
                           'vpn': VpnNotifier}


class NaasNotificationHandler(object):

    def __init__(self, conf, sc):
        self.conf = conf
        self.sc = sc

    def handle_notification(self, context, notification_data):
        try:
            resource_data = notification_data['notification'][0]['data']
            handler = ServicetypeToHandlerMap[notification_data[
                'info']['service_type']](self.conf, self.sc)
            method = getattr(handler, resource_data['notification_type'])
            # Handle RPC Event
            method(context, notification_data)
            # Handle Event
            request_data = {'context': context.to_dict(),
                            'notification_data': notification_data
                            }
            event = self.sc.new_event(id=resource_data[
                'notification_type'].upper(),
                key=resource_data[
                'notification_type'].upper(),
                data=request_data)
            self.sc.post_event(event)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            msg = ("Generic exception (%s) while handling message (%s) : %s"
                   % (e,
                      notification_data,
                      traceback.format_exception(exc_type,
                                                 exc_value,
                                                 exc_traceback)))
            LOG.error(msg)
