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
from gbpservice.nfp.core import poll as core_pt
import gbpservice.nfp.lib.transport as transport
from gbpservice.nfp.proxy_agent.lib import topics as a_topics

from neutron import context as n_context

from oslo_log import log as oslo_logging

import sys
import traceback

LOGGER = oslo_logging.getLogger(__name__)
LOG = nfp_common.log

ResourceMap = {
    'device_orch': a_topics.DEVICE_ORCH_TOPIC,
    'service_orch': a_topics.SERVICE_ORCH_TOPIC,
    'nas_service': a_topics.CONFIG_ORCH_TOPIC
}


"""Periodic Class to pull notification from configurator"""


class PullNotification(core_pt.PollEventDesc):

    def __init__(self, sc, conf):
        self._sc = sc
        self._conf = conf

    def handle_event(self, ev):
        self._sc.poll_event(ev)

    def _method_handler(self, notification):
        # Method handles notification as per resource, resource_type and method
        try:
            requester = notification['info']['context']['requester']
            topic = ResourceMap[requester]
            context = notification['info']['context']['neutron_context']
            rpcClient = transport.RPCClient(topic)
            rpc_ctx = n_context.Context.from_dict(context)
            rpcClient.cctxt.cast(rpc_ctx,
                                 'network_function_notification',
                                 notification_data=notification)
        except Exception as e:
            raise Exception(e)

    @core_pt.poll_event_desc(event='PULL_NOTIFICATIONS', spacing=1)
    def pull_notifications(self, ev):
        """Pull and handle notification from configurator."""
        notifications = transport.get_response_from_configurator(self._conf)

        if not isinstance(notifications, list):
            LOG(LOGGER, 'ERROR', "Notfications not list, %s" % (notifications))

        else:
            for notification in notifications:
                if not notification:
                    LOG(LOGGER, 'INFO', "Receiver Response: Empty")
                    continue
                try:
                    self._method_handler(notification)
                except AttributeError:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    LOG(LOGGER, 'ERROR',
                        "AttributeError while handling message %s : %s " % (
                            notification, traceback.format_exception(
                                exc_type, exc_value, exc_traceback)))

                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    LOG(LOGGER, 'ERROR', "Generic exception (%s) \
                       while handling message (%s) : %s" % (
                        e, notification, traceback.format_exception(
                            exc_type, exc_value, exc_traceback)))
