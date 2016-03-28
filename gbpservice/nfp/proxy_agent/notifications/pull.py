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
from gbpservice.nfp.proxy_agent.notifications import handler as nh

from oslo_log import log as logging


LOGGER = logging.getLogger(__name__)
LOG = nfp_common.log

"""Periodic Class to pull notification from configurator"""


class PullNotification(core_pt.PollEventDesc):

    def __init__(self, sc, conf):
        self._sc = sc
        self._conf = conf

    def handle_event(self, ev):
        self._sc.poll_event(ev)

    def _method_handler(self, notification):
        # Method handles notification as per resource,receiver and method
        mod = nh.NotificationHandler()
        mod_method = getattr(mod, notification['method'])
        reciever = notification['receiver']
        if reciever == 'device_orchestrator' or reciever == 'orchestrator':
            mod_method(notification['resource'],
                       notification['kwargs'])

        elif reciever == 'service_orchestrator':
            mod_method(notification['resource'],
                       notification['kwargs'],
                       device=False)
        else:
            mod_method(notification['resource'], **notification['kwargs'])

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
                    LOG(LOGGER, 'ERROR',
                        "AttributeError while handling message %s " % (
                            notification))
                except Exception as e:
                    # import sys
                    # import traceback
                    # exc_type, exc_value, exc_traceback = sys.exc_info()
                    # print traceback.format_exception(exc_type, exc_value,
                    #                                 exc_traceback)
                    LOG(LOGGER, 'ERROR', "Generic exception (%s) \
                       while handling message (%s)" % (e, notification))
