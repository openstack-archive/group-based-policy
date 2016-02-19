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

import time

from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

_NAME_ = 'Visibility'

EVENT = nfp_event.Event

LOG = nfp_logging.getLogger(__name__)


def nfp_module_init(controller, conf):
    evs = [
        EVENT(id='EVENT_ID_1', handler=EventsHandler(controller)),
        EVENT(id='EVENT_ID_2', handler=EventsHandler(controller)),
        EVENT(id='EVENT_ID_3', handler=EventsHandler(controller)),
        EVENT(id='EVENT_ID_4', handler=EventsHandler(controller))]
    controller.register_events(evs)


def module_test(controller, conf):
    event = controller.create_event(
        id='EVENT_ID_1', data='Ahmed',
        serialize=True, binding_key='EVENT_ID_1', lifetime=30)
    controller.post_event(event)


class EventsHandler(nfp_api.NfpEventHandler):

    def __init__(self, controller):
        self._controller = controller

    def handle_event(self, event):
        message = "Handle Event %s" % (event.identify())
        LOG.info(message)
        if event.id == 'EVENT_ID_1':
            # LOG.info("ADDING POLL EVENT %s CURR TIME %s" %
            #    (event.identify(), time.time()))
            self._controller.poll_event(event, max_times=10, spacing=1)
            event = self._controller.create_event(
                id='EVENT_ID_2', data='Ahmed',
                serialize=True, binding_key='EVENT_ID_1', lifetime=40)
            self._controller.post_event(event)
        elif event.id == 'EVENT_ID_2':
            self._controller.poll_event(event, max_times=10)
            event = self._controller.create_event(
                id='EVENT_ID_3', data='Ahmed',
                serialize=True, binding_key='EVENT_ID_1', lifetime=30)
            self._controller.post_event(event)
        elif event.id == 'EVENT_ID_3':
            event = self._controller.create_event(
                id='EVENT_ID_4', data='Ahmed',
                serialize=True, binding_key='EVENT_ID_1', lifetime=10)
            self._controller.post_event(event)

    def handle_poll_event(self, event):
        message = "Event TIMEDOUT %s CURR TIME : %s" % (
            event.identify(), time.time())
        LOG.info(message)

    def event_cancelled(self, event, reason):
        message = "Event %s cancelled reason %s" % (
            event.identify(), reason)
        LOG.info(message)

    @nfp_api.poll_event_desc(event='EVENT_ID_2', spacing=2)
    def event_1_poll_event(self, event):
        message = "Event TIMEDOUT %s CURR TIME : %s" % (
            event.identify(), time.time())
        LOG.info(message)
