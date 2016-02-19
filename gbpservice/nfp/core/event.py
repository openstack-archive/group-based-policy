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

import multiprocessing
import os
import time
import uuid as pyuuid

from oslo_log import log as oslo_logging

from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core import threadpool as nfp_tp

LOGGER = oslo_logging.getLogger(__name__)
LOG = nfp_common.log
identify = nfp_common.identify

"""Descriptor of event. """


class EventDesc(object):

    def __init__(self, **kwargs):
        # Unique id of the event, generated if not passed.
        self.uid = kwargs.get('key', pyuuid.uuid4())
        # Poll descriptor of the event.
        self.poll_event = None
        # Worker handling this event.
        self.worker_attached = None
        # When this event was last run
        self.last_run = None

        if not self.uid:
            self.uid = pyuuid.uuid4()

"""Definition of an 'EVENT' in NFP framework.

    NFP modules instantiates object of this class to define and
    create internal events.
"""


class Event(object):

    def __init__(self, **kwargs):
        # ID of the event, can be same for multiple events
        self.id = kwargs.get('id')
        # Module context, not decoded by core
        self.data = kwargs.get('data', None)
        # Handler used only @the time of registration
        self.handler = kwargs.get('handler', None)
        # To serialize this event.
        self.serialize = kwargs.get('serialize', False)
        # Events with same binding_key are related.
        self.binding_key = kwargs.get('binding_key', None)
        # Lifetime of event in seconds
        self.lifetime = kwargs.get('lifetime', 0)
        # Max number of times this event can be polled.
        # Default, till stopped or forever.
        self.max_times = -1
        # Identifies whether event.data is zipped
        self.zipped = False
        # Added for log metadata
        self.context = kwargs.get('context', None)

    def identify(self):
        if hasattr(self, 'desc'):
            return "(Event -> id=%s,key=%s)" % (self.id, self.desc.uid)
        else:
            return "(Event -> id=%s,key=%s)" % (self.id, '')

"""Handles the sequencing of related events.

    If Event needs to be sequenced it is queued otherwise
    it is scheduled. Caller will fetch the sequenced events
    waiting to be scheduled in subsequent calls.
"""


class EventSequencer(object):

    def __init__(self, sc):
        self._sc = sc
        """
        sequenced events are stored in following format :
        {'binding_key':{'in_use':True, 'queue':[]}}
        """
        self._sequencer_map = {}

    def get(self):
        """Get an event from the sequencer map.

            Invoked by workers to get the first event in sequencer map.
            Since it is a FIFO, first event could be waiting long to be
            scheduled.
            Loops over copy of sequencer map and returns the first waiting
            event.
        """
        seq_map = self._sequencer_map
        for bkey, val in seq_map.iteritems():
            in_use = val['in_use']
            if not in_use and val['queue']:
                # Return the first element of the
                # queue in first free sequencer.
                # should not pop here, event done will
                # remove it. useful in restart cases later.
                event = val['queue'][0]
                val['in_use'] = True
                LOG(LOGGER, 'DEBUG', "%s - sequencer_get - returning"
                    % (event.identify()))
                return event

    def add(self, event):
        """Add the event to the sequencer.

            Checks if there is already a related event scheduled,
            if not, will not queue the event. If yes, then will
            queue this event.
            Returns True(queued)/False(not queued).
        """
        queued = False
        try:
            seq_map = self._sequencer_map[event.binding_key]
            seq_map['queue'].append(event)
            queued = True
            LOG(LOGGER, 'DEBUG', "%s - sequencer_add - an event"
                "already in progress, queueing" % (event.identify()))
        except KeyError as err:
            self._sequencer_map[event.binding_key] = {
                'in_use': True, 'queue': [event]}
            err = err
            LOG(LOGGER, 'DEBUG',
                "%s - sequencer_add - first event "
                "in sequence, scheduling it" % (event.identify()))
        return queued

    def copy(self):
        """Returns the copy of sequencer_map to caller.

            Used by the caller to iterate over the sequencer /
            read operations.
        """
        copy = dict(self._sequencer_map)
        return copy

    def remove(self, event):
        """Removes an event from sequencer map.

            If this is the last related event in the map, then
            the complete entry is deleted from sequencer map.
        """
        bkey = event.binding_key
        self._sequencer_map[bkey]['queue'].remove(event)
        self._sequencer_map[bkey]['in_use'] = False
        LOG(LOGGER, 'DEBUG', "%s - sequencer - removed" % (
            event.identify()))

    def delete_eventmap(self, event):
        """Internal method to delete event map, if it is empty. """
        seq_map = self._sequencer_map[event.binding_key]
        if seq_map['queue'] == []:
            LOG(LOGGER, 'DEBUG',
                "sequencer - no events -"
                "deleting entry - %s"
                % (event.binding_key))
            del self._sequencer_map[
                event.desc.worker_attached][event.binding_key]

"""Handles the processing of evens in event queue.

    Executes in the context of worker process, runs in loop to fetch
    the events and process them. As processing, invokes the registered
    handler for the event.
"""


class EventQueueHandler(object):

    def __init__(self, sc, conf, pipe, ehs, modules):
        # Pool of green threads per process
        self._conf = conf
        self._tpool = nfp_tp.ThreadPool()
        self._pipe = pipe
        self._ehs = ehs
        self._nfp_modules = modules
        self._sc = sc

    def _get(self):
        """Internal function to get an event for processing.

            First checks in sequencer map - these events could be
            waiting for long.
            If no events, then fetch the events from event_queue -
            listener process adds events into this queue.
            Returns the event to be processed.
        """
        # Check if any event can be pulled from serialize_map - this evs may be
        # waiting long enough
        event = self._sc.sequencer_get_event()
        if not event:
            try:
                if self._pipe.poll(0.1):
                    event = self._pipe.recv()
            except multiprocessing.TimeoutError as err:
                err = err
                pass
            if event:
                # If this event needs to be serialized and is first event
                # then the same is returned back, otherwise None is
                # returned. If event need not be serialized then it is
                # returned.
                event = self._sc.sequencer_put_event(event)
        return event

    def _dispatch_poll_event(self, eh, ev):
        """Internal function to handle the poll event.

            Poll task adds the timedout events to the worker process.
            This method handles such timedout events in worker context.
            Invoke the decorated timeout handler for the event, if any.
            (or) invoke the default 'handle_poll_event' method of registered
            handler.
            """
        t = self._tpool.dispatch(self._sc.poll_event_timedout, eh, ev)
        LOG(LOGGER, 'DEBUG',
            "%s - dispatch poll event - "
            "to event handler: %s - "
            "in thread: %s"
            % (ev.identify(), identify(eh), t.identify()))

    def run(self, pipe):
        """Worker process loop to fetch & process events from event queue.

            Gets the events from event queue which is
            python multiprocessing.queue.
            Listener process adds events into this queue for worker process
            to handle it.
            Handles 3 different type of events -
            a) POLL_EVENT - Event added by poller due to timeout.
            b) POLL_EVENT_CANCELLED - Event added by poller due to event
                getting cancelled as it timedout configured number of
                max times.
            c) EVENT - Internal event added by listener process.
        """
        LOG(LOGGER, 'INFO',
            "%d - worker started" % (os.getpid()))
        # Update my identity on my copy of controller
        self._sc._process_name = 'worker-process'
        # Update my pid in worker map
        self._sc._worker_pipe_map[os.getpid()] = pipe
        # Initialize the nfp modules again from worker.
        # This is because modules are initializing some contexts
        # in module_init which is invoked before starting workers,
        # forked workers get the copy of such contexts, and module
        # logic end up using stale contexts.
        # Better to initialize again and ignore re registrations.
        self._sc.modules_init(self._nfp_modules)
        while True:
            event = self._get()
            if event:
                self._sc.decompress(event)
                LOG(LOGGER, 'DEBUG',
                    "%s - worker - got new event" % (event.identify()))
                eh = self._ehs.get(event)
                if not event.desc.poll_event:
                    t = self._tpool.dispatch(eh.handle_event, event)
                    LOG(LOGGER, 'DEBUG', "%s - dispatch internal event -"
                        "to event handler:%s - "
                        "in thread:%s" % (
                            event.identify(),
                            identify(eh), t.identify()))
                else:
                    self._dispatch_poll_event(eh, event)
            time.sleep(0)  # Yield the CPU


def load_nfp_symbols(namespace):
    nfp_common.load_nfp_symbols(namespace)

load_nfp_symbols(globals())
