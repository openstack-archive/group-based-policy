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

import os
import sys
import time
import copy
import six
import random

from Queue import Empty as QEMPTY
from Queue import Full as QFULL

from oslo_log import log as oslo_logging
from oslo_config import cfg as oslo_config
from oslo_service import periodic_task as oslo_periodic_task
from oslo_service import loopingcall as oslo_looping_call

from gbpservice.nfp.core import threadpool as nfp_tp
from gbpservice.nfp.core import fifo as nfp_fifo
from gbpservice.nfp.core.common import *

LOG = oslo_logging.getLogger(__name__)
PID = os.getpid()


""" Decorator definition """


def poll_event_desc(*args, **kwargs):
    def decorator(f):
        f._desc = True
        f._spacing = kwargs.pop('spacing', 0)
        f._event = kwargs.pop('event', None)
        return f

    return decorator

""" Meta class. """


class _Meta(type):

    def __init__(cls, names, bases, dict_):
        """Metaclass that allows us to collect decorated periodic tasks."""
        super(_Meta, cls).__init__(names, bases, dict_)

        try:
            cls._poll_event_descs = dict(cls._poll_event_descs)
        except AttributeError:
            cls._poll_event_descs = {}

        for value in cls.__dict__.values():
            if getattr(value, '_desc', False):
                desc = value
                name = desc.__name__
                cls._poll_event_descs[desc._event] = desc

""" Implements the logic to manage periodicity of events.
    Reference to corresponding decorated methods are returned
    if event has timedout.
"""


@six.add_metaclass(_Meta)
class PollEventDesc(object):

    def __init__(self):
        super(PollEventDesc, self).__init__()

    def _nearest_boundary(self, last_run, spacing):
        """Find nearest boundary which is in the past,
        which is a multiple of the
        spacing with the last run as an offset.

        Eg if last run was 10 and spacing was 7,
        the new last run could be: 17, 24,
        31, 38...

        0% to 5% of the spacing value will be added
        to this value to ensure tasks
        do not synchronize. This jitter is rounded
        to the nearest second, this
        means that spacings smaller than 20 seconds
        will not have jitter.
        """
        current_time = time.time()
        if last_run is None:
            return current_time
        delta = current_time - last_run
        offset = delta % spacing
        # Add up to 5% jitter
        jitter = int(spacing * (random.random() / 20))
        return current_time - offset + jitter

    def _timedout(self, desc, event):
        """ Check if event timedout w.r.t its spacing. """
        spacing = desc._spacing
        last_run = event.last_run
        delta = 0

        if last_run:
            delta = last_run + spacing - time.time()
        if delta > 0:
            return None
        event.last_run = self._nearest_boundary(last_run, spacing)
        return event

    def check_timedout(self, event):
        """ Check if event timedout w.r.t its spacing.

            First check if the spacing is set for this event, if
            not then return the event - in this case events timeout
            at the periodicity of polling task.
            If yes, then check if event timedout.
        """
        if event.id not in self._poll_event_descs.keys():
            return event
        else:
            desc = self._poll_event_descs[event.id]
            return self._timedout(desc, event)

    def get_poll_event_desc(self, event):
        """ Get the registered event handler for the event.

            Check if the event has a specific periodic handler
            defined, if then return it.
        """
        if event.id not in self._poll_event_descs.keys():
            return None
        return self._poll_event_descs[event.id]


""" Periodic task to poll for nfp events.

    Derived from oslo periodic task, polls periodically for the
    NFP events, invokes registered event handler for the timedout
    event.
"""


class PollingTask(oslo_periodic_task.PeriodicTasks):

    def __init__(self, sc):
        super(PollingTask, self).__init__(oslo_config.CONF)
        self._sc = sc
        pulse = oslo_looping_call.FixedIntervalLoopingCall(
            self.run_periodic_tasks, None, None)
        pulse.start(
            interval=oslo_config.CONF.periodic_interval, initial_delay=None)

    @oslo_periodic_task.periodic_task(spacing=1)
    def periodic_sync_task(self, context):
        LOG.debug(_("Periodic sync task invoked !"))
        # invoke the common class to handle event timeouts
        self._sc.timeout()

""" Handles the polling queue, searches for the timedout events.

    Invoked in PollingTask, fetches new events from pollQ to cache them.
    Searches in cache for timedout events, enqueues timedout events to
    respective worker process. Event stays in cache till it is declared to
    be complete or cancelled.
    Event gets cancelled, if it is polled for max number of times. By default,
    it is huge number unless otherwise specified by logic which enqueues this
    event.
"""


class PollQueueHandler(object):

    def __init__(self, sc, qu, ehs, batch=-1):
        self._sc = sc
        self._ehs = ehs
        self._pollq = qu
        self._procidx = 0
        self._procpending = 0
        self._batch = 10 if batch == -1 else batch
        self._cache = nfp_fifo.Fifo(sc)

    def _get(self):
        """ Internal method to get messages from pollQ.

            Handles the empty queue exception.
        """
        try:
            return self._pollq.get(timeout=0.1)
        except QEMPTY:
            return None

    def _cancelled(self, ev):
        """ To cancel an event.

            Removes the event from internal cache and scheds the
            event to worker to handle any cleanup.
        """
        LOG.info(_("Poll event %s cancelled" % (ev.identify())))
        ev.poll_event = 'POLL_EVENT_CANCELLED'
        self._event_done(ev)
        self._sc.post_event(ev)

    def _schedule(self, ev):
        """ Schedule the event to approp worker.

            Checks if the event has timedout and if yes,
            then schedules it to the approp worker. Approp worker -
            worker which handled this event earlier.
        """
        LOG.debug(_("Schedule event %s" % (ev.identify())))
        eh = self._ehs.get(ev)
        """ Check if the event has any defined spacing interval, if yes
            then did it timeout w.r.t the spacing ?
            If yes, then event is scheduled.
            Spacing for event can only be defined if the registered event
            handler is derived from periodic task class. Following check
            is for same.
        """
        if isinstance(eh, PollEventDesc):
            if eh.check_timedout(ev):
                LOG.info(_(
                    "Event %s timed out -"
                    "scheduling it to a worker" % (ev.identify())))
                self._sc.post_event(ev)
                return ev
        else:
            LOG.info(_(
                "Event %s timed out -"
                "scheduling it to a worker" % (ev.identify())))
            self._sc.post_event(ev)
            return ev
        return None

    def _process_event(self, ev):
        """ Process different type of poll event. """

        LOG.debug(_("Processing poll event %s" % (ev.identify())))
        if ev.id == 'POLL_EVENT_DONE':
            return self._event_done(ev)
        copyev = copy.deepcopy(ev)
        copyev.serialize = False
        copyev.poll_event = 'POLL_EVENT'
        if copyev.max_times == 0:
            return self._cancelled(copyev)
        if self._schedule(copyev):
            ev.max_times -= 1
            ev.last_run = copyev.last_run

    def _event_done(self, ev):
        """ Marks the event as complete.

            Invoked by caller to mark the event as complete.
            Removes the event from internal cache.
        """
        LOG.info(_("Poll event %s to be marked done !" % (ev.identify())))
        self.remove(ev)

    def add(self, event):
        """ Adds an event to the pollq.

            Invoked in context of worker process
            to send event to polling task.
        """
        LOG.debug(_("Add event %s to the pollq" % (event.identify())))
        self._pollq.put(event)

    def remove(self, event):
        """ Remove an event from polling cache.

            All the events which matches with the event.key
            are removed from cache.
        """
        LOG.info(_("Remove event %s from pollq" % (event.identify())))
        LOG.info(
            _("Removing all poll events with key %s" % (event.identify())))
        remevs = []
        cache = self._cache.copy()
        for elem in cache:
            if elem.key == event.key:
                LOG.info(_(
                    "Event %s key matched event %s key - "
                    "removing event %s from pollq"
                    % (elem.identify(), event.identify(), elem.identify())))
                remevs.append(elem)
        self._cache.remove(remevs)

    def fill(self):
        """ Fill polling cache with events from poll queue.

            Fetch messages from poll queue which is
            python mutiprocessing.queue and fill local cache.
            Events need to persist and polled they are declated complete
            or cancelled.
        """
        LOG.debug(_("Fill events from multi processing Q to internal cache"))
        # Get some events from queue into cache
        for i in range(0, 10):
            ev = self._get()
            if ev:
                LOG.debug(_(
                    "Got new event %s from multi processing Q"
                    % (ev.identify())))
                self._cache.put(ev)

    def peek(self, idx, count):
        """ Peek for events instead of popping.

            Peek into specified number of events, this op does
            not result in pop of events from queue, hence the events
            are not lost.
        """
        LOG.debug(_("Peek poll events from index:%d count:%d" % (idx, count)))
        cache = self._cache.copy()
        qlen = len(cache)
        LOG.debug(_("Number of elements in poll q - %d" % (qlen)))
        pull = qlen if (idx + count) > qlen else count
        return cache[idx:(idx + pull)], pull

    def run(self):
        """ Invoked in loop of periodic task to check for timedout events. """
        # Fill the cache first
        self.fill()
        # Peek the events from cache
        evs, count = self.peek(0, self._batch)
        for ev in evs:
            self._process_event(ev)
        self._procidx = (self._procidx + count) % (self._batch)
