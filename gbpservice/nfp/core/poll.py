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
import random
import six
import time

from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
from oslo_service import loopingcall as oslo_looping_call
from oslo_service import periodic_task as oslo_periodic_task

from gbpservice.nfp.core import common as nfp_common

LOGGER = oslo_logging.getLogger(__name__)
LOG = nfp_common.log
identify = nfp_common.identify

"""Decorator definition """


def poll_event_desc(*args, **kwargs):
    def decorator(f):
        f._desc = True
        f._spacing = kwargs.pop('spacing', 0)
        f._event = kwargs.pop('event', None)
        return f

    return decorator

"""Meta class. """


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
                # name = desc.__name__
                cls._poll_event_descs[desc._event] = desc

"""Implements the logic to manage periodicity of events.
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
        """Check if event timedout w.r.t its spacing. """
        spacing = desc._spacing
        last_run = event.desc.last_run
        delta = 0

        if last_run:
            delta = last_run + spacing - time.time()
        if delta > 0:
            return None
        event.desc.last_run = self._nearest_boundary(last_run, spacing)
        return event

    def check_timedout(self, event):
        """Check if event timedout w.r.t its spacing.

            First check if the spacing is set for this event, if
            not then return the event - in this case events timeout
            at the periodicity of polling task.
            If yes, then check if event timedout.
        """
        try:
            desc = self._poll_event_descs[event.id]
            return self._timedout(desc, event)
        except KeyError as exc:
            exc = exc
            return event

    def get_poll_event_desc(self, event):
        """Get the registered event handler for the event.

            Check if the event has a specific periodic handler
            defined, if then return it.
        """
        try:
            return self._poll_event_descs[event.id]
        except KeyError as exc:
            exc = exc
            return None


"""Periodic task to poll for nfp events.

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

    @oslo_periodic_task.periodic_task(spacing=2)
    def periodic_sync_task(self, context):
        # invoke the common class to handle event timeouts
        self._sc.timeout()

"""Handles the polling queue, searches for the timedout events.

    Invoked in PollingTask, fetches new events from pollQ to cache them.
    Searches in cache for timedout events, enqueues timedout events to
    respective worker process. Event stays in cache till it is declared to
    be complete or cancelled.
    Event gets cancelled, if it is polled for max number of times. By default,
    it is huge number unless otherwise specified by logic which enqueues this
    event.
"""


class PollQueueHandler(object):

    def __init__(self, sc, pipes, ehs):
        self._sc = sc
        self._ehs = ehs
        self._pipes = pipes
        self._cache = nfp_common.NfpFifo(sc)

    def run(self):
        """Invoked in loop of periodic task to check for timedout events. """
        # Fill the cache first
        self._fill_polling_cache()
        cache = self._cache.copy()
        for event in cache:
            self._process_event(cache, event)

    def add_event(self, event):
        """Adds an event to the poll cache.

            Invoked in context of worker process
            to send event to polling task.
        """
        LOG(LOGGER, 'DEBUG', "%s - added for polling" % (event.identify()))
        self._cache.put(event)

    def event_expired(self, eh, event):
        """Invoked when an event is expired.

            Invokes the nfp module method to notify
            that event has expired.

            Executor: worker-process
        """
        try:
            LOG(LOGGER, 'DEBUG', "%s - event expired" % (event.identify()))
            eh.event_cancelled(event.data, reason='EVENT_EXPIRED')
        except AttributeError:
            LOG(LOGGER, 'DEBUG',
                "%s - handler does not implement"
                "event_cancelled method" % (identify(eh)))

    def event_timedout(self, eh, event):
        """Invoked when an event timedout.

            When worker recieves a timedout, this method
            will invoke approp method of nfp module based
            on the type of timedout event and registered
            handler.

            Executor: worker-process.
        """
        if isinstance(eh, PollEventDesc):
            # Check if this event has a decorated timeout method
            peh = eh.get_poll_event_desc(event)
            if peh:
                ret = peh(eh, event)
                LOG(LOGGER, 'DEBUG',
                    "%s - timedout - invoking method:%s - "
                    "of handler:%s" % (
                        event.identify(), identify(peh), identify(eh)))
            else:
                ret = eh.handle_poll_event(event)
                LOG(LOGGER, 'DEBUG',
                    "%s - timedout - "
                    "invoking method:handle_poll_event - "
                    "of handler:%s" % (
                        event.identify(), identify(eh)))
        else:
            ret = eh.handle_poll_event(event)
            LOG(LOGGER, 'DEBUG',
                "%s - timedout - invoking method:handle_poll_event - "
                "of handler:%s" % (
                    event.identify(), identify(eh)))

        self._event_dispatched(eh, event, ret)

    def _get(self, pipe, timeout=0.1):
        """Internal method to get messages from pollQ.

            Handles the empty queue exception.
        """
        try:
            if pipe.poll(timeout):
                return pipe.recv()
        except multiprocessing.TimeoutError as err:
            err = err
            return None

    def _poll_event_cancelled(self, eh, event):
        try:
            LOG(LOGGER, 'DEBUG',
                "%s - poll event cancelled - "
                "invoking method:poll_event_cancel - "
                "of handler:%s"
                % (event.identify(), identify(eh)))
            eh.poll_event_cancel(event)
        except AttributeError:
            LOG(LOGGER, 'DEBUG',
                "%s - poll event cancelled - "
                "handler:%s - does not implement"
                "poll_event_cancel method" % (
                    event.identify(), identify(eh)))
        return

    def _get_default_status(self, event, ret):
        status = {'poll': True, 'event': event}
        if ret and 'event' in ret.keys():
            status['event'] = ret['event']
        if ret and 'poll' in ret.keys():
            status['poll'] = ret['poll']
        return status

    def _event_dispatched(self, eh, event, ret):
        status = self._get_default_status(event, ret)
        uevent = status['event']
        poll = status['poll']

        uevent.max_times = event.max_times - 1

        if not uevent.max_times:
            return self._poll_event_cancelled(eh, event)

        if poll:
            uevent.serialize = False
            return self._sc.poll_event(uevent, max_times=uevent.max_times)

    def _schedule(self, ev):
        """Schedule the event to approp worker.

            Checks if the event has timedout and if yes,
            then schedules it to the approp worker. Approp worker -
            worker which handled this event earlier.

            Executor: distributor-process
        """
        eh = self._ehs.get(ev)
        # Check if the event has any defined spacing interval, if yes
        # then did it timeout w.r.t the spacing ?
        # If yes, then event is scheduled.
        # Spacing for event can only be defined if the registered event
        # handler is derived from periodic task class. Following check
        # is for same.
        if isinstance(eh, PollEventDesc):
            if eh.check_timedout(ev):
                self._sc.post_timedoutevent(ev)
                return ev
        else:
            self._sc.post_timedoutevent(ev)
            return ev
        return None

    def _poll_event_scheduled(self, ev):
        """Marks the event as complete.

            Invoked by caller to mark the event as complete.
            Removes the event from internal cache.
        """
        self._cache.remove([ev])

    def _schedule_poll_event(self, ev):
        """Schedule a timedout to worker. """
        ev.desc.poll_event = 'POLL_EVENT'
        ev.serialize = False
        ev = self._schedule(ev)
        if ev:
            self._poll_event_scheduled(ev)

    def _process_event(self, cache, ev):
        """Process different types of poll event.

            'POLL_EVENT_CANCEL' - stop polling on this event.
            'POLL_EVENT_EXPIRY' - Poll for expiry of an event.
            <*> - Poll for timeout w.r.t its spacing

            Executor: distributor-process
        """

        LOG(LOGGER, 'DEBUG', "%s - processing - from worker:%d" %
            (ev.identify(), os.getpid()))

        if ev.desc.poll_event != 'POLL_EVENT':
            self._cache.remove([ev])
            return self._sc.post_event(ev)

        if ev.id == 'POLL_EVENT_CANCEL':
            return self._poll_event_scheduled(ev)

        if ev.id == 'POLL_EVENT_EXPIRY':
            ev.max_times -= 1
            if not ev.max_times:
                # Mark event as expired and schedule event
                ev.id = 'EVENT_EXPIRED'
                self._schedule_poll_event(ev)
        else:
            self._schedule_poll_event(ev)

    def _pull_event(self, pipe, timeout=0.1):
        """Pull event from multiprocessing queue.

            Wait for some timeout if event is not
            available.
        """
        event = self._get(pipe, timeout=timeout)
        if event:
            LOG(LOGGER, 'DEBUG',
                "%s - new poll event" % (event.identify()))
            self._cache.put(event)
        return event

    def _fill_polling_cache(self):
        """Fill polling cache with events from poll queue.

            Fetch messages from poll queue which is
            python mutiprocessing.queue and fill local cache.
            Events need to persist and polled they are declated complete
            or cancelled.
        """
        # Wait for the first event and for subsequent,
        # pull in as much as possible with some max limit.
        # as the same thread has to poll for already pulled
        # events.
        for pipe in self._pipes:
            timeout = 0.01
            counter = 0
            # REVISIT(mak): Can the constant 10 be derived ?
            while counter < 1 and self._pull_event(pipe, timeout=timeout):
                timeout = 0
                counter += 1


def load_nfp_symbols(namespace):
    """Load all the global symbols in namespace. """
    nfp_common.load_nfp_symbols(namespace)

load_nfp_symbols(globals())
