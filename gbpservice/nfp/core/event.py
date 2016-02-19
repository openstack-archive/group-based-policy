import os
import sys
import time

from Queue import Empty as QEMPTY
from Queue import Full as QFULL

from oslo_log import log as oslo_logging
from oslo_config import cfg as oslo_config
from gbpservice.nfp.core import threadpool as nfp_tp
from gbpservice.nfp.core import poll as nfp_poll
from gbpservice.nfp.core.common import *

LOG = oslo_logging.getLogger(__name__)
PID = os.getpid()

""" Definition of an 'EVENT' in NFP framework.

    NFP modules instantiates object of this class to define and
    create internal events.
"""


class Event(object):

    def __init__(self, **kwargs):
        self.serialize = kwargs.get(
            'serialize') if 'serialize' in kwargs else False
        self.binding_key = kwargs.get(
            'binding_key') if 'binding_key' in kwargs else None
        self.id = kwargs.get('id')
        self.key = kwargs.get('key')
        self.data = kwargs.get('data') if 'data' in kwargs else None
        self.handler = kwargs.get('handler') if 'handler' in kwargs else None
        self.poll_event = None  # Not to be used by user
        self.worker_attached = None  # Not to be used by user
        self.last_run = None  # Not to be used by user
        self.max_times = -1  # Not to be used by user

    def identify(self):
        return "(id=%s,key=%s)" % (self.id, self.key)

""" Handles the sequencing of related events.

    If Event needs to be sequenced it is queued otherwise
    it is scheduled. Caller will fetch the sequenced events
    waiting to be scheduled in subsequent calls.
"""


class EventSequencer(object):

    def __init__(self, sc):
        self._sc = sc
        """
        sequenced events are stored in following format :
        {'pid':{'binding_key':{'in_use':True, 'queue':[]}}}
        """
        self._sequencer_map = {}

    def add(self, ev):
        """ Add the event to the sequencer.

            Checks if there is already a related event scheduled,
            if not, will not queue the event. If yes, then will
            queue this event.
            Returns True(queued)/False(not queued).
        """
        queued = False
        LOG.debug(_("Sequence event %s" % (ev.identify())))
        self._sc.lock()
        if ev.worker_attached not in self._sequencer_map:
            self._sequencer_map[ev.worker_attached] = {}
        seq_map = self._sequencer_map[ev.worker_attached]
        if ev.binding_key in seq_map.keys():
            queued = True
            LOG.debug(_(
                "There is already an event in progress"
                "Queueing event %s" % (ev.identify())))

            seq_map[ev.binding_key]['queue'].append(ev)
        else:
            LOG.debug(_(
                "Scheduling first event to exec"
                "Event %s" % (ev.identify())))
            seq_map[ev.binding_key] = {'in_use': True, 'queue': []}
        self._sc.unlock()
        return queued

    def copy(self):
        """ Returns the copy of sequencer_map to caller. """
        self._sc.lock()
        copy = dict(self._sequencer_map)
        self._sc.unlock()
        return copy

    def remove(self, ev):
        """ Removes an event from sequencer map.

            If this is the last related event in the map, then
            the complete entry is deleted from sequencer map.
        """
        self._sc.lock()
        self._sequencer_map[ev.worker_attached][
            ev.binding_key]['queue'].remove(ev)
        self._sc.unlock()

    def delete_eventmap(self, ev):
        """ Internal method to delete event map, if it is empty. """
        self._sc.lock()
        seq_map = self._sequencer_map[ev.worker_attached][ev.binding_key]
        if seq_map['queue'] == []:
            LOG.debug(_(
                "No more events in the seq map -"
                "Deleting the entry (%d) (%s)"
                % (ev.worker_attached, ev.binding_key)))
            del self._sequencer_map[ev.worker_attached][ev.binding_key]
        self._sc.unlock()

""" Handles the processing of evens in event queue.

    Executes in the context of worker process, runs in loop to fetch
    the events and process them. As processing, invokes the registered
    handler for the event.
"""


class EventQueueHandler(object):

    def __init__(self, sc, qu, ehs):
        # Pool of green threads per process
        self._tpool = nfp_tp.ThreadPool()
        self._evq = qu
        self._ehs = ehs
        self._sc = sc

    def _get(self):
        """ Internal function to get an event for processing.

            First checks in sequencer map - these events could be
            waiting for long.
            If no events, then fetch the events from event_queue -
            listener process adds events into this queue.
            Returns the event to be processed.
        """
        # Check if any event can be pulled from serialize_map - this evs may be
        # waiting long enough
        LOG.debug(_("Checking serialize Q for events long pending"))
        ev = self._sc.sequencer_get_event()
        if not ev:
            LOG.debug(_(
                "No event pending in sequencer Q - "
                "checking the event Q"))
            try:
                ev = self._evq.get(timeout=0.1)
            except QEMPTY:
                pass
            if ev:
                LOG.debug(_(
                    "Checking if the ev %s to be serialized"
                    % (ev.identify())))
                """
                If this event needs to be serialized and is first event
                then the same is returned back, otherwise None is
                returned. If event need not be serialized then it is
                returned.
                """
                ev = self._sc.sequencer_put_event(ev)
        return ev

    def _cancelled(self, eh, ev):
        """ Internal function to cancel an event.

            Removes it from poll_queue also.
            Invokes the 'poll_event_cancel' method of the
            registered handler if it is implemented.
        """
        LOG.info(_(
            "Event %s cancelled -"
            "invoking %s handler's poll_event_cancel method"
            % (ev.identify(), identify(eh))))
        try:
            self._sc.poll_event_done(ev)
            eh.poll_event_cancel(ev)
        except AttributeError:
            LOG.info(_(
                "Handler %s does not implement"
                "poll_event_cancel method" % (identify(eh))))

    def _poll_event(self, eh, ev):
        """ Internal function to handle the poll event.

            Poll task adds the timedout events to the worker process.
            This method handles such timedout events in worker context.
            Invoke the decorated timeout handler for the event, if any.
            (or) invoke the default 'handle_poll_event' method of registered
            handler.
            """
        LOG.debug(_(
            "Event %s to be scheduled to handler %s"
            % (ev.identify(), identify(eh))))

        # Event handler can implement decorated timeout methods only if it
        # is dervied from periodic_task. Checking here.
        if isinstance(eh, nfp_poll.PollEventDesc):
            # Check if this event has a decorated timeout method
            peh = eh.get_poll_event_desc(ev)
            if peh:
                t = self._tpool.dispatch(peh, eh, ev)
                LOG.info(_(
                    "Dispatched method %s of handler %s"
                    "for event %s to thread %s"
                    % (identify(peh), identify(eh),
                        ev.identify(), t.identify())))

            else:
                t = self._tpool.dispatch(eh.handle_poll_event, ev)
                LOG.info(_(
                    "Dispatched handle_poll_event() of handler %s"
                    "for event %s to thread %s"
                    % (identify(eh),
                        ev.identify(), t.identify())))
        else:
            t = self._tpool.dispatch(eh.handle_poll_event, ev)
            LOG.info(_(
                "Dispatched handle_poll_event() of handler %s"
                "for event %s to thread %s"
                % (identify(eh),
                    ev.identify(), t.identify())))

    def run(self, qu):
        """ Worker process loop to fetch & process events from event queue.

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
        LOG.info(_("Started worker process - %s" % (PID)))
        while True:
            ev = self._get()
            if ev:
                LOG.debug(_("Got event %s" % (ev.identify())))
                eh = self._ehs.get(ev)
                if not ev.poll_event:
                    t = self._tpool.dispatch(eh.handle_event, ev)
                    LOG.debug(_(
                        "Event %s is not poll event - "
                        "disptaching handle_event() of handler %s"
                        "to thread %s"
                        % (ev.identify(), identify(eh), t.identify())))
                else:
                    if ev.poll_event == 'POLL_EVENT_CANCELLED':
                        LOG.debug(
                            _("Got cancelled event %s" % (ev.identify())))
                        self._cancelled(eh, ev)
                    else:
                        LOG.info(
                            _("Got POLL Event %s scheduling"
                                % (ev.identify())))
                        self._poll_event(eh, ev)
            time.sleep(0)  # Yield the CPU
