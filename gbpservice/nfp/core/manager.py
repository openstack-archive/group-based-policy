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

from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import executor as nfp_executor
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import path as nfp_path
from gbpservice.nfp.core import sequencer as nfp_sequencer
from gbpservice.nfp.core import watchdog as nfp_watchdog

LOG = nfp_logging.getLogger(__name__)
NfpEventManager = nfp_event.NfpEventManager
NfpGraphExecutor = nfp_executor.EventGraphExecutor
WATCHDOG = nfp_watchdog.Watchdog


def IS_SCHEDULED_EVENT_ACK(event):
    return event.desc.flag == nfp_event.EVENT_ACK


def IS_SCHEDULED_NEW_EVENT(event):
    return event.desc.type == nfp_event.SCHEDULE_EVENT and (
        event.desc.flag == nfp_event.EVENT_NEW
    )


def IS_EVENT_COMPLETE(event):
    return event.desc.flag == nfp_event.EVENT_COMPLETE


def IS_EVENT_GRAPH(event):
    return event.desc.graph


def IS_PATH_COMPLETE_EVENT(event):
    return event.id == 'PATH_COMPLETE'


"""Manages the forked childs.

    Invoked periodically, compares the alive childs with
    snapshot and reports the difference to the caller.
"""


class NfpProcessManager(object):

    def __init__(self, conf, controller):
        self._conf = conf
        self._controller = controller
        self._child_snapshot = []

    def new_child(self, pid, pipe):
        # Pass, as we will learn from comparision as watcher
        pass

    def _dead(self, dead):
        for proc in dead:
            self._child_snapshot.remove(proc)

    def _new(self, new):
        if new:
            self._child_snapshot.extend(new)

    def child_watcher(self):
        # Get the current set of childrens
        current = self._controller.get_childrens()
        set1 = set(current)
        set2 = set(self._child_snapshot)
        new = set1 - set2
        dead = set2 - set1

        self._dead(dead)
        self._new(new)

        return list(dead), list(new)


"""Manager for nfp resources.

    Manages all the nfp resources - process, events, polling queue etc.
    Mixes the specific managers.
"""


class NfpResourceManager(NfpProcessManager, NfpEventManager):

    def __init__(self, conf, controller):
        self._conf = conf
        self._controller = controller
        # Process, Event mixin, {'pid': event_manager}
        self._resource_map = {}
        # Cache of event objects - {'uuid':<event>}
        self._event_cache = {}
        # watchdog object mapping with event id - {'uuid':<watchdog>}
        self._watchdog_map = {}
        # ID of the distributor process
        self._distributor_process_id = os.getpid()
        # Single sequencer to be used by all event managers
        self._event_sequencer = nfp_sequencer.EventSequencer()
        # Graph executor
        self.graph_executor = NfpGraphExecutor(self)

        NfpProcessManager.__init__(self, conf, controller)
        NfpEventManager.__init__(self, conf, controller, self._event_sequencer)

    def new_child(self, pid, pipe):
        """Invoked when a new child is spawned.

            Associates an event manager with this child, maintains
            the map. Manages the process. If this process is killed,
            the event_manager is assigned to new process.

            :param process: Context of new process.
            :param pipe: Pipe to communicate with this child.
        """
        ev_manager = NfpEventManager(
            self._conf, self._controller,
            self._event_sequencer,
            pipe=pipe, pid=pid)
        self._resource_map.update(dict({pid: ev_manager}))
        super(NfpResourceManager, self).new_child(pid, pipe)

    def manager_run(self):
        """Invoked periodically to check on resources.

            a) Checks if childrens are active or any killed.
            b) Checks if there are messages from any of workers.
            c) Dispatches the events ready to be handled to workers.
        """
        self._child_watcher()
        self._event_watcher()

    def get_event(self, event_id):
        return self._event_cache[event_id]

    def _event_acked(self, event):
        """Post handling after event is dispatched to worker. """
        event.desc.acked = True
        nfp_path.event_complete(event)

    def _dispatch_event(self, event):
        """Dispatch event to a worker. """
        load_info = self._load_init()
        event_manager, load_info = self._get_min_loaded_em(load_info)
        event_manager.dispatch_event(event)

    def _graph_event(self, event):
        if isinstance(event.desc.graph, dict):
            graph = event.desc.graph
            # root = graph['root']

            event.desc.graph = graph['id']

            self._event_cache[event.desc.uuid] = event

            if event.desc.uuid == graph['root']:
                # graph = {'id': <>, 'data': {}, 'root': <>}
                self.graph_executor.add(graph)
        else:
            graph = event.desc.graph
            self.graph_executor.run(graph, event.desc.uuid)

    def _graph_event_complete(self, event):
        self.graph_executor.conntinue(event.desc.uuid, event.result)

    def _scheduled_new_event(self, event):
        # Cache the event object
        self._event_cache[event.desc.uuid] = event

        # Event needs to be sequenced ?
        if not event.sequence:
            # Since event is dispatched, remove its
            # graph link, modules may decide to use
            # same event as non graph event
            event.desc.graph = None

            decision = nfp_path.schedule_event(event)
            if decision == 'schedule':
                # Dispatch to a worker
                self._dispatch_event(event)
                LOG.debug("Watchdog started for event - %s" %
                          (event.identify()))
                self._watchdog(event)
            elif decision == 'discard':
                message = "Discarding path event - %s" % (event.identify())
                LOG.info(message)
                self._controller.event_complete(event, result='FAILED')
        else:
            message = "(event - %s) - sequencing" % (
                event.identify())
            LOG.debug(message)
            # Sequence the event which will be processed later
            self._event_sequencer.sequence(event.binding_key, event)

        return event.sequence

    def _handle_path_complete(self, event):
        try:
            path_type = event.desc.path_type
            path_key = event.desc.path_key
            nfp_path.path_complete(path_type, path_key)
        except Exception as e:
            message = "Exception - %r - while handling"\
                "event - %s" % (e, event.identify())
            LOG.error(message)

    def event_expired(self, event=None):
        if event:
            LOG.debug("Watchdog expired for event - %s" % (event.identify()))
            self._watchdog_map.pop(event.desc.uuid, None)
            self._controller.event_complete(event, result='FAILED')

    def _scheduled_event_ack(self, ack_event):
        self._event_acked(ack_event)

    def _watchdog_cancel(self, event):
        try:
            LOG.debug("Watchdog cancelled for event - %s" % (event.identify()))
            wd = self._watchdog_map.pop(event.desc.uuid)
            wd.cancel()
        except KeyError:
            pass

    def _watchdog(self, event, handler=None):
        if not handler:
            handler = self.event_expired
        if event.lifetime != -1:
            wd = WATCHDOG(handler,
                          seconds=event.lifetime,
                          event=event)
            self._watchdog_map[event.desc.uuid] = wd

    def _scheduled_event_complete(self, event):
        # Pop it from cache
        cached_event = None
        try:
            cached_event = self._event_cache.pop(event.desc.uuid)
            cached_event.result = event.result
            # Mark the event as acked
            self._watchdog_cancel(event)
            # Get the em managing the event
            evmanager = self._get_event_manager(event.desc.worker)
            assert evmanager
            evmanager.pop_event(event)
        except KeyError as kerr:
            kerr = kerr
            message = "(event - %s) - completed, not in cache" % (
                event.identify())
            LOG.debug(message)
        except AssertionError as aerr:
            message = "%s" % (aerr.message)
            LOG.debug(message)
        finally:
            # Release the sequencer for this sequence,
            # so that next event can get scheduled.
            self._event_sequencer.release(event.binding_key, event)
            self._graph_event_complete(event)

    def _stop_poll_event(self, event):
        try:
            to_stop = event.data['key']
            event.desc.uuid = to_stop
            self._watchdog_cancel(event)
        except Exception as e:
            message = "Exception - %r - while handling"\
                "event - %s" % (e, event.identify())
            LOG.error(message)

    def _non_schedule_event(self, event):
        if event.desc.type == nfp_event.POLL_EVENT:
            if event.desc.flag == nfp_event.POLL_EVENT_STOP:
                self._stop_poll_event(event)
            else:
                message = "(event - %s) - polling for event, spacing(%d)" % (
                    event.identify(), event.desc.poll_desc.spacing)
                LOG.debug(message)
                # If the poll event is generated without any parent
                # event, then worker would not be pre-assigned.
                # In such case, assign a random worker
                if not event.desc.worker:
                    event.desc.worker = self._resource_map.keys()[0]
                event.lifetime = event.desc.poll_desc.spacing
                self._watchdog(event, handler=self._poll_timedout)
        else:
            message = "(event - %s) - Unknown non scheduled event" % (
                event.identify())
            LOG.error(message)

    def process_events_by_ids(self, event_ids):
        for event_id in event_ids:
            try:
                event = self._event_cache[event_id]
                self.process_events([event])
            except KeyError as kerr:
                kerr = kerr
                message = "%s - event missing in cache" % (
                    event_id)
                LOG.error(message)

    def process_events(self, events):
        """Process the consumed event.

            Based on the event type, new event will
            be added to cache, completed event is
            removed from cache, poll event is added
            to pollq.

        """
        for event in events:
            message = "%s - processing event" % (event.identify())
            LOG.debug(message)
            if IS_PATH_COMPLETE_EVENT(event):
                self._handle_path_complete(event)
            elif IS_SCHEDULED_EVENT_ACK(event):
                self._scheduled_event_ack(event)
            elif IS_SCHEDULED_NEW_EVENT(event):
                if IS_EVENT_GRAPH(event):
                    self._graph_event(event)
                else:
                    self._scheduled_new_event(event)
            elif IS_EVENT_COMPLETE(event):
                self._scheduled_event_complete(event)
            else:
                self._non_schedule_event(event)

    def _event_watcher(self):
        """Watches for events for each event manager.

            Invokes each event manager to get events from workers.
            Also checks parent process event manager.
        """
        events = []
        # Get events from sequencer
        events = self._event_sequencer.run()
        events += nfp_path.run()
        for pid, event_manager in self._resource_map.iteritems():
            events += event_manager.event_watcher(timeout=0.01)
        # Process the type of events received, dispatch only the
        # required ones.
        self.process_events(events)

    def _init_event_manager(self, from_em, to_em):
        pending_event_ids = to_em.init_from_event_manager(from_em)
        # Reprocess all the pending events, module handlers can
        # continue processing of unacked events.
        self.process_events_by_ids(pending_event_ids)

    def _replace_child(self, killed, new):
        childrens = self._controller.get_childrens()
        wrap = childrens[new]
        pipe = wrap.child_pipe_map[new]
        self.new_child(new, pipe)
        new_em = self._resource_map[new]
        killed_em = self._resource_map[killed]
        new_em.init_from_event_manager(killed_em)
        # Dispatch the pending events to the new worker through new em
        self._replay_events(new_em)

    def _replay_events(self, event_manager):
        pending_event_ids = event_manager.get_pending_events()
        for event_id in pending_event_ids:
            try:
                message = "%s - replaying event" % (event_id)
                LOG.info(message)
                event_manager.dispatch_event(
                    self._event_cache[event_id], cache=False)
            except KeyError as kerr:
                kerr = kerr
                message = "%s - eventid missing in cache" % (
                    event_id)
                LOG.error(message)

    def _child_watcher(self):
        dead, new = super(NfpResourceManager, self).child_watcher()
        if len(dead) and len(dead) != len(new):
            message = "Killed process - %s, "
            "New Process - %s, "
            "does not match in count, few killed process"
            "will not be replaced" % (str(dead), str(new))
            LOG.error(message)

        # Loop over dead workers and assign its
        # event manager to one of the new worker
        for killed_proc in dead:
            new_proc = new.pop()
            self._replace_child(killed_proc, new_proc)
            del self._resource_map[killed_proc]

    def _load_init(self):
        """Intializes load with current information. """
        load_info = []
        for pid, event_manager in self._resource_map.iteritems():
            load = event_manager.get_load()
            load_info.append([event_manager, load, pid])

        return load_info

    def _get_min_loaded_em(self, load_info):
        """Returns the min loaded event_manager. """
        minloaded = min(load_info, key=lambda x: x[1])
        load = minloaded[1] + 1
        load_info[load_info.index(minloaded)][1] = load
        return minloaded[0], load_info

    def _get_event_manager(self, pid):
        """Returns event manager of a process. """
        if pid == self._distributor_process_id:
            return self
        else:
            return self._resource_map.get(pid)

    def _poll_timedout(self, event):
        """Callback for poller when event timesout. """
        message = "(event - %s) - timedout" % (event.identify())
        LOG.debug(message)

        try:
            evmanager = self._get_event_manager(event.desc.worker)
            message = "(event-%s) event manager not found" % (event.identify())
            assert evmanager, message
            if nfp_path.schedule_event(event) == 'schedule':
                evmanager.dispatch_event(event,
                                         event_type=nfp_event.POLL_EVENT,
                                         inc_load=False, cache=False)
        except AssertionError as aerr:
            LOG.debug(aerr.message)
        except Exception as e:
            message = ("Unknown exception=%r - event=%s" % (
                       e, event.identify()))
            LOG.error(message)
