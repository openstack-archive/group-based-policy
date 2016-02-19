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

import collections
import multiprocessing
import uuid as pyuuid

from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api
from gbpservice.nfp.core import sequencer as nfp_seq

LOG = nfp_logging.getLogger(__name__)
identify = nfp_common.identify

"""Event Types """
SCHEDULE_EVENT = 'schedule_event'
POLL_EVENT = 'poll_event'
STASH_EVENT = 'stash_event'
EVENT_EXPIRED = 'event_expired'
EVENT_GRAPH = 'event_graph'

"""Event Flag """
EVENT_NEW = 'new_event'
EVENT_COMPLETE = 'event_done'
EVENT_ACK = 'event_ack'

"""Sequencer status. """
SequencerEmpty = nfp_seq.SequencerEmpty
SequencerBusy = nfp_seq.SequencerBusy

deque = collections.deque


class EventGraphNode(object):

    def __init__(self, event, p_event=None):
        self.p_link = ()
        self.c_links = []
        self.w_links = []
        self.e_links = []
        self.event = event
        self.result = None

        if p_event:
            self.p_link = p_event

    def __getstate__(self):
        return (self.p_link, self.c_links,
                self.e_links, self.w_links, self.event, self.result)

    def __setstate__(self, state):
        (self.p_link, self.c_links, self.e_links,
            self.w_links, self.event, self.result) = state

    def add_link(self, event):
        self.c_links.append(event)
        self.w_links.append(event)

    def remove_link(self, event):
        self.e_links.append(event)
        self.w_links.remove(event)

    def remove_c_link(self, event):
        try:
            self.c_links.remove(event)
        except ValueError:
            pass

    def get_c_links(self):
        return self.c_links

    def get_w_links(self):
        return self.w_links

    def get_executed_links(self):
        return self.e_links


class EventGraph(object):

    def __init__(self, event):
        self.root_node = EventGraphNode(event.desc.uuid)
        self.nodes = {event.desc.uuid: self.root_node}

    def __getstate__(self):
        return self.root_node, self.nodes

    def __setstate__(self, state):
        self.root_node, self.nodes = state

    def add_node(self, event, p_event):
        node = EventGraphNode(event.desc.uuid, p_event.desc.uuid)
        self.nodes.update({event.desc.uuid: node})
        p_node = self.nodes.get(p_event.desc.uuid)
        p_node.add_link(event.desc.uuid)

    def remove_node(self, node):
        p_node = self.nodes.get(node.p_link)
        if p_node:
            p_node.remove_link(node.event)
        return p_node

    def unlink_node(self, node):
        p_node = self.nodes.get(node.p_link)
        if p_node:
            p_node.remove_c_link(node.event)

    def get_pending_leaf_nodes(self, node):
        c_links = node.get_c_links()
        c_nodes = []
        for link in c_links:
            c_nodes.append(self.nodes[link])

        return c_nodes

    def waiting_events(self, node):
        return len(node.get_w_links())

    def get_leaf_node_results(self, event):
        results = []
        node = self.nodes[event.desc.uuid]
        e_links = node.get_executed_links()
        for link in e_links:
            node = self.nodes[link]
            uuid = node.event
            key, id = uuid.split(':')
            result = nfp_common.Object()
            setattr(result, 'id', id)
            setattr(result, 'key', key)
            setattr(result, 'result', node.result)
            results.append(result)
        return results

    def get_node(self, event):
        return self.nodes[event]

"""Defines poll descriptor of an event.

    Holds all of the polling information of an
    event.
"""


class PollDesc(object):

    def __init__(self, **kwargs):
        # Spacing of the event, event will timeout @this spacing.
        self.spacing = kwargs.get('spacing')
        # Max times event can be polled, is autocancelled after.
        self.max_times = kwargs.get('max_times')
        # Reference to original event, UUID.
        self.ref = kwargs.get('ref')

"""Defines the descriptor of an event.

    Holds the metadata for an event. Useful
    for event processing. Not exposed to nfp modules.
"""


class EventDesc(object):

    def __init__(self, **kwargs):
        # Unique id of the event, use what user passed or
        # generate a new unique id.
        uuid = kwargs.get('key', pyuuid.uuid4())
        id = kwargs.get('id', '')

        self.uuid = str(uuid) + ':' + id

        # see 'Event Types'
        self.type = kwargs.get('type')
        # see 'Event Flag'
        self.flag = kwargs.get('flag')
        # PID of worker which is handling this event
        self.worker = kwargs.get('worker')
        # Polling descriptor of event
        self.poll_desc = kwargs.get('poll_desc')

    def from_desc(self, desc):
        self.type = desc.type
        self.flag = desc.flag
        self.worker = desc.worker
        self.poll_desc = desc.poll_desc

    def to_dict(self):
        return {'uuid': self.uuid,
                'type': self.type,
                'flag': self.flag,
                'worker': self.worker,
                'poll_desc': self.poll_desc
                }

"""Defines the event structure.

    Nfp modules need to create object of the class
    to create an event.
"""


class Event(object):

    def __init__(self, **kwargs):
        # ID of event as passed by module
        self.id = kwargs.get('id')
        # Data blob
        self.data = kwargs.get('data')
        # Whether to sequence this event w.r.t
        # other related events.
        self.sequence = kwargs.get('serialize', False)
        # Unique key to be associated with the event
        self.key = kwargs.get('key')
        # Binding key to define relation between
        # different events.
        self.binding_key = kwargs.get('binding_key')
        # Handler of the event.
        self.handler = kwargs.get('handler')
        # Lifetime of the event in seconds.
        self.lifetime = kwargs.get('lifetime', 0)
        # Identifies whether event.data is zipped
        self.zipped = False
        # Log metadata context
        self.context = kwargs.get('context', {})
        # Prepare the base descriptor
        desc = kwargs.get('desc_dict')
        if desc:
            desc['key'] = self.key
            desc['id'] = self.id
            desc = EventDesc(**desc)
        elif self.key:
            desc = EventDesc(**{'key': self.key,
                                'id': self.id})
        else:
            desc = EventDesc(**{'id': self.id})
        self.desc = desc

        # Will be set if this event is a event graph
        self.graph = kwargs.get('graph', None)
        self.result = None

        cond = self.sequence is True and self.binding_key is None
        assert not cond

    def set_fields(self, **kwargs):
        if 'graph' in kwargs:
            self.graph = kwargs['graph']

    def identify(self):
        if hasattr(self, 'desc'):
            return "uuid=%s,id=%s,type=%s,flag=%s" % (
                self.desc.uuid, self.id, self.desc.type, self.desc.flag)
        return "id=%s" % (self.id)


"""Table of event handler's.

    Maintains cache of every module's event handlers.
    Also, maintains the polling against event_id
    which are provided as decorators.
"""


class NfpEventHandlers(object):

    def __init__(self):
        # {'event.id': [(event_handler, poll_handler, spacing)]
        self._event_desc_table = {}

    def _log_meta(self, event_id, event_handler=None):
        if event_handler:
            return "(event_id - %s) - (event_handler - %s)" % (
                event_id, identify(event_handler))
        else:
            return "(event_id - %s) - (event_handler - None)" % (event_id)

    def register(self, event_id, event_handler):
        """Registers a handler for event_id.

            Also fetches the decorated poll handlers if any
            for the event and caches it.
        """
        if not isinstance(event_handler, nfp_api.NfpEventHandler):
            message = "%s - Handler is not instance of NfpEventHandler" % (
                self._log_meta(event_id, event_handler))
            LOG.error(message)
            return
        try:
            poll_desc_table = event_handler.get_poll_desc_table()
            poll_handler = poll_desc_table[event_id]
            spacing = poll_handler._spacing
        except KeyError:
            # Default the poll handler and spacing values
            poll_handler = event_handler.handle_poll_event
            spacing = 0

        try:
            self._event_desc_table[event_id].append(
                (event_handler, poll_handler, spacing))
        except KeyError:
            self._event_desc_table[event_id] = [
                (event_handler, poll_handler, spacing)]
        message = "%s - Registered handler" % (
            self._log_meta(event_id, event_handler))
        LOG.debug(message)

    def get_event_handler(self, event_id):
        """Get the handler for the event_id. """
        eh = None
        try:
            eh = self._event_desc_table[event_id][0][0]
        finally:
            message = "%s - Returning event handler" % (
                self._log_meta(event_id, eh))
            LOG.debug(message)
            return eh

    def get_poll_handler(self, event_id):
        """Get the poll handler for event_id. """
        ph = None
        try:
            ph = self._event_desc_table[event_id][0][1]
        finally:
            message = "%s - Returning poll handler" % (
                self._log_meta(event_id, ph))
            LOG.debug(message)
            return ph

    def get_poll_spacing(self, event_id):
        """Return the spacing for event_id. """
        spacing = 0
        try:
            spacing = self._event_desc_table[event_id][0][2]
        finally:
            message = "%s - Poll spacing %d" % (
                self._log_meta(event_id), spacing)
            LOG.debug(message)
            return spacing


"""Manages the lifecycle of event of a process.

    Each process (worker/distributor) is associated
    with a event manager. Event manager pulls events
    from the pipe, caches it, sequences & dispatches
    the events.
"""


class NfpEventManager(object):

    def __init__(self, conf, controller, sequencer, pipe=None, pid=-1):
        self._conf = conf
        self._controller = controller
        # PID of process to which this event manager is associated
        self._pid = pid
        # Duplex pipe to read & write events
        self._pipe = pipe
        # Cache of UUIDs of events which are dispatched to
        # the worker which is handled by this em.
        self._cache = deque()
        # Load on this event manager - num of events pending to be completed
        self._load = 0

    def _log_meta(self, event=None):
        if event:
            return "(event - %s) - (event_manager - %d)" % (
                event.identify(), self._pid)
        else:
            return "(event_manager - %d" % (self._pid)

    def _wait_for_events(self, pipe, timeout=0.01):
        """Wait & pull event from the pipe.

            Wait till timeout for the first event and then
            pull as many as available.
            Returns: Events[] pulled from pipe.
        """
        events = []
        try:
            while pipe.poll(timeout):
                timeout = 0
                event = self._controller.pipe_recv(pipe)
                events.append(event)
        except multiprocessing.TimeoutError as err:
            message = "%s" % (err)
            LOG.exception(message)
        return events

    def init_from_event_manager(self, em):
        """Initialize from existing event manager.

            Invoked when an event manager has to take over
            existing event manager.

            Whole cache is replaced and events are replayed.
            This is used in case where a worker dies, dead
            workers event manager is assigned to new worker.
        """
        # Replay all the events from cache.
        self._cache = em._cache

    def get_pending_events(self):
        return list(self._cache)

    def get_load(self):
        """Return current load on the manager."""
        return self._load

    def pop_event(self, event):
        """Pop the passed event from cache.

            Is called when an event is complete/cancelled.
            If the event was sequenced, then sequencer is
            released to schedule next event.

            Removes event from cache.
        """
        message = "%s - pop event" % (self._log_meta(event))
        LOG.debug(message)
        try:
            self._cache.remove(event.desc.uuid)
            self._load -= 1
        except ValueError as verr:
            verr = verr
            message = "%s - event not in cache" % (
                self._log_meta(event))
            LOG.warn(message)

    def dispatch_event(self, event, event_type=None,
                       inc_load=True, cache=True):
        """Dispatch event to the worker.

            Sends the event to worker through pipe.
            Increments load if event_type is SCHEDULED event,
            poll_event does not contribute to load.
        """
        message = "%s - Dispatching to worker %d" % (
            self._log_meta(event), self._pid)
        LOG.debug(message)
        # Update the worker information in the event.
        event.desc.worker = self._pid
        # Update the event with passed type
        if event_type:
            event.desc.type = event_type
        # Send to the worker
        self._controller.pipe_send(self._pipe, event)

        self._load = (self._load + 1) if inc_load else self._load
        # Add to the cache
        if cache:
            self._cache.append(event.desc.uuid)

    def event_watcher(self, timeout=0.01):
        """Watch for events. """
        return self._wait_for_events(self._pipe, timeout=timeout)
