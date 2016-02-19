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

import ast
import eventlet
eventlet.monkey_patch()

import multiprocessing
import operator
import os
import Queue
import sys
import time
import zlib


from neutron.agent.common import config as n_config
from neutron.common import config as n_common_config

from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
from oslo_service import service as oslo_service

from gbpservice.nfp.core import cfg as nfp_config
from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import event_lb as nfp_lb
from gbpservice.nfp.core import poll as nfp_poll
from gbpservice.nfp.core import rpc as nfp_rpc

LOGGER = oslo_logging.getLogger(__name__)
LOG = nfp_common.log
identify = nfp_common.identify


"""Implements table of registered event handlers. """


class EventHandlers(object):

    def __init__(self):
        self._event_handlers = {}

    def register(self, event_desc):
        """Register an event handler. """
        ehs = self._event_handlers
        LOG(LOGGER, 'DEBUG', "Registering handler %s" %
            (self.identify(event_desc)))
        try:
            ehs[event_desc.id].extend([event_desc])
        except KeyError:
            ehs[event_desc.id] = [event_desc]

    def get(self, event_desc):
        """Return handler of an event. """
        ehs = self._event_handlers
        try:
            # There could be multiple handlers for a given event,
            # returning first one in the list.
            # REVISIT(mak): should multiple handlers be allowed ?
            return ehs[event_desc.id][0].handler
        except KeyError:
            return None

    def identify(self, event):
        return "%s - %s" % (event.identify(), identify(event.handler))


"""Common class implements all the APIs & cache.

    Common class used across modules and classes to access the
    cache of required objects.
    Also, implements the abstracted APIs for NFP modules.
    All the registered handlers, NFP modules, worker process, rpc agents
    etc all instantiated, stored, maintained in this class.
    mixin class for interactions between different classes
    like event handler, poll handler etc.
    Distributor & each worker process has copy of Controller object.
"""


class Controller(object):

    def __init__(self, conf, modules):
        # Configuration object
        self._conf = conf
        # Cache of auto-loaded NFP modules
        self._modules = modules
        # Sequencer to sequence the related events.
        self._sequencer = nfp_event.EventSequencer(self)
        # Map of worker pid to pipe assoc with it.
        self._worker_pipe_map = {}
        # Identity of process which is executing this controller obj.
        self._process_name = 'distributor-process'
        # To wait on an event to be complete.
        self._event = multiprocessing.Event()
        # Queue to stash events.
        self._stashq = multiprocessing.Queue()

    def start(self):
        """Starts all the execution contexts.

            Starts worker process, rpc agents, polling task,
            report task.

            Executor: distributor-process
        """
        self._init()

        for worker in self._workers:
            worker[0].start()
            self._worker_pipe_map[worker[0].pid] = worker[1]

        # Polling task to poll for timer events
        self._polling_task = nfp_poll.PollingTask(self)
        # Seperate task for reporting as report state rpc is a 'call'
        self._reportstate_task = nfp_rpc.ReportStateTask(self)

        for idx, agent in enumerate(self._rpc_agents):
            launcher = oslo_service.launch(oslo_config.CONF, agent[0])
            self._rpc_agents[idx] = agent + (launcher,)

        # Wait for every worker to be up
        time.sleep(self._conf.workers * 1 + 1)

    def wait(self):
        """To wait for workers.

            Executor: distributor-process
        """
        # self.rpc_agents.wait()
        for w in self._workers:
            w[0].join()

    def compress(self, event):
        """Compress event data before sending across process. """
        if event.data and not event.zipped:
            event.zipped = True
            event.data = zlib.compress(str({'cdata': event.data}))

    def decompress(self, event):
        """Decompress before calling module callbacks. """
        if event.data and event.zipped:
            try:
                data = ast.literal_eval(
                    zlib.decompress(event.data))
                event.data = data['cdata']
                event.zipped = False
            except Exception as e:
                LOG(LOGGER, 'ERROR',
                    "Failed to decompress event data, Reason: %s" % (
                        e))
                raise e

    def post_event(self, event):
        """API for NFP module to generate a new internal event.

            Schedules this event to one of the worker. 'binding_key' is
            glue between different events, all events with same 'binding_key'
            are scheduled to same worker process.

            Executor: distributor-process, worker-process
        """
        if self._process_name == 'worker-process':
            # Worker cannot distribute events, so post it to distributor
            pipe = self._worker_pipe_map[os.getpid()]
            self._pipe_send(pipe, event)
            LOG(LOGGER, 'DEBUG', "%s - post event - "
                "worker >> distributor" % (event.identify()))
        else:
            worker = self._loadbalancer.get(event.binding_key)
            event.desc.worker_attached = worker[0].pid
            # Getting queue element of tuple (mp_process, mp_pipe,
            # eventq_handler)
            pipe = worker[1]
            self._pipe_send(pipe, event)
            LOG(LOGGER, 'DEBUG', "%s - post event - "
                "distributor >> worker:%d"
                % (event.identify(), event.desc.worker_attached))

            if event.lifetime:
                self._add_lifetime_event(event)

    def event_done(self, event):
        """API for NFP modules to mark an event complete.

            This is how framework learns that an event is complete and
            any other sequenced event can now be scheduled.
            Ideally, for event module at some point should call event_done.

            Executor: worker-process
        """
        LOG(LOGGER, 'DEBUG', "%s - event complete" % (event.identify()))
        seq_map = self._sequencer.copy()
        try:
            seq_q = seq_map[event.binding_key]['queue']
            for seq_event in seq_q:
                if seq_event.desc.uid == event.desc.uid:
                    LOG(LOGGER, 'DEBUG', "%s - removing from sequencer"
                        % (seq_event.identify()))
                    self._sequencer.remove(seq_event)
                    break
            self._sequencer.delete_eventmap(event)
        except KeyError as err:
            LOG(LOGGER, 'DEBUG', "%s - event not in sequencer" %
                (event.identify()))
            # Event not in sequence map
            # Not an issue, event might not have serialized
            err = err
            pass

    def poll_event(self, event, max_times=sys.maxint):
        """API for NFP modules to generate a new poll event.

            Adds event to pollq for the poller to poll on it
            periodically.
            max_times - Defines the max number of times this event
            can timeout, after that event is auto cancelled.

            Executor: distributor-process, worker-process
        """
        if self._process_name == 'distributor-process':
            if not event.desc.worker_attached:
                LOG(LOGGER, 'DEBUG', "%s - poll event -  "
                    "no worker is associated" % (event.identify()))
                # Get some worker from the pool.
                worker = self._loadbalancer.get(None)
                event.desc.worker_attached = worker[0].pid
            LOG(LOGGER, 'DEBUG', "%s - poll event - "
                "distributor - adding to poller" % (
                    event.identify()))
            event.desc.poll_event = 'POLL_EVENT'
            event.max_times = max_times
            self._pollhandler.add_event(event)
        else:
            LOG(LOGGER, 'DEBUG', "%s - poll event - "
                "worker:%d >> distributor"
                % (event.identify(), os.getpid()))
            event.desc.poll_event = 'POLL_EVENT'
            event.max_times = max_times
            event.desc.worker_attached = os.getpid()
            pipe = self._worker_pipe_map[os.getpid()]
            self._pipe_send(pipe, event)

    def poll_event_timedout(self, eh, event):
        """Abstract method for poll handler.

            Demuxes the type of timedout and invokes
            the proper method.

            Executor: worker-process
        """
        LOG(LOGGER, 'DEBUG', "%s - poll event timedout - " %
            (event.identify()))
        if event.id == 'EVENT_EXPIRED':
            self._pollhandler.event_expired(eh, event)
            # Call done to auto cancel the event
            self.event_done(event)
        else:
            self._pollhandler.event_timedout(eh, event)

    def poll_event_done(self, event):
        """API for NFP modules to mark a poll event complete.

            If on any condition, module logic decides to stop polling
            for an event before it gets auto cancelled, then this
            method can be invoked.

            Executor: worker-process
        """
        LOG(LOGGER, 'DEBUG', "%s - poll event complete" % (event.identify()))
        event.id = 'POLL_EVENT_CANCEL'
        self.poll_event(event)

    def new_event(self, **kwargs):
        """API for NFP modules to prep an Event from passed args """
        event = nfp_event.Event(**kwargs)
        desc = nfp_event.EventDesc(**kwargs)
        setattr(event, 'desc', desc)
        return event

    def register_events(self, events):
        """API for NFP modules to register events """
        # Ignore if happens from worker
        if self._process_name == 'worker':
            return
        for event in events:
            LOG(LOGGER, 'DEBUG', "%s - registered handler - %s"
                % (event.identify(), identify(event.handler)))
            self._event_handlers.register(event)

    def register_rpc_agents(self, agents):
        """API for NFP mofules to register rpc agents """
        # Ignore if happens from worker
        if self._process_name == 'worker':
            return
        for agent in agents:
            self._rpc_agents.extend([(agent,)])

    def init_complete(self):
        """Invokes NFP modules init_complete() to do any post init logic """
        for module in self._modules:
            LOG(LOGGER, 'DEBUG', "Invoking init_complete() of module %s"
                % (identify(module)))
            try:
                module.nfp_module_post_init(self, self._conf)
            except AttributeError:
                LOG(LOGGER, 'DEBUG', "Module %s does not implement"
                    "nfp_module_post_init() method - skipping"
                    % (identify(module)))

    def stash_event(self, event):
        """To stash an event.

            This will be invoked by worker process.
            Put this event in queue, distributor will
            pick it up.

            Executor: worker-process
        """
        if self._process_name == 'distributor-process':
            LOG(LOGGER, 'ERROR', "%s - distributor - cannot stash event" % (
                event.identify()))
        else:
            LOG(LOGGER, 'DEBUG', "%s - worker - stashed" % (event.identify()))
            self.compress(event)
            self._stashq.put(event)

    def get_stashed_events(self):
        """To get stashed events.

            Returns available number of stashed events
            as list. Will be invoked by distributor,
            worker cannot pull.

            Executor: distributor-process
        """
        events = []
        if self._process_name == 'distributor-process':
            # wait sometime for first event in the queue
            timeout = 0.1
            try:
                event = self._stashq.get(timeout=timeout)
                self.decompress(event)
                events.append(event)
                timeout = 0
            except Queue.Empty:
                pass
        else:
            LOG(LOGGER, 'ERROR', "worker cannot pull stashed events")
        return events

    def sequencer_put_event(self, event):
        """Put an event in sequencer.

            Check if event needs to be sequenced, this is module logic choice.
            If yes, then invokes sequencer. If this is the first event in
            sequence, it is returned immediately, all subsequent events will be
            sequenced by sequencer till this event is complete.

            Executor: worker-process.
        """
        if not event.serialize:
            return event
        if not self._sequencer.add(event):
            return event
        return None

    def sequencer_get_event(self):
        """Get an event from the sequencer map.

            Executor: worker-process.
        """
        return self._sequencer.get()

    def report_state(self):
        """Invoked by report_task to report states of all agents.

            Executor: report-task of distributor-process.
        """
        for agent in self._rpc_agents:
            rpc_agent = operator.itemgetter(0)(agent)
            rpc_agent.report_state()

    def timeout(self):
        """Invoked by poll task to handle timer events.

            Executor: periodic-task of distributor-process.
        """
        self._pollhandler.run()

    def post_timedoutevent(self, event):
        """To post a timedout event to a worker.

            Timedout event should be posted to same worker
            which generated it.
            Invoked by timer task to schedule a timedout
            event to the correct worker.

            Executor: poll-task of distributor-process
        """
        if not event.desc.worker_attached:
            LOG(LOGGER, 'ERROR', "%s - timedoutevent - "
                "no worker attached, dropping" % (event.identify()))
        else:
            pipe = self._worker_pipe_map[event.desc.worker_attached]
            LOG(LOGGER, 'DEBUG', "%s - timedoutevent -"
                "to worker:%d" % (
                    event.identify(), event.desc.worker_attached))
            self._pipe_send(pipe, event)

    def modules_init(self, modules):
        """Initializes all the loaded NFP modules.

            Invokes "nfp_module_init" method of each module.
            Module can register its rpc & event handlers.

            Executor: distributor-process
        """
        inited_modules = []
        for module in modules:
            LOG(LOGGER, 'DEBUG', "Initializing module %s" %
                (identify(module)))
            try:
                module.nfp_module_init(self, self._conf)
                inited_modules.append(module)
                LOG(LOGGER, 'INFO', "module - %s - initialized" %
                    (identify(module)))
            except AttributeError:
                LOG(LOGGER, 'ERROR', "module - %s - "
                    "nfp_module_init() missing, skip loading"
                    % (identify(module)))
                continue
        return inited_modules

    def _poll_handler_init(self):
        """Initialize poll handler.

            Pollhandler will process the events to be polled
            from worker.

            Executor: distributor-process
        """
        # Prepare list of parent side of pipes with each child
        pipes = []
        for worker in self._workers:
            pipes.append(worker[1])

        handler = nfp_poll.PollQueueHandler(self, pipes, self._event_handlers)
        return handler

    def _init(self):
        """Intializes the NFP multi process framework.

            Top level method to initialize all the resources required.

            Executor: distributor-process
        """
        self._event_handlers = EventHandlers()
        self._rpc_agents = []
        self._modules = self.modules_init(self._modules)
        self._workers = self._workers_init()
        self._pollhandler = self._poll_handler_init()
        self._loadbalancer = nfp_lb.StickyRoundRobin(self._workers)

    def _workers_init(self):
        """Initialize the configured number of worker process.

            This method just creates the process and not start them.
            An event queue per worker process is created.

            Executor: distributor-process.
        """
        wc = oslo_config.CONF.workers
        LOG(LOGGER, 'INFO', "Creating %d number of workers" % (wc))

        ev_workers = [tuple() for w in range(0, wc)]

        for w in range(0, wc):
            # Create pipe for communication.
            ppipe, cpipe = multiprocessing.Pipe(duplex=True)
            # Worker class.
            evq_handler = nfp_event.EventQueueHandler(
                self, self._conf, cpipe, self._event_handlers, self._modules)
            mp_process = multiprocessing.Process
            # create process using multiprocessing.
            worker = mp_process(target=evq_handler.run, args=(cpipe,))
            worker.daemon = True
            ev_workers[w] = ev_workers[w] + (worker, ppipe, evq_handler)
        return ev_workers

    def _add_lifetime_event(self, event):
        """Add a timer event to poll for lifetime of an event.

            For every new event generated in core and lifetime
            set, polling event is auto added. After event expires
            it is autocancelled and module is informed.

            Executor: distributor-process
        """
        # convert event lifetime in to polling time
        max_times = int(
            event.lifetime / self._conf.periodic_interval)
        if event.lifetime % self._conf.periodic_interval:
            max_times += 1

        timer_ev = self.new_event(
            id='POLL_EVENT_EXPIRY', data=event,
            binding_key=event.binding_key, key=event.desc.uid)
        timer_ev.desc.worker_attached = event.desc.worker_attached
        self.poll_event(timer_ev, max_times=max_times)

    def _pipe_send(self, pipe, event):
        """Send data to a pipe.

        """
        self.compress(event)
        pipe.send(event)


def modules_import():
    """Imports all the .py files from specified modules dir """
    modules = []
    base_module = __import__(oslo_config.CONF.modules_dir,
                             globals(), locals(), ['modules'], -1)

    modules_dir = base_module.__path__[0]

    syspath = sys.path
    sys.path = [modules_dir] + syspath

    try:
        files = os.listdir(modules_dir)
    except OSError:
        LOG(LOGGER, 'ERROR', "Failed to read files from directory %s" %
            (modules_dir))
        files = []

    for fname in files:
        if fname.endswith(".py") and fname != '__init__.py':
            try:
                module = __import__(oslo_config.CONF.modules_dir,
                                    globals(), locals(), [fname[:-3]], -1)
                modules += [eval('module.%s' % (fname[:-3]))]
            except Exception as exc:
                LOG(LOGGER, 'ERROR', "NFP module %s import failed." % (fname))

    sys.path = syspath
    return modules


def load_nfp_symbols(namespace):
    """Load all the required symbols in global namespace. """
    nfp_common.load_nfp_symbols(namespace)
    namespace['Event'] = nfp_event.Event
    namespace['EventDesc'] = nfp_event.EventDesc
    namespace['EventSequencer'] = nfp_event.EventSequencer
    namespace['EventQueueHandler'] = nfp_event.EventQueueHandler
    namespace['ReportStateTask'] = nfp_rpc.ReportStateTask
    namespace['PollingTask'] = nfp_poll.PollingTask
    namespace['PollQueueHandler'] = nfp_poll.PollQueueHandler

load_nfp_symbols(globals())


def common_init():
    oslo_config.CONF.register_opts(nfp_config.OPTS)
    oslo_config.CONF.register_opts(
        nfp_config.es_openstack_opts, "keystone_authtoken")

    # Since other imports are registering the logging configuration
    # parameters, these are overridden to make sure that the core
    # configuration parameters are effective.
    oslo_config.CONF.set_override('use_syslog', 'True')
    oslo_config.CONF.set_override('syslog_log_facility', 'local1')

    # n_config.register_interface_driver_opts_helper(oslo_config.CONF)
    # n_config.register_agent_state_opts_helper(oslo_config.CONF)
    # n_config.register_root_helper(oslo_config.CONF)

    n_common_config.init(sys.argv[1:])
    n_config.setup_logging()


def main():
    common_init()

    # Importing all the nfp modules from conf.modules_dir
    modules = modules_import()

    sc = Controller(oslo_config.CONF, modules)
    # Start the controller to start all contexts.
    sc.start()
    # Inform each loaded module about init complete
    sc.init_complete()
    # Wait for the workers
    sc.wait()
