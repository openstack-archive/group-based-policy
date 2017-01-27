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
import pickle
import Queue
import sys
import time
import zlib

from oslo_config import cfg as oslo_config
from oslo_service import service as oslo_service

from gbpservice.nfp.core import cfg as nfp_cfg
from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import launcher as nfp_launcher
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import manager as nfp_manager
from gbpservice.nfp.core import poll as nfp_poll
from gbpservice.nfp.core import rpc as nfp_rpc
from gbpservice.nfp.core import worker as nfp_worker

# REVISIT (mak): Unused, but needed for orchestrator,
# remove from here and add in orchestrator
from neutron.common import config

LOG = nfp_logging.getLogger(__name__)
PIPE = multiprocessing.Pipe
LOCK = multiprocessing.Lock
PROCESS = multiprocessing.Process
identify = nfp_common.identify

# REVISIT (mak): fix to pass compliance check
config = config

"""Implements NFP service.

    Base class for nfp modules, modules can invoke methods
    of this class to interact with core.
"""


class NfpService(object):

    def __init__(self, conf):
        self._conf = conf
        self._event_handlers = nfp_event.NfpEventHandlers()
        self._rpc_agents = {}

    def _make_new_event(self, event):
        """Make a new event from the object passed. """
        desc = event.desc
        event_dict = event.__dict__
        event = self.create_event(**event_dict)
        event.desc.from_desc(desc)
        return event

    def get_event_handlers(self):
        return self._event_handlers

    def register_events(self, event_descs, priority=0):
        """Register event handlers with core. """
        logging_context = nfp_logging.get_logging_context()
        module = logging_context['namespace']
        # REVISIT (mak): change name to register_event_handlers() ?
        for event_desc in event_descs:
            self._event_handlers.register(
                event_desc.id, event_desc.handler,
                module, priority=priority)

    def register_rpc_agents(self, agents):
        """Register rpc handlers with core. """

        for agent in agents:
            topic = agent.topic
            try:
                self._rpc_agents[topic]['agents'].append(agent)
            except KeyError:
                self._rpc_agents[topic] = {}
                self._rpc_agents[topic]['agents'] = [agent]

    def new_event(self, **kwargs):
        """Define and return a new event. """
        return self.create_event(**kwargs)

    def create_event(self, **kwargs):
        """To create a new event. """
        event = None
        try:
            event = nfp_event.Event(**kwargs)
            # Get the logging context stored in thread
            logging_context = nfp_logging.get_logging_context()
            # Log metadata for event handling code
            event.context = logging_context
        except AssertionError as aerr:
            message = "%s" % (aerr)
            LOG.exception(message)
        return event

    def post_graph(self, graph_nodes, root_node):
        """Post graph.

            Since graph is also implemneted with events,
            first post all the node events followed by
            root node event.
        """
        for node in graph_nodes:
            self.post_event(node)

        self.post_event(root_node)

    def post_event(self, event, target=None):
        """Post an event.

            As a base class, it only does the descriptor preparation.
            NfpController class implements the required functionality.
        """
        handler, module = (
            self._event_handlers.get_event_handler(event.id, module=target))
        assert handler, "No handler registered for event %s" % (event.id)
        event.desc.type = nfp_event.SCHEDULE_EVENT
        event.desc.flag = nfp_event.EVENT_NEW
        event.desc.pid = os.getpid()
        event.desc.target = module
        return event

    # REVISIT (mak): spacing=0, caller must explicitly specify
    def poll_event(self, event, spacing=2, max_times=sys.maxint):
        """To poll for an event.

            As a base class, it only does the polling
            descriptor preparation.
            NfpController class implements the required functionality.
        """
        logging_context = nfp_logging.get_logging_context()
        module = logging_context['namespace']
        handler, ev_spacing = (
            self._event_handlers.get_poll_handler(event.id, module=module))
        assert handler, "No poll handler found for event %s" % (event.id)
        assert spacing or ev_spacing, "No spacing specified for polling"
        if ev_spacing:
            spacing = ev_spacing
        refuuid = event.desc.uuid
        event = self._make_new_event(event)
        event.lifetime = 0
        event.desc.type = nfp_event.POLL_EVENT
        event.desc.target = module

        kwargs = {'spacing': spacing,
                  'max_times': max_times,
                  'ref': refuuid}
        poll_desc = nfp_event.PollDesc(**kwargs)

        setattr(event.desc, 'poll_desc', poll_desc)
        return event

    def event_complete(self, event, result=None):
        """To declare and event complete. """
        try:
            pickle.dumps(result)
            event.sequence = False
            event.desc.flag = nfp_event.EVENT_COMPLETE
            event.result = result
            return event
        except Exception as e:
            raise e

    def create_work(self, work):
        """Create a work, collection of events. """
        pass


"""NFP Controller class mixin other nfp classes.

    Nfp modules get the instance of this class when
    they are initialized.
    Nfp modules interact with core using the methods
    of 'Service' class, whose methods are implemented
    in this class.
    Also, it mixes the other nfp core classes to complete
    a nfp module request.
"""


class NfpController(nfp_launcher.NfpLauncher, NfpService):

    def __new__(cls, *args, **kwargs):
        singleton = kwargs.get('singleton', True)
        if singleton is False:
            return object.__new__(cls, *args, **kwargs)

        if not hasattr(cls, '_instance'):
            cls._instance = object.__new__(cls, *args, **kwargs)
        else:
            cls.__init__ = cls.__inited__
        return cls._instance

    def __inited__(self, conf):
        pass

    def __init__(self, conf, singleton=True):
        # Init the super classes.
        nfp_launcher.NfpLauncher.__init__(self, conf)
        NfpService.__init__(self, conf)

        # For book keeping
        self._worker_process = {}
        self._conf = conf
        self._pipe = None
        # Queue to stash events.
        self._stashq = multiprocessing.Queue()

        self._manager = nfp_manager.NfpResourceManager(conf, self)
        self._worker = nfp_worker.NfpWorker(conf)
        self._poll_handler = nfp_poll.NfpPollHandler(conf)

        # ID of process handling this controller obj
        self.PROCESS_TYPE = "distributor"

    def compress(self, event):
        # REVISIT (mak) : zip only if length is > than threshold (1k maybe)
        if event.data and not event.zipped:
            event.zipped = True
            event.data = zlib.compress(str({'cdata': event.data}))

    def decompress(self, event):
        if event.data and event.zipped:
            try:
                data = ast.literal_eval(
                    zlib.decompress(event.data))
                event.data = data['cdata']
                event.zipped = False
            except Exception as e:
                message = "Failed to decompress event data, Reason: %s" % (
                    e)
                LOG.error(message)
                raise e

    def pipe_lock(self, lock):
        if lock:
            lock.acquire()

    def pipe_unlock(self, lock):
        if lock:
            lock.release()

    def pipe_recv(self, pipe, lock):
        self.pipe_lock(lock)
        event = pipe.recv()
        self.pipe_unlock(lock)
        if event:
            self.decompress(event)
        return event

    def pipe_send(self, pipe, lock, event):
        try:
            self.compress(event)
            self.pipe_lock(lock)
            pipe.send(event)
            self.pipe_unlock(lock)
        except Exception as e:
            message = "Failed to send data via pipe, Reason: %s" % (e)
            LOG.error(message)
            raise e

    def _fork(self, args):
        proc = PROCESS(target=self.child, args=args)
        proc.daemon = True
        proc.start()
        return proc

    def _manager_task(self):
        while True:
            # Run 'Manager' here to monitor for workers and
            # events.
            self._manager.manager_run()
            eventlet.greenthread.sleep(0.1)

    def _update_manager(self):
        childs = self.get_childrens()
        for pid, wrapper in childs.iteritems():
            pipe, lock = wrapper.child_pipe_map[pid]
            # Inform 'Manager' class about the new_child.
            self._manager.new_child(pid, pipe, lock)

    def _process_event(self, event):
        self._manager.process_events([event])

    def get_childrens(self):
        # oslo_process.ProcessLauncher has this dictionary,
        # 'NfpLauncher' derives oslo_service.ProcessLauncher
        return self.children

    def fork_child(self, wrap):
        """Forks a child.

            Creates a full duplex pipe for child & parent
            to communicate.

            Returns: Multiprocess object.
        """

        parent_pipe, child_pipe = PIPE(duplex=True)

        # Sometimes Resource Temporarily Not Available (errno=11)
        # is observed with python pipe. There could be many reasons,
        # One theory is if read &
        # write happens at the same instant, pipe does report this
        # error. Using lock to avoid this.
        lock = LOCK()

        # Registered event handlers of nfp module.
        # Workers need copy of this data to dispatch an
        # event to module.
        proc = self._fork(args=(wrap.service, parent_pipe, child_pipe,
                                lock, self))

        message = ("Forked a new child: %d"
                   "Parent Pipe: % s, Child Pipe: % s") % (
                    proc.pid, str(parent_pipe), str(child_pipe))
        LOG.info(message)

        try:
            wrap.child_pipe_map[proc.pid] = (parent_pipe, lock)
        except AttributeError:
            setattr(wrap, 'child_pipe_map', {})
            wrap.child_pipe_map[proc.pid] = (parent_pipe, lock)

        self._worker_process[proc.pid] = proc
        return proc.pid

    def launch(self, workers):
        """Launch the controller.

            Uses Oslo Service to launch with configured #of workers.
            Spawns a manager task to manager nfp events & workers.

            :param workers: #of workers to be launched

            Returns: None
        """
        super(NfpController, self).launch_service(
            self._worker, workers=workers)

    def post_launch(self):
        """Post processing after workers launch.

            Tasks which needs to run only on distributor
            process and any other resources which are not
            expected to be forked are initialized here.
        """
        self._update_manager()

        # create and launch rpc service agent for each topic
        for key, value in self._rpc_agents.iteritems():
            agents = value['agents']
            # Register NFP RPC managers in priority order,
            # so that on rpc, oslo invokes them in the given order,
            # This is required for NFP where multiple managers of
            # different priority register for same rpc.
            sorted_agents = sorted(
                agents, key=operator.attrgetter('priority'), reverse=True)
            rpc_managers = [agent.manager for agent in sorted_agents]
            service = nfp_rpc.RpcService(topic=key, managers=rpc_managers)
            # Launch rpc_service_agent
            # Use threads for launching service
            launcher = oslo_service.launch(
                self._conf, service, workers=None)

            self._rpc_agents[key]['service'] = service
            self._rpc_agents[key]['launcher'] = launcher

        # One task to manage the resources - workers & events.
        eventlet.spawn_n(self._manager_task)
        # Oslo periodic task to poll for timer events
        nfp_poll.PollingTask(self._conf, self)
        # Oslo periodic task for state reporting
        nfp_rpc.ReportStateTask(self._conf, self)

    def poll_add(self, event, timeout, callback):
        """Add an event to poller. """
        self._poll_handler.poll_add(
            event, timeout, callback)

    def poll(self):
        """Invoked in periodic task to poll for timedout events. """
        self._poll_handler.run()

    def report_state(self):
        """Invoked by report_task to report states of all agents. """
        for value in self._rpc_agents.itervalues():
            for agent in value['agents']:
                agent.report_state()

    def _verify_graph(self, graph):
        """Checks for sanity of a graph definition.

            Checks if the same node is root node for
            two subgraphs.
            Unwinds graph and return two values -
            graph signature and graph elements.
        """
        graph_sig = {}
        graph_nodes = []
        for parent, childs in graph.iteritems():
            puuid = parent.desc.uuid
            assert puuid not in graph_sig.keys(), (
                "Event - %s is already root of subgraph - %s" % (
                    puuid, str(graph_sig[puuid])))
            graph_sig[puuid] = []
            for child in childs:
                graph_sig[puuid].append(child.desc.uuid)
                graph_nodes.append(child)

        return graph_sig, graph_nodes

    def post_graph(self, graph, root, graph_str=''):
        """Post a new graph into the system.

            Graph is definition of events to be
            dispatched in a particular pattern.
        """
        graph_sig, graph_nodes = self._verify_graph(graph)
        graph_data = {
            'id': root.desc.uuid + "_" + graph_str,
            'root': root.desc.uuid,
            'data': graph_sig}

        for graph_node in graph_nodes:
            graph_node.desc.graph = graph_data

        root.desc.graph = graph_data

        super(NfpController, self).post_graph(graph_nodes, root)

    def post_event(self, event, target=None):
        """Post a new event into the system.

            If distributor(main) process posts an event, it
            is delivered to the worker.
            If worker posts an event, it is deliverd to
            distributor for processing, where it can decide
            to loadbalance & sequence events.

            :param event: Object of 'Event' class.

            Returns: None
        """
        event = super(NfpController, self).post_event(event, target=target)
        message = "(event - %s) - New event" % (event.identify())
        LOG.debug(message)
        if self.PROCESS_TYPE == "worker":
            # Event posted in worker context, send it to parent process
            message = ("(event - %s) - new event in worker"
                       "posting to distributor process") % (event.identify())

            LOG.debug(message)
            # Send it to the distributor process
            self.pipe_send(self._pipe, self._lock, event)
        else:
            message = ("(event - %s) - new event in distributor"
                       "processing event") % (event.identify())
            LOG.debug(message)
            self._manager.process_events([event])

    def poll_event(self, event, spacing=2, max_times=sys.maxint):
        """Post a poll event into the system.

            Core will poll for this event to timeout, after
            timeout registered handler of module is invoked.

            :param event: Object of 'Event' class.
            :param spacing: Spacing at which event should timeout.
            :param max_times: Max #of times the event can timeout,
                after the max_times, event is auto cancelled by
                the core and the registered handler of module
                is invoked.

            Returns: None
        """
        # Poll event can only be posted by worker not by listener process
        if self.PROCESS_TYPE != "worker":
            message = "(event - %s) - poll event in distributor" % (
                event.identify())
            LOG.debug(message)
            # 'Service' class to construct the poll event descriptor
            event = super(NfpController, self).poll_event(
                event, spacing=spacing, max_times=max_times)
            self._manager.process_events([event])
        else:
            '''
            # Only event which is delivered to a worker can be polled for, coz,
            # after event timeouts, it should be delivered to the same worker,
            # hence the check to make sure the correct event is been asked for
            # polling.
            assert event.desc.worker, "No worker for event %s" % (
                event.identify())
            LOG.debug("(event - %s) - poll event in worker" %
                (event.identify()))
            '''
            # 'Service' class to construct the poll event descriptor
            event = super(NfpController, self).poll_event(
                event, spacing=spacing, max_times=max_times)
            # Send to the distributor process.
            self.pipe_send(self._pipe, self._lock, event)

    def stop_poll_event(self, key, id):
        """To stop the running poll event

        :param key: key of polling event
        :param id: id of polling event
        """
        key = key + ":" + id
        event = self.new_event(id='STOP_POLL_EVENT', data={'key': key})
        event.desc.type = nfp_event.POLL_EVENT
        event.desc.flag = nfp_event.POLL_EVENT_STOP
        if self.PROCESS_TYPE == "worker":
            self.pipe_send(self._pipe, self._lock, event)
        else:
            self._manager.process_events([event])

    def stash_event(self, event):
        """To stash an event.

            This will be invoked by worker process.
            Put this event in queue, distributor will
            pick it up.

            Executor: worker-process
        """
        if self.PROCESS_TYPE == "distributor":
            message = "(event - %s) - distributor cannot stash" % (
                event.identify())
            LOG.debug(message)
        else:
            message = "(event - %s) - stashed" % (event.identify())
            LOG.debug(message)
            self._stashq.put(event)

    def get_stashed_events(self):
        """To get stashed events.

            Returns available number of stashed events
            as list. Will be invoked by distributor,
            worker cannot pull.

            Executor: distributor-process
        """
        events = []
        # return at max 5 events
        maxx = 1
        # wait sometime for first event in the queue
        timeout = 0.1
        while maxx:
            try:
                event = self._stashq.get(timeout=timeout)
                self.decompress(event)
                events.append(event)
                timeout = 0
                maxx -= 1
            except Queue.Empty:
                maxx = 0
                pass
        return events

    def event_complete(self, event, result=None):
        """To mark an event complete.

            Module can invoke this API to mark an event complete.
                a) Next event in sequence will be scheduled.
                b) Event from cache is removed.
                c) Polling for event is stopped.
                d) If the worker dies before event is complete, the
                    event is scheduled to other available workers.

            :param event: Obj of 'Event' class

            Returns: None
        """
        message = "(event - %s) complete" % (event.identify())
        LOG.debug(message)
        event = super(NfpController, self).event_complete(event, result=result)
        if self.PROCESS_TYPE == "distributor":
            self._manager.process_events([event])
        else:
            # Send to the distributor process.
            self.pipe_send(self._pipe, self._lock, event)


def load_nfp_modules(conf, controller):
    modules_dirs = conf.nfp_modules_path
    pymodules = []
    for _dir in modules_dirs:
        pymodules.extend(load_nfp_modules_from_path(conf, controller,
                                                    _dir))
    return pymodules


def load_nfp_modules_from_path(conf, controller, path):
    """ Load all nfp modules from configured directory. """
    pymodules = []
    try:
        base_module = __import__(path,
                                 globals(), locals(), ['modules'], -1)
        modules_dir = base_module.__path__[0]
        try:
            files = os.listdir(modules_dir)
            for pyfile in set([f for f in files if f.endswith(".py")]):
                try:
                    pymodule = __import__(path,
                                          globals(), locals(),
                                          [pyfile[:-3]], -1)
                    pymodule = eval('pymodule.%s' % (pyfile[:-3]))
                    try:
                        namespace = pyfile[:-3].split(".")[-1]
                        nfp_logging.store_logging_context(namespace=namespace)
                        pymodule.nfp_module_init(controller, conf)
                        pymodules += [pymodule]
                        message = "(module - %s) - Initialized" % (
                            identify(pymodule))
                        LOG.debug(message)
                    except AttributeError as e:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        message = "Traceback: %s" % (exc_traceback)
                        LOG.error(message)
                        message = ("(module - %s) - does not implement"
                                   "nfp_module_init()") % (identify(pymodule))
                        LOG.warn(message)
                except ImportError:
                    message = "Failed to import module %s" % (pyfile)
                    LOG.error(message)
        except OSError:
            message = "Failed to read files from %s" % (modules_dir)
            LOG.error(message)
    except ImportError:
        message = "Failed to import module from path %s" % (
            path)
        LOG.error(message)

    return pymodules


def controller_init(conf, nfp_controller):
    nfp_controller.launch(conf.workers)
    # Wait for conf.workers*1 + 1 secs for workers to comeup
    time.sleep(conf.workers * 1 + 1)
    nfp_controller.post_launch()


def nfp_modules_post_init(conf, nfp_modules, nfp_controller):
    for module in nfp_modules:
        try:
            namespace = module.__name__.split(".")[-1]
            nfp_logging.store_logging_context(namespace=namespace)
            module.nfp_module_post_init(nfp_controller, conf)
        except AttributeError:
            message = ("(module - %s) - does not implement"
                       "nfp_module_post_init(), ignoring") % (identify(module))
            LOG.debug(message)


def extract_module(args):
    try:
        index = args.index('--module')
        module = args[index + 1]
        args.remove('--module')
        args.remove(module)
        return args, module
    except ValueError:
        print("--module <name> missing from cmd args")
        sys.exit(-1)


def load_module_opts(conf):
    module = conf.module
    # register each opt from <module> section
    # to default section.
    module_opts = eval('conf.%s.keys' % (module))()
    for module_opt in module_opts:
        module_cfg_opt = eval("conf.%s._group._opts['%s']['opt']" % (
            module, module_opt))
        module_cfg_opt_value = eval("conf.%s.%s" % (module, module_opt))
        conf.register_opt(module_cfg_opt)
        conf.set_override(module_opt, module_cfg_opt_value)


def main():
    args, module = extract_module(sys.argv[1:])
    conf = nfp_cfg.init(module, args)
    conf.module = module
    load_module_opts(conf)
    nfp_logging.init_logger(oslo_config.CONF.logger_class)
    nfp_common.init()
    nfp_controller = NfpController(conf)
    # Load all nfp modules from path configured
    nfp_modules = load_nfp_modules(conf, nfp_controller)
    # Init the controller, launch required contexts
    controller_init(conf, nfp_controller)
    # post_init of each module
    nfp_modules_post_init(conf, nfp_modules, nfp_controller)
    # Wait for every exec context to complete
    nfp_controller.wait()
