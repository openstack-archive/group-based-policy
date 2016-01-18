import os
import time
import sys

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg

from neutron.agent.common import config
from neutron.common import config as common_config

from neutron.openstack.common import log as logging

from gbpservice.neutron.nsf.core.lahq import LookAheadQueue
from gbservice.neutron.nsf.core import cfg as core_cfg
from gbpservice.neutron.nsf.core import lb as core_lb
from gbpservice.neutron.nsf.core import threadpool as core_tp

if core_cfg.SERVER == 'rpc':
    from neutron.common import rpc as n_rpc
if core_cfg.SERVER == 'unix':
    from gbpservice.neutron.nsf.core import unix as n_rpc

from neutron.openstack.common import periodic_task

from multiprocessing import Process, Queue, Lock
import multiprocessing as multiprocessing

from neutron.openstack.common import service as os_service

LOG = logging.getLogger(__name__)


class RpcManager(n_rpc.RpcCallback):

    def __init__(self, conf):
        super(RpcManager, self).__init__()


class RpcAgent(n_rpc.Service):

    def __init__(self, sc, host=None, topic=None, manager=None):
        super(RpcAgent, self).__init__(host=host, topic=topic, manager=manager)
        self.periodic_task = PeriodicTask(sc)

    def start(self):
        super(RpcAgent, self).start()
        self.tg.add_timer(
            cfg.CONF.periodic_interval,
            # self.manager.run_periodic_tasks,
            self.periodic_task.run_periodic_tasks,
            None,
            None
        )


class RpcAgents(object):

    def __init__(self):
        self.services = []
        self.launchers = []

    def add(self, agents):
        self.services.extend(agents)

    def launch(self):
        for s in self.services:
            l = os_service.launch(s)
            self.launchers.extend([l])

    def wait(self):
        for l in self.launchers:
            l.wait()


class PeriodicTask(periodic_task.PeriodicTasks):

    def __init__(self, sc):
        super(PeriodicTask, self).__init__()
        self._sc = sc

    @periodic_task.periodic_task(spacing=1)
    def periodic_sync_task(self, context):
        LOG.debug(_("Periodic sync task invoked !"))
        self._sc.timeout()


class Event(object):

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.data = kwargs.get('data')
        self.handler = kwargs.get('handler')


class PollWorker(object):

    def __init__(self, qu, eh, batch=-1):
        self._pollq = qu
        self._eh = eh
        self._procidx = 0
        self._procpending = 0
        self._batch = 10 if batch == -1 else batch

    def add(self, event, id):
        self._pollq.put(event)

    def poll(self):
        # On each timeout try to process max num of events
        evs = self._pollq.peek(self._procidx, self._batch)
        for ev in evs:
            self._eh.get(ev).handle_event(ev)
        self._procidx = (self._procidx + self._batch) % (self._batch)


class TimerWorker(object):

    def __init__(self, qu, eh, batch=-1):
        self._pollq = qu
        self._eh = eh
        self._procidx = 0
        self._procpending = 0
        self._batch = 10 if batch == -1 else batch

    def run(self, qu):
        while True:
            # On each timeout try to process max num of events
            evs = self._pollq.peek(self._procidx, self._batch)
            for ev in evs:
                self._eh.get(ev).handle_event(ev)
            self._procidx = (self._procidx + self._batch) % (self._batch)
        time.sleep(1)  # Yield the CPU


class EventWorker(object):

    def __init__(self, qu, eh):
        self._tpool = core_tp.ThreadPool()
        self._evq = qu
        self._eh = eh

    def run(self, qu):
        while True:
            ev = self._evq.get()
            if ev:
                eh = self._eh.get(ev)
                self._tpool.dispatch(eh.handle_event, ev)
            time.sleep(0)  # Yield the CPU


class EventHandlers(object):

    def __init__(self):
        self._ehs = {}

    def register(self, ev):
        if self._ehs.has_key(ev.id):
            self._ehs[ev.id].extend([ev])
        else:
            self._ehs[ev.id] = [ev]

    def get(self, ev):
        for id, eh in self._ehs.iteritems():
            if id == ev.id:
                return eh[0].handler
        return None


class ServiceController(object):

    def __init__(self, conf, modules):
        self._conf = conf
        self.modules = modules

    def workers_init(self):
        wc = 2 * (multiprocessing.cpu_count())
        if cfg.CONF.workers != wc:
            wc = cfg.CONF.workers
            LOG.debug("Creating configured #of workers:%d" % (wc))

        workers = [tuple() for w in range(0, wc)]

        for w in range(0, wc):
            qu = LookAheadQueue()
            proc = Process(target=EventWorker(qu, self.ehs).run, args=(qu,))
            proc.daemon = True
            workers[w] = workers[w] + (proc, qu)

        qu = LookAheadQueue()
        proc = Process(target=TimerWorker(qu, self.ehs).run, args=(qu,))
        proc.daemon = True
        timer_worker = (proc, qu)
        return workers, timer_worker

    def poll_init(self):
        qu = LookAheadQueue()
        ph = PollWorker(qu, self.ehs)
        return ph

    def modules_init(self, modules):
        for module in modules:
            try:
                module.module_init(self, self._conf)
            except AttributeError as s:
                print(module.__dict__)
                raise AttributeError(module.__file__ + ': ' + str(s))
            return modules

    def _init(self):
        self.ehs = EventHandlers()
        self.rpc_agents = RpcAgents()
        self.modules = self.modules_init(self.modules)
        self.workers, self.timer_worker = self.workers_init()
        self.pollhandler = self.poll_init()
        self.loadbalancer = getattr(
            globals()['core_lb'], cfg.CONF.RpcLoadBalancer)(self.workers)

    def wait(self):
        # self.rpc_agents.wait()
        for w in self.workers:
            w[0].join()

    def start(self):
        self._init()

        # for m in self.modules:
            # m.run()

        self.rpc_agents.launch()

        self.timer_worker[0].start()
        for w in self.workers:
            w[0].start()

    def rpc_event(self, event, id):
        worker = self.loadbalancer.get(id)
        qu = worker[1]
        qu.put(event)

    def poll_event(self, event, id):
        self.pollhandler.add(event, id)
            # qu = self.timer_worker[1]
            # qu.put(event)

    def timeout(self):
        self.pollhandler.poll()

    def register_events(self, evs):
        for ev in evs:
            self.ehs.register(ev)

    def register_rpc_agents(self, agents):
        self.rpc_agents.add(agents)

    def event(self, **kwargs):
        return Event(**kwargs)

    def unit_test(self):
        for module in self.modules:
            module.unit_test(self._conf, self)


def modules_import():
    modules = []
    # os.path.realpath(__file__)
    base_module = __import__(
        cfg.CONF.modules_dir, globals(), locals(), ['modules'], -1)
    # modules_dir = os.getcwd() + "/../modules"
    modules_dir = base_module.__path__[0]
    syspath = sys.path
    sys.path = [modules_dir] + syspath
    try:
        files = os.listdir(modules_dir)
    except OSError:
        print "Failed to read files"
        files = []

    for fname in files:
        if fname.endswith(".py") and fname != '__init__.py':
            module = __import__(
                cfg.CONF.modules_dir, globals(), locals(), [fname[:-3]], -1)
            modules += [eval('module.%s' % (fname[:-3]))]
            # modules += [__import__(fname[:-3])]
    sys.path = syspath
    return modules


def main():
    cfg.CONF.register_opts(core_cfg.OPTS)
    modules = modules_import()
    config.register_interface_driver_opts_helper(cfg.CONF)
    config.register_agent_state_opts_helper(cfg.CONF)
    config.register_root_helper(cfg.CONF)

    common_config.init(sys.argv[1:])
    config.setup_logging()

    sc = ServiceController(cfg.CONF, modules)
    sc.start()
    sc.unit_test()
    sc.wait()
