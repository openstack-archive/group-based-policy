import os
import time
import sys
import copy

import eventlet
eventlet.monkey_patch()

from multiprocessing.queues import Queue
from Queue import Empty, Full

from oslo.config import cfg

from neutron.agent.common import config
from neutron.common import config as common_config

from neutron.openstack.common import log as logging

from gbpservice.neutron.nsf.core import cfg as core_cfg
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
        '''
        self.tg.add_timer(
            #cfg.CONF.evs_polling_interval,
            cfg.CONF.periodic_interval,
            # self.manager.run_periodic_tasks,
            self.periodic_task.run_periodic_tasks,
            None,
            None
        )
        '''


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
        # self._sc.timeout()


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
        self.poll_event = False  # Not to be used by user
        self.worker_attached = None  # Not to be used by user


class EventCache(object):

    def __init__(self, sc):
        self._sc = sc
        self._cache = []

    def rem(self, ev):
        self._sc.lock()
        self._cache.remove(ev)
        self._sc.unlock()

    def rem_multi(self, evs):
        self._sc.lock()
        for ev in evs:
            self._cache.remove(ev)
        self._sc.unlock()

    def add(self, ev):
        self._sc.lock()
        self._cache.append(ev)
        self._sc.unlock()

    def copy(self):
        self._sc.lock()
        evs = self._cache[:]
        self._sc.unlock()
        return evs


class Serializer(object):

    def __init__(self, sc):
        self._sc = sc
        self._serializer_map = {}
            #{'pid':{'binding_key':{'in_use':True, 'queue':[]}}}

    def serialize(self, ev):
        queued = False
        self._sc.lock()
        if ev.worker_attached not in self._serializer_map:
            self._serializer_map[ev.worker_attached] = {}
        mapp = self._serializer_map[ev.worker_attached]
        if ev.binding_key in mapp.keys():
            queued = True
            mapp[ev.binding_key]['queue'].append(ev)
        else:
            mapp[ev.binding_key] = {'in_use': True, 'queue': []}
        self._sc.unlock()
        return queued

    def deserialize(self, ev):
        self._sc.lock()
        mapp = self._serializer_map[ev.worker_attached][ev.binding_key]
        if mapp['queue'] == []:
            del self._serializer_map[ev.worker_attached][ev.binding_key]
        self._sc.unlock()

    def copy(self):
        self._sc.lock()
        copy = dict(self._serializer_map)
        self._sc.unlock()
        return copy

    def remove(self, ev):
        self._sc.lock()
        self._serializer_map[ev.worker_attached][
            ev.binding_key]['queue'].remove(ev)
        self._sc.unlock()


class PollWorker(object):

    def __init__(self, sc, qu, eh, batch=-1):
        self._sc = sc
        self._cache = EventCache(sc)
        self._pollq = qu
        self._procidx = 0
        self._procpending = 0
        self._batch = 10 if batch == -1 else batch

    def add(self, event):
        self._pollq.put(event)

    def rem(self, event):
        remevs = []
        cache = self._cache.copy()
        for el in cache:
            if el.key == event.key:
                remevs.append(el)
        self._cache.rem_multi(remevs)

    def _get(self):
        try:
            return self._pollq.get(timeout=0.1)
        except Empty:
            return None

    def fill(self):
        # Get some events from queue into cache
        for i in range(0, 10):
            ev = self._get()
            if ev:
                self._cache.add(ev)

    def peek(self, idx, count):
        cache = self._cache.copy()
        qlen = len(cache)
        pull = qlen if (idx + count) > qlen else count
        return cache[idx:(idx + pull)], pull

    def event_done(self, ev):
        self.rem(ev)

    def event(self, ev):
        ev1 = copy.deepcopy(ev)
        ev1.serialize = False
        ev1.poll_event = True
        self._sc.rpc_event(ev1)

    def process(self, ev):
        self.event_done(ev) if ev.id == 'POLL_EVENT_DONE' else self.event(ev)

    def poll(self):
        # Fill the cache first
        self.fill()
        # Peek the events from cache
        evs, count = self.peek(0, self._batch)
        for ev in evs:
            self.process(ev)
        self._procidx = (self._procidx + count) % (self._batch)


class EventWorker(object):

    def __init__(self, sc, qu, eh):
        self._tpool = core_tp.ThreadPool()
        self._evq = qu
        self._eh = eh
        self._sc = sc

    def _get(self):
        # Check if any event can be pulled from serialize_map - this evs may be
        # waiting long enough
        ev = self._sc.serialize_get()
        if not ev:
            try:
                ev = self._evq.get(timeout=0.1)
            except Empty:
                pass
            if ev:
                ev = self._sc.serialize(ev)
        return ev

    def run(self, qu):
        while True:
            ev = self._get()
            if ev:
                eh = self._eh.get(ev)
                if not ev.poll_event:
                    self._tpool.dispatch(eh.handle_event, ev)
                else:
                    self._tpool.dispatch(eh.handle_poll_event, ev)
            time.sleep(0)  # Yield the CPU

    '''
    def _get_ev(self):
        return self._evq.get()

    def run(self, qu):
        while True:
            ev = self._get_ev()
            if ev:
                ev.worker = self
                eh = self._eh.get(ev)
                if not ev.poll_event:
                    self._tpool.dispatch(eh.handle_event, ev)
                else:
                    self._tpool.dispatch(eh.handle_poll_event, ev)
            time.sleep(0)  # Yield the CPU
    '''


class EventHandlers(object):

    def __init__(self):
        self._ehs = {}

    def register(self, ev):
        if ev.id in self._ehs.keys():
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
        self._lock = Lock()
        self._serializer = Serializer(self)

    def lock(self):
        self._lock.acquire()

    def unlock(self):
        self._lock.release()

    def event_done(self, ev):
        mapp = self._serializer.copy()
        mapp = mapp[ev.worker_attached]
        if ev.binding_key not in mapp:
            return

        qu = mapp[ev.binding_key]['queue']
        for elem in qu:
            if elem.key == ev.key:
                self._serializer.remove(elem)
                break
        self._serializer.deserialize(ev)

    def serialize(self, ev):
        if not ev.serialize:
            return ev
        if not self._serializer.serialize(ev):
            return ev
        return None

    def serialize_get(self):
        smap = self._serializer.copy()
        for mapp in smap.values():
            for val in mapp.values():
                if val['in_use']:
                    continue
                else:
                    if val['queue'] == []:
                        continue
                    return val['queue'][0]
        return None

    def workers_init(self):
        wc = 2 * (multiprocessing.cpu_count())
        if cfg.CONF.workers != wc:
            wc = cfg.CONF.workers
            LOG.debug("Creating configured #of workers:%d" % (wc))

        workers = [tuple() for w in range(0, wc)]

        for w in range(0, wc):
            # qu = LookAheadQueue()
            qu = Queue()
            evworker = EventWorker(self, qu, self.ehs)
            proc = Process(target=evworker.run, args=(qu,))
            proc.daemon = True
            workers[w] = workers[w] + (proc, qu, evworker)
        return workers

    def poll_init(self):
        # qu = LookAheadQueue()
        qu = Queue()
        ph = PollWorker(self, qu, self.ehs)
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
        # self.workers, self.timer_worker = self.workers_init()
        self.workers = self.workers_init()
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

        # self.timer_worker[0].start()
        for w in self.workers:
            w[0].start()

    def rpc_event(self, event):
        worker = self.loadbalancer.get(event.binding_key)
        event.worker_attached = worker[0].pid
        qu = worker[1]
        qu.put(event)

    def poll_event(self, event):
        self.pollhandler.add(event)

    def poll_event_done(self, event):
        event.id = 'POLL_EVENT_DONE'
        self.pollhandler.add(event)

    def timeout(self):
        self.pollhandler.poll()

    def poll(self):
        while True:
            self.timeout()
            time.sleep(1)

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
    base_module = __import__(cfg.CONF.modules_dir,
                             globals(), locals(), ['modules'], -1)
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
            module = __import__(cfg.CONF.modules_dir,
                                globals(), locals(), [fname[:-3]], -1)
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
    sc.poll()
    sc.wait()
