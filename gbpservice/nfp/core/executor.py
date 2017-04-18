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


from argparse import Namespace

from gbpservice.nfp.core import context
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import threadpool as core_tp

LOG = nfp_logging.getLogger(__name__)


class InUse(Exception):

    """Exception raised when same task executor instance
        is fired twice or jobs
        added after executor is fired.
    """
    pass


def check_in_use(f):
    """Check if instance of task executor is already
        fired and executing jobs.
    """

    def wrapped(self, *args, **kwargs):
        if self.fired:
            raise InUse("Executor in use")
        return f(self, *args, **kwargs)
    return wrapped


class TaskExecutor(object):

    """Executes given jobs in green threads.

        Any number of jobs can be added till executor
        is fired. When fired, executes all jobs in
        parallel in green threads. Waits for threads
        to complete, captures the return values of thread
        function.
        Caller can choose to pass result_store where the
        return value will be updated.
    """

    def __init__(self, jobs=0):
        if not jobs:
            self.thread_pool = core_tp.ThreadPool()
        else:
            self.thread_pool = core_tp.ThreadPool(thread_pool_size=jobs)

        self.pipe_line = []
        self.fired = False

    @check_in_use
    def add_job(self, id, func, *args, **kwargs):
        result_store = kwargs.pop('result_store', None)

        job = {
            'id': id, 'method': func,
            'args': args, 'kwargs': kwargs
        }

        if result_store is not None:
            job.update({'result_store': result_store})

        LOG.debug("TaskExecutor - (job - %s) added to pipeline" %
                  (str(job)))

        self.pipe_line.append(job)

    def _complete(self):
        LOG.debug("TaskExecutor - complete")
        self.pipe_line = []
        self.fired = False

    def dispatch(self, job):
        context.init()
        return job['method'](*job['args'], **job['kwargs'])

    @check_in_use
    def fire(self):
        self.fired = True
        for job in self.pipe_line:
            LOG.debug(
                "TaskExecutor - (job - %s) dispatched" %
                (str(job)))

            th = self.thread_pool.dispatch(self.dispatch, job)
            job['thread'] = th

        for job in self.pipe_line:
            result = job['thread'].wait()
            LOG.debug(
                "TaskExecutor - (job - %s) complete" %
                (str(job)))

            job.pop('thread')
            job['result'] = result
            if 'result_store' in job.keys():
                job['result_store']['result'] = result

        done_jobs = self.pipe_line[:]
        self._complete()
        return done_jobs


class EventGraphExecutor(object):

    """Executor which executs a graph of events.

        An event graph can consist of events defined
        in any combination of parallel and sequence
        events. Executor will execute them in the
        order and manner specified.
        Eg., E1 -> (E2, E3)
                [E1 should execute after E2, E3 completes,
                 while E2 & E3 can happen in parallel]
            E2 -> (E4, E5)
                [E2 should execute after E4, E5 completes,
                 while E4 & E5 should happen in sequence]
            E3 -> (None)
                [No child events for E3]

        Executor will run the above graph and execute events
        in the exact specific order mentioned.
        At each level, parent event holds the result of child
        events, caller can use parent event complete notification
        to get the child events execution status.
    """

    def __init__(self, manager):
        self.manager = manager
        self.running = {}

    def add(self, graph):
        assert graph['id'] not in self.running.keys(), "Graph - %s \
            is already running" % (graph['id'])
        graph['results'] = dict.fromkeys(graph['data'])
        self.running[graph['id']] = graph
        self.run(graph['id'], graph['root'])

    def run(self, graph_id, node):
        graph = self.running[graph_id]
        leafs = self._leafs(graph['data'], node)
        if leafs == []:
            results = self._results(graph, node)
            self._schedule(node, results=results)
        else:
            self._dispatch(graph, leafs)

    def _results(self, graph, node):
        try:
            return self.running['results'][node]
        except KeyError:
            return []

    def _dispatch(self, graph, nodes):
        for node in nodes:
            event = self.manager.get_event(node)
            if event.sequence:
                self._schedule(node)
            else:
                self.run(graph['id'], node)

    def _leafs(self, tree, root):
        leafs = []
        try:
            leafs = tree[root]
        finally:
            return leafs

    def _root(self, graph, of):
        tree = graph['data']
        for root, nodes in tree.iteritems():
            if of in nodes:
                return root
        return None

    def _schedule(self, node, results=None):
        results = results or []
        event = self.manager.get_event(node)
        event.result = results
        self.manager._scheduled_new_event(event)

    def _graph(self, node):
        for graph in self.running.values():
            root = self._root(graph, node)
            if root:
                return graph

    def _prepare_result(self, node, result):
        result_obj = Namespace()
        key, id = node.split(':')
        result_obj.id = id
        result_obj.key = key
        result_obj.result = result
        return result_obj

    def _update_result(self, graph, root, result):
        if not graph['results'][root]:
            graph['results'][root] = []
        graph['results'][root].append(result)
        return graph['results'][root]

    def conntinue(self, completed_node, result):
        graph = self._graph(completed_node)
        if graph:
            if completed_node == graph['root']:
                # Graph is complete here, remove from running_instances
                self.running.pop(graph['id'])
            else:
                root = self._root(graph, completed_node)
                graph['data'][root].remove(completed_node)
                result = self._prepare_result(completed_node, result)
                results = self._update_result(graph, root, result)
                if graph['data'][root] == []:
                    self._schedule(root, results=results)
