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

    @check_in_use
    def fire(self):
        self.fired = True
        for job in self.pipe_line:
            LOG.debug(
                "TaskExecutor - (job - %s) dispatched" %
                (str(job)))

            th = self.thread_pool.dispatch(
                job['method'], *job['args'], **job['kwargs'])
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


def set_node(f):
    """To find and set a graph node for a
        given event.
    """

    def decorator(self, *args, **kwargs):
        node = kwargs.get('node')
        event = kwargs.get('event')
        if not node:
            if not event:
                kwargs['node'] = self.graph.root_node
            else:
                kwargs['node'] = self.graph.get_node(event)
        return f(self, *args, **kwargs)
    return decorator


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

    def __init__(self, manager, graph):
        self.manager = manager
        self.graph = graph

    @set_node
    def run(self, event=None, node=None):
        LOG.debug("GraphExecutor - (event - %s)" %
                  (node.event))

        # Call to check if event would get sequenced
        if self.manager.schedule_graph_event(
                node.event, self.graph, dispatch=False):
            LOG.debug("GraphExecutor - "
                      "(event - %s) - sequenced" %
                      (node.event))
            # Event would have got added to sequencer,
            # unlink it from pending links of graph
            return self.graph.unlink_node(node)

        l_nodes = self.graph.get_pending_leaf_nodes(node)
        LOG.debug("GraphExecutor - "
                  "(event - %s) - number of leaf nodes - %d" %
                  (node.event, len(l_nodes)))

        if not l_nodes:
            if not self.graph.waiting_events(node):
                LOG.debug("GraphExecutor - "
                          "(event - %s) - Scheduling event" %
                          (node.event))
                self.manager.schedule_graph_event(node.event, self.graph)
                self.graph.unlink_node(node)

        if l_nodes:
            for l_node in l_nodes:
                LOG.debug("GraphExecutor -"
                          "(event - %s) executing leaf node" %
                          (node.event))
                self.run(node=l_node)

    @set_node
    def event_complete(self, result, event=None, node=None):
        LOG.debug("GraphExecutor - (event - %s) complete" %
                  (node.event))
        node.result = result
        p_node = self.graph.remove_node(node)
        if p_node:
            LOG.debug("GraphExecutor - "
                      "(event - %s) complete, rerunning parent - %s" %
                      (node.event, p_node.event))
            self.run(node=p_node)
