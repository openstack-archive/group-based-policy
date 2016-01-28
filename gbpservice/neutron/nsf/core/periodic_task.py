import random
import time
import time

from oslo.config import cfg
import six

# from neutron.openstack.common.gettextutils import _, _LE, _LI
# from neutron.openstack.common import log as logging

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def periodic_task(*args, **kwargs):
    def decorator(f):
        # Control if run at all
        f._periodic_task = True
        # Control frequency
        f._periodic_spacing = kwargs.pop('spacing', 0)
        f._periodic_event = kwargs.pop('event', None)
        f._periodic_last_run = None
        return f

    return decorator


class _PeriodicTasksMeta(type):

    def __init__(cls, names, bases, dict_):
        """Metaclass that allows us to collect decorated periodic tasks."""
        super(_PeriodicTasksMeta, cls).__init__(names, bases, dict_)

        try:
            cls._periodic_tasks = cls._periodic_tasks[:]
        except AttributeError:
            cls._periodic_tasks = []

        try:
            cls._ev_to_periodic_task_map = dict(cls._ev_to_periodic_task_map)
        except AttributeError:
            cls._ev_to_periodic_task_map = {}

        for value in cls.__dict__.values():
            if getattr(value, '_periodic_task', False):
                task = value
                name = task.__name__
                cls._periodic_tasks.append((name, task))
                cls._ev_to_periodic_task_map[task._periodic_event] = task


@six.add_metaclass(_PeriodicTasksMeta)
class PeriodicTasks(object):

    def __init__(self):
        super(PeriodicTasks, self).__init__()

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

    def _timedout(self, task, event):
        spacing = task._periodic_spacing
        # last_run = task._periodic_last_run
        last_run = event.last_run

        if last_run is not None:
            delta = last_run + spacing - time.time()
            if delta > 0:
                return None
            LOG.debug("Periodic task %(task_name)s timedout",
                      {"full_task_name": task.__name__})

        event.last_run = self._nearest_boundary(last_run, spacing)
        # task._periodic_last_run = self._nearest_boundary(
        #                    last_run, spacing)
        return event

    def check_timedout(self, event):
        if event.id not in self._ev_to_periodic_task_map.keys():
            return None
        else:
            task = self._ev_to_periodic_task_map[event.id]
            return self._timedout(task, event)

    def get_periodic_event_handler(self, event):
        if event.id not in self._ev_to_periodic_task_map.keys():
            return None
        return self._ev_to_periodic_task_map[event.id]
