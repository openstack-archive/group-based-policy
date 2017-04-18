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


import heapq
import signal
from time import time

from gbpservice.nfp.core import log as nfp_logging


LOG = nfp_logging.getLogger(__name__)

alarmlist = []

__new_alarm = lambda t, f, a, k: (t + time(), f, a, k)
__next_alarm = lambda: int(
    round(alarmlist[0][0] - time())) if alarmlist else None
__set_alarm = lambda: signal.alarm(max(__next_alarm(), 1))


class Watchdog(object):

    def __init__(self, callback, seconds=20 * 60, **kwargs):
        self._seconds = seconds
        self._callback = callback
        self.kwargs = kwargs

        self._alarm = alarm(self._seconds, self.timedout)

    def timedout(self):
        try:
            self._callback(**self.kwargs)
        except Exception as e:
            message = "Unexpected exception - %s" % (e)
            LOG.error(message)

    def cancel(self):
        try:
            cancel(self._alarm)
        except ValueError:
            pass
        except Exception as e:
            message = "Unexpected exception - %s" % (e)
            LOG.error(message)


def __clear_alarm():
    """Clear an existing alarm.

    If the alarm signal was set to a callable other than our own, queue the
    previous alarm settings.
    """
    oldsec = signal.alarm(0)
    oldfunc = signal.signal(signal.SIGALRM, __alarm_handler)
    if oldsec > 0 and oldfunc != __alarm_handler:
        heapq.heappush(alarmlist, (__new_alarm(oldsec, oldfunc, [], {})))


def __alarm_handler(*zargs):
    """Handle an alarm by calling any due heap entries and resetting the alarm.

    Note that multiple heap entries might get called, especially if calling an
    entry takes a lot of time.
    """
    try:
        nextt = __next_alarm()
        while nextt is not None and nextt <= 0:
            (tm, func, args, keys) = heapq.heappop(alarmlist)
            func(*args, **keys)
            nextt = __next_alarm()
    finally:
        if alarmlist:
            __set_alarm()


def alarm(sec, func, *args, **keys):
    """Set an alarm.

    When the alarm is raised in `sec` seconds, the handler will call `func`,
    passing `args` and `keys`. Return the heap entry (which is just a big
    tuple), so that it can be cancelled by calling `cancel()`.
    """
    __clear_alarm()
    try:
        newalarm = __new_alarm(sec, func, args, keys)
        heapq.heappush(alarmlist, newalarm)
        return newalarm
    finally:
        __set_alarm()


def cancel(alarm):
    """Cancel an alarm by passing the heap entry returned by `alarm()`.

    It is an error to try to cancel an alarm which has already occurred.
    """
    __clear_alarm()
    try:
        alarmlist.remove(alarm)
        heapq.heapify(alarmlist)
    finally:
        if alarmlist:
            __set_alarm()
