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

import eventlet
import heapq
import sched
import time as pytime

from oslo_service import loopingcall as oslo_looping_call
from oslo_service import periodic_task as oslo_periodic_task

Scheduler = sched.scheduler

"""Handles the queue of poll events.

    Derives from python scheduler, since base scheduler does
    a tight loop and does not leave the invoked context.
    Derived here to return if no event timedout, invoked
    periodically by caller to check for timedout events.
"""


class NfpPollHandler(Scheduler):

    def __init__(self, conf):
        self._conf = conf
        Scheduler.__init__(self, pytime.time, eventlet.greenthread.sleep)

    def run(self):
        """Run to find timedout event. """
        q = self._queue
        timefunc = self.timefunc
        pop = heapq.heappop
        if q:
            time, priority, action, argument = checked_event = q[0]
            now = timefunc()
            if now < time:
                return
            else:
                event = pop(q)
                # Verify that the event was not removed or altered
                # by another thread after we last looked at q[0].
                if event is checked_event:
                    action(*argument)
                else:
                    heapq.heappush(q, event)

    def poll_add(self, event, timeout, method):
        """Enter the event to be polled. """
        self.enter(timeout, 1, method, (event,))

"""Periodic task to poll for timer events.

    Periodically checks for expiry of events.
"""


class PollingTask(oslo_periodic_task.PeriodicTasks):

    def __init__(self, conf, controller):
        super(PollingTask, self).__init__(conf)

        self._controller = controller
        pulse = oslo_looping_call.FixedIntervalLoopingCall(
            self.run_periodic_tasks, None, None)
        pulse.start(
            interval=1, initial_delay=None)

    @oslo_periodic_task.periodic_task(spacing=1)
    def poll(self, context):
        # invoke the common class to handle event timeouts
        self._controller.poll()
