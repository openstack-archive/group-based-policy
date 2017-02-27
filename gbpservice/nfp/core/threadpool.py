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
import os

from eventlet import greenpool
from eventlet import greenthread

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


def _thread_done(gt, *args, **kwargs):
    kwargs['pool'].thread_done(kwargs['thread'])


"""Descriptor class for green thread """


class Thread(object):

    def __init__(self, thread, pool):
        self.thread = thread
        self.thread.link(_thread_done, pool=pool, thread=self)

    def stop(self):
        self.thread.kill()

    def wait(self):
        return self.thread.wait()

    def link(self, func, *args, **kwargs):
        self.thread.link(func, *args, **kwargs)

    def identify(self):
        return "(%d -> %s)" % (os.getpid(), 'Thread')

"""Abstract class to manage green threads """


class ThreadPool(object):

    def __init__(self, thread_pool_size=10):
        self.pool = greenpool.GreenPool(thread_pool_size)
        self.threads = []

    def dispatch(self, callback, *args, **kwargs):
        """Invokes the specified function in one of the thread """
        gt = self.pool.spawn(callback, *args, **kwargs)
        th = Thread(gt, self)
        self.threads.append(th)
        return th

    def thread_done(self, thread):
        """Invoked when thread is complete, remove it from cache """
        self.threads.remove(thread)

    def stop(self):
        """To stop the thread """
        current = greenthread.getcurrent()

        # Make a copy
        for x in self.threads[:]:
            if x is current:
                # Skipping the current thread
                continue
            try:
                x.stop()
            except Exception as ex:
                message = "Exception - %s" % (ex)
                LOG.exception(message)

    def wait(self):
        """Wait for the thread """
        current = greenthread.getcurrent()

        # Make a copy
        for x in self.threads[:]:
            if x is current:
                continue
            try:
                x.wait()
            except eventlet.greenlet.GreenletExit:
                pass
            except Exception as ex:
                message = "Unexpected exception - %r" % (ex)
                LOG.error(message)
