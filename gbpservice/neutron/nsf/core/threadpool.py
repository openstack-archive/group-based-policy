import time
import eventlet
eventlet.monkey_patch()
from eventlet import event
from eventlet import greenpool
from eventlet import greenthread
import os
import sys
import threading


def _thread_done(gt, *args, **kwargs):
    kwargs['pool'].thread_done(kwargs['thread'])


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


class ThreadPool(object):

    def __init__(self, thread_pool_size=10):
        self.pool = greenpool.GreenPool(thread_pool_size)
        self.threads = []

    def dispatch(self, callback, *args, **kwargs):
        gt = self.pool.spawn(callback, *args, **kwargs)
        th = Thread(gt, self)
        self.threads.append(th)
        return th

    def thread_done(self, thread):
        self.threads.remove(thread)

    def stop(self):
        current = greenthread.getcurrent()

        # Iterate over a copy of self.threads so thread_done doesn't
        # modify the list while we're iterating
        for x in self.threads[:]:
            if x is current:
                # don't kill the current thread.
                continue
            try:
                x.stop()
            except Exception as ex:
                print ex

    def wait(self):
        current = greenthread.getcurrent()

        # Iterate over a copy of self.threads so thread_done doesn't
        # modify the list while we're iterating
        for x in self.threads[:]:
            if x is current:
                continue
            try:
                x.wait()
            except eventlet.greenlet.GreenletExit:
                pass
            except Exception as ex:
                print ex

"""
def PrintMe(arg1, arg2):
    time.sleep(10)
    print "Hi, its me - (%d)" %(threading.current_thread().ident)
    #done = event.Event()
    #done.wait()


if __name__=='__main__':
    tp = ThreadPool()
    while True:
        tp.dispatch(PrintMe, None, None)
        time.sleep(1)
        print "Hi, its not me"

    #tp.wait()
"""
