from multiprocessing import Process, Lock
from multiprocessing.queues import Queue
from Queue import Empty, Full

import eventlet
eventlet.monkey_patch()
import os
import time

class LookAheadQueue(Queue):
    def __init__(self, maxsize=0):
        self._memq_ = []
        Queue.__init__(self, maxsize)

    def peek(self, pos, count):
        #Better to fill queue from pipe
        queued = Queue.qsize(self)
        tempq = []
        try:
		    for n in range(0, queued):
			    tempq.append(self.get())
        except Empty:
		    pass
        self._rlock.acquire()
        self._memq_.extend(tempq)
        qlen = len(self._memq_)
        pull = qlen if (pos + count) > qlen else count
        values = self._memq_[pos:(pos+pull)]
        self._rlock.release()
        return values

    def remove(self, elem):
        self._rlock.acquire()
        self._memq_.remove(elem)
        self._rlock.release()

    def get(self):
        elem = None
        try:
            elem = Queue.get(self, timeout=0.1)
        except Empty:
            pass

        if elem:		
            self._rlock.acquire()
            self._memq_.append(elem)
            self._rlock.release()

        return elem

    def flush(self):
        self._rlock.acquire()
        self._memq_ = []
        self._rlock.release()
