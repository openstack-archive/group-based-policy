import sys
from collections import deque


class Queue(object):

    class Empty(Exception):

        '''
        Exception raised when queue is empty and dequeue is attempted.
        '''
        pass

    class Full(Exception):

        '''
        Exception raised when queue is full and enqueue is attempted.
        '''
        pass

    def __init__(self, sc, maxsize=-1):
        self._sc = sc
        self._size = sys.maxint if maxsize == -1 else maxsize
        self._q = deque()

    def _qsize(self):
        return len(self._q)

    def _empty(self):
        if not self._qsize():
            raise Queue.Empty()

    def _full(self):
        if self._size == self._qsize():
            raise Queue.Full()

    def _pop(self, out):
        out.append(self._q.popleft())
        return out

    def put(self, msg):
        try:
            self._sc.lock()
            self._full()
            self._q.append(msg)
        finally:
            self._sc.unlock()

    def get(self, limit=sys.maxint):
        items = []
        try:
            self._sc.lock()
            self._empty()
            for i in range(0, limit):
                items = self._pop(items)
        except Queue.Empty:
            pass
        finally:
            self._sc.unlock()
            return items

    def copy(self):
        self._sc.lock()
        qu = list(self._q)
        self._sc.unlock()
        return qu

    def remove(self, items):
        try:
            self._sc.lock()
            for item in items:
                self._q.remove(item)
        finally:
            self._sc.unlock()
