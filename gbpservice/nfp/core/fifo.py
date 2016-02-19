import sys
from collections import deque

""" Implements FIFO using python deque.

    New methods to support 'get' more than one element,
    'copy' the queue, 'remove' multiple messages are added.
"""


class Fifo(object):

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

    def _is_empty(self):
        if not self._qsize():
            raise Queue.Empty()

    def _is_full(self):
        if self._size == self._qsize():
            raise Queue.Full()

    def _pop(self, out):
        out.append(self._q.popleft())
        return out

    def put(self, msg):
        """ Puts a message in queue. """
        try:
            self._sc.lock()
            self._is_full()
            self._q.append(msg)
        finally:
            self._sc.unlock()

    def get(self, limit=sys.maxint):
        """ Get passed number of messages.

            If there are less messages in the queue than requested,
            then available number of messages are returned.
        """
        msgs = []
        try:
            self._sc.lock()
            self._is_empty()
            for i in range(0, limit):
                msgs = self._pop(msgs)
        except Queue.Empty:
            pass
        finally:
            self._sc.unlock()
            return msgs

    def copy(self):
        """ Copies the queue and returns the copy. """
        self._sc.lock()
        qu = list(self._q)
        self._sc.unlock()
        return qu

    def remove(self, msgs):
        """ Remove list of messages from the fifo """
        try:
            self._sc.lock()
            for msg in msgs:
                self._q.remove(msg)
        finally:
            self._sc.unlock()
