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
