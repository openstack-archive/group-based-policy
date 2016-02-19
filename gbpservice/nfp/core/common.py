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

import collections
import pdb
import Queue
import sys
import sys

deque = collections.deque


def log(logger, level, msg):
    eval('_log_%s' % (level.lower()))(logger, msg)


def _log_info(logger, msg):
    logger.info(msg)


def _log_debug(logger, msg):
    logger.debug(msg)


def _log_error(logger, msg):
    logger.error(msg)


def _log_warn(logger, msg):
    logger.warn(msg)


def _log_exception(logger, msg):
    logger.exception(msg)


class ForkedPdb(pdb.Pdb):

    """A Pdb subclass that may be used
    from a forked multiprocessing child

    """

    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = file('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin


def _is_class(obj):
    return 'class' in str(type(obj))


def _name(obj):
    """Helper method to construct name of an object.

    'module.class' if object is of type 'class'
    'module.class.method' if object is of type 'method'
    """
    # If it is callable, then it is a method
    if callable(obj):
        return "{0}.{1}.{2}".format(
            type(obj.im_self).__module__,
            type(obj.im_self).__name__,
            obj.__name__)
    # If obj is of type class
    elif _is_class(obj):
        return "{0}.{1}".format(
            type(obj).__module__,
            type(obj).__name__)
    else:
        return obj.__name__


def identify(obj):
    """Helper method to display identify an object.

    Useful for logging. Decodes based on the type of obj.
    Supports 'class' & 'method' types for now.
    """
    try:
        return "(%s)" % (_name(obj))
    except Exception:
        """Some unknown type, returning empty """
        return ""


def load_nfp_symbols(namespace):
    namespace['identify'] = identify
    namespace['log_info'] = _log_info
    namespace['log_debug'] = _log_debug
    namespace['log_error'] = _log_error
    namespace['log_exception'] = _log_exception


"""Wrapper class over python deque.

    Implements firsinfirsout logic.
    New methods to support 'get' more than one element,
    'copy' the queue, 'remove' multiple messages are added.
"""


class NfpFifo(object):

    class Empty(Exception):

        """Exception raised when queue is empty and dequeue is attempted.
        """
        pass

    class Full(Exception):

        """Exception raised when queue is full and enqueue is attempted.
        """
        pass

    def __init__(self, sc, maxsize=-1):
        self._sc = sc
        self._size = sys.maxint if maxsize == -1 else maxsize
        self._queue = deque()

    def _qsize(self):
        return len(self._queue)

    def _is_empty(self):
        if not self._qsize():
            raise Queue.Empty()

    def _is_full(self):
        if self._size == self._qsize():
            raise Queue.Full()

    def _pop(self, out):
        self._is_empty()
        out.append(self._queue.popleft())
        return out

    def put(self, msg):
        """Puts a message in queue. """
        self._is_full()
        self._queue.append(msg)

    def get(self, limit=sys.maxint):
        """Get max requested number of messages.

            If there are less messages in the queue than requested,
            then available number of messages are returned.
        """
        msgs = []
        try:
            for i in range(0, limit):
                msgs = self._pop(msgs)
        except Queue.Empty:
            pass
        finally:
            return msgs

    def copy(self):
        """Return the copy of queue. """
        qu = list(self._queue)
        return qu

    def remove(self, msgs):
        """Remove list of messages from the fifo """
        try:
            for msg in msgs:
                self._queue.remove(msg)
        except ValueError as err:
            err = err
