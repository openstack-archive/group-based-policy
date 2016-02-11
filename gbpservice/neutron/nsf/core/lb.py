import os
import sys


class RoundRobin(object):

    def __init__(self, workers):
        self._workers = workers
        self._rridx = 0
        self._rrsize = len(self._workers)

    def _rr(self):
        item = self._workers[self._rridx]
        self._rridx = (self._rridx + 1) % (self._rrsize)
        return item

    def get(self, rsrcid):
        return self._rr()

    def rem(self, rsrcid):
        pass


class StickyRoundRobin(object):

    def __init__(self, workers):
        self._workers = workers
        self._assoc = {}
        self._rridx = 0
        self._rrsize = len(self._workers)

    def _rr(self):
        item = self._workers[self._rridx]
        self._rridx = (self._rridx + 1) % (self._rrsize)
        return item

    def get(self, rsrcid):
        if rsrcid in self._assoc.keys():
            worker = self._assoc[rsrcid]
        else:
            worker = self._rr()
            self._assoc[rsrcid] = worker
        return worker

    def rem(self, rsrcid):
        del self._assoc[rsrcid]
