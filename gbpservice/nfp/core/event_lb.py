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


"""Implements round robin algo with stickiness to a worker.

    All the events with same rsrcid, are scheduled to same
    worker. Maintains the map in dict.
"""


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
        if not rsrcid:
            return self._rr()

        if rsrcid in self._assoc.keys():
            worker = self._assoc[rsrcid]
        else:
            worker = self._rr()
            self._assoc[rsrcid] = worker
        return worker
