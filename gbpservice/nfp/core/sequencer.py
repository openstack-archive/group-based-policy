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

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)

deque = collections.deque


class SequencerEmpty(Exception):
    pass


class SequencerBusy(Exception):
    pass

"""Sequences the events. """


class EventSequencer(object):

    class Sequencer(object):

        def __init__(self):
            # Events not scheduled are queued
            self._waitq = deque()
            # Currently scheduled event
            self._scheduled = None

        def _is_busy(self):
            if self._scheduled:
                raise SequencerBusy

        def _is_empty(self):
            if not len(self._waitq):
                raise SequencerEmpty

        def sequence(self, event):
            self._waitq.append(event)

        def run(self):
            """Run to get event to be scheduled.

                If sequencer is busy - i.e, an event is already
                scheduled and in progress raises busy except.
                If sequencer is empty - i.e, no event in sequencer
                raises empty except.
            """
            self._is_busy()
            self._is_empty()
            # Pop the first element in the queue - FIFO
            self._scheduled = self._waitq.popleft()
            return self._scheduled

        def is_scheduled(self, event):
            if self._scheduled:
                return self._scheduled.desc.uuid == event.desc.uuid and (
                    self._scheduled.id == event.id)
            return True

        def release(self):
            self._scheduled = None

    def __init__(self):
        # Sequence of related events
        # {key: sequencer()}
        self._sequencer = {}

    def sequence(self, key, event):
        try:
            self._sequencer[key].sequence(event)
        except KeyError:
            self._sequencer[key] = self.Sequencer()
            self._sequencer[key].sequence(event)
        message = "Sequenced event - %s" % (event.identify())
        LOG.error(message)

    def run(self):
        events = []
        # Loop over copy and delete from original
        sequencers = dict(self._sequencer)
        for key, sequencer in sequencers.iteritems():
            try:
                event = sequencer.run()
                if event:
                    message = "Desequence event - %s" % (
                        event.identify())
                    LOG.error(message)
                    event.sequence = False
                    events.append(event)
            except SequencerBusy as exc:
                pass
            except SequencerEmpty as exc:
                exc = exc
                message = "Sequencer empty"
                LOG.debug(message)
                del self._sequencer[key]
        return events

    def release(self, key, event):
        try:
            message = "(event - %s) checking to release" % (event.identify())
            LOG.debug(message)
            if self._sequencer[key].is_scheduled(event):
                message = "(event - %s) Releasing sequencer" % (
                    event.identify())
                LOG.debug(message)
                self._sequencer[key].release()
        except KeyError:
            return
