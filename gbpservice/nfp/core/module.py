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

from abc import abstractmethod
import six


def poll_event_desc(*args, **kwargs):
    """Poll Event Decorator.

    NFP modules can define the poll handlers using
    this decorator.
    """
    def decorator(f):
        f._desc = True
        f._spacing = kwargs.pop('spacing', 0)
        f._event = kwargs.pop('event', None)
        return f

    return decorator

"""Meta class. """


class _Meta(type):

    def __init__(cls, names, bases, dict_):
        """Metaclass that allows us to collect decorated periodic tasks."""
        super(_Meta, cls).__init__(names, bases, dict_)

        try:
            cls._poll_desc_table = dict(cls._poll_desc_table)
        except AttributeError:
            cls._poll_desc_table = {}

        for value in cls.__dict__.values():
            if getattr(value, '_desc', False):
                desc = value
                cls._poll_desc_table[desc._event] = desc

"""Base class for nfp event handlers.

Nfp modules derive and implement event handlers
of this class.
"""


@six.add_metaclass(_Meta)
class NfpEventHandler(object):
    # __metaclass__ = ABCMeta

    def __init__(self):
        super(NfpEventHandler, self).__init__()

    def get_poll_desc_table(self):
        return self._poll_desc_table

    @abstractmethod
    def handle_event(self, event):
        """To handle an event.

        :param event: Object of 'Event' class.

        Returns: None
        """
        pass

    @abstractmethod
    def handle_poll_event(self, event):
        """To handle a poll event.

        Core framework will inovke this method of event handler
        when an event timesout.

        :param event: Object of 'Event' class.

        Returns: {'poll':True/False, 'event':<Updated event>}
            'poll': To repoll for the event.
            'event': Updated event, if not passed core will
                repoll on the old event.
        """
        pass

    @abstractmethod
    def event_cancelled(self, event, reason):
        """Notifies that an event is cancelled by core.

        Event could get cancelled,
            a) Event expired. Module can set lifetime for
                an event. If event is not complete with in
                the time, it is auto expired by core.
            b) Event max timedout. Module can set max number
                of times to poll for an event. Event is cancelled
                after the max times.

        :param event: Cancelled event. Object of 'Event' class.
        :param reason: Reason for cancellation. String.

        Returns: None
        """
        pass
