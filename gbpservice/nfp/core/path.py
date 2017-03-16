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


from gbpservice.nfp.core import log as nfp_logging

import collections
import six

deque = collections.deque

LOG = nfp_logging.getLogger(__name__)


class Supress(object):

    def __init__(self, ignore_list=None):
        self._ignore = ignore_list or []

    def __enter__(self):
        pass

    def __exit__(self, e_type, e_value, traceback):
        if e_type in self._ignore:
            return True
        for exception in self._ignore:
            if isinstance(e_type, exception):
                return True


class Path(object):

    def __init__(self, name):
        self._waitq = deque()
        self.name = name
        self.count = 0
        self.invalid = False

    def queue(self, event):
        self._waitq.append(event)

    def pop(self):
        events = []

        with Supress([IndexError]):
            events.append(self._waitq.popleft())
        return events

    def done(self):
        self._waitq.clear()

# {'key': {'current':Path, 'waiting':Path}
paths = {}


def run():
    for key, path in six.iteritems(paths):
        if path['current'].count == 0:
            path['current'].done()
            if path['waiting'].name != 'INVALID':
                path['current'] = path['waiting']
                path['current'].invalid = False
                path['waiting'] = Path('INVALID')

    events = []
    # Get any queued events in the current path
    for key, path in six.iteritems(paths):
        events += path['current'].pop()
    return events


def event_complete(event):
    name = event.desc.path_type
    key = event.desc.path_key

    if not name:
        return
    name = name.upper()
    with Supress([KeyError]):
        path = paths[key]
        if path['current'].name != name:
            return
        path['current'].count -= 1


def schedule_event(event):
    name = event.desc.path_type
    key = event.desc.path_key

    if not name:
        return 'schedule'

    name = name.upper()

    try:
        path = paths[key]
        if path['current'].name == name:
            if path['current'].invalid:
                return 'discard'
            path['current'].count += 1
            return 'schedule'

        if path['waiting'].name == name:
            path['waiting'].queue(event)
            return 'wait'

        if path['current'].name != name:
            return 'discard'
    except Exception:
        return 'schedule'
    return 'schedule'


def path_complete(path_type, key):
    try:
        path = paths[key]
        if path['current'].name == path_type.upper() and (
                path['waiting'].name == 'INVALID'):
            paths.pop(key)
    except KeyError:
        message = "Path completion - %s path does not exist with key %s" % (
            path_type, key)
        LOG.debug(message)


def create_path(key):
        # Create cannot progress if there is already a path
        # with the same key in any state
    try:
        path = paths[key]
        assert False, "Path (%s) with key (%s) is already in progress" % (
            path['current'].name, key)
    except KeyError:
        # Create new path
        paths[key] = {'current': Path('CREATE'), 'waiting': Path('INVALID')}


def delete_path(key):
    try:
        path = paths[key]
        if path['current'].name != 'DELETE':
            path['waiting'] = Path('DELETE')
            path['current'].invalid = True
        else:
            assert False, ("Delete Path (%s) with key (%s)"
                           "is already in progress" % (
                               path['current'].name, key))
    except KeyError:
        paths[key] = {'current': Path('DELETE'), 'waiting': Path('INVALID')}


def update_path(key):
    # Update cannot progress if there is DELETE already in progress
    # or DELETE already waiting.
    try:
        path = paths[key]
        assert False, "Path (%s) with key (%s) is in progress" % (
            path.name, key)
    except KeyError:
        # Create new path
        paths[key] = {'current': Path('UPDATE'), 'waiting': Path('INVALID')}
