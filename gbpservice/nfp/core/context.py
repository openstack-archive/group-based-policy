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

import threading


class LogContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'meta_id': self.data.get('meta_id', '-'),
                'nfi_id': self.data.get('nfi_id', '-'),
                'nfd_id': self.data.get('nfd_id', '-'),
                'path': self.data.get('path'),
                'auth_token': self.data.get('auth_token'),
                'namespace': self.data.get('namespace')
            }
        return self.data


class CoreContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        return {
            'log_context': LogContext(self.data.get('log_context')).purge(),
            'event_desc': self.data.get('event_desc')
        }


class NfpContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        return CoreContext(self.data).purge()


Context = threading.local()


def init_log_context():
    return {
        'meta_id': '-',
        'nfi_id': '-',
        'nfd_id': '-',
        'path': '-',
        'auth_token': None,
        'namespace': None
    }


def init(data=None):
    if not data:
        data = {}
    if 'log_context' not in data.keys():
        data['log_context'] = init_log_context()
    if 'event_desc' not in data.keys():
        data['event_desc'] = {}
    Context.context = NfpContext(data)
    context = getattr(Context, 'context')
    return context.data


def get():
    try:
        context = getattr(Context, 'context')
        return context.data
    except AttributeError:
        return init()


def purge():
    try:
        context = getattr(Context, 'context')
        return context.purge()
    except AttributeError:
        init()
        context = getattr(Context, 'context')
        return context.purge()
