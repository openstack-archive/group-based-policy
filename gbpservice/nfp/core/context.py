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

nfp_context_store = threading.local()


class NfpContext(object):

    def __init__(self, context):
        self.context = context

    def get_context(self):
        return self.context


def store_nfp_context(context):
    nfp_context_store.context = NfpContext(context)


def clear_nfp_context():
    nfp_context_store.context = None


def get_nfp_context():
    context = getattr(nfp_context_store, 'context', None)
    if context:
        return context.get_context()
    return {}
