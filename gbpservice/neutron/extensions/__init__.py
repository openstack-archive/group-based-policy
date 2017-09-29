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

import functools

GBP_PLURALS = {}


def register_plurals(plural_mappings):
    for plural, single in plural_mappings.items():
        GBP_PLURALS[single] = plural


def get_plural(single):
    return GBP_PLURALS.get(single)


def disable_transaction_guard(f):
    # We do not want to enforce transaction guard
    # TODO(annak): this is a temporary measure since GUARD_TRANSACTION
    # is expected to stop being enforced in near future
    @functools.wraps(f)
    def inner(self, context, *args, **kwargs):
        setattr(context, 'GUARD_TRANSACTION', False)
        return f(self, context, *args, **kwargs)
    return inner
