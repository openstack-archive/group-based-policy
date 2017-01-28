# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
#
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

from oslo_db.sqlalchemy import enginefacade


@property
def noop_writer(self):
    """Override TransactionContextManager cloning"""
    return self


enginefacade._TransactionContextManager.writer = noop_writer


from neutron.api import extensions
from neutron.callbacks import registry

from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.plugins.ml2plus import extension_overrides

# Monkeypatch Neutron to allow overriding its own extension
# descriptors. Note that extension descriptor classes cannot be
# monkeypatched directly because they are loaded explicitly by file
# name and then used immediately.

_real_get_extensions_path = extensions.get_extensions_path


def get_extensions_path(service_plugins=None):
    path = _real_get_extensions_path(service_plugins)
    return extension_overrides.__path__[0] + ':' + path


extensions.get_extensions_path = get_extensions_path


import sys

from neutron.common import exceptions as nexcp
from neutron import context as n_context


class NoSession(nexcp.BadRequest):
    message = _("No DB session in scope ")


def get_current_session():
    i = 1
    not_found = True
    try:
        while not_found:
            for val in sys._getframe(i).f_locals.itervalues():
                if isinstance(val, n_context.Context):
                    ctx = val
                    not_found = False
                    break
            i = i + 1
        return ctx.session
    except Exception:
        raise NoSession()


def notify(resource, event, trigger, **kwargs):
    if 'context' in kwargs:
        session = kwargs['context'].session
    else:
        session = get_current_session()

    txn = local_api.get_outer_transaction(session.transaction)
    local_api.send_or_queue_registry_notification(
        session, txn, resource, event, trigger, **kwargs)


registry.notify = notify
