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

from neutron.api import extensions

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

from neutron import context as n_context

from gbpservice.network.neutronv2 import local_api


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
        return


from neutron.callbacks import registry


def notify(resource, event, trigger, **kwargs):
    if 'context' in kwargs:
        session = kwargs['context'].session
    else:
        session = get_current_session()

    txn = None
    if session:
        txn = local_api.get_outer_transaction(session.transaction)
    local_api.send_or_queue_registry_notification(
        session, txn, resource, event, trigger, **kwargs)


registry.notify = notify


from neutron._i18n import _LE
from neutron.callbacks import events
from neutron.callbacks import exceptions
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def _notify_loop(resource, event, trigger, **kwargs):
    """The notification loop."""
    errors = []
    callbacks = kwargs.pop('callbacks', None)
    if not callbacks:
        callbacks = list(registry._get_callback_manager()._callbacks[
            resource].get(event, {}).items())
    LOG.debug("Notify callbacks %s for %s, %s", callbacks, resource, event)
    for callback_id, callback in callbacks:
        try:
            callback(resource, event, trigger, **kwargs)
        except Exception as e:
            abortable_event = (
                event.startswith(events.BEFORE) or
                event.startswith(events.PRECOMMIT)
            )
            if not abortable_event:
                LOG.exception(_LE("Error during notification for "
                                  "%(callback)s %(resource)s, %(event)s"),
                              {'callback': callback_id,
                               'resource': resource, 'event': event})
            else:
                LOG.error(_LE("Callback %(callback)s raised %(error)s"),
                          {'callback': callback_id, 'error': e})
            errors.append(exceptions.NotificationError(callback_id, e))
    return errors


original_notify_loop = registry._get_callback_manager()._notify_loop


from inspect import isclass
from inspect import isfunction
from inspect import ismethod


# The undecorated() and looks_like_a_decorator() functions have been
# borrowed from the undecorated python library since RPM or Debian
# packages are not readily available.
def looks_like_a_decorator(a):
    return (
        isfunction(a) or ismethod(a) or isclass(a)
    )


def undecorated(o):
    """Remove all decorators from a function, method or class"""
    # class decorator
    if type(o) is type:
        return o

    try:
        # python2
        closure = o.func_closure
    except AttributeError:
        pass

    try:
        # python3
        closure = o.__closure__
    except AttributeError:
        return

    if closure:
        for cell in closure:
            # avoid infinite recursion
            if cell.cell_contents is o:
                continue

            # check if the contents looks like a decorator; in that case
            # we need to go one level down into the dream, otherwise it
            # might just be a different closed-over variable, which we
            # can ignore.

            # Note: this favors supporting decorators defined without
            # @wraps to the detriment of function/method/class closures
            if looks_like_a_decorator(cell.cell_contents):
                undecd = undecorated(cell.cell_contents)
                if undecd:
                    return undecd
        else:
            return o
    else:
        return o


from neutron.db.quota import api as quota_api
from neutron import quota


f = quota_api.remove_reservation
quota_api.commit_reservation = undecorated(f)


def commit_reservation(context, reservation_id):
    quota_api.commit_reservation(context, reservation_id, set_dirty=False)


quota.QUOTAS.get_driver().commit_reservation = commit_reservation


from oslo_db import exception as oslodb_exception
from oslo_db.sqlalchemy import exc_filters
from sqlalchemy import exc as sqla_exc


@exc_filters.filters("*", sqla_exc.DBAPIError, r".*")
def _raise_for_remaining_DBAPIError(error, match, engine_name, is_disconnect):
    """Filter for remaining DBAPIErrors.

    Filter for remaining DBAPIErrors and wrap if they represent
    a disconnect error.
    """
    if is_disconnect:
        raise oslodb_exception.DBConnectionError(error)
    else:
        # The following log statement is being patched here to log
        # at the debug level as opposed to at error level in the original
        # code.
        LOG.debug(('DBAPIError exception wrapped from %s') % error)
        raise oslodb_exception.DBError(error)


exc_filters._raise_for_remaining_DBAPIError = _raise_for_remaining_DBAPIError
