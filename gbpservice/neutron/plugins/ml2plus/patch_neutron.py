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


from gbpservice.common import utils as gbp_utils


def get_current_session():
    return gbp_utils.get_current_session()


from neutron.plugins.ml2 import ovo_rpc


# The following reduces the ERROR log level for a message
# which is seen when a port_update even is sent. The
# port_update is intentionally sent in the pre_commit
# phase by the apic_aim mechanism driver, but is not
# what neutron expects and hence it flags it.
ovo_rpc.LOG.error = ovo_rpc.LOG.debug


from neutron.callbacks import registry

from gbpservice.network.neutronv2 import local_api


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

from neutron.db import common_db_mixin as common_db_api
from neutron.db.quota import api as quota_api
from neutron.db.quota import driver  # noqa
from neutron.db.quota import models as quota_models
from neutron import quota
from neutron.quota import resource_registry as res_reg
from oslo_config import cfg


f = quota_api.remove_reservation
quota_api.commit_reservation = undecorated(f)


def commit_reservation(context, reservation_id):
    quota_api.commit_reservation(context, reservation_id, set_dirty=False)


quota.QUOTAS.get_driver().commit_reservation = commit_reservation


def patched_set_resources_dirty(context):
    if not cfg.CONF.QUOTAS.track_quota_usage:
        return

    with context.session.begin(subtransactions=True):
        for res in res_reg.get_all_resources().values():
            if res_reg.is_tracked(res.name) and res.dirty:
                dirty_tenants_snap = res._dirty_tenants.copy()
                for tenant_id in dirty_tenants_snap:
                    query = common_db_api.model_query(
                            context, quota_models.QuotaUsage)
                    query = query.filter_by(resource=res.name).filter_by(
                            tenant_id=tenant_id)
                    usage_data = query.first()
                    # Set dirty if not set already. This effectively
                    # patches the inner notify method:
                    # https://github.com/openstack/neutron/blob/newton-eol/
                    # neutron/api/v2/base.py#L481
                    # to avoid updating the QuotaUsages table outside
                    # from that method (which starts a new transaction).
                    # The dirty marking would have been already done
                    # in the ml2plus manager at the end of the pre_commit
                    # stage (and prior to the plugin initiated transaction
                    # completing).
                    if usage_data and not usage_data.dirty:
                        res.mark_dirty(context)


quota.resource_registry.set_resources_dirty = patched_set_resources_dirty


from neutron._i18n import _LI
from oslo_db.sqlalchemy import exc_filters


exc_filters._LE = _LI
exc_filters.LOG.exception = exc_filters.LOG.debug


from neutron_lib.api import validators


if not hasattr(validators, '_collect_duplicates'):
    # This is from neutron-lib 1.5.0 since Ocata package
    # might come with a lower release which has a bug in
    # _validate_list_of_items

    def _collect_duplicates(data_list):
        """Collects duplicate items from a list and returns them.

        :param data_list: A list of items to check for duplicates. The list may
        include dict items.
        :returns: A set of items that are duplicates in data_list. If no
        duplicates are found, the returned set is empty.
        """
        seen = []
        dups = set()
        for datum in data_list:
            if datum in seen:
                dups.add(datum)
                continue
            seen.append(datum)
        return dups

    def new_validate_list_of_items(item_validator, data, *args, **kwargs):
        if not isinstance(data, list):
            msg = _("'%s' is not a list") % data
            return msg

        dups = _collect_duplicates(data)

        if dups:
            msg = _("Duplicate items in the list: '%s'") % ', '.join(
                [str(d) for d in dups])
            return msg

        for item in data:
            msg = item_validator(item, *args, **kwargs)
            if msg:
                return msg

    validators._validate_list_of_items = new_validate_list_of_items


from neutron.db import models_v2
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import models
from sqlalchemy.orm import exc


# REVISIT: This method gets decorated in Pike for removal in Queens. So this
# patching might need to be changed in Pike and removed in Queens.
def patched_get_locked_port_and_binding(context, port_id):
    """Get port and port binding records for update within transaction."""
    LOG.debug("Using patched_get_locked_port_and_binding")
    try:
        port = (context.session.query(models_v2.Port).
                enable_eagerloads(False).
                filter_by(id=port_id).
                one())
        binding = (context.session.query(models.PortBinding).
                   enable_eagerloads(False).
                   filter_by(port_id=port_id).
                   one())
        return port, binding
    except exc.NoResultFound:
        return None, None


ml2_db.get_locked_port_and_binding = patched_get_locked_port_and_binding


from neutron.db import db_base_plugin_v2


DEVICE_OWNER_SVI_PORT = 'apic:svi'
db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS.append(DEVICE_OWNER_SVI_PORT)
