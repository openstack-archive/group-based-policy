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

from gbpservice.neutron.plugins.ml2plus import driver_api

from neutron.db import api as db_api
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers
from neutron.quota import resource_registry
from oslo_log import log
from oslo_utils import excutils

LOG = log.getLogger(__name__)


class MechanismManager(managers.MechanismManager):

    def __init__(self):
        super(MechanismManager, self).__init__()

    def _call_on_drivers(self, method_name, context,
            continue_on_failure=False, raise_db_retriable=False):
        super(MechanismManager, self)._call_on_drivers(
                method_name, context, continue_on_failure=False,
                raise_db_retriable=False)
        if method_name.endswith('_precommit'):
            # This does the same thing as:
            # https://github.com/openstack/neutron/blob/newton-eol/neutron/
            # api/v2/base.py#L489
            # but from within the scope of the plugin's transaction, such
            # that if it fails, everything that happened prior to this in
            # precommit phase can also be rolled back.
            resource_name = method_name.replace('_precommit', '').replace(
                    'create_', '').replace('update_', '').replace(
                            'delete_', '')
            tracked_resource = resource_registry.get_resource(resource_name)
            tracked_resource._dirty_tenants.add(context.current['tenant_id'])
            resource_registry.set_resources_dirty(context._plugin_context)

    def _call_on_extended_drivers(self, method_name, context,
                                  continue_on_failure=False,
                                  raise_db_retriable=False):
        """Call a method on all extended mechanism drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all mechanism drivers once one has raised an exception
        :param raise_db_retriable: whether or not to treat retriable db
        exception by mechanism drivers to propagate up to upper layer so
        that upper layer can handle it or error in ML2 player
        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver call fails. or DB retriable error when
        raise_db_retriable=False. See neutron.db.api.is_retriable for
        what db exception is retriable
        """
        errors = []
        for driver in self.ordered_mech_drivers:
            if isinstance(driver.obj, driver_api.MechanismDriver):
                try:
                    getattr(driver.obj, method_name)(context)
                except Exception as e:
                    if raise_db_retriable and db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug("DB exception raised by Mechanism "
                                      "driver '%(name)s' in %(method)s",
                                      {'name': driver.name,
                                       'method': method_name},
                                      exc_info=e)
                    LOG.exception(
                        "Mechanism driver '%(name)s' failed in "
                        "%(method)s",
                        {'name': driver.name, 'method': method_name}
                    )
                    errors.append(e)
                    if not continue_on_failure:
                        break
        if errors:
            raise ml2_exc.MechanismDriverError(
                method=method_name,
                errors=errors
            )

    def ensure_tenant(self, plugin_context, tenant_id):
        for driver in self.ordered_mech_drivers:
            if isinstance(driver.obj, driver_api.MechanismDriver):
                try:
                    driver.obj.ensure_tenant(plugin_context, tenant_id)
                except Exception as e:
                    if db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug("DB exception raised by Mechanism "
                                      "driver '%(name)s' in ensure_tenant",
                                      {'name': driver.name},
                                      exc_info=e)
                    LOG.exception("Mechanism driver '%s' failed in "
                                  "ensure_tenant", driver.name)
                    raise ml2_exc.MechanismDriverError(method="ensure_tenant")

    def create_subnetpool_precommit(self, context):
        self._call_on_extended_drivers("create_subnetpool_precommit",
                                       context, raise_db_retriable=True)

    def create_subnetpool_postcommit(self, context):
        self._call_on_extended_drivers("create_subnetpool_postcommit",
                                       context)

    def update_subnetpool_precommit(self, context):
        self._call_on_extended_drivers("update_subnetpool_precommit",
                                       context, raise_db_retriable=True)

    def update_subnetpool_postcommit(self, context):
        self._call_on_extended_drivers("update_subnetpool_postcommit",
                                       context, continue_on_failure=True)

    def delete_subnetpool_precommit(self, context):
        self._call_on_extended_drivers("delete_subnetpool_precommit",
                                       context, raise_db_retriable=True)

    def delete_subnetpool_postcommit(self, context):
        self._call_on_extended_drivers("delete_subnetpool_postcommit",
                                       context, continue_on_failure=True)

    def create_address_scope_precommit(self, context):
        self._call_on_extended_drivers("create_address_scope_precommit",
                                       context, raise_db_retriable=True)

    def create_address_scope_postcommit(self, context):
        self._call_on_extended_drivers("create_address_scope_postcommit",
                                       context)

    def update_address_scope_precommit(self, context):
        self._call_on_extended_drivers("update_address_scope_precommit",
                                       context, raise_db_retriable=True)

    def update_address_scope_postcommit(self, context):
        self._call_on_extended_drivers("update_address_scope_postcommit",
                                       context, continue_on_failure=True)

    def delete_address_scope_precommit(self, context):
        self._call_on_extended_drivers("delete_address_scope_precommit",
                                       context, raise_db_retriable=True)

    def delete_address_scope_postcommit(self, context):
        self._call_on_extended_drivers("delete_address_scope_postcommit",
                                       context, continue_on_failure=True)

    def create_security_group_precommit(self, context):
        self._call_on_extended_drivers("create_security_group_precommit",
                                       context, raise_db_retriable=True)

    def create_security_group_postcommit(self, context):
        self._call_on_extended_drivers("create_security_group_postcommit",
                                       context)

    def update_security_group_precommit(self, context):
        self._call_on_extended_drivers("update_security_group_precommit",
                                       context, raise_db_retriable=True)

    def update_security_group_postcommit(self, context):
        self._call_on_extended_drivers("update_security_group_postcommit",
                                       context, continue_on_failure=True)

    def delete_security_group_precommit(self, context):
        self._call_on_extended_drivers("delete_security_group_precommit",
                                       context, raise_db_retriable=True)

    def delete_security_group_postcommit(self, context):
        self._call_on_extended_drivers("delete_security_group_postcommit",
                                       context, continue_on_failure=True)

    def create_security_group_rule_precommit(self, context):
        self._call_on_extended_drivers("create_security_group_rule_precommit",
                                       context, raise_db_retriable=True)

    def create_security_group_rule_postcommit(self, context):
        self._call_on_extended_drivers("create_security_group_rule_postcommit",
                                       context)

    def update_security_group_rule_precommit(self, context):
        self._call_on_extended_drivers("update_security_group_rule_precommit",
                                       context, raise_db_retriable=True)

    def update_security_group_rule_postcommit(self, context):
        self._call_on_extended_drivers("update_security_group_rule_postcommit",
                                       context, continue_on_failure=True)

    def delete_security_group_rule_precommit(self, context):
        self._call_on_extended_drivers("delete_security_group_rule_precommit",
                                       context, raise_db_retriable=True)

    def delete_security_group_rule_postcommit(self, context):
        self._call_on_extended_drivers("delete_security_group_rule_postcommit",
                                       context, continue_on_failure=True)


class ExtensionManager(managers.ExtensionManager):

    def __init__(self):
        super(ExtensionManager, self).__init__()

    def _call_on_extended_drivers(self, method_name, plugin_context, data,
                                  result):
        """Call a method on all extended extension drivers."""
        for driver in self.ordered_ext_drivers:
            if isinstance(driver.obj, driver_api.ExtensionDriver):
                try:
                    getattr(driver.obj, method_name)(plugin_context, data,
                                                     result)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.info("Extension driver '%(name)s' failed in "
                                 "%(method)s",
                                 {'name': driver.name, 'method': method_name})

    # Overrides ML2 implementation to avoid eating retriable
    # exceptions, as well as to support calling only on extension
    # drivers extended for ML2Plus.
    def _call_on_dict_driver(self, method_name, session, base_model, result,
                             extended_only=False, has_base_model=True):

        # Bulk operations might not be implemented by all drivers
        def noop(*args, **kwargs):
            pass

        for driver in self.ordered_ext_drivers:
            if not extended_only or isinstance(
                    driver.obj, driver_api.ExtensionDriver):
                try:
                    if not has_base_model:
                        getattr(driver.obj, method_name, noop)(session,
                                                               result)
                    else:
                        getattr(driver.obj, method_name, noop)(session,
                                                               base_model,
                                                               result)
                except Exception as e:
                    if db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug(
                                "DB exception raised by extension driver "
                                "'%(name)s' in %(method)s",
                                {'name': driver.name, 'method': method_name},
                                exc_info=e)
                    LOG.exception(
                        "Extension driver '%(name)s' failed in %(method)s",
                        {'name': driver.name, 'method': method_name})
                    raise ml2_exc.ExtensionDriverError(driver=driver.name)

    def process_create_subnetpool(self, plugin_context, data, result):
        self._call_on_extended_drivers("process_create_subnetpool",
                                       plugin_context, data, result)

    def process_update_subnetpool(self, plugin_context, data, result):
        self._call_on_extended_drivers("process_update_subnetpool",
                                       plugin_context, data, result)

    def extend_subnetpool_dict(self, session, base_model, result):
        self._call_on_dict_driver("extend_subnetpool_dict",
                                  session, base_model, result, True)

    def process_create_address_scope(self, plugin_context, data, result):
        self._call_on_extended_drivers("process_create_address_scope",
                                       plugin_context, data, result)

    def process_update_address_scope(self, plugin_context, data, result):
        self._call_on_extended_drivers("process_update_address_scope",
                                       plugin_context, data, result)

    def extend_address_scope_dict(self, session, base_model, result):
        self._call_on_dict_driver("extend_address_scope_dict",
                                  session, base_model, result, True)

    def extend_subnetpool_dict_bulk(self, session, result):
        self._call_on_dict_driver("extend_subnetpool_dict_bulk",
                                  session, None, result, True,
                                  has_base_model=False)

    def extend_address_scope_dict_bulk(self, session, result):
        self._call_on_dict_driver("extend_address_scope_dict_bulk",
                                  session, None, result, True,
                                  has_base_model=False)

    def extend_network_dict_bulk(self, session, result):
        self._call_on_dict_driver("extend_network_dict_bulk", session,
                                  None, result, has_base_model=False)

    def extend_subnet_dict_bulk(self, session, result):
        self._call_on_dict_driver("extend_subnet_dict_bulk", session,
                                  None, result, has_base_model=False)

    def extend_port_dict_bulk(self, session, result):
        self._call_on_dict_driver("extend_port_dict_bulk", session, None,
                                  result, has_base_model=False)
