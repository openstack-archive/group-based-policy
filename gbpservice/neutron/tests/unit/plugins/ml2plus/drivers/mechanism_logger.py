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

from neutron.tests.unit.plugins.ml2.drivers import (
    mechanism_logger as ml2_logger)
from oslo_log import log

from gbpservice._i18n import _LI
from gbpservice.neutron.plugins.ml2plus import driver_api

LOG = log.getLogger(__name__)


class LoggerPlusMechanismDriver(driver_api.MechanismDriver,
                                ml2_logger.LoggerMechanismDriver):
    """Mechanism driver that logs all calls and parameters made.

    Generally used for testing and debugging.
    """

    def initialize(self):
        LOG.info(_LI("initialize called"))

    def ensure_tenant(self, plugin_context, tenant_id):
        LOG.info(_LI("ensure_tenant called with tenant_id %s"), tenant_id)

    def _log_subnetpool_call(self, method_name, context):
        LOG.info(_("%(method)s called with subnetpool settings %(current)s "
                   "(original settings %(original)s)"),
                 {'method': method_name,
                  'current': context.current,
                  'original': context.original})

    def create_subnetpool_precommit(self, context):
        self._log_subnetpool_call("create_subnetpool_precommit",
                                  context)

    def create_subnetpool_postcommit(self, context):
        self._log_subnetpool_call("create_subnetpool_postcommit",
                                  context)

    def update_subnetpool_precommit(self, context):
        self._log_subnetpool_call("update_subnetpool_precommit",
                                  context)

    def update_subnetpool_postcommit(self, context):
        self._log_subnetpool_call("update_subnetpool_postcommit",
                                  context)

    def delete_subnetpool_precommit(self, context):
        self._log_subnetpool_call("delete_subnetpool_precommit",
                                  context)

    def delete_subnetpool_postcommit(self, context):
        self._log_subnetpool_call("delete_subnetpool_postcommit",
                                  context)

    def _log_address_scope_call(self, method_name, context):
        LOG.info(_("%(method)s called with address_scope settings %(current)s "
                   "(original settings %(original)s)"),
                 {'method': method_name,
                  'current': context.current,
                  'original': context.original})

    def create_address_scope_precommit(self, context):
        self._log_address_scope_call("create_address_scope_precommit",
                                     context)

    def create_address_scope_postcommit(self, context):
        self._log_address_scope_call("create_address_scope_postcommit",
                                     context)

    def update_address_scope_precommit(self, context):
        self._log_address_scope_call("update_address_scope_precommit",
                                     context)

    def update_address_scope_postcommit(self, context):
        self._log_address_scope_call("update_address_scope_postcommit",
                                     context)

    def delete_address_scope_precommit(self, context):
        self._log_address_scope_call("delete_address_scope_precommit",
                                     context)

    def delete_address_scope_postcommit(self, context):
        self._log_address_scope_call("delete_address_scope_postcommit",
                                     context)
