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

from neutron.db import api as db_api
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as oslo_db_excp
from oslo_log import log
from oslo_policy import policy as oslo_policy
from oslo_utils import excutils
from sqlalchemy import exc as sqlalchemy_exc
import stevedore

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import exceptions as gp_exc


LOG = log.getLogger(__name__)
cfg.CONF.import_opt('policy_drivers',
                    'gbpservice.neutron.services.grouppolicy.config',
                    group='group_policy')


class PolicyDriverManager(stevedore.named.NamedExtensionManager):
    """Manage group policy enforcement using drivers.

    Defines precommit and post_commit operations for the
    create, update, and delete operations on the Group Policy
    resources.

    precommit operation:
    Notifies all policy drivers during policy_target creation.

    Raises neutron.services.grouppolicy.common.GroupPolicyDriverError
    if any policy driver create_policy_target_precommit call fails.

    Called within the database transaction. If a policy driver
    raises an exception, then a GroupPolicyDriverError is propogated
    to the caller, triggering a rollback. There is no guarantee
    that all policy drivers are called in this case.

    postcommit operation:
    Notifies all policy drivers after policy_target creation.

    Raises neutron.services.grouppolicy.common.GroupPolicyDriverError
    if any policy driver create_policy_target_postcommit call fails.

    Called after the database transaction. If a policy driver
    raises an exception, then a GroupPolicyDriverError is propagated
    to the caller, where the policy_target will be deleted, triggering
    any required cleanup. There is no guarantee that all policy
    drivers are called in this case.
    """

    def __init__(self):
        # Registered policy drivers, keyed by name.
        self.policy_drivers = {}
        # Ordered list of policy drivers, defining
        # the order in which the drivers are called.
        self.ordered_policy_drivers = []
        self.reverse_ordered_policy_drivers = []

        LOG.info("Configured policy driver names: %s",
                 cfg.CONF.group_policy.policy_drivers)
        super(PolicyDriverManager,
              self).__init__('gbpservice.neutron.group_policy.policy_drivers',
                             cfg.CONF.group_policy.policy_drivers,
                             invoke_on_load=True,
                             name_order=True)
        LOG.info("Loaded policy driver names: %s", self.names())
        self._register_policy_drivers()

    def _register_policy_drivers(self):
        """Register all policy drivers.

        This method should only be called once in the PolicDriverManager
        constructor.
        """
        for ext in self:
            self.policy_drivers[ext.name] = ext
            self.ordered_policy_drivers.append(ext)

        self.reverse_ordered_policy_drivers = self.ordered_policy_drivers[::-1]
        LOG.info("Registered policy drivers: %s",
                 [driver.name for driver in self.ordered_policy_drivers])

    def initialize(self):
        # Group Policy bulk operations requires each driver to support them.
        # However, this is currently not supported at the plugin level,
        # so setting it to False. When the plugin does support it, we can
        # set it to True such that the drivers can override it.
        self.native_bulk_support = False
        for driver in self.ordered_policy_drivers:
            LOG.info("Initializing policy driver '%s'", driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_on_drivers(self, method_name, context=None,
                         continue_on_failure=False):
        """Helper method for calling a method across all policy drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all policy drivers once one has raised an exception
        :raises: neutron.services.group_policy.common.GroupPolicyDriverError
        if any policy driver call fails.
        """
        error = False
        drivers = (self.ordered_policy_drivers if not
                   method_name.startswith('delete') else
                   self.reverse_ordered_policy_drivers)
        if method_name == 'start_rpc_listeners':
            servers = []
        for driver in drivers:
            try:
                if method_name == 'start_rpc_listeners':
                    server = getattr(driver.obj, method_name)()
                    if server:
                        servers.extend(server)
                else:
                    getattr(driver.obj, method_name)(context)
            except Exception as e:
                if db_api.is_retriable(e):
                    with excutils.save_and_reraise_exception():
                        LOG.debug(
                            "Policy driver '%(name)s' failed in"
                            " %(method)s, operation will be retried",
                            {'name': driver.name, 'method': method_name}
                        )
                elif isinstance(e, gp_exc.GroupPolicyException) or isinstance(
                    e, n_exc.NeutronException) or isinstance(
                        e, oslo_policy.PolicyNotAuthorized):
                    with excutils.save_and_reraise_exception():
                        LOG.exception(
                            "Policy driver '%(name)s' failed in"
                            " %(method)s",
                            {'name': driver.name, 'method': method_name}
                        )
                elif isinstance(e, sqlalchemy_exc.InvalidRequestError):
                    LOG.exception(
                        "Policy driver '%(name)s' failed in %(method)s ",
                        "with sqlalchemy.exc.InvalidRequestError",
                        {'name': driver.name, 'method': method_name})
                    raise oslo_db_excp.RetryRequest(e)
                else:
                    error = True
                    # We are eating a non-GBP/non-Neutron exception here
                    LOG.exception(
                        "Policy driver '%(name)s' failed in %(method)s",
                        {'name': driver.name, 'method': method_name})
                    if not continue_on_failure:
                        break
        if error:
            raise gp_exc.GroupPolicyDriverError(method=method_name)

        if method_name == 'start_rpc_listeners':
            return servers

    def ensure_tenant(self, plugin_context, tenant_id):
        for driver in self.ordered_policy_drivers:
            if isinstance(driver.obj, api.PolicyDriver):
                try:
                    driver.obj.ensure_tenant(plugin_context, tenant_id)
                except Exception as e:
                    if db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug("Policy driver '%(driver)s' failed in "
                                      "ensure_tenant, operation will "
                                      "be retried", {'driver': driver.name})
                    else:
                        LOG.exception("Policy driver '%s' failed in "
                                      "ensure_tenant", driver.name)
                        raise gp_exc.GroupPolicyDriverError(
                                method="ensure_tenant")

    def create_policy_target_precommit(self, context):
        self._call_on_drivers("create_policy_target_precommit", context)

    def create_policy_target_postcommit(self, context):
        self._call_on_drivers("create_policy_target_postcommit", context)

    def update_policy_target_precommit(self, context):
        self._call_on_drivers("update_policy_target_precommit", context)

    def update_policy_target_postcommit(self, context):
        self._call_on_drivers("update_policy_target_postcommit", context)

    def delete_policy_target_precommit(self, context):
        self._call_on_drivers("delete_policy_target_precommit", context)

    def delete_policy_target_postcommit(self, context):
        self._call_on_drivers("delete_policy_target_postcommit", context,
                              continue_on_failure=True)

    def get_policy_target_status(self, context):
        self._call_on_drivers("get_policy_target_status", context)

    def create_policy_target_group_precommit(self, context):
        self._call_on_drivers("create_policy_target_group_precommit", context)

    def create_policy_target_group_postcommit(self, context):
        self._call_on_drivers("create_policy_target_group_postcommit", context)

    def update_policy_target_group_precommit(self, context):
        self._call_on_drivers("update_policy_target_group_precommit", context)

    def update_policy_target_group_postcommit(self, context):
        self._call_on_drivers("update_policy_target_group_postcommit", context)

    def delete_policy_target_group_precommit(self, context):
        self._call_on_drivers("delete_policy_target_group_precommit", context)

    def delete_policy_target_group_postcommit(self, context):
        self._call_on_drivers("delete_policy_target_group_postcommit", context,
                              continue_on_failure=True)

    def get_policy_target_group_status(self, context):
        self._call_on_drivers("get_policy_target_group_status", context)

    def create_application_policy_group_precommit(self, context):
        self._call_on_drivers("create_application_policy_group_precommit",
                              context)

    def create_application_policy_group_postcommit(self, context):
        self._call_on_drivers("create_application_policy_group_postcommit",
                              context)

    def update_application_policy_group_precommit(self, context):
        self._call_on_drivers("update_application_policy_group_precommit",
                              context)

    def update_application_policy_group_postcommit(self, context):
        self._call_on_drivers("update_application_policy_group_postcommit",
                              context)

    def delete_application_policy_group_precommit(self, context):
        self._call_on_drivers("delete_application_policy_group_precommit",
                              context)

    def delete_application_policy_group_postcommit(self, context):
        self._call_on_drivers("delete_application_policy_group_postcommit",
                              context, continue_on_failure=True)

    def get_application_policy_group_status(self, context):
        self._call_on_drivers("get_application_policy_group_status", context)

    def create_l2_policy_precommit(self, context):
        self._call_on_drivers("create_l2_policy_precommit", context)

    def create_l2_policy_postcommit(self, context):
        self._call_on_drivers("create_l2_policy_postcommit", context)

    def update_l2_policy_precommit(self, context):
        self._call_on_drivers("update_l2_policy_precommit", context)

    def update_l2_policy_postcommit(self, context):
        self._call_on_drivers("update_l2_policy_postcommit", context)

    def delete_l2_policy_precommit(self, context):
        self._call_on_drivers("delete_l2_policy_precommit", context)

    def delete_l2_policy_postcommit(self, context):
        self._call_on_drivers("delete_l2_policy_postcommit", context,
                              continue_on_failure=True)

    def get_l2_policy_status(self, context):
        self._call_on_drivers("get_l2_policy_status", context)

    def create_l3_policy_precommit(self, context):
        self._call_on_drivers("create_l3_policy_precommit", context)

    def create_l3_policy_postcommit(self, context):
        self._call_on_drivers("create_l3_policy_postcommit", context)

    def update_l3_policy_precommit(self, context):
        self._call_on_drivers("update_l3_policy_precommit", context)

    def update_l3_policy_postcommit(self, context):
        self._call_on_drivers("update_l3_policy_postcommit", context)

    def delete_l3_policy_precommit(self, context):
        self._call_on_drivers("delete_l3_policy_precommit", context)

    def delete_l3_policy_postcommit(self, context):
        self._call_on_drivers("delete_l3_policy_postcommit", context,
                              continue_on_failure=True)

    def get_l3_policy_status(self, context):
        self._call_on_drivers("get_l3_policy_status", context)

    def create_network_service_policy_precommit(self, context):
        self._call_on_drivers(
            "create_network_service_policy_precommit", context)

    def create_network_service_policy_postcommit(self, context):
        self._call_on_drivers(
            "create_network_service_policy_postcommit", context)

    def update_network_service_policy_precommit(self, context):
        self._call_on_drivers(
            "update_network_service_policy_precommit", context)

    def update_network_service_policy_postcommit(self, context):
        self._call_on_drivers(
            "update_network_service_policy_postcommit", context)

    def delete_network_service_policy_precommit(self, context):
        self._call_on_drivers(
            "delete_network_service_policy_precommit", context)

    def delete_network_service_policy_postcommit(self, context):
        self._call_on_drivers(
            "delete_network_service_policy_postcommit", context,
            continue_on_failure=True)

    def get_network_service_policy_status(self, context):
        self._call_on_drivers("get_network_service_policy_status", context)

    def create_policy_classifier_precommit(self, context):
        self._call_on_drivers("create_policy_classifier_precommit", context)

    def create_policy_classifier_postcommit(self, context):
        self._call_on_drivers("create_policy_classifier_postcommit", context)

    def update_policy_classifier_precommit(self, context):
        self._call_on_drivers("update_policy_classifier_precommit", context)

    def update_policy_classifier_postcommit(self, context):
        self._call_on_drivers("update_policy_classifier_postcommit", context)

    def delete_policy_classifier_precommit(self, context):
        self._call_on_drivers("delete_policy_classifier_precommit", context)

    def delete_policy_classifier_postcommit(self, context):
        self._call_on_drivers("delete_policy_classifier_postcommit", context,
                              continue_on_failure=True)

    def get_policy_classifier_status(self, context):
        self._call_on_drivers("get_policy_classifier_status", context)

    def create_policy_action_precommit(self, context):
        self._call_on_drivers("create_policy_action_precommit", context)

    def create_policy_action_postcommit(self, context):
        self._call_on_drivers("create_policy_action_postcommit", context)

    def update_policy_action_precommit(self, context):
        self._call_on_drivers("update_policy_action_precommit", context)

    def update_policy_action_postcommit(self, context):
        self._call_on_drivers("update_policy_action_postcommit", context)

    def delete_policy_action_precommit(self, context):
        self._call_on_drivers("delete_policy_action_precommit", context)

    def delete_policy_action_postcommit(self, context):
        self._call_on_drivers("delete_policy_action_postcommit", context,
                              continue_on_failure=True)

    def get_policy_action_status(self, context):
        self._call_on_drivers("get_policy_action_status", context)

    def create_policy_rule_precommit(self, context):
        self._call_on_drivers("create_policy_rule_precommit", context)

    def create_policy_rule_postcommit(self, context):
        self._call_on_drivers("create_policy_rule_postcommit", context)

    def update_policy_rule_precommit(self, context):
        self._call_on_drivers("update_policy_rule_precommit", context)

    def update_policy_rule_postcommit(self, context):
        self._call_on_drivers("update_policy_rule_postcommit", context)

    def delete_policy_rule_precommit(self, context):
        self._call_on_drivers("delete_policy_rule_precommit", context)

    def delete_policy_rule_postcommit(self, context):
        self._call_on_drivers("delete_policy_rule_postcommit", context,
                              continue_on_failure=True)

    def get_policy_rule_status(self, context):
        self._call_on_drivers("get_policy_rule_status", context)

    def create_policy_rule_set_precommit(self, context):
        self._call_on_drivers("create_policy_rule_set_precommit", context)

    def create_policy_rule_set_postcommit(self, context):
        self._call_on_drivers("create_policy_rule_set_postcommit", context)

    def update_policy_rule_set_precommit(self, context):
        self._call_on_drivers("update_policy_rule_set_precommit", context)

    def update_policy_rule_set_postcommit(self, context):
        self._call_on_drivers("update_policy_rule_set_postcommit", context)

    def delete_policy_rule_set_precommit(self, context):
        self._call_on_drivers("delete_policy_rule_set_precommit", context)

    def delete_policy_rule_set_postcommit(self, context):
        self._call_on_drivers("delete_policy_rule_set_postcommit", context,
                              continue_on_failure=True)

    def get_policy_rule_set_status(self, context):
        self._call_on_drivers("get_policy_rule_set_status", context)

    def create_external_segment_precommit(self, context):
        self._call_on_drivers("create_external_segment_precommit",
                              context)

    def create_external_segment_postcommit(self, context):
        self._call_on_drivers("create_external_segment_postcommit",
                              context)

    def update_external_segment_precommit(self, context):
        self._call_on_drivers("update_external_segment_precommit",
                              context)

    def update_external_segment_postcommit(self, context):
        self._call_on_drivers("update_external_segment_postcommit",
                              context)

    def delete_external_segment_precommit(self, context):
        self._call_on_drivers("delete_external_segment_precommit",
                              context)

    def delete_external_segment_postcommit(self, context):
        self._call_on_drivers("delete_external_segment_postcommit",
                              context, continue_on_failure=True)

    def get_external_segment_status(self, context):
        self._call_on_drivers("get_external_segment_status", context)

    def create_external_policy_precommit(self, context):
        self._call_on_drivers("create_external_policy_precommit",
                              context)

    def create_external_policy_postcommit(self, context):
        self._call_on_drivers("create_external_policy_postcommit",
                              context)

    def update_external_policy_precommit(self, context):
        self._call_on_drivers("update_external_policy_precommit",
                              context)

    def update_external_policy_postcommit(self, context):
        self._call_on_drivers("update_external_policy_postcommit",
                              context)

    def delete_external_policy_precommit(self, context):
        self._call_on_drivers("delete_external_policy_precommit",
                              context)

    def delete_external_policy_postcommit(self, context):
        self._call_on_drivers("delete_external_policy_postcommit",
                              context, continue_on_failure=True)

    def get_external_policy_status(self, context):
        self._call_on_drivers("get_external_policy_status", context)

    def create_nat_pool_precommit(self, context):
        self._call_on_drivers("create_nat_pool_precommit", context)

    def create_nat_pool_postcommit(self, context):
        self._call_on_drivers("create_nat_pool_postcommit", context)

    def update_nat_pool_precommit(self, context):
        self._call_on_drivers("update_nat_pool_precommit", context)

    def update_nat_pool_postcommit(self, context):
        self._call_on_drivers("update_nat_pool_postcommit", context)

    def delete_nat_pool_precommit(self, context):
        self._call_on_drivers("delete_nat_pool_precommit", context)

    def delete_nat_pool_postcommit(self, context):
        self._call_on_drivers("delete_nat_pool_postcommit", context,
                              continue_on_failure=True)

    def get_nat_pool_status(self, context):
        self._call_on_drivers("get_nat_pool_status", context)

    def start_rpc_listeners(self):
        return self._call_on_drivers("start_rpc_listeners")

    def validate_state(self, repair):
        result = api.VALIDATION_PASSED
        for driver in self.ordered_policy_drivers:
            this_result = driver.obj.validate_state(repair)
            if (this_result == api.VALIDATION_FAILED_UNREPAIRABLE or
                (this_result == api.VALIDATION_FAILED_REPAIRABLE and
                 result != api.VALIDATION_FAILED_UNREPAIRABLE) or
                (this_result == api.VALIDATION_REPAIRED and
                 result == api.VALIDATION_PASSED)):
                result = this_result
        return result
