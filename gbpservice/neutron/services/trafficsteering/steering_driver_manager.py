# Copyright 2015, Instituto de Telecomunicacoes - Polo de Aveiro.
# All rights reserved.
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


import stevedore

from oslo_config import cfg
from oslo_log import log

from gbpservice.neutron.services.trafficsteering.common import exceptions


LOG = log.getLogger(__name__)


class SteeringDriverManager(stevedore.named.NamedExtensionManager):
    """Manage traffic steering enforcement using drivers."""

    def __init__(self):
        self.steering_drivers = {}
        self.ordered_steering_drivers = []

        LOG.info(_("Configured steering driver names: %s"),
                 cfg.CONF.traffic_steering.steering_drivers)
        super(SteeringDriverManager, self).__init__(
            'neutron.traffic_steering.steering_drivers',
            cfg.CONF.traffic_steering.steering_drivers,
            invoke_on_load=True,
            name_order=True)
        LOG.info(_("Loaded steering driver names: %s"), self.names())
        self._register_steering_drivers()

    def _register_steering_drivers(self):
        """Register all steering drivers.

        This method should only be called once in the SteeringDriverManager
        constructor.
        """
        for ext in self:
            self.steering_drivers[ext.name] = ext
            self.ordered_steering_drivers.append(ext)
        LOG.info(_("Registered steering drivers: %s"),
                 [driver.name for driver in self.ordered_steering_drivers])

    def initialize(self):
        self.native_bulk_support = True
        for driver in self.ordered_steering_drivers:
            LOG.info(_("Initializing steering driver '%s'"), driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_on_drivers(self, method_name, context,
                         continue_on_failure=False):
        """Helper method for calling a method across all steering drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all steering drivers once one has raised an exception
        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver call fails.
        """
        error = False
        for driver in self.ordered_steering_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception:
                LOG.exception(
                    _("Steering driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                error = True
                if not continue_on_failure:
                    break
        if error:
            raise exceptions.SteeringDriverError(
                method=method_name
            )

    def create_port_chain_precommit(self, context):
        """Notify all steering drivers during port chain creation.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver create_port_chain_precommit call fails.

        Called within the database transaction. If a steering driver
        raises an exception, then a SteeringDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all steering drivers are called in this case.
        """
        self._call_on_drivers("create_port_chain_precommit", context)

    def create_port_chain_postcommit(self, context):
        """Notify all steering drivers after port chain creation.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver create_port_chain_postcommit call fails.

        Called after the database transaction. If a steering driver
        raises an exception, then a SteeringDriverError is propagated
        to the caller, where the port chain will be deleted, triggering
        any required cleanup. There is no guarantee that all steering
        drivers are called in this case.
        """
        self._call_on_drivers("create_port_chain_postcommit", context)

    def update_port_chain_precommit(self, context):
        """Notify all steering drivers during port chain update.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver update_port_chain_precommit call fails.

        Called within the database transaction. If a steering driver
        raises an exception, then a SteeringDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all steering drivers are called in this case.
        """
        self._call_on_drivers("update_port_chain_precommit", context)

    def update_port_chain_postcommit(self, context):
        """Notify all steering drivers after port chain update.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver update_port_chain_postcommit call fails.

        Called after the database transaction. If any steering driver
        raises an error, then the error is logged but we continue to
        call every other steering driver. A SteeringDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_port_chain_postcommit", context,
                              continue_on_failure=True)

    def delete_port_chain_precommit(self, context):
        """Notify all steering drivers during port chain deletion.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver delete_port_chain_precommit call fails.

        Called within the database transaction. If a steering driver
        raises an exception, then a SteeringDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all steering drivers are called in this case.
        """
        self._call_on_drivers("delete_port_chain_precommit", context)

    def delete_port_chain_postcommit(self, context):
        """Notify all steering drivers after port chain deletion.

        :raises: neutron.plugins.trafficsteering.common.SteeringDriverError
        if any steering driver delete_port_chain_postcommit call fails.

        Called after the database transaction. If any steering driver
        raises an error, then the error is logged but we continue to
        call every other steering driver. A SteeringDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        port chain resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        port chain.
        """
        self._call_on_drivers("delete_port_chain_postcommit", context,
                              continue_on_failure=True)