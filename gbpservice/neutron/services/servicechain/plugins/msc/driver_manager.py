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

from oslo_config import cfg
from oslo_log import log
import stevedore

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice.neutron.services.servicechain.common import (
    exceptions as sc_exc)


LOG = log.getLogger(__name__)
cfg.CONF.import_opt(
    'servicechain_drivers',
    'gbpservice.neutron.services.servicechain.plugins.msc.config',
    group='servicechain')


class DriverManager(stevedore.named.NamedExtensionManager):
    """Route servicechain APIs to servicechain drivers.

    """

    def __init__(self):
        # Registered servicechain drivers, keyed by name.
        self.drivers = {}
        # Ordered list of servicechain drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []

        LOG.info(_LI("Configured servicechain driver names: %s"),
                 cfg.CONF.servicechain.servicechain_drivers)
        super(DriverManager,
              self).__init__(
                  'gbpservice.neutron.servicechain.servicechain_drivers',
                  cfg.CONF.servicechain.servicechain_drivers,
                  invoke_on_load=True, name_order=True)
        LOG.info(_LI("Loaded servicechain driver names: %s"), self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all servicechain drivers.

        This method should only be called once in the DriverManager
        constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info(_LI("Registered servicechain drivers: %s"),
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        # ServiceChain bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info(_LI("Initializing servicechain driver '%s'"), driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_on_drivers(self, method_name, context):
        """Helper method for calling a method across all servicechain drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all servicechain drivers once one has raised an exception
        :raises: neutron.services.servicechain.common.ServiceChainDriverError
        if any servicechain driver call fails.
        """
        error = False
        for driver in self.ordered_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except sc_exc.ServiceChainException:
                # This is an exception for the user.
                raise
            except Exception:
                # This is an internal failure.
                LOG.exception(
                    _LE("ServiceChain driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                error = True
        if error:
            raise sc_exc.ServiceChainDriverError(
                method=method_name
            )

    def create_servicechain_node_precommit(self, context):
        self._call_on_drivers("create_servicechain_node_precommit", context)

    def create_servicechain_node_postcommit(self, context):
        self._call_on_drivers("create_servicechain_node_postcommit", context)

    def update_servicechain_node_precommit(self, context):
        self._call_on_drivers("update_servicechain_node_precommit", context)

    def update_servicechain_node_postcommit(self, context):
        self._call_on_drivers("update_servicechain_node_postcommit", context)

    def delete_servicechain_node_precommit(self, context):
        self._call_on_drivers("delete_servicechain_node_precommit", context)

    def delete_servicechain_node_postcommit(self, context):
        self._call_on_drivers("delete_servicechain_node_postcommit", context)

    def create_servicechain_spec_precommit(self, context):
        self._call_on_drivers("create_servicechain_spec_precommit", context)

    def create_servicechain_spec_postcommit(self, context):
        self._call_on_drivers("create_servicechain_spec_postcommit", context)

    def update_servicechain_spec_precommit(self, context):
        self._call_on_drivers("update_servicechain_spec_precommit", context)

    def update_servicechain_spec_postcommit(self, context):
        self._call_on_drivers("update_servicechain_spec_postcommit", context)

    def delete_servicechain_spec_precommit(self, context):
        self._call_on_drivers("delete_servicechain_spec_precommit", context)

    def delete_servicechain_spec_postcommit(self, context):
        self._call_on_drivers("delete_servicechain_spec_postcommit", context)

    def create_servicechain_instance_precommit(self, context):
        self._call_on_drivers("create_servicechain_instance_precommit",
                              context)

    def create_servicechain_instance_postcommit(self, context):
        self._call_on_drivers("create_servicechain_instance_postcommit",
                              context)

    def update_servicechain_instance_precommit(self, context):
        self._call_on_drivers("update_servicechain_instance_precommit",
                              context)

    def update_servicechain_instance_postcommit(self, context):
        self._call_on_drivers("update_servicechain_instance_postcommit",
                              context)

    def delete_servicechain_instance_precommit(self, context):
        self._call_on_drivers("delete_servicechain_instance_precommit",
                              context)

    def delete_servicechain_instance_postcommit(self, context):
        self._call_on_drivers("delete_servicechain_instance_postcommit",
                              context)

    def create_service_profile_precommit(self, context):
        self._call_on_drivers("create_service_profile_precommit",
                              context)

    def create_service_profile_postcommit(self, context):
        self._call_on_drivers("create_service_profile_postcommit",
                              context)

    def update_service_profile_precommit(self, context):
        self._call_on_drivers("update_service_profile_precommit",
                              context)

    def update_service_profile_postcommit(self, context):
        self._call_on_drivers("update_service_profile_postcommit",
                              context)

    def delete_service_profile_precommit(self, context):
        self._call_on_drivers("delete_service_profile_precommit",
                              context)

    def delete_service_profile_postcommit(self, context):
        self._call_on_drivers("delete_service_profile_postcommit",
                              context)
