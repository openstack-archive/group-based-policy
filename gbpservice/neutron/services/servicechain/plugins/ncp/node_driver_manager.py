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

from neutron.common import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
import stevedore

from gbpservice.neutron.services.servicechain.plugins.ncp import config  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp import model

LOG = logging.getLogger(__name__)


class NodeDriverManager(stevedore.named.NamedExtensionManager):
    """Route servicechain APIs to servicechain node drivers.

    """

    def __init__(self):
        # Registered node drivers, keyed by name.
        self.drivers = {}
        # Ordered list of node drivers.
        self.ordered_drivers = []
        names = cfg.CONF.node_composition_plugin.node_drivers
        LOG.info(_("Configured service chain node driver names: %s"), names)
        super(NodeDriverManager,
              self).__init__(
                  'gbpservice.neutron.servicechain.ncp_drivers', names,
                  invoke_on_load=True, name_order=True)
        LOG.info(_("Loaded service chain node driver names: %s"), self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all service chain node drivers."""
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info(_("Registered service chain node drivers: %s"),
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        """Initialize all the service chain node drivers."""
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info(_("Initializing service chain node drivers '%s'"),
                     driver.name)
            driver.obj.initialize(driver.name)
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def schedule_deploy(self, context):
        """Schedule Node Driver for Node creation.

        Given a NodeContext, this method returns the driver capable of creating
        the specific node.
        """
        for driver in self.ordered_drivers:
            try:
                driver.obj.validate_create(context)
                model.set_node_owner(context, driver.obj.name)
                return driver.obj
            except n_exc.NeutronException as e:
                LOG.warn(e.message)

    def schedule_destroy(self, context):
        """Schedule Node Driver for Node disruption.

        Given a NodeContext, this method returns the driver capable of
        destroying the specific node.
        """
        driver = self.get_owning_driver(context)
        if driver:
            model.unset_node_owner(context)
        return driver

    def schedule_update(self, context):
        """Schedule Node Driver for Node Update.

        Given a NodeContext, this method returns the driver capable of updating
        the specific node.
        """
        driver = self.get_owning_driver(context)
        if driver:
            driver.validate_update(context)
        return driver

    def clear_node_owner(self, context):
        """Remove Node Driver ownership set for a Node

        Given a NodeContext, this method removes the Node owner mapping in DB.
        This method is used when we want to perform a disruptive chain update
        by deleting and recreating the Node instances
        """
        model.unset_node_owner(context)

    def get_owning_driver(self, context):
        owner = model.get_node_owner(context)
        if owner:
            driver = self.drivers.get(owner[0].driver_name)
            return driver.obj if driver else None
