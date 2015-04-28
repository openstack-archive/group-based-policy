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
from oslo_log import log as logging
import stevedore

from gbpservice.neutron.services.servicechain.plugins.ncp import config  # noqa

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
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)