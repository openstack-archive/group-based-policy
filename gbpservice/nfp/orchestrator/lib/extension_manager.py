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
import stevedore

cfg.CONF.register_opt(cfg.StrOpt('drivers'),
                      'nfp_orchestration_drivers')

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """

    """

    def __init__(self, sc_context, conf):
        super(ExtensionManager, self).__init__(
            'gbpservice.nfp.orchestrator.drivers',
            cfg.CONF.nfp_orchestration_drivers.drivers,
            invoke_on_load=True,
            invoke_kwds={'config': conf})
        self.drivers = dict()
        LOG.debug("Loaded extension driver names: %s" % self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            # self.ordered_ext_drivers.append(ext)
            driver_type = ext.name
            if driver_type in self.drivers:
                pass
            else:
                self.drivers[driver_type] = ext.obj

    def initialize(self):
        for _, driver in self.drivers.iteritems():
            # LOG.debug(_("Initializing extension driver '%s'"), driver.name)
            driver.obj.initialize()
