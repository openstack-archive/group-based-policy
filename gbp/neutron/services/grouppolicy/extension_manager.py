# Copyright (c) 2014 OpenStack Foundation
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

from neutron.openstack.common import log
from oslo.config import cfg
import stevedore

LOG = log.getLogger(__name__)


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""

    def __init__(self):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        LOG.info(_("Configured extension driver names: %s"),
                 cfg.CONF.group_policy.extension_drivers)
        super(ExtensionManager, self).__init__(
            'gbp.neutron.group_policy.extension_drivers',
            cfg.CONF.group_policy.extension_drivers,
            invoke_on_load=True,
            name_order=True)
        LOG.info(_("Loaded extension driver names: %s"), self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info(_("Registered extension drivers: %s"),
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info(_("Initializing extension driver '%s'"), driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            alias = driver.obj.extension_alias
            exts.append(alias)
            LOG.info(_("Got %(alias)s extension from driver '%(drv)s'"),
                     {'alias': alias, 'drv': driver.name})
        return exts

    def _call_on_ext_drivers(self, method_name, session, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, data, result)
            except Exception:
                LOG.exception(
                    _("Extension driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )

    def process_create_policy_target(self, session, data, result):
        """Call all extension drivers during policy_target creation."""
        self._call_on_ext_drivers("process_create_policy_target",
                                  session, data, result)

    def process_update_policy_target(self, session, data, result):
        """Call all extension drivers during policy_target update."""
        self._call_on_ext_drivers("process_update_policy_target",
                                  session, data, result)

    def extend_policy_target_dict(self, session, result):
        """Call all extension drivers to extend policy_target dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_target_dict(session, result)

    def process_create_policy_target_group(self, session, data, result):
        """Call all extension drivers during policy_target_group creation."""
        self._call_on_ext_drivers("process_create_policy_target_group",
                                  session, data, result)

    def process_update_policy_target_group(self, session, data, result):
        """Call all extension drivers during policy_target_group update."""
        self._call_on_ext_drivers("process_update_policy_target_group",
                                  session, data, result)

    def extend_policy_target_group_dict(self, session, result):
        """Call all extension drivers to extend policy_target_group dictionary.
        """
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_target_group_dict(session, result)

    def process_create_l2_policy(self, session, data, result):
        """Call all extension drivers during l2_policy creation."""
        self._call_on_ext_drivers("process_create_l2_policy",
                                  session, data, result)

    def process_update_l2_policy(self, session, data, result):
        """Call all extension drivers during l2_policy update."""
        self._call_on_ext_drivers("process_update_l2_policy",
                                  session, data, result)

    def extend_l2_policy_dict(self, session, result):
        """Call all extension drivers to extend l2_policy dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_l2_policy_dict(session, result)

    def process_create_l3_policy(self, session, data, result):
        """Call all extension drivers during l3_policy creation."""
        self._call_on_ext_drivers("process_create_l3_policy",
                                  session, data, result)

    def process_update_l3_policy(self, session, data, result):
        """Call all extension drivers during l3_policy update."""
        self._call_on_ext_drivers("process_update_l3_policy",
                                  session, data, result)

    def extend_l3_policy_dict(self, session, result):
        """Call all extension drivers to extend l3_policy dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_l3_policy_dict(session, result)
