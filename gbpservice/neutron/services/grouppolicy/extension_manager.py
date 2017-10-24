# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
import stevedore

from gbpservice.neutron.services.grouppolicy.common import exceptions as gp_exc


LOG = log.getLogger(__name__)


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""

    def __init__(self):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        LOG.info("Configured extension driver names: %s",
                 cfg.CONF.group_policy.extension_drivers)
        super(ExtensionManager, self).__init__(
            'gbpservice.neutron.group_policy.extension_drivers',
            cfg.CONF.group_policy.extension_drivers,
            invoke_on_load=True,
            name_order=True)
        LOG.info("Loaded extension driver names: %s", self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info("Registered extension drivers: %s",
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info("Initializing extension driver '%s'", driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            alias = driver.obj.extension_alias
            exts.append(alias)
            LOG.info("Got %(alias)s extension from driver '%(drv)s'",
                     {'alias': alias, 'drv': driver.name})
        return exts

    def _call_on_ext_drivers(self, method_name, session, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, data, result)
            except (gp_exc.GroupPolicyException, n_exc.NeutronException):
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        "Extension driver '%(name)s' "
                        "failed in %(method)s",
                        {'name': driver.name, 'method': method_name}
                    )
            except Exception:
                LOG.exception("Extension driver '%(name)s' "
                              "failed in %(method)s",
                              {'name': driver.name, 'method': method_name})
                # We are replacing a non-GBP/non-Neutron exception here
                raise gp_exc.GroupPolicyDriverError(method=method_name)

    def process_create_policy_target(self, session, data, result):
        """Call all extension drivers during PT creation."""
        self._call_on_ext_drivers("process_create_policy_target",
                                  session, data, result)

    def process_update_policy_target(self, session, data, result):
        """Call all extension drivers during PT update."""
        self._call_on_ext_drivers("process_update_policy_target",
                                  session, data, result)

    def extend_policy_target_dict(self, session, result):
        """Call all extension drivers to extend PT dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_target_dict(session, result)

    def process_create_policy_target_group(self, session, data, result):
        """Call all extension drivers during PTG creation."""
        self._call_on_ext_drivers("process_create_policy_target_group",
                                  session, data, result)

    def process_update_policy_target_group(self, session, data, result):
        """Call all extension drivers during PTG update."""
        self._call_on_ext_drivers("process_update_policy_target_group",
                                  session, data, result)

    def extend_policy_target_group_dict(self, session, result):
        """Call all extension drivers to extend PTG dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_target_group_dict(session, result)

    def process_create_application_policy_group(self, session, data, result):
        """Call all extension drivers during PTG creation."""
        self._call_on_ext_drivers("process_create_application_policy_group",
                                  session, data, result)

    def process_update_application_policy_group(self, session, data, result):
        """Call all extension drivers during PTG update."""
        self._call_on_ext_drivers("process_update_application_policy_group",
                                  session, data, result)

    def extend_application_policy_group_dict(self, session, result):
        """Call all extension drivers to extend PTG dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_application_policy_group_dict(session, result)

    def process_create_l2_policy(self, session, data, result):
        """Call all extension drivers during L2P creation."""
        self._call_on_ext_drivers("process_create_l2_policy",
                                  session, data, result)

    def process_update_l2_policy(self, session, data, result):
        """Call all extension drivers during L2P update."""
        self._call_on_ext_drivers("process_update_l2_policy",
                                  session, data, result)

    def extend_l2_policy_dict(self, session, result):
        """Call all extension drivers to extend L2P dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_l2_policy_dict(session, result)

    def process_create_l3_policy(self, session, data, result):
        """Call all extension drivers during L3P creation."""
        self._call_on_ext_drivers("process_create_l3_policy",
                                  session, data, result)

    def process_update_l3_policy(self, session, data, result):
        """Call all extension drivers during L3P update."""
        self._call_on_ext_drivers("process_update_l3_policy",
                                  session, data, result)

    def extend_l3_policy_dict(self, session, result):
        """Call all extension drivers to extend L3P dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_l3_policy_dict(session, result)

    def process_create_policy_classifier(self, session, data, result):
        """Call all extension drivers during PC creation."""
        self._call_on_ext_drivers("process_create_policy_classifier",
                                  session, data, result)

    def process_update_policy_classifier(self, session, data, result):
        """Call all extension drivers during PC update."""
        self._call_on_ext_drivers("process_update_policy_classifier",
                                  session, data, result)

    def extend_policy_classifier_dict(self, session, result):
        """Call all extension drivers to extend PC dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_classifier_dict(session, result)

    def process_create_policy_action(self, session, data, result):
        """Call all extension drivers during PA creation."""
        self._call_on_ext_drivers("process_create_policy_action",
                                  session, data, result)

    def process_update_policy_action(self, session, data, result):
        """Call all extension drivers during PA update."""
        self._call_on_ext_drivers("process_update_policy_action",
                                  session, data, result)

    def extend_policy_action_dict(self, session, result):
        """Call all extension drivers to extend PA dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_action_dict(session, result)

    def process_create_policy_rule(self, session, data, result):
        """Call all extension drivers during PR creation."""
        self._call_on_ext_drivers("process_create_policy_rule",
                                  session, data, result)

    def process_update_policy_rule(self, session, data, result):
        """Call all extension drivers during PR update."""
        self._call_on_ext_drivers("process_update_policy_rule",
                                  session, data, result)

    def extend_policy_rule_dict(self, session, result):
        """Call all extension drivers to extend PR dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_rule_dict(session, result)

    def process_create_policy_rule_set(self, session, data, result):
        """Call all extension drivers during PRS creation."""
        self._call_on_ext_drivers("process_create_policy_rule_set",
                                  session, data, result)

    def process_update_policy_rule_set(self, session, data, result):
        """Call all extension drivers during PRS update."""
        self._call_on_ext_drivers("process_update_policy_rule_set",
                                  session, data, result)

    def extend_policy_rule_set_dict(self, session, result):
        """Call all extension drivers to extend PRS dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_policy_rule_set_dict(session, result)

    def process_create_network_service_policy(self, session, data, result):
        """Call all extension drivers during NSP creation."""
        self._call_on_ext_drivers("process_create_network_service_policy",
                                  session, data, result)

    def process_update_network_service_policy(self, session, data, result):
        """Call all extension drivers during NSP update."""
        self._call_on_ext_drivers("process_update_network_service_policy",
                                  session, data, result)

    def extend_network_service_policy_dict(self, session, result):
        """Call all extension drivers to extend NSP dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_network_service_policy_dict(session, result)

    def process_create_external_segment(self, session, data, result):
        """Call all extension drivers during EP creation."""
        self._call_on_ext_drivers("process_create_external_segment",
                                  session, data, result)

    def process_update_external_segment(self, session, data, result):
        """Call all extension drivers during EP update."""
        self._call_on_ext_drivers("process_update_external_segment",
                                  session, data, result)

    def extend_external_segment_dict(self, session, result):
        """Call all extension drivers to extend EP dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_external_segment_dict(session, result)

    def process_create_external_policy(self, session, data, result):
        """Call all extension drivers during EP creation."""
        self._call_on_ext_drivers("process_create_external_policy",
                                  session, data, result)

    def process_update_external_policy(self, session, data, result):
        """Call all extension drivers during EP update."""
        self._call_on_ext_drivers("process_update_external_policy",
                                  session, data, result)

    def extend_external_policy_dict(self, session, result):
        """Call all extension drivers to extend EP dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_external_policy_dict(session, result)

    def process_create_nat_pool(self, session, data, result):
        """Call all extension drivers during NP creation."""
        self._call_on_ext_drivers("process_create_nat_pool",
                                  session, data, result)

    def process_update_nat_pool(self, session, data, result):
        """Call all extension drivers during NP update."""
        self._call_on_ext_drivers("process_update_nat_pool",
                                  session, data, result)

    def extend_nat_pool_dict(self, session, result):
        """Call all extension drivers to extend NP dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_nat_pool_dict(session, result)
