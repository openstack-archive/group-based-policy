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

from neutron._i18n import _LI
from neutron import manager as n_manager
from oslo_log import log as logging

from gbpservice.neutron.extensions import cisco_apic_gbp
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class AIMExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = cisco_apic_gbp.ALIAS
    _extension_dict = cisco_apic_gbp.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.info(_LI("AIM Extension __init__"))
        self._policy_driver = None

    @property
    def _pd(self):
        if not self._policy_driver:
            gbp_plugin = (n_manager.NeutronManager.get_service_plugins()
                          .get("GROUP_POLICY"))
            policy_mgr = gbp_plugin.policy_driver_manager
            self._policy_driver = policy_mgr.policy_drivers['aim_mapping'].obj
        return self._policy_driver

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def extend_policy_target_group_dict(self, session, result):
        self._pd.extend_policy_target_group_dict(session, result)

    def extend_policy_rule_dict(self, session, result):
        self._pd.extend_policy_rule_dict(session, result)

    def extend_policy_rule_set_dict(self, session, result):
        self._pd.extend_policy_rule_set_dict(session, result)
