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

from neutron_lib.plugins import directory
from oslo_log import log as logging

from gbpservice._i18n import _LI
from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_auto_ptg_db as auto_ptg_db)
from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_intra_ptg_db as intra_ptg_db)
from gbpservice.neutron.db.grouppolicy import group_policy_db as gp_db
from gbpservice.neutron.extensions import cisco_apic_gbp
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class AIMExtensionDriver(api.ExtensionDriver,
                         intra_ptg_db.ApicIntraPtgDBMixin,
                         auto_ptg_db.ApicAutoPtgDBMixin):
    _supported_extension_alias = cisco_apic_gbp.ALIAS
    _extension_dict = cisco_apic_gbp.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.info(_LI("AIM Extension __init__"))
        self._policy_driver = None

    @property
    def _pd(self):
        if not self._policy_driver:
            gbp_plugin = directory.get_plugin("GROUP_POLICY")
            policy_mgr = gbp_plugin.policy_driver_manager
            self._policy_driver = policy_mgr.policy_drivers['aim_mapping'].obj
        return self._policy_driver

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def _set_intra_ptg_allow(self, session, data, result):
        ptg = data['policy_target_group']
        ptg_db = (session.query(gp_db.PolicyTargetGroup)
                  .filter_by(id=result['id']).one())
        if not ptg_db:
            raise gpolicy.PolicyTargetGroupNotFound(
                policy_target_group_id=result['id'])
        if 'intra_ptg_allow' in ptg:
            self.set_intra_ptg_allow(
                session, policy_target_group_id=result['id'],
                intra_ptg_allow=ptg['intra_ptg_allow'])
            result['intra_ptg_allow'] = ptg['intra_ptg_allow']
        else:
            self._extend_ptg_dict_with_intra_ptg_allow(session, result)

    def _extend_ptg_dict_with_intra_ptg_allow(self, session, result):
        result['intra_ptg_allow'] = self.get_intra_ptg_allow(
            session, policy_target_group_id=result['id'])

    def process_create_policy_target_group(self, session, data, result):
        self._set_intra_ptg_allow(session, data, result)
        result['is_auto_ptg'] = bool(
            gpolicy.AUTO_PTG_REGEX.match(result['id']))
        self.set_is_auto_ptg(
            session, policy_target_group_id=result['id'],
            is_auto_ptg=result['is_auto_ptg'])

    def process_update_policy_target_group(self, session, data, result):
        self._set_intra_ptg_allow(session, data, result)

    def extend_policy_target_group_dict(self, session, result):
        self._extend_ptg_dict_with_intra_ptg_allow(session, result)
        result['is_auto_ptg'] = self.get_is_auto_ptg(
            session, policy_target_group_id=result['id'])
        self._pd.extend_policy_target_group_dict(session, result)

    def extend_application_policy_group_dict(self, session, result):
        self._pd.extend_application_policy_group_dict(session, result)

    def extend_policy_rule_dict(self, session, result):
        self._pd.extend_policy_rule_dict(session, result)

    def extend_policy_rule_set_dict(self, session, result):
        self._pd.extend_policy_rule_set_dict(session, result)
