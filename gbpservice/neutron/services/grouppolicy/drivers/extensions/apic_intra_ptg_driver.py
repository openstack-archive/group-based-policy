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
from oslo_log import log as logging

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_intra_ptg_db as db)
from gbpservice.neutron.db.grouppolicy import group_policy_db as gp_db
from gbpservice.neutron.extensions import apic_intra_ptg as ext
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class ApicIntraPtgExtensionDriver(api.ExtensionDriver,
                                  db.ApicIntraPtgDBMixin):
    _supported_extension_alias = ext.CISCO_APIC_GBP_INTRA_PTG_EXT
    _extension_dict = ext.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.info(_LI("ApicIntraPtgExtensionDriver __init__"))

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_policy_target_group(self, session, data, result):
        ptg = data['policy_target_group']
        if 'intra_ptg_allow' in ptg:
            ptg_db = (session.query(gp_db.PolicyTargetGroup)
                      .filter_by(id=result['id']).one())
            if not ptg_db:
                raise gpolicy.PolicyTargetGroupNotFound(
                    policy_target_group_id=result['id'])
            self.set_intra_ptg_allow(
                session, policy_target_group_id=result['id'],
                intra_ptg_allow=ptg['intra_ptg_allow'])
            result['intra_ptg_allow'] = ptg['intra_ptg_allow']

    def process_update_policy_target_group(self, session, data, result):
        self.process_create_policy_target_group(session, data, result)

    def extend_policy_target_group_dict(self, session, result):
        result['intra_ptg_allow'] = self.get_intra_ptg_allow(
            session, policy_target_group_id=result['id'])
