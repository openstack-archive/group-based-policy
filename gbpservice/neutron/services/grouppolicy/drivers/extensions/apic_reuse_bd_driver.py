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
    apic_reuse_bd_db as db)
from gbpservice.neutron.db.grouppolicy import group_policy_db as gp_db
from gbpservice.neutron.extensions import apic_reuse_bd as ext
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class ApicReuseBdExtensionDriver(api.ExtensionDriver,
                                 db.ApicReuseBdDBMixin):
    _supported_extension_alias = ext.CISCO_APIC_GBP_REUSE_BD_EXT
    _extension_dict = ext.EXTENDED_ATTRIBUTES_2_0

    def __init__(self):
        LOG.info(_LI("ApicReuseBdExtensionDriver __init__"))

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_l2_policy(self, session, data, result):
        l2p = data['l2_policy']
        if l2p.get('reuse_bd'):
            target_l2p = (session.query(gp_db.L2Policy)
                          .filter_by(id=l2p['reuse_bd']).first())
            if not target_l2p:
                raise gpolicy.L2PolicyNotFound(l2_policy_id=l2p['reuse_bd'])
            self.add_reuse_bd_l2policy(session, result['id'], l2p['reuse_bd'])
            result['reuse_bd'] = l2p['reuse_bd']

    def extend_l2_policy_dict(self, session, result):
        row = self.get_reuse_bd_l2policy(session, l2_policy_id=result['id'])
        if row:
            result['reuse_bd'] = row.target_l2_policy_id
