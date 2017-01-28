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

from neutron_lib.db import model_base
import sqlalchemy as sa


class ApicAllowedVMNameDB(model_base.BASEV2):
    __tablename__ = 'gp_apic_mapping_allowed_vm_names'
    l3_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l3_policies.id',
                                           ondelete="CASCADE"),
                             primary_key=True)
    allowed_vm_name = sa.Column(sa.String(255), primary_key=True)


class ApicAllowedVMNameDBMixin(object):

    def get_l3_policy_allowed_vm_names(self, session, l3_policy_id):
        rows = (session.query(ApicAllowedVMNameDB).filter_by(
                l3_policy_id=l3_policy_id).all())
        return rows

    def get_l3_policy_allowed_vm_name(self, session, l3_policy_id,
                                      allowed_vm_name):
        row = (session.query(ApicAllowedVMNameDB).filter_by(
            l3_policy_id=l3_policy_id,
            allowed_vm_name=allowed_vm_name).one())
        return row

    def add_l3_policy_allowed_vm_name(self, session, l3_policy_id,
                                      allowed_vm_name):
        row = ApicAllowedVMNameDB(l3_policy_id=l3_policy_id,
                                  allowed_vm_name=allowed_vm_name)
        session.add(row)

    def delete_l3_policy_allowed_vm_name(self, session, l3_policy_id,
                                         allowed_vm_name):
        row = self.get_l3_policy_allowed_vm_name(
            session, l3_policy_id, allowed_vm_name)
        session.delete(row)
