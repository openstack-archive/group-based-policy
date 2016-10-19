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

from neutron.db import model_base
import sqlalchemy as sa


class PortEndpoint(model_base.BASEV2):
    __tablename__ = 'gp_apic_port_endpoints'
    port_id = sa.Column(
        sa.String(36), sa.ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True)
    endpoint = sa.Column(sa.LargeBinary, nullable=True)
    up_to_date = sa.Column(sa.Boolean, default=False, nullable=False)


class PortEndpointManager(object):

    def update(self, session, port_id, endpoint=None, up_to_date=None):
        with session.begin(subtransactions=True):
            current = self.get(session, port_id)
            if not current:
                # Create
                current = PortEndpoint(port_id=port_id, endpoint=endpoint,
                                       up_to_date=up_to_date or False)
            if endpoint is not None:
                current.endpoint = endpoint
            if up_to_date is not None:
                current.up_to_date = up_to_date
            session.add(current)
            return current

    def get(self, session, port_id):
        with session.begin(subtransactions=True):
            return session.query(PortEndpoint).filter_by(
                port_id=port_id).first()
