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
from oslo_log import log as logging
import sqlalchemy as sa

from gbpservice.neutron.db.grouppolicy import group_policy_db as gp_db

LOG = logging.getLogger(__name__)
PROVIDER = 'provider'
CONSUMER = 'consumer'
MANAGEMENT = 'management'
RELATIONSHIPS = [PROVIDER, CONSUMER, MANAGEMENT]


class NodeToDriverMapping(model_base.BASEV2):
    """Node to Driver mapping DB.

    This table keeps track of the driver owning a specific SC Node based on
    the SC instance
    """

    __tablename__ = 'ncp_node_to_driver_mapping'
    servicechain_node_id = sa.Column(sa.String(36),
                                     sa.ForeignKey('sc_nodes.id',
                                                   ondelete='CASCADE'),
                                     nullable=False, primary_key=True)
    # Based on the extension name
    driver_name = sa.Column(sa.String(36), nullable=False)
    servicechain_instance_id = sa.Column(sa.String(36),
                                         sa.ForeignKey('sc_instances.id',
                                                       ondelete='CASCADE'),
                                         primary_key=True)


class ServiceTarget(model_base.BASEV2):
    """Service related policy targets.

    Internal information regarding the policy targets owned by services.
    """

    __tablename__ = 'ncp_service_targets'
    policy_target_id = sa.Column(sa.String(36),
                                 sa.ForeignKey(gp_db.PolicyTarget.id,
                                               ondelete='CASCADE'),
                                 nullable=False, primary_key=True)
    # Not a FK to avoid constraint error on SCI delete
    # keeping the DB entry is useful to identify uncleaned PTs
    servicechain_instance_id = sa.Column(sa.String(36),
                                         nullable=False, primary_key=True)
    # Not a FK to avoid constraint error on SCN delete.
    # keeping the DB entry is useful to identify uncleaned PTs
    servicechain_node_id = sa.Column(sa.String(36),
                                     nullable=False, primary_key=True)
    # Defines on which "side" of the chain the PT is placed. typically
    # its values can be "provider", "consumer" or "management"
    relationship = sa.Column(sa.String(25), nullable=False)
    position = sa.Column(sa.Integer)


def set_node_owner(context, driver_name):
    session = context.session
    with session.begin(subtransactions=True):
            owner = NodeToDriverMapping(
                servicechain_instance_id=context.instance['id'],
                servicechain_node_id=context.current_node['id'],
                driver_name=driver_name)
            session.add(owner)


def get_node_owner(context):
    session = context.session
    with session.begin(subtransactions=True):
        query = session.query(NodeToDriverMapping)
        query = query.filter_by(
            servicechain_instance_id=context.instance['id'])
        query = query.filter_by(
            servicechain_node_id=context.current_node['id'])
        return query.all()


def unset_node_owner(context):
    session = context.session
    with session.begin(subtransactions=True):
        query = session.query(NodeToDriverMapping)
        query = query.filter_by(
            servicechain_instance_id=context.instance['id'])
        query = query.filter_by(
            servicechain_node_id=context.current_node['id'])
        for owner in query.all():
            session.delete(owner)


def set_service_target(context, policy_target_id, relationship):
    session = context.session
    with session.begin(subtransactions=True):
            owner = ServiceTarget(
                policy_target_id=policy_target_id,
                servicechain_instance_id=context.instance['id'],
                servicechain_node_id=context.current_node['id'],
                position=context.current_position,
                relationship=relationship)
            session.add(owner)


def get_service_targets(session, policy_target_id=None, relationship=None,
                        servicechain_instance_id=None, position=None,
                        servicechain_node_id=None):
    with session.begin(subtransactions=True):
        query = _prepare_service_target_query(
            session, policy_target_id=policy_target_id,
            relationship=relationship,
            servicechain_instance_id=servicechain_instance_id,
            position=position, servicechain_node_id=servicechain_node_id)
        return query.all()


def get_service_targets_count(session, policy_target_id=None,
                              relationship=None, servicechain_instance_id=None,
                              position=None, servicechain_node_id=None):
    with session.begin(subtransactions=True):
        query = _prepare_service_target_query(
            session, policy_target_id=policy_target_id,
            relationship=relationship,
            servicechain_instance_id=servicechain_instance_id,
            position=position, servicechain_node_id=servicechain_node_id)
        return query.count()


def _prepare_service_target_query(session, policy_target_id=None,
                                  relationship=None,
                                  servicechain_instance_id=None, position=None,
                                  servicechain_node_id=None):
    query = session.query(ServiceTarget)
    if servicechain_instance_id:
        query = query.filter_by(
            servicechain_instance_id=servicechain_instance_id)
    if servicechain_node_id:
        query = query.filter_by(
            servicechain_node_id=servicechain_node_id)
    if policy_target_id:
        query = query.filter_by(policy_target_id=policy_target_id)
    if position:
        query = query.filter_by(position=position)
    if relationship:
        query = query.filter_by(relationship=relationship)
    return query
