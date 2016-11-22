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
from sqlalchemy import orm


class GroupProxyMapping(model_base.BASEV2):
    __tablename__ = 'gp_group_proxy_mappings'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete="CASCADE"), primary_key=True)
    # A group can only be proxied by one single group
    proxied_group_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('gp_policy_target_groups.id'))
    # A group can only proxy one single other group
    # REVISIT(ivar): Can a backref be put here instead?
    proxy_group_id = sa.Column(sa.String(36),
                               sa.ForeignKey('gp_policy_target_groups.id',
                                             ondelete="SET NULL"))
    proxy_type = sa.Column(sa.String(24))
    enforce_service_chains = sa.Column(sa.Boolean, default=True,
                                       nullable=False)


class ProxyGatewayMapping(model_base.BASEV2):
    __tablename__ = 'gp_proxy_gateway_mappings'
    policy_target_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_targets.id',
                                     ondelete="CASCADE"), primary_key=True)
    proxy_gateway = sa.Column(sa.Boolean, nullable=False)
    group_default_gateway = sa.Column(sa.Boolean, nullable=False)


class L3PolicyProxySubnetpoolV4Association(model_base.BASEV2):
    """Models one to many relation between a L3Policy and v4 Subnetpools."""
    __tablename__ = 'gp_l3_policy_proxy_subnetpool_v4_associations'
    l3_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_proxy_ip_pool_mapping.l3_policy_id',
                                     ondelete='CASCADE'),
        primary_key=True)
    subnetpool_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnetpools.id'), primary_key=True)


class L3PolicyProxySubnetpoolV6Association(model_base.BASEV2):
    """Models one to many relation between a L3Policy and v6 Subnetpools."""
    __tablename__ = 'gp_l3_policy_proxy_subnetpool_v6_associations'
    l3_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_proxy_ip_pool_mapping.l3_policy_id',
                                     ondelete='CASCADE'),
        primary_key=True)
    subnetpool_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnetpools.id', ondelete='CASCADE'),
        primary_key=True)


class ProxyIPPoolMapping(model_base.BASEV2):
    __tablename__ = 'gp_proxy_ip_pool_mapping'

    l3_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_l3_policies.id', ondelete="CASCADE"),
        primary_key=True)
    proxy_ip_pool = sa.Column(sa.String(64), nullable=False)
    proxy_subnet_prefix_length = sa.Column(sa.Integer, nullable=False)
    proxy_subnetpools_v4 = orm.relationship(
        L3PolicyProxySubnetpoolV4Association, cascade='all', lazy="joined")
    proxy_subnetpools_v6 = orm.relationship(
        L3PolicyProxySubnetpoolV6Association, cascade='all', lazy="joined")


class ProxyGroupDbManager(object):

    def _update_proxy_subnetpools_for_l3_policy(self, session, l3p_id,
                                                subnetpools, ip_version=4):
        # Add/remove associations for changes in subnetpools
        # TODO(Sumit): Before disassociating a subnetpool, check that
        # there is no PT present on a subnet which belongs to that subnetpool
        # TODO(ivar): check subnetpool uuid
        if subnetpools is None:
            return
        with session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy_pool_mapping(session, l3p_id)
            new_subnetpools = set(subnetpools)
            if ip_version == 4:
                old_subnetpools = set(sp.subnetpool_id
                                      for sp in l3p_db.proxy_subnetpools_v4)
            else:
                old_subnetpools = set(sp.subnetpool_id
                                      for sp in l3p_db.proxy_subnetpools_v6)
            for sp in new_subnetpools - old_subnetpools:
                if ip_version == 4:
                    assoc = L3PolicyProxySubnetpoolV4Association(
                        l3_policy_id=l3p_id, subnetpool_id=sp)
                    l3p_db.proxy_subnetpools_v4.append(assoc)
                else:
                    assoc = L3PolicyProxySubnetpoolV6Association(
                        l3_policy_id=l3p_id, subnetpool_id=sp)
                    l3p_db.proxy_subnetpools_v6.append(assoc)
            for sp in old_subnetpools - new_subnetpools:
                if ip_version == 4:
                    assoc = (session.query(
                        L3PolicyProxySubnetpoolV4Association).filter_by(
                            l3_policy_id=l3p_id, subnetpool_id=sp).one())
                    l3p_db.proxy_subnetpools_v4.remove(assoc)
                else:
                    assoc = (session.query(
                        L3PolicyProxySubnetpoolV6Association).filter_by(
                            l3_policy_id=l3p_id, subnetpool_id=sp).one())
                    l3p_db.proxy_subnetpools_v6.remove(assoc)
                session.delete(assoc)

    def _get_l3_policy_pool_mapping(self, session, l3p_id):
        return session.query(ProxyIPPoolMapping).filter_by(
            l3_policy_id=l3p_id).first()
