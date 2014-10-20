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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.common import log
from neutron.db import model_base
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

from gbp.neutron.db.grouppolicy import group_policy_db as gpdb


LOG = logging.getLogger(__name__)


class EndpointMapping(gpdb.Endpoint):
    """Mapping of Endpoint to Neutron Port."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # REVISIT(ivar): Set null on delete is a temporary workaround until Nova
    # bug 1158684 is fixed.
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete='SET NULL'),
                        nullable=True, unique=True)


class EndpointGroupSubnetAssociation(model_base.BASEV2):
    """Models the many to many relation between EndpointGroup and Subnets."""
    __tablename__ = 'gp_endpoint_group_subnet_associations'
    endpoint_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_endpoint_groups.id'),
                                  primary_key=True)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          primary_key=True)


class EndpointGroupMapping(gpdb.EndpointGroup):
    """Mapping of EndpointGroup to set of Neutron Subnets."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    subnets = orm.relationship(EndpointGroupSubnetAssociation,
                               cascade='all', lazy="joined")


class L2PolicyMapping(gpdb.L2Policy):
    """Mapping of L2Policy to Neutron Network."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'),
                           nullable=True, unique=True)


class L3PolicyRouterAssociation(model_base.BASEV2):
    """Models the many to many relation between L3Policies and Routers."""
    __tablename__ = 'gp_l3_policy_router_associations'
    l3_policy_id = sa.Column(sa.String(36), sa.ForeignKey('gp_l3_policies.id'),
                             primary_key=True)
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          primary_key=True)


class L3PolicyMapping(gpdb.L3Policy):
    """Mapping of L3Policy to set of Neutron Routers."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    routers = orm.relationship(L3PolicyRouterAssociation,
                               cascade='all', lazy="joined")


class GroupPolicyMappingDbPlugin(gpdb.GroupPolicyDbPlugin):
    """Group Policy Mapping interface implementation using SQLAlchemy models.
    """

    def _make_endpoint_dict(self, ep, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_endpoint_dict(ep)
        res['port_id'] = ep.port_id
        return self._fields(res, fields)

    def _make_endpoint_group_dict(self, epg, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_endpoint_group_dict(epg)
        res['subnets'] = [subnet.subnet_id for subnet in epg.subnets]
        return self._fields(res, fields)

    def _make_l2_policy_dict(self, l2p, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_l2_policy_dict(l2p)
        res['network_id'] = l2p.network_id
        return self._fields(res, fields)

    def _make_l3_policy_dict(self, l3p, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_l3_policy_dict(l3p)
        res['routers'] = [router.router_id for router in l3p.routers]
        return self._fields(res, fields)

    def _set_port_for_endpoint(self, context, ep_id, port_id):
        with context.session.begin(subtransactions=True):
            ep_db = self._get_endpoint(context, ep_id)
            ep_db.port_id = port_id

    def _add_subnet_to_endpoint_group(self, context, epg_id, subnet_id):
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, epg_id)
            assoc = EndpointGroupSubnetAssociation(endpoint_group_id=epg_id,
                                                   subnet_id=subnet_id)
            epg_db.subnets.append(assoc)
        return [subnet.subnet_id for subnet in epg_db.subnets]

    def _set_network_for_l2_policy(self, context, l2p_id, network_id):
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2p_id)
            l2p_db.network_id = network_id

    def _add_router_to_l3_policy(self, context, l3p_id, router_id):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            assoc = L3PolicyRouterAssociation(l3_policy_id=l3p_id,
                                              router_id=router_id)
            l3p_db.routers.append(assoc)
        return [router.router_id for router in l3p_db.routers]

    @log.log
    def create_endpoint(self, context, endpoint):
        ep = endpoint['endpoint']
        tenant_id = self._get_tenant_id_for_create(context, ep)
        with context.session.begin(subtransactions=True):
            ep_db = EndpointMapping(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=ep['name'],
                                    description=ep['description'],
                                    endpoint_group_id=
                                    ep['endpoint_group_id'],
                                    port_id=ep['port_id'])
            context.session.add(ep_db)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        epg = endpoint_group['endpoint_group']
        tenant_id = self._get_tenant_id_for_create(context, epg)
        with context.session.begin(subtransactions=True):
            epg_db = EndpointGroupMapping(id=uuidutils.generate_uuid(),
                                          tenant_id=tenant_id,
                                          name=epg['name'],
                                          description=epg['description'],
                                          l2_policy_id=epg['l2_policy_id'],
                                          network_service_policy_id=
                                          epg['network_service_policy_id'])
            context.session.add(epg_db)
            if 'subnets' in epg:
                for subnet in epg['subnets']:
                    assoc = EndpointGroupSubnetAssociation(
                        endpoint_group_id=epg_db.id,
                        subnet_id=subnet
                    )
                    epg_db.subnets.append(assoc)
            self._process_contracts_for_epg(context, epg_db, epg)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        epg = endpoint_group['endpoint_group']
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, endpoint_group_id)
            self._process_contracts_for_epg(context, epg_db, epg)
            if 'subnets' in epg:
                # Add/remove associations for changes in subnets.
                new_subnets = set(epg['subnets'])
                old_subnets = set(subnet.subnet_id
                                  for subnet in epg_db.subnets)
                for subnet in new_subnets - old_subnets:
                    assoc = EndpointGroupSubnetAssociation(
                        endpoint_group_id=endpoint_group_id, subnet_id=subnet)
                    epg_db.subnets.append(assoc)
                for subnet in old_subnets - new_subnets:
                    assoc = (context.session.
                             query(EndpointGroupSubnetAssociation).
                             filter_by(endpoint_group_id=endpoint_group_id,
                                       subnet_id=subnet).
                             one())
                    epg_db.subnets.remove(assoc)
                    context.session.delete(assoc)
                # Don't update epg_db.subnets with subnet IDs.
                del epg['subnets']
            epg_db.update(epg)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def create_l2_policy(self, context, l2_policy):
        l2p = l2_policy['l2_policy']
        tenant_id = self._get_tenant_id_for_create(context, l2p)
        with context.session.begin(subtransactions=True):
            l2p_db = L2PolicyMapping(id=uuidutils.generate_uuid(),
                                     tenant_id=tenant_id,
                                     name=l2p['name'],
                                     description=l2p['description'],
                                     l3_policy_id=l2p['l3_policy_id'],
                                     network_id=l2p['network_id'])
            context.session.add(l2p_db)
        return self._make_l2_policy_dict(l2p_db)

    @log.log
    def create_l3_policy(self, context, l3_policy):
        l3p = l3_policy['l3_policy']
        tenant_id = self._get_tenant_id_for_create(context, l3p)
        self.validate_subnet_prefix_length(l3p['ip_version'],
                                           l3p['subnet_prefix_length'])
        with context.session.begin(subtransactions=True):
            l3p_db = L3PolicyMapping(id=uuidutils.generate_uuid(),
                                     tenant_id=tenant_id,
                                     name=l3p['name'],
                                     ip_version=l3p['ip_version'],
                                     ip_pool=l3p['ip_pool'],
                                     subnet_prefix_length=
                                     l3p['subnet_prefix_length'],
                                     description=l3p['description'])
            context.session.add(l3p_db)
            if 'routers' in l3p:
                for router in l3p['routers']:
                    assoc = L3PolicyRouterAssociation(
                        l3_policy_id=l3p_db.id,
                        router_id=router
                    )
                    l3p_db.routers.append(assoc)
        return self._make_l3_policy_dict(l3p_db)

    @log.log
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        l3p = l3_policy['l3_policy']
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3_policy_id)
            if 'subnet_prefix_length' in l3p:
                self.validate_subnet_prefix_length(l3p_db.ip_version,
                                                   l3p['subnet_prefix_length'])
            if 'routers' in l3p:
                # Add/remove associations for changes in routers.
                new_routers = set(l3p['routers'])
                old_routers = set(router.router_id
                                  for router in l3p_db.routers)
                for router in new_routers - old_routers:
                    assoc = L3PolicyRouterAssociation(
                        l3_policy_id=l3_policy_id, router_id=router)
                    l3p_db.routers.append(assoc)
                for router in old_routers - new_routers:
                    assoc = (context.session.query(L3PolicyRouterAssociation).
                             filter_by(l3_policy_id=l3_policy_id,
                                       router_id=router).
                             one())
                    l3p_db.routers.remove(assoc)
                    context.session.delete(assoc)
                # Don't update l3p_db.routers with router IDs.
                del l3p['routers']
            l3p_db.update(l3p)
        return self._make_l3_policy_dict(l3p_db)
