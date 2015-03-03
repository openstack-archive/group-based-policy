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

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb


LOG = logging.getLogger(__name__)


class PolicyTargetMapping(gpdb.PolicyTarget):
    """Mapping of PolicyTarget to Neutron Port."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # REVISIT(ivar): Set null on delete is a temporary workaround until Nova
    # bug 1158684 is fixed.
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete='SET NULL'),
                        nullable=True, unique=True)


class PTGToSubnetAssociation(model_base.BASEV2):
    """Many to many relation between PolicyTargetGroup and Subnets."""
    __tablename__ = 'gp_ptg_to_subnet_associations'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id'),
        primary_key=True)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          primary_key=True)


class PolicyTargetGroupMapping(gpdb.PolicyTargetGroup):
    """Mapping of PolicyTargetGroup to set of Neutron Subnets."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    subnets = orm.relationship(PTGToSubnetAssociation,
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


class ExternalSegmentMapping(gpdb.ExternalSegment):
    """Mapping of L2Policy to Neutron Network."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=True, unique=True)


class GroupPolicyMappingDbPlugin(gpdb.GroupPolicyDbPlugin):
    """Group Policy Mapping interface implementation using SQLAlchemy models.
    """

    def _make_policy_target_dict(self, pt, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_policy_target_dict(pt)
        res['port_id'] = pt.port_id
        return self._fields(res, fields)

    def _make_policy_target_group_dict(self, ptg, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_policy_target_group_dict(ptg)
        res['subnets'] = [subnet.subnet_id for subnet in ptg.subnets]
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

    def _make_external_segment_dict(self, es, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_external_segment_dict(es)
        res['subnet_id'] = es.subnet_id
        return self._fields(res, fields)

    def _set_port_for_policy_target(self, context, pt_id, port_id):
        with context.session.begin(subtransactions=True):
            pt_db = self._get_policy_target(context, pt_id)
            pt_db.port_id = port_id

    def _add_subnet_to_policy_target_group(self, context, ptg_id, subnet_id):
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(context, ptg_id)
            assoc = PTGToSubnetAssociation(policy_target_group_id=ptg_id,
                                           subnet_id=subnet_id)
            ptg_db.subnets.append(assoc)
        return [subnet.subnet_id for subnet in ptg_db.subnets]

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

    def _set_subnet_to_es(self, context, es_id, subnet_id):
        with context.session.begin(subtransactions=True):
            es_db = self._get_external_segment(context, es_id)
            es_db.subnet_id = subnet_id

    def _update_ess_for_l3p(self, context, l3p_id, ess):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            self._set_ess_for_l3p(context, l3p_db, ess)

    @log.log
    def create_policy_target(self, context, policy_target):
        pt = policy_target['policy_target']
        tenant_id = self._get_tenant_id_for_create(context, pt)
        with context.session.begin(subtransactions=True):
            pt_db = PolicyTargetMapping(id=uuidutils.generate_uuid(),
                                        tenant_id=tenant_id,
                                        name=pt['name'],
                                        description=pt['description'],
                                        policy_target_group_id=
                                        pt['policy_target_group_id'],
                                        port_id=pt['port_id'])
            context.session.add(pt_db)
        return self._make_policy_target_dict(pt_db)

    @log.log
    def create_policy_target_group(self, context, policy_target_group):
        ptg = policy_target_group['policy_target_group']
        tenant_id = self._get_tenant_id_for_create(context, ptg)
        with context.session.begin(subtransactions=True):
            ptg_db = PolicyTargetGroupMapping(id=uuidutils.generate_uuid(),
                                              tenant_id=tenant_id,
                                              name=ptg['name'],
                                              description=ptg['description'],
                                              l2_policy_id=ptg['l2_policy_id'],
                                              network_service_policy_id=
                                              ptg['network_service_policy_id'],
                                              shared=ptg.get('shared', False))
            context.session.add(ptg_db)
            if 'subnets' in ptg:
                for subnet in ptg['subnets']:
                    assoc = PTGToSubnetAssociation(
                        policy_target_group_id=ptg_db.id,
                        subnet_id=subnet
                    )
                    ptg_db.subnets.append(assoc)
            self._process_policy_rule_sets_for_ptg(context, ptg_db, ptg)
        return self._make_policy_target_group_dict(ptg_db)

    @log.log
    def update_policy_target_group(self, context, policy_target_group_id,
                                   policy_target_group):
        ptg = policy_target_group['policy_target_group']
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(
                context, policy_target_group_id)
            self._process_policy_rule_sets_for_ptg(context, ptg_db, ptg)
            if 'subnets' in ptg:
                # Add/remove associations for changes in subnets.
                new_subnets = set(ptg['subnets'])
                old_subnets = set(subnet.subnet_id
                                  for subnet in ptg_db.subnets)
                for subnet in new_subnets - old_subnets:
                    assoc = PTGToSubnetAssociation(
                        policy_target_group_id=policy_target_group_id,
                        subnet_id=subnet)
                    ptg_db.subnets.append(assoc)
                for subnet in old_subnets - new_subnets:
                    assoc = (
                        context.session.query(
                            PTGToSubnetAssociation).filter_by(
                                policy_target_group_id=policy_target_group_id,
                                subnet_id=subnet).one())
                    ptg_db.subnets.remove(assoc)
                    context.session.delete(assoc)
                # Don't update ptg_db.subnets with subnet IDs.
                del ptg['subnets']
            ptg_db.update(ptg)
        return self._make_policy_target_group_dict(ptg_db)

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
                                     network_id=l2p['network_id'],
                                     shared=l2p.get('shared', False))
            context.session.add(l2p_db)
        return self._make_l2_policy_dict(l2p_db)

    @log.log
    def create_l3_policy(self, context, l3_policy):
        l3p = l3_policy['l3_policy']
        self.validate_ip_pool(l3p.get('ip_pool', None), l3p['ip_version'])
        tenant_id = self._get_tenant_id_for_create(context, l3p)
        self.validate_subnet_prefix_length(l3p['ip_version'],
                                           l3p['subnet_prefix_length'],
                                           l3p.get('ip_pool', None))
        with context.session.begin(subtransactions=True):
            l3p_db = L3PolicyMapping(id=uuidutils.generate_uuid(),
                                     tenant_id=tenant_id,
                                     name=l3p['name'],
                                     ip_version=l3p['ip_version'],
                                     ip_pool=l3p['ip_pool'],
                                     subnet_prefix_length=
                                     l3p['subnet_prefix_length'],
                                     description=l3p['description'],
                                     shared=l3p.get('shared', False))
            if 'routers' in l3p:
                for router in l3p['routers']:
                    assoc = L3PolicyRouterAssociation(
                        l3_policy_id=l3p_db.id,
                        router_id=router
                    )
                    l3p_db.routers.append(assoc)
            if 'external_segments' in l3p:
                self._set_ess_for_l3p(context, l3p_db,
                                      l3p['external_segments'])
            context.session.add(l3p_db)
        return self._make_l3_policy_dict(l3p_db)

    @log.log
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        l3p = l3_policy['l3_policy']
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3_policy_id)
            if 'subnet_prefix_length' in l3p:
                self.validate_subnet_prefix_length(l3p_db.ip_version,
                                                   l3p['subnet_prefix_length'],
                                                   l3p.get('ip_pool', None))
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
            if 'external_segments' in l3p:
                self._set_ess_for_l3p(context, l3p_db,
                                      l3p['external_segments'])
                del l3p['external_segments']
            l3p_db.update(l3p)
        return self._make_l3_policy_dict(l3p_db)

    @log.log
    def create_external_segment(self, context, external_segment):
        es = external_segment['external_segment']
        tenant_id = self._get_tenant_id_for_create(context, es)
        with context.session.begin(subtransactions=True):
            es_db = ExternalSegmentMapping(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=es['name'], description=es['description'],
                shared=es.get('shared', False), ip_version=es['ip_version'],
                cidr=es['cidr'],
                port_address_translation=es['port_address_translation'],
                subnet_id=es['subnet_id'])
            context.session.add(es_db)
            if 'external_routes' in es:
                self._process_segment_ers(context, es_db, es)
        return self._make_external_segment_dict(es_db)
