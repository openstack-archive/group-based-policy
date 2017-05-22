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

import sys

from neutron import context as n_context
from neutron.db import models_v2
from neutron_lib.db import model_base
from neutron_lib import exceptions as nexc
from oslo_log import helpers as log
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy.common import exceptions
from gbpservice.neutron.services.grouppolicy.common import utils


def get_current_context():
    i = 1
    not_found = True
    try:
        while not_found:
            for val in sys._getframe(i).f_locals.values():
                if isinstance(val, n_context.Context):
                    ctx = val
                    not_found = False
                    break
            i = i + 1
        return ctx
    except Exception:
        return


class AddressScopeUpdateForL3PNotSupported(nexc.BadRequest):
    message = _("Address Scope update for L3 Policy is not supported.")


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


class L3PolicySubnetpoolV4Association(model_base.BASEV2):
    """Models one to many relation between a L3Policy and v4 Subnetpools."""
    __tablename__ = 'gp_l3_policy_subnetpool_v4_associations'
    l3_policy_id = sa.Column(sa.String(36), sa.ForeignKey('gp_l3_policies.id'),
                             primary_key=True)
    subnetpool_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnetpools.id'), primary_key=True)


class L3PolicySubnetpoolV6Association(model_base.BASEV2):
    """Models one to many relation between a L3Policy and v6 Subnetpools."""
    __tablename__ = 'gp_l3_policy_subnetpool_v6_associations'
    l3_policy_id = sa.Column(sa.String(36), sa.ForeignKey('gp_l3_policies.id'),
                             primary_key=True)
    subnetpool_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnetpools.id'), primary_key=True)


class L3PolicyMapping(gpdb.L3Policy):
    """Mapping of L3Policy to set of Neutron Resources."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    routers = orm.relationship(L3PolicyRouterAssociation,
                               cascade='all', lazy="joined")
    address_scope_v4_id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id'),
        nullable=True, unique=True)
    address_scope_v6_id = sa.Column(
        sa.String(36), sa.ForeignKey('address_scopes.id'),
        nullable=True, unique=True)
    subnetpools_v4 = orm.relationship(L3PolicySubnetpoolV4Association,
                                      cascade='all', lazy="joined")
    subnetpools_v6 = orm.relationship(L3PolicySubnetpoolV6Association,
                                      cascade='all', lazy="joined")


class ExternalSegmentMapping(gpdb.ExternalSegment):
    """Mapping of L2Policy to Neutron Network."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=True, unique=True)


class NATPoolMapping(gpdb.NATPool):
    """Mapping of NAT Pool to Neutron Subnet."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=True, unique=True)


class GroupPolicyMappingDbPlugin(gpdb.GroupPolicyDbPlugin):
    """Group Policy Mapping interface implementation using SQLAlchemy models.
    """

    def _make_policy_target_dict(self, pt, fields=None, **kwargs):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_policy_target_dict(pt)
        res['port_id'] = pt.port_id
        res.update(kwargs)
        return self._fields(res, fields)

    def _make_policy_target_group_dict(self, ptg, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_policy_target_group_dict(ptg)
        res['subnets'] = [subnet.subnet_id for subnet in ptg.subnets]
        return self._fields(res, fields)

    def _get_subnetpools(self, id_list):
        context = get_current_context().elevated()
        with context.session.begin(subtransactions=True):
            filters = {'id': id_list}
            return self._get_collection_query(
                context, models_v2.SubnetPool, filters=filters).all()

    def _make_l2_policy_dict(self, l2p, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_l2_policy_dict(l2p)
        res['network_id'] = l2p.network_id
        return self._fields(res, fields)

    def _make_l3_policy_dict(self, l3p, fields=None, ip_pool=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_l3_policy_dict(l3p)
        res['routers'] = [router.router_id for router in l3p.routers]
        res['address_scope_v4_id'] = l3p.address_scope_v4_id
        res['address_scope_v6_id'] = l3p.address_scope_v6_id
        res['subnetpools_v4'] = [sp.subnetpool_id for sp in l3p.subnetpools_v4]
        res['subnetpools_v6'] = [sp.subnetpool_id for sp in l3p.subnetpools_v6]
        if ip_pool:
            res['ip_pool'] = ip_pool
        subnetpools = self._get_subnetpools(res['subnetpools_v4'] +
                                            res['subnetpools_v6'])
        pool_list = [prefix['cidr'] for pool in subnetpools
                     for prefix in pool['prefixes']]
        if pool_list:
            res['ip_pool'] = utils.convert_ip_pool_list_to_string(
                pool_list)
        return self._fields(res, fields)

    def _make_external_segment_dict(self, es, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_external_segment_dict(es)
        res['subnet_id'] = es.subnet_id
        return self._fields(res, fields)

    def _make_nat_pool_dict(self, np, fields=None):
        res = super(GroupPolicyMappingDbPlugin,
                    self)._make_nat_pool_dict(np)
        res['subnet_id'] = np.subnet_id
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

    def _remove_subnets_from_policy_target_groups(self, context, subnet_ids):
        with context.session.begin(subtransactions=True):
            assocs = context.session.query(PTGToSubnetAssociation).filter(
                PTGToSubnetAssociation.subnet_id.in_(subnet_ids)).all()
            for assoc in assocs:
                context.session.delete(assoc)

    def _remove_subnets_from_policy_target_group(self, context, ptg_id):
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(context, ptg_id)
            assocs = (context.session.query(PTGToSubnetAssociation).
                      filter_by(policy_target_group_id=ptg_id).all())
            ptg_db.update({'subnets': []})
            for assoc in assocs:
                context.session.delete(assoc)
        return []

    def _set_network_for_l2_policy(self, context, l2p_id, network_id):
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2p_id)
            l2p_db.network_id = network_id

    def _set_address_scope_for_l3_policy_by_id(
        self, context, l3p_id, address_scope_id, ip_version=4):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            self._set_address_scope_for_l3_policy(
                context, l3p_db, address_scope_id, ip_version)

    def _set_address_scope_for_l3_policy(self, context, l3p_db,
                                         address_scope_id, ip_version=4):
        if not address_scope_id:
            return
        # TODO(Sumit): address_scope_id validation
        with context.session.begin(subtransactions=True):
            if ip_version == 4:
                l3p_db.address_scope_v4_id = address_scope_id
            else:
                l3p_db.address_scope_v6_id = address_scope_id

    def _add_subnetpool_to_l3_policy_by_id(self, context, l3p_id,
                                           subnetpool_id, ip_version=4):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            return self._add_subnetpool_to_l3_policy(
                context, l3p_db, subnetpool_id, ip_version)

    def _add_subnetpool_to_l3_policy(self, context, l3p_db,
                                     subnetpool_id, ip_version=4):
        # TODO(Sumit): subnetpool_id validation
        with context.session.begin(subtransactions=True):
            if ip_version == 4:
                assoc = L3PolicySubnetpoolV4Association(
                    l3_policy_id=l3p_db['id'], subnetpool_id=subnetpool_id)
                l3p_db.subnetpools_v4.append(assoc)
            else:
                assoc = L3PolicySubnetpoolV6Association(
                    l3_policy_id=l3p_db['id'], subnetpool_id=subnetpool_id)
                l3p_db.subnetpools_v6.append(assoc)
        return {4: [sp.subnetpool_id for sp in l3p_db.subnetpools_v4],
                6: [sp.subnetpool_id for sp in l3p_db.subnetpools_v6]}

    def _add_subnetpools_to_l3_policy_by_id(self, context, l3p_id,
                                            subnetpools, ip_version=4):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            self._add_subnetpools_to_l3_policy(
                context, l3p_db, subnetpools, ip_version)

    def _add_subnetpools_to_l3_policy(self, context, l3p_db,
                                      subnetpools, ip_version=4):
        for sp in subnetpools or []:
            self._add_subnetpool_to_l3_policy(
                context, l3p_db, sp, ip_version=ip_version)

    def _remove_subnetpool_from_l3_policy(self, context, l3p_id,
                                          subnetpool_id, ip_version=4):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            if ip_version == 4:
                assoc = (context.session.query(
                    L3PolicySubnetpoolV4Association).filter_by(
                        l3_policy_id=l3p_id,
                        subnetpool_id=subnetpool_id).one())
                l3p_db.subnetpools_v4.remove(assoc)
            else:
                assoc = (context.session.query(
                    L3PolicySubnetpoolV6Association).filter_by(
                        l3_policy_id=l3p_id,
                        subnetpool_id=subnetpool_id).one())
                l3p_db.subnetpools_v6.remove(assoc)
            context.session.delete(assoc)
        return {4: [sp.subnetpool_id for sp in l3p_db.subnetpools_v4],
                6: [sp.subnetpool_id for sp in l3p_db.subnetpools_v6]}

    def _update_subnetpools_for_l3_policy(self, context, l3p_id,
                                          subnetpools, ip_version=4):
        # Add/remove associations for changes in subnetpools
        # TODO(Sumit): Before disassociating a subnetpool, check that
        # there is no PT present on a subnet which belongs to that subnetpool
        if not subnetpools:
            return
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            new_subnetpools = set(subnetpools)
            if ip_version == 4:
                old_subnetpools = set(sp.subnetpool_id
                                      for sp in l3p_db.subnetpools_v4)
            else:
                old_subnetpools = set(sp.subnetpool_id
                                      for sp in l3p_db.subnetpools_v6)
            for sp in new_subnetpools - old_subnetpools:
                if ip_version == 4:
                    assoc = L3PolicySubnetpoolV4Association(
                        l3_policy_id=l3p_id, subnetpool_id=sp)
                    l3p_db.subnetpools_v4.append(assoc)
                else:
                    assoc = L3PolicySubnetpoolV6Association(
                        l3_policy_id=l3p_id, subnetpool_id=sp)
                    l3p_db.subnetpools_v6.append(assoc)
            for sp in old_subnetpools - new_subnetpools:
                if ip_version == 4:
                    assoc = (context.session.query(
                        L3PolicySubnetpoolV4Association).filter_by(
                            l3_policy_id=l3p_id, subnetpool_id=sp).one())
                    l3p_db.subnetpools_v4.remove(assoc)
                else:
                    assoc = (context.session.query(
                        L3PolicySubnetpoolV6Association).filter_by(
                            l3_policy_id=l3p_id, subnetpool_id=sp).one())
                    l3p_db.subnetpools_v6.remove(assoc)
                context.session.delete(assoc)

    def _add_router_to_l3_policy(self, context, l3p_id, router_id):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            assoc = L3PolicyRouterAssociation(l3_policy_id=l3p_id,
                                              router_id=router_id)
            l3p_db.routers.append(assoc)
        return [router.router_id for router in l3p_db.routers]

    def _remove_router_from_l3_policy(self, context, l3p_id, router_id):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            assoc = (context.session.query(L3PolicyRouterAssociation).
                     filter_by(l3_policy_id=l3p_id, router_id=router_id).
                     one())
            l3p_db.routers.remove(assoc)
            context.session.delete(assoc)
        return [router.router_id for router in l3p_db.routers]

    def _set_subnet_to_es(self, context, es_id, subnet_id):
        with context.session.begin(subtransactions=True):
            es_db = self._get_external_segment(context, es_id)
            es_db.subnet_id = subnet_id

    def _set_subnet_to_np(self, context, np_id, subnet_id):
        with context.session.begin(subtransactions=True):
            np_db = self._get_nat_pool(context, np_id)
            np_db.subnet_id = subnet_id

    def _update_ess_for_l3p(self, context, l3p_id, ess):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3p_id)
            self._set_ess_for_l3p(context, l3p_db, ess)

    def _get_nat_pool(self, context, nat_pool_id):
        return self._find_gbp_resource(
            context, NATPoolMapping, nat_pool_id,
            gpolicy.NATPoolNotFound)

    def _get_l3p_ptgs(self, context, l3p_id):
        return super(GroupPolicyMappingDbPlugin, self)._get_l3p_ptgs(
            context, l3p_id, l3p_klass=L3PolicyMapping,
            ptg_klass=PolicyTargetGroupMapping, l2p_klass=L2PolicyMapping)

    def get_l3p_id_from_router_id(self, context, router_id):
        mapping = context.session.query(L3PolicyRouterAssociation).filter_by(
            router_id=router_id).first()
        if mapping:
            return mapping['l3_policy_id']

    def _set_db_np_subnet(self, context, nat_pool, subnet_id):
        with context.session.begin(subtransactions=True):
            nat_pool['subnet_id'] = subnet_id
            db_np = self._get_nat_pool(context, nat_pool['id'])
            db_np.subnet_id = nat_pool['subnet_id']
            context.session.merge(db_np)

    def _get_ptgs_for_subnet(self, context, subnet_id):
        return [x['policy_target_group_id'] for x in
            context.session.query(PTGToSubnetAssociation).filter_by(
                subnet_id=subnet_id)]

    def _validate_pt_port_exta_attributes(self, context, pt):
        attributes = pt.get('port_attributes')
        if attributes:
            # Check network ID not overridden
            if 'network_id' in attributes:
                raise exceptions.InvalidPortExtraAttributes(
                    attribute='network_id', reason='read only attribute')
            if 'fixed_ips' in attributes:
                ptg = self.get_policy_target_group(
                    context, pt['policy_target_group_id'])
                subnets = ptg['subnets']
                for fixed_ip in attributes.get('fixed_ips'):
                    if ('subnet_id' in fixed_ip and
                            fixed_ip['subnet_id'] not in subnets):
                        raise exceptions.InvalidPortExtraAttributes(
                            attribute='fixed_ips:subnet_id',
                            reason='subnet not in PTG')
            if 'allowed_address_pairs' in attributes:
                # REVISIT(ivar); Could be allowed with certain restrictions,
                # but we don't have a use case for it right now
                raise exceptions.InvalidPortExtraAttributes(
                    attribute='allowed_address_pairs',
                    reason='read only attribute')

    @log.log_method_call
    def create_policy_target(self, context, policy_target):
        pt = policy_target['policy_target']
        tenant_id = self._get_tenant_id_for_create(context, pt)
        with context.session.begin(subtransactions=True):
            self._validate_pt_port_exta_attributes(context, pt)
            pt_db = PolicyTargetMapping(id=uuidutils.generate_uuid(),
                                        tenant_id=tenant_id,
                                        name=pt['name'],
                                        description=pt['description'],
                                        policy_target_group_id=
                                        pt['policy_target_group_id'],
                                        port_id=pt['port_id'],
                                        cluster_id=pt['cluster_id'])
            context.session.add(pt_db)
        return self._make_policy_target_dict(
            pt_db, port_attributes=pt.get('port_attributes', {}))

    @log.log_method_call
    def get_policy_targets_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyTargetMapping,
                                          filters=filters)

    @log.log_method_call
    def get_policy_targets(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'policy_target', limit,
                                          marker)
        return self._get_collection(context, PolicyTargetMapping,
                                    self._make_policy_target_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log_method_call
    def create_policy_target_group(self, context, policy_target_group):
        ptg = policy_target_group['policy_target_group']
        tenant_id = self._get_tenant_id_for_create(context, ptg)
        with context.session.begin(subtransactions=True):
            if ptg['service_management']:
                self._validate_service_management_ptg(context, tenant_id)
            uuid = ptg.get('id')
            if not uuid:
                uuid = uuidutils.generate_uuid()
            ptg_db = PolicyTargetGroupMapping(
                id=uuid, tenant_id=tenant_id,
                name=ptg['name'], description=ptg['description'],
                l2_policy_id=ptg['l2_policy_id'],
                application_policy_group_id=ptg.get(
                    'application_policy_group_id', None),
                network_service_policy_id=ptg['network_service_policy_id'],
                shared=ptg.get('shared', False),
                service_management=ptg.get('service_management', False))
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

    @log.log_method_call
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

    @log.log_method_call
    def get_policy_target_groups_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyTargetGroupMapping,
                                          filters=filters)

    def _get_policy_target_groups(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'policy_target_group',
                                          limit, marker)
        return self._get_collection(context, PolicyTargetGroupMapping,
                                    self._make_policy_target_group_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log_method_call
    def get_policy_target_groups(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        return self._get_policy_target_groups(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @log.log_method_call
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
                                     inject_default_route=l2p.get(
                                         'inject_default_route', True),
                                     shared=l2p.get('shared', False))
            context.session.add(l2p_db)
        return self._make_l2_policy_dict(l2p_db)

    @log.log_method_call
    def get_l2_policies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'l2_policy', limit,
                                          marker)
        return self._get_collection(context, L2PolicyMapping,
                                    self._make_l2_policy_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log_method_call
    def get_l2_policies_count(self, context, filters=None):
        return self._get_collection_count(context, L2PolicyMapping,
                                          filters=filters)

    @log.log_method_call
    def create_l3_policy(self, context, l3_policy):
        l3p = l3_policy['l3_policy']
        self.validate_ip_pool(l3p.get('ip_pool', None), l3p['ip_version'])
        # TODO(Sumit): Check consistency of explicit subnetpool's
        # address_scopes
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

            self._set_address_scope_for_l3_policy(
                context, l3p_db, l3p.get('address_scope_v4_id'),
                ip_version=4)
            self._set_address_scope_for_l3_policy(
                context, l3p_db, l3p.get('address_scope_v6_id'),
                ip_version=6)
            self._add_subnetpools_to_l3_policy(
                context, l3p_db, l3p.get('subnetpools_v4'), ip_version=4)
            self._add_subnetpools_to_l3_policy(
                context, l3p_db, l3p.get('subnetpools_v6'), ip_version=6)

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
        return self._make_l3_policy_dict(l3p_db, ip_pool=l3p['ip_pool'])

    @log.log_method_call
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        l3p = l3_policy['l3_policy']

        if 'address_scope_v4_id' in l3p or 'address_scope_v6_id' in l3p:
            raise AddressScopeUpdateForL3PNotSupported()

        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3_policy_id)

            self._update_subnetpools_for_l3_policy(context, l3_policy_id,
                                                   l3p.get('subnetpools_v4'),
                                                   ip_version=4)
            l3p.pop('subnetpools_v4', None)
            self._update_subnetpools_for_l3_policy(context, l3_policy_id,
                                                   l3p.get('subnetpools_v6'),
                                                   ip_version=6)
            l3p.pop('subnetpools_v6', None)

            if 'subnet_prefix_length' in l3p:
                self.validate_subnet_prefix_length(l3p_db.ip_version,
                                                   l3p['subnet_prefix_length'],
                                                   l3p_db.ip_pool)

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

    @log.log_method_call
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

    @log.log_method_call
    def get_external_segments(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'external_segment', limit,
                                          marker)
        return self._get_collection(context, ExternalSegmentMapping,
                                    self._make_external_segment_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_external_segments_count(self, context, filters=None):
        return self._get_collection_count(context, ExternalSegmentMapping,
                                          filters=filters)

    @log.log_method_call
    def create_nat_pool(self, context, nat_pool):
        np = nat_pool['nat_pool']
        tenant_id = self._get_tenant_id_for_create(context, np)
        with context.session.begin(subtransactions=True):
            np_db = NATPoolMapping(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=np['name'], description=np['description'],
                shared=np.get('shared', False), ip_version=np['ip_version'],
                ip_pool=np['ip_pool'],
                external_segment_id=np['external_segment_id'],
                subnet_id=np.get('subnet_id'))
            context.session.add(np_db)
        return self._make_nat_pool_dict(np_db)

    @log.log_method_call
    def get_nat_pools(self, context, filters=None, fields=None,
                      sorts=None, limit=None, marker=None,
                      page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'nat_pool', limit,
                                          marker)
        return self._get_collection(context, NATPoolMapping,
                                    self._make_nat_pool_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)
