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
from sqlalchemy.orm import exc

from neutron.common import log
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants

from gbp.neutron.extensions import group_policy as gpolicy
from gbp.neutron.services.grouppolicy.common import constants as gp_constants


LOG = logging.getLogger(__name__)
MAX_IPV4_SUBNET_PREFIX_LENGTH = 31
MAX_IPV6_SUBNET_PREFIX_LENGTH = 127


class Endpoint(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Endpoint is the lowest unit of abstraction on which a policy is applied.

    This Endpoint is unrelated to the Endpoint terminology used in Keystone.
    """
    __tablename__ = 'gp_endpoints'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    endpoint_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_endpoint_groups.id'),
                                  nullable=True)


class EndpointGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Endpoint Group that is a collection of endpoints."""
    __tablename__ = 'gp_endpoint_groups'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    endpoints = orm.relationship(Endpoint, backref='endpoint_group')
    l2_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l2_policies.id'),
                             nullable=True)


class L2Policy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a L2 Policy for a collection of endpoint_groups."""
    __tablename__ = 'gp_l2_policies'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    endpoint_groups = orm.relationship(EndpointGroup, backref='l2_policy')
    l3_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l3_policies.id'),
                             nullable=True)


class L3Policy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a L3 Policy with a non-overlapping IP address space."""
    __tablename__ = 'gp_l3_policies'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    ip_version = sa.Column(sa.Integer, nullable=False)
    ip_pool = sa.Column(sa.String(64), nullable=False)
    subnet_prefix_length = sa.Column(sa.Integer, nullable=False)
    l2_policies = orm.relationship(L2Policy, backref='l3_policy')


class PolicyRuleActionAssociation(model_base.BASEV2):
    """Many to many relation between PolicyRules and PolicyActions."""
    __tablename__ = 'gp_policy_rule_action_associations'
    policy_rule_id = sa.Column(sa.String(36),
                               sa.ForeignKey('gp_policy_rules.id'),
                               primary_key=True)
    policy_action_id = sa.Column(sa.String(36),
                                 sa.ForeignKey(
                                 'gp_policy_actions.id'),
                                 primary_key=True)


class PolicyRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Group Policy Rule."""
    __tablename__ = 'gp_policy_rules'
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    enabled = sa.Column(sa.Boolean)
    policy_classifier_id = sa.Column(sa.String(36),
                                     sa.ForeignKey(
                                     'gp_policy_classifiers.id'),
                                     nullable=False)
    policy_actions = orm.relationship(PolicyRuleActionAssociation,
                                      backref='gp_policy_rules',
                                      cascade='all', lazy="joined")


class PolicyClassifier(model_base.BASEV2, models_v2.HasId,
                       models_v2.HasTenant):
    """Represents a Group Policy Classifier."""
    __tablename__ = 'gp_policy_classifiers'
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    protocol = sa.Column(sa.Enum(constants.TCP, constants.UDP, constants.ICMP,
                                 name="protocol_type"),
                         nullable=True)
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    direction = sa.Column(sa.Enum(gp_constants.GP_DIRECTION_IN,
                                  gp_constants.GP_DIRECTION_OUT,
                                  gp_constants.GP_DIRECTION_BI,
                                  name='direction'))
    policy_rules = orm.relationship(PolicyRule,
                                    backref='gp_policy_classifiers')


class PolicyAction(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Group Policy Action."""
    __tablename__ = 'gp_policy_actions'
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    action_type = sa.Column(sa.Enum(gp_constants.GP_ALLOW,
                                    gp_constants.GP_REDIRECT,
                                    name='action_type'))
    # Default action_value would be Null when action_type is allow
    # however, value is required if something meaningful needs to be done
    # for redirect
    action_value = sa.Column(sa.String(36), nullable=True)
    policy_rules = orm.relationship(PolicyRuleActionAssociation,
                                    cascade='all', backref='gp_policy_actions')


class GroupPolicyDbPlugin(gpolicy.GroupPolicyPluginBase,
                          common_db_mixin.CommonDbMixin):
    """GroupPolicy plugin interface implementation using SQLAlchemy models."""

    # TODO(Sumit): native bulk support
    __native_bulk_support = False
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self, *args, **kwargs):
        super(GroupPolicyDbPlugin, self).__init__(*args, **kwargs)

    def _get_endpoint(self, context, endpoint_id):
        try:
            return self._get_by_id(context, Endpoint, endpoint_id)
        except exc.NoResultFound:
            raise gpolicy.EndpointNotFound(endpoint_id=endpoint_id)

    def _get_endpoint_group(self, context, endpoint_group_id):
        try:
            return self._get_by_id(context, EndpointGroup, endpoint_group_id)
        except exc.NoResultFound:
            raise gpolicy.EndpointGroupNotFound(
                endpoint_group_id=endpoint_group_id)

    def _get_l2_policy(self, context, l2_policy_id):
        try:
            return self._get_by_id(context, L2Policy, l2_policy_id)
        except exc.NoResultFound:
            raise gpolicy.L2PolicyNotFound(l2_policy_id=l2_policy_id)

    def _get_l3_policy(self, context, l3_policy_id):
        try:
            return self._get_by_id(context, L3Policy, l3_policy_id)
        except exc.NoResultFound:
            raise gpolicy.L3PolicyNotFound(l3_policy_id=
                                           l3_policy_id)

    def _get_policy_classifier(self, context, policy_classifier_id):
        try:
            return self._get_by_id(context, PolicyClassifier,
                                   policy_classifier_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyClassifierNotFound(policy_classifier_id=
                                                   policy_classifier_id)

    def _get_policy_action(self, context, policy_action_id):
        try:
            policy_action = self._get_by_id(context, PolicyAction,
                                            policy_action_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyActionNotFound(policy_action_id=
                                               policy_action_id)
        return policy_action

    def _get_policy_rule(self, context, policy_rule_id):
        try:
            policy_rule = self._get_by_id(context, PolicyRule,
                                          policy_rule_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyRuleNotFound(policy_rule_id=
                                             policy_rule_id)
        return policy_rule

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def _set_l3_policy_for_l2_policy(self, context, l2p_id, l3p_id):
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2p_id)
            l2p_db.l3_policy_id = l3p_id

    def _set_l2_policy_for_endpoint_group(self, context, epg_id, l2p_id):
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, epg_id)
            epg_db.l2_policy_id = l2p_id

    def _set_actions_for_rule(self, context, policy_rule_db, action_id_list):
        pr_db = policy_rule_db
        if not action_id_list:
            pr_db.policy_actions = []
            return
        with context.session.begin(subtransactions=True):
            # We will first check if the new list of actions is valid
            filters = {'id': [a_id for a_id in action_id_list]}
            actions_in_db = self._get_collection_query(context, PolicyAction,
                                                       filters=filters)
            actions_dict = dict((a_db['id'], a_db) for a_db in actions_in_db)
            for action_id in action_id_list:
                if action_id not in actions_dict:
                    # If we find an invalid action in the list we
                    # do not perform the update
                    raise gpolicy.PolicyActionNotFound(policy_action_id=
                                                       action_id)
            # New list of actions is valid so we will first reset the existing
            # list and then add each action in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            pr_db.policy_actions = []
            for action_id in action_id_list:
                assoc = PolicyRuleActionAssociation(policy_rule_id=pr_db.id,
                                                    policy_action_id=action_id)
                pr_db.policy_actions.append(assoc)

    def _make_endpoint_dict(self, ep, fields=None):
        res = {'id': ep['id'],
               'tenant_id': ep['tenant_id'],
               'name': ep['name'],
               'description': ep['description'],
               'endpoint_group_id': ep['endpoint_group_id']}
        return self._fields(res, fields)

    def _make_endpoint_group_dict(self, epg, fields=None):
        res = {'id': epg['id'],
               'tenant_id': epg['tenant_id'],
               'name': epg['name'],
               'description': epg['description'],
               'l2_policy_id': epg['l2_policy_id']}
        res['endpoints'] = [ep['id']
                            for ep in epg['endpoints']]
        # TODO(Sumit): populate contracts when supported
        res['provided_contracts'] = {}
        res['consumed_contracts'] = {}
        return self._fields(res, fields)

    def _make_l2_policy_dict(self, l2p, fields=None):
        res = {'id': l2p['id'],
               'tenant_id': l2p['tenant_id'],
               'name': l2p['name'],
               'description': l2p['description'],
               'l3_policy_id': l2p['l3_policy_id']}
        res['endpoint_groups'] = [epg['id']
                                  for epg in l2p['endpoint_groups']]
        return self._fields(res, fields)

    def _make_l3_policy_dict(self, l3p, fields=None):
        res = {'id': l3p['id'],
               'tenant_id': l3p['tenant_id'],
               'name': l3p['name'],
               'description': l3p['description'],
               'ip_version': l3p['ip_version'],
               'ip_pool': l3p['ip_pool'],
               'subnet_prefix_length':
               l3p['subnet_prefix_length']}
        res['l2_policies'] = [l2p['id']
                              for l2p in l3p['l2_policies']]
        return self._fields(res, fields)

    def _make_policy_classifier_dict(self, pc, fields=None):
        port_range = self._get_port_range_from_min_max_ports(
            pc['port_range_min'],
            pc['port_range_max'])
        res = {'id': pc['id'],
               'tenant_id': pc['tenant_id'],
               'name': pc['name'],
               'description': pc['description'],
               'protocol': pc['protocol'],
               'port_range': port_range,
               'direction': pc['direction']}
        return self._fields(res, fields)

    def _make_policy_action_dict(self, pa, fields=None):
        res = {'id': pa['id'],
               'tenant_id': pa['tenant_id'],
               'name': pa['name'],
               'description': pa['description'],
               'action_type': pa['action_type'],
               'action_value': pa['action_value']}
        return self._fields(res, fields)

    def _make_policy_rule_dict(self, pr, fields=None):
        res = {'id': pr['id'],
               'tenant_id': pr['tenant_id'],
               'name': pr['name'],
               'description': pr['description'],
               'enabled': pr['enabled'],
               'policy_classifier_id': pr['policy_classifier_id']}
        res['policy_actions'] = [pa['policy_action_id']
                                 for pa in pr['policy_actions']]
        return self._fields(res, fields)

    @staticmethod
    def validate_subnet_prefix_length(ip_version, new_prefix_length):
        if (new_prefix_length < 2) or (
            ip_version == 4 and (
                new_prefix_length > MAX_IPV4_SUBNET_PREFIX_LENGTH)) or (
                    ip_version == 6 and (
                        new_prefix_length > MAX_IPV6_SUBNET_PREFIX_LENGTH)):
            raise gpolicy.InvalidDefaultSubnetPrefixLength(
                length=new_prefix_length, protocol=ip_version)
        # TODO(Sumit): Check that subnet_prefix_length is smaller
        # than size of the ip_pool's subnet

    @log.log
    def create_endpoint(self, context, endpoint):
        ep = endpoint['endpoint']
        tenant_id = self._get_tenant_id_for_create(context, ep)
        with context.session.begin(subtransactions=True):
            ep_db = Endpoint(id=uuidutils.generate_uuid(),
                             tenant_id=tenant_id,
                             name=ep['name'],
                             description=ep['description'],
                             endpoint_group_id=ep['endpoint_group_id'])
            context.session.add(ep_db)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def update_endpoint(self, context, endpoint_id, endpoint):
        ep = endpoint['endpoint']
        with context.session.begin(subtransactions=True):
            ep_db = self._get_endpoint(context, endpoint_id)
            ep_db.update(ep)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def delete_endpoint(self, context, endpoint_id):
        with context.session.begin(subtransactions=True):
            ep_db = self._get_endpoint(context, endpoint_id)
            context.session.delete(ep_db)

    @log.log
    def get_endpoint(self, context, endpoint_id, fields=None):
        ep = self._get_endpoint(context, endpoint_id)
        return self._make_endpoint_dict(ep, fields)

    @log.log
    def get_endpoints(self, context, filters=None, fields=None,
                      sorts=None, limit=None, marker=None,
                      page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'endpoint', limit,
                                          marker)
        return self._get_collection(context, Endpoint,
                                    self._make_endpoint_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_endpoints_count(self, context, filters=None):
        return self._get_collection_count(context, Endpoint,
                                          filters=filters)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        epg = endpoint_group['endpoint_group']
        tenant_id = self._get_tenant_id_for_create(context, epg)
        with context.session.begin(subtransactions=True):
            epg_db = EndpointGroup(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=epg['name'],
                                   description=epg['description'],
                                   l2_policy_id=epg['l2_policy_id'])
            # TODO(Sumit): handle contracts when supported
            context.session.add(epg_db)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        epg = endpoint_group['endpoint_group']
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, endpoint_group_id)
            # TODO(Sumit): hanndle contracts when supported
            epg_db.update(epg)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def delete_endpoint_group(self, context, endpoint_group_id):
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, endpoint_group_id)
            context.session.delete(epg_db)

    @log.log
    def get_endpoint_group(self, context, endpoint_group_id, fields=None):
        epg = self._get_endpoint_group(context, endpoint_group_id)
        return self._make_endpoint_group_dict(epg, fields)

    @log.log
    def get_endpoint_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'endpoint_group', limit,
                                          marker)
        return self._get_collection(context, EndpointGroup,
                                    self._make_endpoint_group_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_endpoint_groups_count(self, context, filters=None):
        return self._get_collection_count(context, EndpointGroup,
                                          filters=filters)

    @log.log
    def create_l2_policy(self, context, l2_policy):
        l2p = l2_policy['l2_policy']
        tenant_id = self._get_tenant_id_for_create(context, l2p)
        with context.session.begin(subtransactions=True):
            l2p_db = L2Policy(id=uuidutils.generate_uuid(),
                              tenant_id=tenant_id, name=l2p['name'],
                              description=l2p['description'],
                              l3_policy_id=l2p['l3_policy_id'])
            context.session.add(l2p_db)
        return self._make_l2_policy_dict(l2p_db)

    @log.log
    def update_l2_policy(self, context, l2_policy_id, l2_policy):
        l2p = l2_policy['l2_policy']
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2_policy_id)
            l2p_db.update(l2p)
        return self._make_l2_policy_dict(l2p_db)

    @log.log
    def delete_l2_policy(self, context, l2_policy_id):
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2_policy_id)
            context.session.delete(l2p_db)

    @log.log
    def get_l2_policy(self, context, l2_policy_id, fields=None):
        l2p = self._get_l2_policy(context, l2_policy_id)
        return self._make_l2_policy_dict(l2p, fields)

    @log.log
    def get_l2_policies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'l2_policy', limit,
                                          marker)
        return self._get_collection(context, L2Policy,
                                    self._make_l2_policy_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_l2_policies_count(self, context, filters=None):
        return self._get_collection_count(context, L2Policy,
                                          filters=filters)

    @log.log
    def create_l3_policy(self, context, l3_policy):
        l3p = l3_policy['l3_policy']
        tenant_id = self._get_tenant_id_for_create(context, l3p)
        self.validate_subnet_prefix_length(
            l3p['ip_version'], l3p['subnet_prefix_length'])
        with context.session.begin(subtransactions=True):
            l3p_db = L3Policy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id, name=l3p['name'],
                description=l3p['description'],
                ip_version=l3p['ip_version'],
                ip_pool=l3p['ip_pool'],
                subnet_prefix_length=l3p['subnet_prefix_length'])
            context.session.add(l3p_db)
        return self._make_l3_policy_dict(l3p_db)

    @log.log
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        l3p = l3_policy['l3_policy']
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3_policy_id)
            if 'subnet_prefix_length' in l3p:
                self.validate_subnet_prefix_length(
                    l3p_db.ip_version,
                    l3p['subnet_prefix_length'])
            l3p_db.update(l3p)
        return self._make_l3_policy_dict(l3p_db)

    @log.log
    def delete_l3_policy(self, context, l3_policy_id):
        with context.session.begin(subtransactions=True):
            l3p_db = self._get_l3_policy(context, l3_policy_id)
            context.session.delete(l3p_db)

    @log.log
    def get_l3_policy(self, context, l3_policy_id, fields=None):
        l3p = self._get_l3_policy(context, l3_policy_id)
        return self._make_l3_policy_dict(l3p, fields)

    @log.log
    def get_l3_policies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'l2_policy', limit,
                                          marker)
        return self._get_collection(context, L3Policy,
                                    self._make_l3_policy_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def create_policy_classifier(self, context, policy_classifier):
        pc = policy_classifier['policy_classifier']
        tenant_id = self._get_tenant_id_for_create(context, pc)
        port_min, port_max = self._get_min_max_ports_from_range(
            pc['port_range'])
        with context.session.begin(subtransactions=True):
            pc_db = PolicyClassifier(id=uuidutils.generate_uuid(),
                                     tenant_id=tenant_id,
                                     name=pc['name'],
                                     description=pc['description'],
                                     protocol=pc['protocol'],
                                     port_range_min=port_min,
                                     port_range_max=port_max,
                                     direction=pc['direction'])
            context.session.add(pc_db)
        return self._make_policy_classifier_dict(pc_db)

    @log.log
    def update_policy_classifier(self, context, policy_classifier_id,
                                 policy_classifier):
        pc = policy_classifier['policy_classifier']
        with context.session.begin(subtransactions=True):
            pc_db = self._get_policy_classifier(context, policy_classifier_id)
            if 'port_range' in pc:
                port_min, port_max = self._get_min_max_ports_from_range(
                    pc['port_range'])
                pc.update({'port_range_min': port_min,
                           'port_range_max': port_max})
                del pc['port_range']
            pc_db.update(pc)
        return self._make_policy_classifier_dict(pc_db)

    @log.log
    def delete_policy_classifier(self, context, policy_classifier_id):
        with context.session.begin(subtransactions=True):
            pc_db = self._get_policy_classifier(context, policy_classifier_id)
            context.session.delete(pc_db)

    @log.log
    def get_policy_classifier(self, context, policy_classifier_id,
                              fields=None):
        pc = self._get_policy_classifier(context, policy_classifier_id)
        return self._make_policy_classifier_dict(pc, fields)

    @log.log
    def get_policy_classifiers(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'policy_classifier', limit,
                                          marker)
        return self._get_collection(context, PolicyClassifier,
                                    self._make_policy_classifier_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_policy_classifiers_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyClassifier,
                                          filters=filters)

    @log.log
    def create_policy_action(self, context, policy_action):
        pa = policy_action['policy_action']
        tenant_id = self._get_tenant_id_for_create(context, pa)
        with context.session.begin(subtransactions=True):
            pa_db = PolicyAction(id=uuidutils.generate_uuid(),
                                 tenant_id=tenant_id,
                                 name=pa['name'],
                                 description=pa['description'],
                                 action_type=pa['action_type'],
                                 action_value=pa['action_value'])
            context.session.add(pa_db)
        return self._make_policy_action_dict(pa_db)

    @log.log
    def update_policy_action(self, context, policy_action_id, policy_action):
        pa = policy_action['policy_action']
        with context.session.begin(subtransactions=True):
            pa_db = self._get_policy_action(context, policy_action_id)
            pa_db.update(pa)
        return self._make_policy_action_dict(pa_db)

    @log.log
    def delete_policy_action(self, context, policy_action_id):
        with context.session.begin(subtransactions=True):
            pa_db = self._get_policy_action(context, policy_action_id)
            context.session.delete(pa_db)

    @log.log
    def get_policy_action(self, context, id, fields=None):
        pa = self._get_policy_action(context, id)
        return self._make_policy_action_dict(pa, fields)

    @log.log
    def get_policy_actions(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'policy_action', limit,
                                          marker)
        return self._get_collection(context, PolicyAction,
                                    self._make_policy_action_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_policy_actions_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyAction,
                                          filters=filters)

    @log.log
    def create_policy_rule(self, context, policy_rule):
        pr = policy_rule['policy_rule']
        tenant_id = self._get_tenant_id_for_create(context, pr)
        with context.session.begin(subtransactions=True):
            pr_db = PolicyRule(id=uuidutils.generate_uuid(),
                               tenant_id=tenant_id, name=pr['name'],
                               description=pr['description'],
                               enabled=pr['enabled'],
                               policy_classifier_id=pr['policy_classifier_id'])
            context.session.add(pr_db)
            self._set_actions_for_rule(context, pr_db,
                                       pr['policy_actions'])
        return self._make_policy_rule_dict(pr_db)

    @log.log
    def update_policy_rule(self, context, policy_rule_id, policy_rule):
        pr = policy_rule['policy_rule']
        with context.session.begin(subtransactions=True):
            pr_db = self._get_policy_rule(context, policy_rule_id)
            if 'policy_actions' in pr:
                self._set_actions_for_rule(context, pr_db,
                                           pr['policy_actions'])
                del pr['policy_actions']
            pr_db.update(pr)
        return self._make_policy_rule_dict(pr_db)

    @log.log
    def delete_policy_rule(self, context, policy_rule_id):
        with context.session.begin(subtransactions=True):
            pr_db = self._get_policy_rule(context, policy_rule_id)
            context.session.delete(pr_db)

    @log.log
    def get_policy_rule(self, context, policy_rule_id, fields=None):
        pr = self._get_policy_rule(context, policy_rule_id)
        return self._make_policy_rule_dict(pr, fields)

    @log.log
    def get_policy_rules(self, context, filters=None, fields=None):
        return self._get_collection(context, PolicyRule,
                                    self._make_policy_rule_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_policy_rules_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyRule,
                                          filters=filters)

    @log.log
    def create_contract(self, context, contract):
        pass

    @log.log
    def update_contract(self, context, contract_id, contract):
        pass

    @log.log
    def get_contracts(self, context, filters=None, fields=None):
        pass

    @log.log
    def get_contract(self, context, contract_id, fields=None):
        pass

    @log.log
    def delete_contract(self, context, contract_id):
        pass
