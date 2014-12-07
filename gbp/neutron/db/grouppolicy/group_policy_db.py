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
from neutron import context
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


class PolicyTarget(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Lowest unit of abstraction on which a policy is applied."""
    __tablename__ = 'gp_policy_targets'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    policy_target_group_id = sa.Column(sa.String(36),
                                       sa.ForeignKey(
                                           'gp_policy_target_groups.id'),
                                       nullable=True)


class PTGToPRSProvidingAssociation(model_base.BASEV2):
    """Many to many providing relation between PTGs and Policy Rule Sets."""
    __tablename__ = 'gp_ptg_to_prs_providing_associations'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id'),
                                   primary_key=True)
    policy_target_group_id = sa.Column(sa.String(36),
                                       sa.ForeignKey(
                                           'gp_policy_target_groups.id'),
                                       primary_key=True)


class PTGToPRSConsumingAssociation(model_base.BASEV2):
    """Many to many consuming relation between PTGs and Policy Rule Sets."""
    __tablename__ = 'gp_ptg_to_prs_consuming_associations'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id'),
                                   primary_key=True)
    policy_target_group_id = sa.Column(sa.String(36),
                                       sa.ForeignKey(
                                           'gp_policy_target_groups.id'),
                                       primary_key=True)


class PolicyTargetGroup(model_base.BASEV2, models_v2.HasId,
                        models_v2.HasTenant):
    """It is a collection of policy_targets."""
    __tablename__ = 'gp_policy_target_groups'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    policy_targets = orm.relationship(PolicyTarget,
                                      backref='policy_target_group')
    l2_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l2_policies.id'),
                             nullable=True)
    network_service_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_network_service_policies.id'),
        nullable=True)
    provided_policy_rule_sets = orm.relationship(
        PTGToPRSProvidingAssociation,
        backref='providing_policy_target_group', cascade='all, delete-orphan')
    consumed_policy_rule_sets = orm.relationship(
        PTGToPRSConsumingAssociation,
        backref='consuming_policy_target_group', cascade='all, delete-orphan')


class L2Policy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a L2 Policy for a collection of policy_target_groups."""
    __tablename__ = 'gp_l2_policies'
    type = sa.Column(sa.String(15))
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    policy_target_groups = orm.relationship(PolicyTargetGroup,
                                            backref='l2_policy')
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


class NetworkServiceParam(model_base.BASEV2, models_v2.HasId):
    """Represents a network service param used in a NetworkServicePolicy."""
    __tablename__ = 'gp_network_service_params'
    param_type = sa.Column(sa.String(50), nullable=False)
    param_name = sa.Column(sa.String(50), nullable=False)
    param_value = sa.Column(sa.String(50), nullable=False)
    network_service_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_network_service_policies.id'),
        nullable=False)


class NetworkServicePolicy(
    model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Network Service Policy."""
    __tablename__ = 'gp_network_service_policies'
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    policy_target_groups = orm.relationship(PolicyTargetGroup,
                                            backref='network_service_policy')
    network_service_params = orm.relationship(
        NetworkServiceParam, backref='network_service_policy')


class PRSToPRAssociation(model_base.BASEV2):
    """Many to many relation between Policy Rule Set and Policy rules."""
    __tablename__ = 'gp_prs_to_pr_associations'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id'),
                                   primary_key=True)
    policy_rule_id = sa.Column(sa.String(36),
                               sa.ForeignKey('gp_policy_rules.id'),
                               primary_key=True)


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
    action_type = sa.Column(sa.Enum(gp_constants.GP_ACTION_ALLOW,
                                    gp_constants.GP_ACTION_REDIRECT,
                                    name='action_type'))
    # Default action_value would be Null when action_type is allow
    # however, value is required if something meaningful needs to be done
    # for redirect
    action_value = sa.Column(sa.String(36), nullable=True)
    policy_rules = orm.relationship(PolicyRuleActionAssociation,
                                    cascade='all', backref='gp_policy_actions')


class PolicyRuleSet(model_base.BASEV2, models_v2.HasTenant):
    """It is a collection of Policy rules."""
    __tablename__ = 'gp_policy_rule_sets'
    id = sa.Column(sa.String(36), primary_key=True,
                   default=uuidutils.generate_uuid)
    name = sa.Column(sa.String(50))
    description = sa.Column(sa.String(255))
    parent_id = sa.Column(sa.String(255),
                          sa.ForeignKey('gp_policy_rule_sets.id'),
                          nullable=True)
    child_policy_rule_sets = orm.relationship(
        'PolicyRuleSet', backref=orm.backref('parent', remote_side=[id]))
    policy_rules = orm.relationship(PRSToPRAssociation,
                                    backref='policy_rule_set', lazy="joined",
                                    cascade='all, delete-orphan')
    providing_policy_target_groups = orm.relationship(
        PTGToPRSProvidingAssociation,
        backref='provided_policy_rule_set', lazy="joined", cascade='all')
    consuming_policy_target_groups = orm.relationship(
        PTGToPRSConsumingAssociation,
        backref='consumed_policy_rule_set', lazy="joined", cascade='all')


class GroupPolicyDbPlugin(gpolicy.GroupPolicyPluginBase,
                          common_db_mixin.CommonDbMixin):
    """GroupPolicy plugin interface implementation using SQLAlchemy models."""

    # TODO(Sumit): native bulk support
    __native_bulk_support = False
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self, *args, **kwargs):
        super(GroupPolicyDbPlugin, self).__init__(*args, **kwargs)

    def _get_policy_target(self, context, policy_target_id):
        try:
            return self._get_by_id(context, PolicyTarget, policy_target_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyTargetNotFound(
                policy_target_id=policy_target_id)

    def _get_policy_target_group(self, context, policy_target_group_id):
        try:
            return self._get_by_id(
                context, PolicyTargetGroup, policy_target_group_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyTargetGroupNotFound(
                policy_target_group_id=policy_target_group_id)

    def _get_l2_policy(self, context, l2_policy_id):
        try:
            return self._get_by_id(context, L2Policy, l2_policy_id)
        except exc.NoResultFound:
            raise gpolicy.L2PolicyNotFound(l2_policy_id=l2_policy_id)

    def _get_l3_policy(self, context, l3_policy_id):
        try:
            return self._get_by_id(context, L3Policy, l3_policy_id)
        except exc.NoResultFound:
            raise gpolicy.L3PolicyNotFound(l3_policy_id=l3_policy_id)

    def _get_network_service_policy(self, context, network_service_policy_id):
        try:
            return self._get_by_id(context, NetworkServicePolicy,
                                   network_service_policy_id)
        except exc.NoResultFound:
            raise gpolicy.NetworkServicePolicyNotFound(
                network_service_policy_id=network_service_policy_id)

    def _get_policy_classifier(self, context, policy_classifier_id):
        try:
            return self._get_by_id(context, PolicyClassifier,
                                   policy_classifier_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyClassifierNotFound(
                policy_classifier_id=policy_classifier_id)

    def _get_policy_action(self, context, policy_action_id):
        try:
            policy_action = self._get_by_id(context, PolicyAction,
                                            policy_action_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyActionNotFound(
                policy_action_id=policy_action_id)
        return policy_action

    def _get_policy_rule(self, context, policy_rule_id):
        try:
            policy_rule = self._get_by_id(context, PolicyRule,
                                          policy_rule_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyRuleNotFound(
                policy_rule_id=policy_rule_id)
        return policy_rule

    def _get_policy_rule_set(self, context, policy_rule_set_id):
        try:
            policy_rule_set = self._get_by_id(
                context, PolicyRuleSet, policy_rule_set_id)
        except exc.NoResultFound:
            raise gpolicy.PolicyRuleSetNotFound(
                policy_rule_set_id=policy_rule_set_id)
        return policy_rule_set

    @staticmethod
    def _get_min_max_ports_from_range(port_range):
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
            actions_set = set(a_db['id'] for a_db in actions_in_db)
            for action_id in action_id_list:
                if action_id not in actions_set:
                    # If we find an invalid action in the list we
                    # do not perform the update
                    raise gpolicy.PolicyActionNotFound(
                        policy_action_id=action_id)
            # New list of actions is valid so we will first reset the existing
            # list and then add each action in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            pr_db.policy_actions = []
            for action_id in action_id_list:
                assoc = PolicyRuleActionAssociation(policy_rule_id=pr_db.id,
                                                    policy_action_id=action_id)
                pr_db.policy_actions.append(assoc)

    def _validate_policy_rule_set_list(self, context,
                                       policy_rule_sets_id_list):
        with context.session.begin(subtransactions=True):
            filters = {'id': [c_id for c_id in policy_rule_sets_id_list]}
            policy_rule_sets_in_db = self._get_collection_query(
                context, PolicyRuleSet, filters=filters)
            existing_policy_rule_set_ids = set(
                c_db['id'] for c_db in policy_rule_sets_in_db)
            for policy_rule_set_id in policy_rule_sets_id_list:
                if policy_rule_set_id not in existing_policy_rule_set_ids:
                    # If we find an invalid policy_rule_set id in the list we
                    # dont process the entire list
                    raise gpolicy.PolicyRuleSetNotFound(
                        policy_rule_set_id=policy_rule_set_id)
            return policy_rule_sets_in_db

    def _set_providers_or_consumers_for_policy_target_group(
            self, context, ptg_db, policy_rule_sets_dict, provider=True):
        # TODO(Sumit): Check that the same policy_rule_set ID does not belong
        # to provider and consumer dicts
        if not policy_rule_sets_dict:
            if provider:
                ptg_db.provided_policy_rule_sets = []
                return
            else:
                ptg_db.consumed_policy_rule_sets = []
                return
        with context.session.begin(subtransactions=True):
            policy_rule_sets_id_list = policy_rule_sets_dict.keys()
            # We will first check if the new list of policy_rule_sets is valid
            self._validate_policy_rule_set_list(
                context, policy_rule_sets_id_list)
            # New list of policy_rule_sets is valid so we will first reset the
            # existing list and then add each policy_rule_set.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            if provider:
                ptg_db.provided_policy_rule_sets = []
            else:
                ptg_db.consumed_policy_rule_sets = []
            for policy_rule_set_id in policy_rule_sets_id_list:
                if provider:
                    assoc = PTGToPRSProvidingAssociation(
                        policy_target_group_id=ptg_db.id,
                        policy_rule_set_id=policy_rule_set_id)
                    ptg_db.provided_policy_rule_sets.append(assoc)
                else:
                    assoc = PTGToPRSConsumingAssociation(
                        policy_target_group_id=ptg_db.id,
                        policy_rule_set_id=policy_rule_set_id)
                    ptg_db.consumed_policy_rule_sets.append(assoc)

    def _set_children_for_policy_rule_set(self, context,
                                          policy_rule_set_db, child_id_list):
        if not child_id_list:
            policy_rule_set_db.child_policy_rule_sets = []
            return
        if policy_rule_set_db['parent_id']:
            # Only one hierarchy level allowed for now
            raise gpolicy.ThreeLevelPolicyRuleSetHierarchyNotSupported(
                policy_rule_set_id=policy_rule_set_db['id'])
        with context.session.begin(subtransactions=True):
            # We will first check if the new list of policy_rule_sets is valid

            policy_rule_sets_in_db = self._validate_policy_rule_set_list(
                context, child_id_list)
            for child in policy_rule_sets_in_db:
                if (child['child_policy_rule_sets'] or
                        child['id'] == policy_rule_set_db['id']):
                    # Only one level policy_rule_set relationship supported for
                    # now. No loops allowed
                    raise gpolicy.BadPolicyRuleSetRelationship(
                        parent_id=policy_rule_set_db['id'],
                        child_id=child['id'])
            # New list of child policy_rule_sets is valid so we will first
            # reset the existing list and then add each policy_rule_set.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing child policy_rule_sets.
            policy_rule_set_db.child_policy_rule_sets = []
            for child in policy_rule_sets_in_db:
                policy_rule_set_db.child_policy_rule_sets.append(child)

    def _set_rules_for_policy_rule_set(self, context,
                                       policy_rule_set_db, rule_id_list):
        prs_db = policy_rule_set_db
        if not rule_id_list:
            prs_db.policy_rules = []
            return
        with context.session.begin(subtransactions=True):
            # We will first check if the new list of rules is valid
            filters = {'id': [r_id for r_id in rule_id_list]}
            rules_in_db = self._get_collection_query(context, PolicyRule,
                                                     filters=filters)
            rule_ids = set(r_db['id'] for r_db in rules_in_db)
            for rule_id in rule_id_list:
                if rule_id not in rule_ids:
                    # If we find an invalid rule in the list we
                    # do not perform the update
                    raise gpolicy.PolicyRuleNotFound(policy_rule_id=rule_id)
            # New list of rules is valid so we will first reset the existing
            # list and then add each rule in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            prs_db.policy_rules = []
            for rule_id in rule_id_list:
                prs_rule_db = PRSToPRAssociation(
                    policy_rule_id=rule_id,
                    policy_rule_set_id=prs_db.id)
                prs_db.policy_rules.append(prs_rule_db)

    def _process_policy_rule_sets_for_ptg(self, context, ptg_db, ptg):
        if 'provided_policy_rule_sets' in ptg:
            self._set_providers_or_consumers_for_policy_target_group(
                context, ptg_db, ptg['provided_policy_rule_sets'])
            del ptg['provided_policy_rule_sets']
        if 'consumed_policy_rule_sets' in ptg:
            self._set_providers_or_consumers_for_policy_target_group(
                context, ptg_db, ptg['consumed_policy_rule_sets'], False)
            del ptg['consumed_policy_rule_sets']
        return ptg

    def _set_l3_policy_for_l2_policy(self, context, l2p_id, l3p_id):
        with context.session.begin(subtransactions=True):
            l2p_db = self._get_l2_policy(context, l2p_id)
            l2p_db.l3_policy_id = l3p_id

    def _set_l2_policy_for_policy_target_group(self, context, ptg_id, l2p_id):
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(context, ptg_id)
            ptg_db.l2_policy_id = l2p_id

    def _set_network_service_policy_for_policy_target_group(
            self, context, ptg_id, nsp_id):
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(context, ptg_id)
            ptg_db.network_service_policy_id = nsp_id

    def _set_params_for_network_service_policy(
            self, context, network_service_policy_db, network_service_policy):
        nsp_db = network_service_policy_db
        params = network_service_policy['network_service_params']
        if not params:
            nsp_db.network_service_params = []
            return
        with context.session.begin(subtransactions=True):
            nsp_db.network_service_params = []
            for param in params:
                param_db = NetworkServiceParam(
                    param_type=param['type'],
                    param_name=param['name'],
                    param_value=param['value'])
                nsp_db.network_service_params.append(param_db)
            del network_service_policy['network_service_params']

    def _make_policy_target_dict(self, pt, fields=None):
        res = {'id': pt['id'],
               'tenant_id': pt['tenant_id'],
               'name': pt['name'],
               'description': pt['description'],
               'policy_target_group_id': pt['policy_target_group_id']}
        return self._fields(res, fields)

    def _make_policy_target_group_dict(self, ptg, fields=None):
        res = {'id': ptg['id'],
               'tenant_id': ptg['tenant_id'],
               'name': ptg['name'],
               'description': ptg['description'],
               'l2_policy_id': ptg['l2_policy_id'],
               'network_service_policy_id': ptg['network_service_policy_id']}
        res['policy_targets'] = [
            pt['id'] for pt in ptg['policy_targets']]
        res['provided_policy_rule_sets'] = (
            [pprs['policy_rule_set_id'] for pprs in ptg[
                'provided_policy_rule_sets']])
        res['consumed_policy_rule_sets'] = (
            [cprs['policy_rule_set_id'] for cprs in ptg[
                'consumed_policy_rule_sets']])
        return self._fields(res, fields)

    def _make_l2_policy_dict(self, l2p, fields=None):
        res = {'id': l2p['id'],
               'tenant_id': l2p['tenant_id'],
               'name': l2p['name'],
               'description': l2p['description'],
               'l3_policy_id': l2p['l3_policy_id']}
        res['policy_target_groups'] = [
            ptg['id'] for ptg in l2p['policy_target_groups']]
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

    def _make_network_service_policy_dict(self, nsp, fields=None):
        res = {'id': nsp['id'],
               'tenant_id': nsp['tenant_id'],
               'name': nsp['name'],
               'description': nsp['description']}
        res['policy_target_groups'] = [
            ptg['id'] for ptg in nsp['policy_target_groups']]
        params = []
        for param in nsp['network_service_params']:
            params.append({
                gp_constants.GP_NETWORK_SVC_PARAM_TYPE: param['param_type'],
                gp_constants.GP_NETWORK_SVC_PARAM_NAME: param['param_name'],
                gp_constants.GP_NETWORK_SVC_PARAM_VALUE: param['param_value']})
        res['network_service_params'] = params
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

    def _make_policy_rule_set_dict(self, prs, fields=None):
        res = {'id': prs['id'],
               'tenant_id': prs['tenant_id'],
               'name': prs['name'],
               'description': prs['description']}
        if prs['parent']:
            res['parent_id'] = prs['parent']['id']
        else:
            res['parent_id'] = None
        ctx = context.get_admin_context()
        if 'child_policy_rule_sets' in prs:
            # They have been updated
            res['child_policy_rule_sets'] = [
                child_prs['id'] for child_prs in prs['child_policy_rule_sets']]
        else:
            with ctx.session.begin(subtransactions=True):
                filters = {'parent_id': [prs['id']]}
                child_prs_in_db = self._get_collection_query(
                    ctx, PolicyRuleSet, filters=filters)
                res['child_policy_rule_sets'] = [child_prs['id']
                                                 for child_prs
                                                 in child_prs_in_db]

        res['policy_rules'] = [pr['policy_rule_id']
                               for pr in prs['policy_rules']]
        res['providing_policy_target_groups'] = [
            ptg['policy_target_group_id']
            for ptg in prs['providing_policy_target_groups']]
        res['consuming_policy_target_groups'] = [
            ptg['policy_target_group_id']
            for ptg in prs['consuming_policy_target_groups']]
        return self._fields(res, fields)

    def _get_policy_rule_policy_rule_sets(self, context, policy_rule_id):
        return [x['policy_rule_set_id'] for x in
                context.session.query(PRSToPRAssociation).filter_by(
                    policy_rule_id=policy_rule_id)]

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
    def create_policy_target(self, context, policy_target):
        pt = policy_target['policy_target']
        tenant_id = self._get_tenant_id_for_create(context, pt)
        with context.session.begin(subtransactions=True):
            pt_db = PolicyTarget(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=pt['name'], description=pt['description'],
                policy_target_group_id=pt['policy_target_group_id'])
            context.session.add(pt_db)
        return self._make_policy_target_dict(pt_db)

    @log.log
    def update_policy_target(self, context, policy_target_id, policy_target):
        pt = policy_target['policy_target']
        with context.session.begin(subtransactions=True):
            pt_db = self._get_policy_target(context, policy_target_id)
            pt_db.update(pt)
        return self._make_policy_target_dict(pt_db)

    @log.log
    def delete_policy_target(self, context, policy_target_id):
        with context.session.begin(subtransactions=True):
            pt_db = self._get_policy_target(context, policy_target_id)
            context.session.delete(pt_db)

    @log.log
    def get_policy_target(self, context, policy_target_id, fields=None):
        pt = self._get_policy_target(context, policy_target_id)
        return self._make_policy_target_dict(pt, fields)

    @log.log
    def get_policy_targets(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'policy_target', limit,
                                          marker)
        return self._get_collection(context, PolicyTarget,
                                    self._make_policy_target_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_policy_targets_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyTarget,
                                          filters=filters)

    @log.log
    def create_policy_target_group(self, context, policy_target_group):
        ptg = policy_target_group['policy_target_group']
        tenant_id = self._get_tenant_id_for_create(context, ptg)
        with context.session.begin(subtransactions=True):
            ptg_db = PolicyTargetGroup(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=ptg['name'], description=ptg['description'],
                l2_policy_id=ptg['l2_policy_id'],
                network_service_policy_id=ptg['network_service_policy_id'])
            context.session.add(ptg_db)
            self._process_policy_rule_sets_for_ptg(context, ptg_db, ptg)
        return self._make_policy_target_group_dict(ptg_db)

    @log.log
    def update_policy_target_group(self, context, policy_target_group_id,
                                   policy_target_group):
        ptg = policy_target_group['policy_target_group']
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(
                context, policy_target_group_id)
            ptg = self._process_policy_rule_sets_for_ptg(context, ptg_db, ptg)
            ptg_db.update(ptg)
        return self._make_policy_target_group_dict(ptg_db)

    @log.log
    def delete_policy_target_group(self, context, policy_target_group_id):
        with context.session.begin(subtransactions=True):
            ptg_db = self._get_policy_target_group(
                context, policy_target_group_id)
            context.session.delete(ptg_db)

    @log.log
    def get_policy_target_group(self, context, policy_target_group_id,
                                fields=None):
        ptg = self._get_policy_target_group(context, policy_target_group_id)
        return self._make_policy_target_group_dict(ptg, fields)

    @log.log
    def get_policy_target_groups(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        marker_obj = self._get_marker_obj(
            context, 'policy_target_group', limit, marker)
        return self._get_collection(context, PolicyTargetGroup,
                                    self._make_policy_target_group_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_policy_target_groups_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyTargetGroup,
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
    def create_network_service_policy(self, context, network_service_policy):
        nsp = network_service_policy['network_service_policy']
        tenant_id = self._get_tenant_id_for_create(context, nsp)
        with context.session.begin(subtransactions=True):
            nsp_db = NetworkServicePolicy(id=uuidutils.generate_uuid(),
                                          tenant_id=tenant_id,
                                          name=nsp['name'],
                                          description=nsp['description'])
            context.session.add(nsp_db)
            self._set_params_for_network_service_policy(
                context, nsp_db, nsp)
        return self._make_network_service_policy_dict(nsp_db)

    @log.log
    def update_network_service_policy(
        self, context, network_service_policy_id, network_service_policy):
        nsp = network_service_policy['network_service_policy']
        with context.session.begin(subtransactions=True):
            nsp_db = self._get_network_service_policy(
                context, network_service_policy_id)
            if 'network_service_params' in network_service_policy:
                self._set_params_for_network_service_policy(
                    context, nsp_db, nsp)
            nsp_db.update(nsp)
        return self._make_network_service_policy_dict(nsp_db)

    @log.log
    def delete_network_service_policy(
        self, context, network_service_policy_id):
        with context.session.begin(subtransactions=True):
            nsp_db = self._get_network_service_policy(
                context, network_service_policy_id)
            context.session.delete(nsp_db)

    @log.log
    def get_network_service_policy(
            self, context, network_service_policy_id, fields=None):
        nsp = self._get_network_service_policy(
            context, network_service_policy_id)
        return self._make_network_service_policy_dict(nsp, fields)

    @log.log
    def get_network_service_policies(
            self, context, filters=None, fields=None, sorts=None, limit=None,
            marker=None, page_reverse=False):
        marker_obj = self._get_marker_obj(
            context, 'network_service_policy', limit, marker)
        return self._get_collection(context, NetworkServicePolicy,
                                    self._make_network_service_policy_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_network_service_policies_count(self, context, filters=None):
        return self._get_collection_count(context, NetworkServicePolicy,
                                          filters=filters)

    @log.log
    def create_policy_classifier(self, context, policy_classifier):
        pc = policy_classifier['policy_classifier']
        tenant_id = self._get_tenant_id_for_create(context, pc)
        port_min, port_max = GroupPolicyDbPlugin._get_min_max_ports_from_range(
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
                port_min, port_max = (GroupPolicyDbPlugin.
                                      _get_min_max_ports_from_range(
                                          pc['port_range']))
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
    def create_policy_rule_set(self, context, policy_rule_set):
        prs = policy_rule_set['policy_rule_set']
        tenant_id = self._get_tenant_id_for_create(context, prs)
        with context.session.begin(subtransactions=True):
            prs_db = PolicyRuleSet(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=prs['name'],
                                   description=prs['description'])
            context.session.add(prs_db)
            self._set_rules_for_policy_rule_set(context, prs_db,
                                                prs['policy_rules'])
            self._set_children_for_policy_rule_set(
                context, prs_db, prs['child_policy_rule_sets'])
        return self._make_policy_rule_set_dict(prs_db)

    @log.log
    def update_policy_rule_set(self, context, policy_rule_set_id,
                               policy_rule_set):
        prs = policy_rule_set['policy_rule_set']
        with context.session.begin(subtransactions=True):
            prs_db = self._get_policy_rule_set(context, policy_rule_set_id)
            if 'policy_rules' in prs:
                self._set_rules_for_policy_rule_set(
                    context, prs_db, prs['policy_rules'])
                del prs['policy_rules']
            if 'child_policy_rule_sets' in prs:
                self._set_children_for_policy_rule_set(
                    context, prs_db, prs['child_policy_rule_sets'])
                del prs['child_policy_rule_sets']
            prs_db.update(prs)
        return self._make_policy_rule_set_dict(prs_db)

    @log.log
    def delete_policy_rule_set(self, context, policy_rule_set_id):
        with context.session.begin(subtransactions=True):
            prs_db = self._get_policy_rule_set(context, policy_rule_set_id)
            context.session.delete(prs_db)

    @log.log
    def get_policy_rule_set(self, context, policy_rule_set_id, fields=None):
        prs = self._get_policy_rule_set(context, policy_rule_set_id)
        return self._make_policy_rule_set_dict(prs, fields)

    @log.log
    def get_policy_rule_sets(self, context, filters=None, fields=None):
        return self._get_collection(context, PolicyRuleSet,
                                    self._make_policy_rule_set_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_policy_rule_sets_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyRuleSet,
                                          filters=filters)
