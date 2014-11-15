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

from neutron.api.v2 import attributes as nattr
from neutron.common import log
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging

from gbp.neutron.db.grouppolicy import group_policy_mapping_db
from gbp.neutron.services.grouppolicy.common import exceptions as gp_exc
from gbp.neutron.services.grouppolicy import group_policy_context as p_context
from gbp.neutron.services.grouppolicy import policy_driver_manager as manager


LOG = logging.getLogger(__name__)


class GroupPolicyPlugin(group_policy_mapping_db.GroupPolicyMappingDbPlugin):

    """Implementation of the Group Policy Model Plugin.

    This class manages the workflow of Group Policy request/response.
    Most DB related works are implemented in class
    db_group_policy_mapping.GroupPolicyMappingDbMixin.
    """
    supported_extension_aliases = ["group-policy", "group-policy-mapping"]

    # Shared attribute validation rules:
    # - A shared resource cannot use/link a non-shared resource
    # - A shared resource cannot be reverted to non-shared if used/linked by
    # other shared resources, or by any resource owned by any other tenant

    # In the usage graph, specify which resource has to be checked to validate
    # sharing policy conformity:
    # usage_graph = {<to_check>: {<attribute>: <type>}, ...}
    # <attribute> is the field on the <to_check> dictionary that can be used
    # to retrieve the UUID/s of the specific object <type>

    usage_graph = {'l3_policy': {},
                   'l2_policy': {'l3_policy_id': 'l3_policy'},
                   'policy_target_group': {
                       'network_service_policy_id': 'network_service_policy',
                       'l2_policy_id': 'l2_policy',
                       'provided_policy_rule_sets': 'policy_rule_set',
                       'consumed_policy_rule_sets': 'policy_rule_set'},
                   'network_service_policy': {},
                   'policy_rule': {
                       'policy_classifier_id': 'policy_classifier',
                       'policy_actions': 'policy_action'},
                   'policy_action': {},
                   'policy_classifier': {},
                   'policy_rule_set': {
                       'parent_id': 'policy_rule_set',
                       'policy_rules': 'policy_rule'}}
    _plurals = None

    @property
    def plurals(self):
        if not self._plurals:
            self._plurals = dict((nattr.PLURALS[k], k) for k in nattr.PLURALS)
        return self._plurals

    def _validate_shared_create(self, context, obj, identity):
        if not obj.get('shared'):
            return
        links = self.usage_graph.get(identity, {})
        for attr in links:
            ids = obj[attr]
            if ids:
                if isinstance(ids, basestring):
                    ids = [ids]
                ref_type = links[attr]
                linked_objects = getattr(
                    self, 'get_%s' % self.plurals[ref_type])(
                        context, filters={'id': ids})
                for linked in linked_objects:
                    if not linked.get('shared'):
                        raise gp_exc.SharedResourceReferenceError(
                            res_type=identity, res_id=obj['id'],
                            ref_type=ref_type, ref_id=linked['id'])

    def _validate_shared_update(self, context, original, updated, identity):
        if updated.get('shared'):
            # Even though the shared attribute may not be changed, the objects
            # it is referring to might. For this reason we run the reference
            # validation every time a shared resource is updated
            # TODO(ivar): run only when relevant updates happen
            self._validate_shared_create(context, updated, identity)
        elif updated.get('shared') != original.get('shared'):
            getattr(self, '_validate_%s_unshare' % identity)(context, updated)

    def _check_shared_or_different_tenant(self, context, obj,
                                          method, attr, value=None):
        tenant_id = obj['tenant_id']
        refs = method(context, filters={attr: value or [obj['id']]})
        for ref in refs:
            if ref.get('shared') or tenant_id != ref['tenant_id']:
                raise gp_exc.NonSharedNetworkOnSharedL2PolicyNotSupported()

    def _validate_l3_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_l2_policies, 'l3_policy_id')

    def _validate_l2_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups, 'l2_policy_id')

    def _validate_policy_target_group_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_targets, 'policy_target_group_id')

    def _validate_network_service_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups,
            'network_service_policy_id')

    def _validate_policy_rule_set_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups, 'id',
            obj['providing_policy_target_groups'] +
            obj['consuming_policy_target_groups'])

    def _validate_policy_classifier_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rules, 'policy_classifier_id')

    def _validate_policy_rule_unshare(self, context, obj):
        c_ids = self._get_policy_rule_policy_rule_sets(context, obj['id'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rule_sets, 'id', c_ids)

    def _validate_policy_action_unshare(self, context, obj):
        r_ids = self._get_policy_action_rules(context, obj['id'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rules, 'id', r_ids)

    def __init__(self):
        self.policy_driver_manager = manager.PolicyDriverManager()
        super(GroupPolicyPlugin, self).__init__()
        self.policy_driver_manager.initialize()

    @log.log
    def create_policy_target(self, context, policy_target):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_target(context, policy_target)
            policy_context = p_context.PolicyTargetContext(self, context,
                                                           result)
            self.policy_driver_manager.create_policy_target_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_target_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_policy_target_postcommit "
                            "failed, deleting policy_target '%s'"),
                          result['id'])
                self.delete_policy_target(context, result['id'])

        return result

    @log.log
    def update_policy_target(self, context, policy_target_id, policy_target):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_target = super(
                GroupPolicyPlugin, self).get_policy_target(context,
                                                           policy_target_id)
            updated_policy_target = super(
                GroupPolicyPlugin, self).update_policy_target(
                    context, policy_target_id, policy_target)
            policy_context = p_context.PolicyTargetContext(
                self, context, updated_policy_target,
                original_policy_target=original_policy_target)
            self.policy_driver_manager.update_policy_target_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_target_postcommit(
            policy_context)
        return updated_policy_target

    @log.log
    def delete_policy_target(self, context, policy_target_id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_target = self.get_policy_target(context, policy_target_id)
            policy_context = p_context.PolicyTargetContext(
                self, context, policy_target)
            self.policy_driver_manager.delete_policy_target_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_target(
                context, policy_target_id)

        try:
            self.policy_driver_manager.delete_policy_target_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_policy_target_postcommit "
                            "failed, deleting policy_rule_set '%s'"),
                          policy_target_id)

    @log.log
    def create_policy_target_group(self, context, policy_target_group):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_target_group(
                               context, policy_target_group)
            self._validate_shared_create(context, result,
                                         'policy_target_group')
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, result)
            self.policy_driver_manager.create_policy_target_group_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_target_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_policy_target_group_postcommit "
                            "failed, deleting policy_target_group '%s'"),
                          result['id'])
                self.delete_policy_target_group(context, result['id'])

        return result

    @log.log
    def update_policy_target_group(self, context, policy_target_group_id,
                                   policy_target_group):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_target_group = super(
                GroupPolicyPlugin, self).get_policy_target_group(
                    context, policy_target_group_id)
            updated_policy_target_group = super(
                GroupPolicyPlugin, self).update_policy_target_group(
                    context, policy_target_group_id, policy_target_group)
            self._validate_shared_update(context, original_policy_target_group,
                                         updated_policy_target_group,
                                         'policy_target_group')
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, updated_policy_target_group,
                original_policy_target_group=original_policy_target_group)
            self.policy_driver_manager.update_policy_target_group_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_target_group_postcommit(
            policy_context)

        return updated_policy_target_group

    @log.log
    def delete_policy_target_group(self, context, policy_target_group_id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_target_group = self.get_policy_target_group(
                context, policy_target_group_id)
            if policy_target_group['policy_targets']:
                raise gp_exc.PolicyTargetGroupInUse(
                    policy_target_group=policy_target_group_id)
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, policy_target_group)
            self.policy_driver_manager.delete_policy_target_group_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_target_group(
                context, policy_target_group_id)

        try:
            self.policy_driver_manager.delete_policy_target_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_policy_target_group_postcommit "
                            "failed, deleting policy_target_group '%s'"),
                          policy_target_group_id)

    @log.log
    def create_l2_policy(self, context, l2_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l2_policy(context, l2_policy)
            self._validate_shared_create(context, result, 'l2_policy')
            policy_context = p_context.L2PolicyContext(self, context, result)
            self.policy_driver_manager.create_l2_policy_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_l2_policy_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_l2_policy_postcommit "
                            "failed, deleting l2_policy '%s'"), result['id'])
                self.delete_l2_policy(context, result['id'])

        return result

    @log.log
    def update_l2_policy(self, context, l2_policy_id, l2_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_l2_policy = super(GroupPolicyPlugin,
                                       self).get_l2_policy(context,
                                                           l2_policy_id)
            updated_l2_policy = super(GroupPolicyPlugin,
                                      self).update_l2_policy(
                                          context, l2_policy_id, l2_policy)
            self._validate_shared_update(context, original_l2_policy,
                                         updated_l2_policy, 'l2_policy')
            policy_context = p_context.L2PolicyContext(
                self, context, updated_l2_policy,
                original_l2_policy=original_l2_policy)
            self.policy_driver_manager.update_l2_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_l2_policy_postcommit(
            policy_context)
        return updated_l2_policy

    @log.log
    def delete_l2_policy(self, context, l2_policy_id):
        session = context.session
        with session.begin(subtransactions=True):
            l2_policy = self.get_l2_policy(context, l2_policy_id)
            policy_context = p_context.L2PolicyContext(self, context,
                                                       l2_policy)
            self.policy_driver_manager.delete_l2_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_l2_policy(context,
                                                            l2_policy_id)

        try:
            self.policy_driver_manager.delete_l2_policy_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_l2_policy_postcommit "
                            " failed, deleting l2_policy '%s'"), l2_policy_id)

    @log.log
    def create_network_service_policy(self, context, network_service_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_network_service_policy(
                               context, network_service_policy)
            self._validate_shared_create(context, result,
                                         'network_service_policy')
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, result)
            pdm = self.policy_driver_manager
            pdm.create_network_service_policy_precommit(
                policy_context)

        try:
            pdm.create_network_service_policy_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_network_service_policy_postcommit "
                            "failed, deleting network_service_policy '%s'"),
                          result['id'])
                self.delete_network_service_policy(context, result['id'])

        return result

    @log.log
    def update_network_service_policy(self, context, network_service_policy_id,
                                      network_service_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_network_service_policy = super(
                GroupPolicyPlugin, self).get_network_service_policy(
                    context, network_service_policy_id)
            updated_network_service_policy = super(
                GroupPolicyPlugin, self).update_network_service_policy(
                    context, network_service_policy_id, network_service_policy)
            self._validate_shared_update(
                context, original_network_service_policy,
                updated_network_service_policy, 'network_service_policy')
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, updated_network_service_policy,
                original_network_service_policy=
                original_network_service_policy)
            self.policy_driver_manager.update_network_service_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_network_service_policy_postcommit(
            policy_context)
        return updated_network_service_policy

    @log.log
    def delete_network_service_policy(
        self, context, network_service_policy_id):
        session = context.session
        with session.begin(subtransactions=True):
            network_service_policy = self.get_network_service_policy(
                context, network_service_policy_id)
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, network_service_policy)
            self.policy_driver_manager.delete_network_service_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_network_service_policy(
                context, network_service_policy_id)

        try:
            pdm = self.policy_driver_manager
            pdm.delete_network_service_policy_postcommit(policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_network_service_policy_postcommit "
                            " failed, deleting network_service_policy '%s'"),
                          network_service_policy_id)

    @log.log
    def create_l3_policy(self, context, l3_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l3_policy(context, l3_policy)
            self._validate_shared_create(context, result, 'l3_policy')
            policy_context = p_context.L3PolicyContext(self, context,
                                                       result)
            self.policy_driver_manager.create_l3_policy_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_l3_policy_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_l3_policy_postcommit "
                            "failed, deleting l3_policy '%s'"), result['id'])
                self.delete_l3_policy(context, result['id'])

        return result

    @log.log
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_l3_policy = super(GroupPolicyPlugin,
                                       self).get_l3_policy(context,
                                                           l3_policy_id)
            updated_l3_policy = super(
                GroupPolicyPlugin, self).update_l3_policy(
                    context, l3_policy_id, l3_policy)
            self._validate_shared_update(context, original_l3_policy,
                                         updated_l3_policy, 'l3_policy')
            policy_context = p_context.L3PolicyContext(
                self, context, updated_l3_policy,
                original_l3_policy=original_l3_policy)
            self.policy_driver_manager.update_l3_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_l3_policy_postcommit(
            policy_context)
        return updated_l3_policy

    @log.log
    def delete_l3_policy(self, context, l3_policy_id, check_unused=False):
        session = context.session
        with session.begin(subtransactions=True):
            if (check_unused and
                (session.query(group_policy_mapping_db.L2PolicyMapping).
                 filter_by(l3_policy_id=l3_policy_id).count())):
                return False
            l3_policy = self.get_l3_policy(context, l3_policy_id)
            policy_context = p_context.L3PolicyContext(self, context,
                                                       l3_policy)
            self.policy_driver_manager.delete_l3_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_l3_policy(context,
                                                            l3_policy_id)

        try:
            self.policy_driver_manager.delete_l3_policy_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_l3_policy_postcommit "
                            " failed, deleting l3_policy '%s'"), l3_policy_id)
        return True

    @log.log
    def create_policy_classifier(self, context, policy_classifier):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                GroupPolicyPlugin, self).create_policy_classifier(
                    context, policy_classifier)
            self._validate_shared_create(context, result, 'policy_classifier')
            policy_context = p_context.PolicyClassifierContext(self, context,
                                                               result)
            self.policy_driver_manager.create_policy_classifier_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_classifier_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_classifier_postcommit"
                    " failed, deleting policy_classifier '%s'"), result['id'])
                self.delete_policy_classifier(context, result['id'])

        return result

    @log.log
    def update_policy_classifier(self, context, id, policy_classifier):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_classifier = super(
                GroupPolicyPlugin, self).get_policy_classifier(context, id)
            updated_policy_classifier = super(
                GroupPolicyPlugin, self).update_policy_classifier(
                    context, id, policy_classifier)
            self._validate_shared_update(context, original_policy_classifier,
                                         updated_policy_classifier,
                                         'policy_classifier')
            policy_context = p_context.PolicyClassifierContext(
                self, context, updated_policy_classifier,
                original_policy_classifier=original_policy_classifier)
            self.policy_driver_manager.update_policy_classifier_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_classifier_postcommit(
            policy_context)
        return updated_policy_classifier

    @log.log
    def delete_policy_classifier(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_classifier = self.get_policy_classifier(context, id)
            policy_context = p_context.PolicyClassifierContext(
                self, context, policy_classifier)
            self.policy_driver_manager.delete_policy_classifier_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_classifier(
                context, id)

        try:
            self.policy_driver_manager.delete_policy_classifier_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_policy_classifier_postcommit"
                    " failed, deleting policy_classifier '%s'"), id)

    @log.log
    def create_policy_action(self, context, policy_action):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_action(context, policy_action)
            self._validate_shared_create(context, result, 'policy_action')
            policy_context = p_context.PolicyActionContext(self, context,
                                                           result)
            self.policy_driver_manager.create_policy_action_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_action_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_action_postcommit "
                    "failed, deleting policy_action '%s'"), result['id'])
                self.delete_policy_action(context, result['id'])

        return result

    @log.log
    def update_policy_action(self, context, id, policy_action):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_action = super(
                GroupPolicyPlugin, self).get_policy_action(context, id)
            updated_policy_action = super(
                GroupPolicyPlugin, self).update_policy_action(context, id,
                                                              policy_action)
            self._validate_shared_update(context, original_policy_action,
                                         updated_policy_action,
                                         'policy_action')
            policy_context = p_context.PolicyActionContext(
                self, context, updated_policy_action,
                original_policy_action=original_policy_action)
            self.policy_driver_manager.update_policy_action_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_action_postcommit(
            policy_context)
        return updated_policy_action

    @log.log
    def delete_policy_action(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_action = self.get_policy_action(context, id)
            policy_context = p_context.PolicyActionContext(self, context,
                                                           policy_action)
            self.policy_driver_manager.delete_policy_action_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_action(context, id)

        try:
            self.policy_driver_manager.delete_policy_action_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_policy_action_postcommit "
                    "failed, deleting policy_action '%s'"), id)

    @log.log
    def create_policy_rule(self, context, policy_rule):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                GroupPolicyPlugin, self).create_policy_rule(
                    context, policy_rule)
            self._validate_shared_create(context, result, 'policy_rule')
            policy_context = p_context.PolicyRuleContext(self, context,
                                                         result)
            self.policy_driver_manager.create_policy_rule_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_rule_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_rule_postcommit"
                    " failed, deleting policy_rule '%s'"), result['id'])
                self.delete_policy_rule(context, result['id'])

        return result

    @log.log
    def update_policy_rule(self, context, id, policy_rule):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_rule = super(
                GroupPolicyPlugin, self).get_policy_rule(context, id)
            updated_policy_rule = super(
                GroupPolicyPlugin, self).update_policy_rule(
                    context, id, policy_rule)
            self._validate_shared_update(context, original_policy_rule,
                                         updated_policy_rule, 'policy_rule')
            policy_context = p_context.PolicyRuleContext(
                self, context, updated_policy_rule,
                original_policy_rule=original_policy_rule)
            self.policy_driver_manager.update_policy_rule_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_rule_postcommit(
            policy_context)
        return updated_policy_rule

    @log.log
    def delete_policy_rule(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_rule = self.get_policy_rule(context, id)
            policy_context = p_context.PolicyRuleContext(self, context,
                                                         policy_rule)
            self.policy_driver_manager.delete_policy_rule_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_rule(
                context, id)

        try:
            self.policy_driver_manager.delete_policy_rule_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_policy_rule_postcommit"
                    " failed, deleting policy_rule '%s'"), id)

    @log.log
    def create_policy_rule_set(self, context, policy_rule_set):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_rule_set(
                               context, policy_rule_set)
            self._validate_shared_create(context, result, 'policy_rule_set')
            policy_context = p_context.PolicyRuleSetContext(
                self, context, result)
            self.policy_driver_manager.create_policy_rule_set_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_rule_set_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_rule_set_postcommit "
                    "failed, deleting policy_rule_set '%s'"), result['id'])
                self.delete_policy_rule_set(context, result['id'])

        return result

    @log.log
    def update_policy_rule_set(self, context, id, policy_rule_set):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_rule_set = super(
                GroupPolicyPlugin, self).get_policy_rule_set(context, id)
            updated_policy_rule_set = super(
                GroupPolicyPlugin, self).update_policy_rule_set(
                    context, id, policy_rule_set)
            self._validate_shared_update(context, original_policy_rule_set,
                                         updated_policy_rule_set,
                                         'policy_rule_set')
            policy_context = p_context.PolicyRuleSetContext(
                self, context, updated_policy_rule_set,
                original_policy_rule_set=original_policy_rule_set)
            self.policy_driver_manager.update_policy_rule_set_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_rule_set_postcommit(
            policy_context)
        return updated_policy_rule_set

    @log.log
    def delete_policy_rule_set(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_rule_set = self.get_policy_rule_set(context, id)
            policy_context = p_context.PolicyRuleSetContext(
                self, context, policy_rule_set)
            self.policy_driver_manager.delete_policy_rule_set_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_rule_set(context, id)

        try:
            self.policy_driver_manager.delete_policy_rule_set_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_policy_rule_set_postcommit "
                    "failed, deleting policy_rule_set '%s'"), id)
