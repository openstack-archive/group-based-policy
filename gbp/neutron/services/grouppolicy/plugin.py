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

    def __init__(self):
        self.policy_driver_manager = manager.PolicyDriverManager()
        super(GroupPolicyPlugin, self).__init__()
        self.policy_driver_manager.initialize()

    @log.log
    def create_endpoint(self, context, endpoint):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).create_endpoint(context,
                                                                    endpoint)
            policy_context = p_context.EndpointContext(self, context, result)
            self.policy_driver_manager.create_endpoint_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_endpoint_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_endpoint_postcommit "
                            "failed, deleting endpoint '%s'"), result['id'])
                self.delete_endpoint(context, result['id'])

        return result

    @log.log
    def update_endpoint(self, context, endpoint_id, endpoint):
        session = context.session
        with session.begin(subtransactions=True):
            original_endpoint = super(GroupPolicyPlugin,
                                      self).get_endpoint(context, endpoint_id)
            updated_endpoint = super(GroupPolicyPlugin,
                                     self).update_endpoint(context,
                                                           endpoint_id,
                                                           endpoint)
            policy_context = p_context.EndpointContext(
                self, context, updated_endpoint,
                original_endpoint=original_endpoint)
            self.policy_driver_manager.update_endpoint_precommit(
                policy_context)

        self.policy_driver_manager.update_endpoint_postcommit(policy_context)
        return updated_endpoint

    @log.log
    def delete_endpoint(self, context, endpoint_id):
        session = context.session
        with session.begin(subtransactions=True):
            endpoint = self.get_endpoint(context, endpoint_id)
            policy_context = p_context.EndpointContext(self, context, endpoint)
            self.policy_driver_manager.delete_endpoint_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_endpoint(context,
                                                           endpoint_id)

        try:
            self.policy_driver_manager.delete_endpoint_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_endpoint_postcommit "
                            "failed, deleting contract '%s'"), endpoint_id)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_endpoint_group(context, endpoint_group)
            policy_context = p_context.EndpointGroupContext(self, context,
                                                            result)
            self.policy_driver_manager.create_endpoint_group_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_endpoint_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_endpoint_group_postcommit "
                            "failed, deleting endpoint_group '%s'"),
                          result['id'])
                self.delete_endpoint_group(context, result['id'])

        return result

    @log.log
    def update_endpoint_group(self, context, endpoint_group_id,
                              endpoint_group):
        session = context.session
        with session.begin(subtransactions=True):
            original_endpoint_group = super(GroupPolicyPlugin,
                                            self).get_endpoint_group(
                                                context, endpoint_group_id)
            updated_endpoint_group = super(GroupPolicyPlugin,
                                           self).update_endpoint_group(
                                               context, endpoint_group_id,
                                               endpoint_group)
            policy_context = p_context.EndpointGroupContext(
                self, context, updated_endpoint_group,
                original_endpoint_group=original_endpoint_group)
            self.policy_driver_manager.update_endpoint_group_precommit(
                policy_context)

        self.policy_driver_manager.update_endpoint_group_postcommit(
            policy_context)

        return updated_endpoint_group

    @log.log
    def delete_endpoint_group(self, context, endpoint_group_id):
        session = context.session
        with session.begin(subtransactions=True):
            endpoint_group = self.get_endpoint_group(context,
                                                     endpoint_group_id)
            # TODO(sumit) : Do not delete if EPG has EPs
            policy_context = p_context.EndpointGroupContext(self, context,
                                                            endpoint_group)
            self.policy_driver_manager.delete_endpoint_group_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_endpoint_group(
                context, endpoint_group_id)

        try:
            self.policy_driver_manager.delete_endpoint_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_endpoint_group_postcommit "
                            "failed, deleting endpoint_group '%s'"),
                          endpoint_group_id)

    @log.log
    def create_l2_policy(self, context, l2_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l2_policy(context, l2_policy)
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
    def create_l3_policy(self, context, l3_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l3_policy(context, l3_policy)
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
    def create_contract(self, context, contract):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).create_contract(context,
                                                                    contract)
            policy_context = p_context.ContractContext(self, context, result)
            self.policy_driver_manager.create_contract_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_contract_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("policy_driver_manager.create_contract_postcommit "
                            "failed, deleting contract '%s'"), result['id'])
                self.delete_contract(context, result['id'])

        return result

    @log.log
    def update_contract(self, context, id, contract):
        session = context.session
        with session.begin(subtransactions=True):
            original_contract = super(GroupPolicyPlugin,
                                      self).get_contract(context, id)
            updated_contract = super(GroupPolicyPlugin,
                                     self).update_contract(context, id,
                                                           contract)
            policy_context = p_context.ContractContext(
                self, context, updated_contract,
                original_contract=original_contract)
            self.policy_driver_manager.update_contract_precommit(
                policy_context)

        self.policy_driver_manager.update_contract_postcommit(policy_context)
        return updated_contract

    @log.log
    def delete_contract(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            contract = self.get_contract(context, id)
            policy_context = p_context.ContractContext(self, context, contract)
            self.policy_driver_manager.delete_contract_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_contract(context, id)

        try:
            self.policy_driver_manager.delete_contract_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("policy_driver_manager.delete_contract_postcommit "
                            "failed, deleting contract '%s'"), id)
