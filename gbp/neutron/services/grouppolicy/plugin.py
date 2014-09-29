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
    def delete_l3_policy(self, context, l3_policy_id):
        session = context.session
        with session.begin(subtransactions=True):
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
