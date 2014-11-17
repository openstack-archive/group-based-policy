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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class PolicyTargetContext(object):
    """Context passed to policy engine for policy_target resource changes.

    A PolicyTargetContext instance wraps a policy_target resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_target.

        Return the current state of the policy_target, as defined by
        GroupPolicyPlugin.create_policy_target.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_target.

        Return the original state of the policy_target, prior to a call to
        update_policy_target. Method is only valid within calls to
        update_policy_target_precommit and update_policy_target_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_port_id(self, port_id):
        """Set the port for the policy_target.

        :param port_id: Port to which policy_target is mapped.

        Set the neutron port to which the policy_target is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyTargetGroupContext(object):
    """Context passed to policy engine for policy_target_group resource changes.

    PolicyTargetContext instance wraps a policy_target_group resource. It
    provides helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_target_group.

        Return the current state of the policy_target_group, as defined by
        GroupPolicyPlugin.create_policy_target_group.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_target_group.

        Return the original state of the policy_target_group, prior to a call
        to update_policy_target_group. Method is only valid within calls to
        update_policy_target_group_precommit and
        update_policy_target_group_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_l2_policy_id(self, l2_policy_id):
        """Set the l2_policy for the policy_target_group.

        :param l2_policy_id: l2_policy for the policy_target_group.

        Set the l2_policy for the policy_target_group.
        """
        pass

    @abc.abstractmethod
    def set_network_service_policy_id(self, network_service_policy_id):
        """Set the network_service_policy for the policy_target_group.

        :param network_service_policy_id: network_service_policy for the ptg.

        Set the network_service_policy for the policy_target_group.
        """
        pass

    @abc.abstractmethod
    def add_subnet(self, subnet_id):
        """Add the subnet to the policy_target_group.

        :param subnet_id: Subnet to which policy_target_group is mapped.

        Add a neutron subnet to the set of subnets to which the
        policy_target_group is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class L2PolicyContext(object):
    """Context passed to policy engine for l2_policy resource changes.

    A L2_ContextContext instance wraps an l2_policy resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the l2_policy.

        Return the current state of the l2_policy, as defined by
        GroupPolicyPlugin.create_l2_policy.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the l2_policy.

        Return the original state of the l2_policy, prior to a call to
        update_l2_policy. Method is only valid within calls to
        update_l2_policy_precommit and update_l2_policy_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_l3_policy_id(self, l3_policy_id):
        """Set the l3_policy for the l2_policy.

        :param l3_policy_id: l3_policy for the l2_policy.

        Set the l3_policy for the l2_policy.
        """
        pass

    @abc.abstractmethod
    def set_network_id(self, network_id):
        """Set the network for the l2_policy.

        :param network_id: Network to which l2_policy is mapped.

        Set the neutron network to which the l2_policy is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class L3PolicyContext(object):

    """Context passed to policy engine for l3_policy resource changes.

    A L3PolicyContext instance wraps an l3_policy resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the l3_policy.

        Return the current state of the l3_policy, as defined by
        GroupPolicyPlugin.create_l3_policy.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the l3_policy.

        Return the original state of the l3_policy, prior to a call to
        update_l3_policy. Method is only valid within calls to
        update_l3_policy_precommit and update_l3_policy_postcommit.
        """
        pass

    @abc.abstractmethod
    def add_router(self, router_id):
        """Add the router to the l3_policy.

        :param router_id: Router to which l3_policy is mapped.

        Add a neutron router to the set of routers to which the
        l3_policy is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class NetworkServicePolicyContext(object):
    """
    Context passed to policy engine for network_service_policy resource
    changes.

    A NetworkServicePolicyContext instance wraps a network_service_policy
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached for convenient
    access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the network_service_policy.

        Return the current state of the network_service_policy, as defined by
        GroupPolicyPlugin.create_network_service_policy.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the network_service_policy.

        Return the original state of the network_service_policy, prior to a
        call to
        update_network_service_policy. Method is only valid within calls to
        update_network_service_policy_precommit and
        update_network_service_policy_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyClassifierContext(object):
    """Context passed to policy engine for policy_classifier resource changes.

    An PolicyClassifierContext instance wraps a policy_classifier resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_classifier.

        Return the current state of the policy_classifier, as defined by
        GroupPolicyPlugin.create_policy_classifier.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_classifier.

        Return the original state of the policy_classifier, prior to a call to
        update_policy_classifier. Method is only valid within calls to
        update_policy_classifier_precommit and
        update_policy_classifier_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyActionContext(object):
    """Context passed to policy engine for policy_action resource changes.

    An PolicyActionContext instance wraps a policy_action resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_action.

        Return the current state of the policy_action, as defined by
        GroupPolicyPlugin.create_policy_action.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_action.

        Return the original state of the policy_action, prior to a call to
        update_policy_action. Method is only valid within calls to
        update_policy_action_precommit and update_policy_action_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyRuleContext(object):
    """Context passed to policy engine for policy_rule resource changes.

    An PolicyRuleContext instance wraps a policy_rule resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_rule.

        Return the current state of the policy_rule, as defined by
        GroupPolicyPlugin.create_policy_rule.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_rule.

        Return the original state of the policy_rule, prior to a call to
        update_policy_rule. Method is only valid within calls to
        update_policy_rule_precommit and
        update_policy_rule_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyRuleSetContext(object):
    """Context passed to policy engine for changes to policy_rule_set resources.

    PolicyRuleSetContext instance wraps a policy_rule_set resource. It
    provides helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the policy_rule_set.

        Return the current state of the policy_rule_set, as defined by
        GroupPolicyPlugin.create_policy_rule_set.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the policy_rule_set.

        Return the original state of the policy_rule_set, prior to a call to
        update_policy_rule_set. Method is only valid within calls to
        update_policy_rule_set_precommit and update_policy_rule_set_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PolicyDriver(object):
    """Define stable abstract interface for Group Policy drivers.

    A policy driver is called on the creation, update, and deletion
    of all Group Policy resources. For every event, there are two methods that
    get called - one within the database transaction (method suffix of
    _precommit), one right afterwards (method suffix of _postcommit).

    Exceptions raised by methods called inside the transaction can
    rollback, but should not make any blocking calls (for example,
    REST requests to an outside controller). Methods called after
    transaction commits can make blocking external calls, though these
    will block the entire process. Exceptions raised in calls after
    the transaction commits may cause the associated resource to be
    deleted.

    Because rollback outside of the transaction is not done in the
    case of update of resources, all data validation must be done within
    methods that are part of the database transaction.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    def create_policy_target_precommit(self, context):
        """Allocate resources for a new policy_target.

        :param context: PolicyTargetContext instance describing the new
        policy_target.
        """
        pass

    def create_policy_target_postcommit(self, context):
        """Create a policy_target.

        :param context: PolicyTargetContext instance describing the new
        policy_target.
        """
        pass

    def update_policy_target_precommit(self, context):
        """Update resources of a policy_target.

        :param context: PolicyTargetContext instance describing the new
        state of the policy_target, as well as the original state prior
        to the update_policy_target call.
        """
        pass

    def update_policy_target_postcommit(self, context):
        """Update a policy_target.

        :param context: PolicyTargetContext instance describing the new
        state of the policy_target, as well as the original state prior
        to the update_policy_target call.
        """
        pass

    def delete_policy_target_precommit(self, context):
        """Delete resources for a policy_target.

        :param context: PolicyTargetContext instance describing the current
        state of the policy_target, prior to the call to delete it.
        """
        pass

    def delete_policy_target_postcommit(self, context):
        """Delete a policy_target.

        :param context: PolicyTargetContext instance describing the current
        state of the policy_target, prior to the call to delete it.
        """
        pass

    def create_policy_target_group_precommit(self, context):
        """Allocate resources for a new policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the new
        policy_target_group.
        """
        pass

    def create_policy_target_group_postcommit(self, context):
        """Create a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the new
        policy_target_group.
        """
        pass

    def update_policy_target_group_precommit(self, context):
        """Update resources of a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the new
        state of the policy_target_group, as well as the original state prior
        to the update_policy_target_group call.
        """
        pass

    def update_policy_target_group_postcommit(self, context):
        """Update a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the new
        state of the policy_target_group, as well as the original state prior
        to the update_policy_target_group call.
        """
        pass

    def delete_policy_target_group_precommit(self, context):
        """Delete resources for a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the
        current state of the policy_target_group, prior to the call to delete
        it.
        """
        pass

    def delete_policy_target_group_postcommit(self, context):
        """Delete a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the
        current state of the policy_target_group, prior to the call to delete
        it.
        """
        pass

    def create_l2_policy_precommit(self, context):
        """Allocate resources for a new l2_policy.

        :param context: L2PolicyContext instance describing the new
        l2_policy.
        """
        pass

    def create_l2_policy_postcommit(self, context):
        """Create a l2_policy.

        :param context: L2PolicyContext instance describing the new
        l2_policy.
        """
        pass

    def update_l2_policy_precommit(self, context):
        """Update resources of a l2_policy.

        :param context: L2PolicyContext instance describing the new
        state of the l2_policy, as well as the original state prior
        to the update_l2_policy call.
        """
        pass

    def update_l2_policy_postcommit(self, context):
        """Update a l2_policy.

        :param context: L2PolicyContext instance describing the new
        state of the l2_policy, as well as the original state prior
        to the update_l2_policy call.
        """
        pass

    def delete_l2_policy_precommit(self, context):
        """Delete resources for a l2_policy.

        :param context: L2PolicyContext instance describing the current
        state of the l2_policy, prior to the call to delete it.
        """
        pass

    def delete_l2_policy_postcommit(self, context):
        """Delete a l2_policy.

        :param context: L2PolicyContext instance describing the current
        state of the l2_policy, prior to the call to delete it.
        """
        pass

    def create_l3_policy_precommit(self, context):
        """Allocate resources for a new l3_policy.

        :param context: L3PolicyContext instance describing the new
        l3_policy.
        """
        pass

    def create_l3_policy_postcommit(self, context):
        """Create a l3_policy.

        :param context: L3PolicyContext instance describing the new
        l3_policy.
        """
        pass

    def update_l3_policy_precommit(self, context):
        """Update resources of a l3_policy.

        :param context: L3PolicyContext instance describing the new
        state of the l3_policy, as well as the original state prior
        to the update_l3_policy call.
        """
        pass

    def update_l3_policy_postcommit(self, context):
        """Update a l3_policy.

        :param context: L3PolicyContext instance describing the new
        state of the l3_policy, as well as the original state prior
        to the update_l3_policy call.
        """
        pass

    def delete_l3_policy_precommit(self, context):
        """Delete resources for a l3_policy.

        :param context: L3PolicyContext instance describing the current
        state of the l3_policy, prior to the call to delete it.
        """
        pass

    def delete_l3_policy_postcommit(self, context):
        """Delete a l3_policy.

        :param context: L3PolicyContext instance describing the current
        state of the l3_policy, prior to the call to delete it.
        """
        pass

    def create_policy_classifier_precommit(self, context):
        """Allocate resources for a new policy_classifier.

        :param context: PolicyClassifierContext instance describing the new
        policy_classifier.
        """
        pass

    def create_policy_classifier_postcommit(self, context):
        """Create a policy_classifier.

        :param context: PolicyClassifierContext instance describing the new
        policy_classifier.
        """
        pass

    def update_policy_classifier_precommit(self, context):
        """Update resources of a policy_classifier.

        :param context: PolicyClassifierContext instance describing the new
        state of the policy_classifier, as well as the original state prior
        to the update_policy_classifier call.
        """
        pass

    def update_policy_classifier_postcommit(self, context):
        """Update a policy_classifier.

        :param context: PolicyClassifierContext instance describing the new
        state of the policy_classifier, as well as the original state prior
        to the update_policy_classifier call.
        """
        pass

    def delete_policy_classifier_precommit(self, context):
        """Delete resources for a policy_classifier.

        :param context: PolicyClassifierContext instance describing the current
        state of the policy_classifier, prior to the call to delete it.
        """
        pass

    def delete_policy_classifier_postcommit(self, context):
        """Delete a policy_classifier.

        :param context: PolicyClassifierContext instance describing the current
        state of the policy_classifier, prior to the call to delete it.
        """
        pass

    def create_policy_action_precommit(self, context):
        """Allocate resources for a new policy_action.

        :param context: PolicyActionContext instance describing the new
        policy_action.
        """
        pass

    def create_policy_action_postcommit(self, context):
        """Create a policy_action.

        :param context: PolicyActionContext instance describing the new
        policy_action.
        """
        pass

    def update_policy_action_precommit(self, context):
        """Update resources of a policy_action.

        :param context: PolicyActionContext instance describing the new
        state of the policy_action, as well as the original state prior
        to the update_policy_action call.
        """
        pass

    def update_policy_action_postcommit(self, context):
        """Update a policy_action.

        :param context: PolicyActionContext instance describing the new
        state of the policy_action, as well as the original state prior
        to the update_policy_action call.
        """
        pass

    def delete_policy_action_precommit(self, context):
        """Delete resources for a policy_action.

        :param context: PolicyActionContext instance describing the current
        state of the policy_action, prior to the call to delete it.
        """
        pass

    def delete_policy_action_postcommit(self, context):
        """Delete a policy_action.

        :param context: PolicyActionContext instance describing the current
        state of the policy_action, prior to the call to delete it.
        """
        pass

    def create_policy_rule_precommit(self, context):
        """Allocate resources for a new policy_rule.

        :param context: PolicyRuleContext instance describing the new
        policy_rule.
        """
        pass

    def create_policy_rule_postcommit(self, context):
        """Create a policy_rule.

        :param context: PolicyRuleContext instance describing the new
        policy_rule.
        """
        pass

    def update_policy_rule_precommit(self, context):
        """Update resources of a policy_rule.

        :param context: PolicyRuleContext instance describing the new
        state of the policy_rule, as well as the original state prior
        to the update_policy_rule call.
        """
        pass

    def update_policy_rule_postcommit(self, context):
        """Update a policy_rule.

        :param context: PolicyRuleContext instance describing the new
        state of the policy_rule, as well as the original state prior
        to the update_policy_rule call.
        """
        pass

    def delete_policy_rule_precommit(self, context):
        """Delete resources for a policy_rule.

        :param context: PolicyRuleContext instance describing the current
        state of the policy_rule, prior to the call to delete it.
        """
        pass

    def delete_policy_rule_postcommit(self, context):
        """Delete a policy_rule.

        :param context: PolicyRuleContext instance describing the current
        state of the policy_rule, prior to the call to delete it.
        """
        pass

    def create_policy_rule_set_precommit(self, context):
        """Allocate resources for a new policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the new
        policy_rule_set.
        """
        pass

    def create_policy_rule_set_postcommit(self, context):
        """Create a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the new
        policy_rule_set.
        """
        pass

    def update_policy_rule_set_precommit(self, context):
        """Update resources of a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the new
        state of the policy_rule_set, as well as the original state prior
        to the update_policy_rule_set call.
        """
        pass

    def update_policy_rule_set_postcommit(self, context):
        """Update a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the new
        state of the policy_rule_set, as well as the original state prior
        to the update_policy_rule_set call.
        """
        pass

    def delete_policy_rule_set_precommit(self, context):
        """Delete resources for a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the current
        state of the policy_rule_set, prior to the call to delete it.
        """
        pass

    def delete_policy_rule_set_postcommit(self, context):
        """Delete a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the current
        state of the policy_rule_set, prior to the call to delete it.
        """
        pass

    def create_network_service_policy_precommit(self, context):
        """Allocate resources for a new network service policy.

        :param context: NetworkServicePolicyContext instance describing the new
        network service policy.
        """
        pass

    def create_network_service_policy_postcommit(self, context):
        """Create a network service policy.

        :param context: NetworkServicePolicyContext instance describing the new
        network service policy.
        """
        pass

    def update_network_service_policy_precommit(self, context):
        """Update resources of a network service policy.

        :param context: NetworkServicePolicyContext instance describing the new
        state of the NetworkServicePolicy, as well as the original state prior
        to the update_network_service_policy call.
        """
        pass

    def update_network_service_policy_postcommit(self, context):
        """Update a network service policy.

        :param context: NetworkServicePolicyContext instance describing the new
        state of the NetworkServicePolicy, as well as the original state prior
        to the update_network_service_policy call.
        """
        pass

    def delete_network_service_policy_precommit(self, context):
        """Delete resources for a network service policy.

        :param context: NetworkServicePolicyContext instance describing the
        current state of the NetworkServicePolicy, prior to the call to
        delete it.
        """
        pass

    def delete_network_service_policy_postcommit(self, context):
        """Delete a network service policy.

        :param context: NetworkServicePolicyContext instance describing the
        current state of the NetworkServicePolicy, prior to the call to
        delete it.
        """
        pass
