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

from neutron.api.v2 import attributes
from oslo_log import log as logging
import six
from sqlalchemy.orm import exc as orm_exc

from gbpservice.common import utils

LOG = logging.getLogger(__name__)


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

    @abc.abstractmethod
    def set_external_fixed_ips(self, external_segment_id, ips):
        """Add the external_fixed_ips to the l3_policy.

        :param external_segment_id: ES to which l3_policy is mapped.
        :param ips: IPs assigned for that ES.
        """
        pass

    @abc.abstractmethod
    def set_external_segment(self, external_segment_id):
        """Add the external_segment to the l3_policy.

        :param external_segment_id: ES to which l3_policy is mapped.
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
class ExternalSegmentContext(object):

    """Context passed to policy engine for external_segment resource.

    A ExternalSegmentContext instance wraps an external_segment
    resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the external_segment.

        Return the current state of the external_segment, as defined by
        GroupPolicyPlugin.create_external_segment.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the external_segment.

        Return the original state of the external_segment, prior to a
        call to update_external_segment. Method is only valid within
        calls to update_external_segment_precommit and
        update_external_segment_postcommit.
        """
        pass

    @abc.abstractmethod
    def add_subnet(self, subnet_id):
        """Add the subnet to the external_segment.

        :param subnet_id: Subnet to which external_segment is mapped.

        Add a neutron subnet to the set of routers to which the
        external_segment is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ExternalPolicyContext(object):

    """Context passed to policy engine for external_policy resource.

    A ExternalPolicyContext instance wraps an external_policy
    resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the external_policy.

        Return the current state of the external_policy, as defined by
        GroupPolicyPlugin.create_external_policy.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the external_policy.

        Return the original state of the external_policy, prior to a
        call to update_external_policy. Method is only valid within
        calls to update_external_policy_precommit and
        update_external_policy_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_external_segment(self, external_segment_id):
        """Add the external_segment to the external_policy.

        :param external_segment_id: ES to which external_policy is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class NatPoolContext(object):

    """Context passed to policy engine for nat_pool resource.

    A NatPoolContext instance wraps an nat_pool
    resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the nat_pool.

        Return the current state of the nat_pool, as defined by
        GroupPolicyPlugin.create_nat_pool.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the nat_pool.

        Return the original state of the nat_pool, prior to a
        call to update_nat_pool. Method is only valid within
        calls to update_nat_pool_precommit and
        update_nat_pool_postcommit.
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

    def get_policy_target_status(self, context):
        """Get most recent status of a policy_target.

        :param context: PolicyTargetContext instance describing the current
        state of the policy_target, prior to the call to this get. Driver
        can update the status and status_details. This status change will be
        reflected as the new status and status_details of the resource.
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

    def get_policy_target_group_status(self, context):
        """Get most recent status of a policy_target_group.

        :param context: PolicyTargetGroupContext instance describing the
        current state of the policy_target_group, prior to the call to this
        get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_l2_policy_status(self, context):
        """Get most recent status of a l2_policy.

        :param context: L2PolicyContext instance describing the current
        state of the l2_policy, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_l3_policy_status(self, context):
        """Get most recent status of a l3_policy.

        :param context: L3PolicyContext instance describing the current
        state of the l3_policy, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_policy_classifier_status(self, context):
        """Get most recent status of a policy_classifier.

        :param context: PolicyClassifierContext instance describing the current
        state of the policy_classifier, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_policy_action_status(self, context):
        """Get most recent status of a policy_action.

        :param context: PolicyActionContext instance describing the current
        state of the policy_action, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_policy_rule_status(self, context):
        """Get most recent status of a policy_rule.

        :param context: PolicyRuleContext instance describing the current
        state of the policy_rule, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_policy_rule_set_status(self, context):
        """Get most recent status of a policy_rule_set.

        :param context: PolicyRuleSetContext instance describing the current
        state of the policy_rule_set, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
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

    def get_network_service_policy_status(self, context):
        """Get most recent status of a network_service_policy.

        :param context: NetworkServicePolicyContext instance describing the
        current state of the network_service_policy, prior to the call to this
        get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
        """
        pass

    def create_external_segment_precommit(self, context):
        """Allocate resources for a new network service policy.

        :param context: ExternalSegmentContext instance describing the
        new network service policy.
        """
        pass

    def create_external_segment_postcommit(self, context):
        """Create a network service policy.

        :param context: ExternalSegmentContext instance describing the
        new network service policy.
        """
        pass

    def update_external_segment_precommit(self, context):
        """Update resources of a network service policy.

        :param context: ExternalSegmentContext instance describing the
        new state of the ExternalSegment, as well as the original state
        prior to the update_external_segment call.
        """
        pass

    def update_external_segment_postcommit(self, context):
        """Update a network service policy.

        :param context: ExternalSegmentContext instance describing the
        new state of the ExternalSegment, as well as the original state
        prior to the update_external_segment call.
        """
        pass

    def delete_external_segment_precommit(self, context):
        """Delete resources for a network service policy.

        :param context: ExternalSegmentContext instance describing the
        current state of the ExternalSegment, prior to the call to
        delete it.
        """
        pass

    def delete_external_segment_postcommit(self, context):
        """Delete a network service policy.

        :param context: ExternalSegmentContext instance describing the
        current state of the ExternalSegment, prior to the call to
        delete it.
        """
        pass

    def get_external_segment_status(self, context):
        """Get most recent status of a external_segment.

        :param context: ExternalSegmentContext instance describing the
        current state of the external_segment, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
        """
        pass

    def create_external_policy_precommit(self, context):
        """Allocate resources for a new network service policy.

        :param context: ExternalPolicyContext instance describing the
        new network service policy.
        """
        pass

    def create_external_policy_postcommit(self, context):
        """Create a network service policy.

        :param context: ExternalPolicyContext instance describing the
        new network service policy.
        """
        pass

    def update_external_policy_precommit(self, context):
        """Update resources of a network service policy.

        :param context: ExternalPolicyContext instance describing the
        new state of the ExternalPolicy, as well as the original state
        prior to the update_external_policy call.
        """
        pass

    def update_external_policy_postcommit(self, context):
        """Update a network service policy.

        :param context: ExternalPolicyContext instance describing the
        new state of the ExternalPolicy, as well as the original state
        prior to the update_external_policy call.
        """
        pass

    def delete_external_policy_precommit(self, context):
        """Delete resources for a network service policy.

        :param context: ExternalPolicyContext instance describing the
        current state of the ExternalPolicy, prior to the call to
        delete it.
        """
        pass

    def delete_external_policy_postcommit(self, context):
        """Delete a network service policy.

        :param context: ExternalPolicyContext instance describing the
        current state of the ExternalPolicy, prior to the call to
        delete it.
        """
        pass

    def get_external_policy_status(self, context):
        """Get most recent status of a external_policy.

        :param context: ExternalPolicyContext instance describing the
        current state of the external_policy, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
        """
        pass

    def create_nat_pool_precommit(self, context):
        """Allocate resources for a new network service policy.

        :param context: NatPoolContext instance describing the
        new network service policy.
        """
        pass

    def create_nat_pool_postcommit(self, context):
        """Create a network service policy.

        :param context: NatPoolContext instance describing the
        new network service policy.
        """
        pass

    def update_nat_pool_precommit(self, context):
        """Update resources of a network service policy.

        :param context: NatPoolContext instance describing the
        new state of the NatPool, as well as the original state
        prior to the update_nat_pool call.
        """
        pass

    def update_nat_pool_postcommit(self, context):
        """Update a network service policy.

        :param context: NatPoolContext instance describing the
        new state of the NatPool, as well as the original state
        prior to the update_nat_pool call.
        """
        pass

    def delete_nat_pool_precommit(self, context):
        """Delete resources for a network service policy.

        :param context: NatPoolContext instance describing the
        current state of the NatPool, prior to the call to
        delete it.
        """
        pass

    def delete_nat_pool_postcommit(self, context):
        """Delete a network service policy.

        :param context: NatPoolContext instance describing the
        current state of the NatPool, prior to the call to
        delete it.
        """
        pass

    def get_nat_pool_status(self, context):
        """Get most recent status of a nat_pool.

        :param context: NatPoolContext instance describing the
        current state of the nat_pool, prior to the call to this get.
        Driver can update the status and status_details. This status change
        will be reflected as the new status and status_details of the resource.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ExtensionDriver(object):
    """Define stable abstract interface for Group Policy extension drivers.

    An extension driver extends the core resources implemented by the
    group policy service plugin with additional attributes. Methods
    that process create and update operations for these resources
    validate and persist values for extended attributes supplied
    through the API. Other methods extend the resource dictionaries
    returned from the API operations with the values of the extended
    attributes.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    @abc.abstractproperty
    def extension_alias(self):
        """Supported extension alias.

        Return the alias identifying the Group Policy API extension
        supported by this driver.
        """
        pass

    def process_create_policy_target(self, session, data, result):
        """Process extended attributes for policy_target creation.

        :param session: database session
        :param data: dictionary of incoming policy_target data
        :param result: policy_target dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_target attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_target(self, session, data, result):
        """Process extended attributes for policy_target update.

        :param session: database session
        :param data: dictionary of incoming policy_target data
        :param result: policy_target dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_target attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_policy_target_dict(self, session, result):
        """Add extended attributes to policy_target dictionary.

        :param session: database session
        :param result: policy_target dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a policy_target
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a policy_target operation.
        """
        pass

    def process_create_policy_target_group(self, session, data, result):
        """Process extended attributes for policy_target_group creation.

        :param session: database session
        :param data: dictionary of incoming policy_target_group data
        :param result: policy_target_group dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_target_group attributes defined by
        this driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_target_group(self, session, data, result):
        """Process extended attributes for policy_target_group update.

        :param session: database session
        :param data: dictionary of incoming policy_target_group data
        :param result: policy_target_group dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_target_group attributes defined by
        this driver. Extended attribute values, whether updated or
        not, must also be added to result.
        """
        pass

    def extend_policy_target_group_dict(self, session, result):
        """Add extended attributes to policy_target_group dictionary.

        :param session: database session
        :param result: policy_target_group dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        policy_target_group dictionary to be used for mechanism driver
        calls and/or returned as the result of a policy_target_group
        operation.
        """
        pass

    def process_create_l2_policy(self, session, data, result):
        """Process extended attributes for l2_policy creation.

        :param session: database session
        :param data: dictionary of incoming l2_policy data
        :param result: l2_policy dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended l2_policy attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_l2_policy(self, session, data, result):
        """Process extended attributes for l2_policy update.

        :param session: database session
        :param data: dictionary of incoming l2_policy data
        :param result: l2_policy dictionary to extend

        Called inside transaction context on session to validate and
        update any extended l2_policy attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_l2_policy_dict(self, session, result):
        """Add extended attributes to l2_policy dictionary.

        :param session: database session
        :param result: l2_policy dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a l2_policy
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a l2_policy operation.
        """
        pass

    def process_create_l3_policy(self, session, data, result):
        """Process extended attributes for l3_policy creation.

        :param session: database session
        :param data: dictionary of incoming l3_policy data
        :param result: l3_policy dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended l3_policy attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_l3_policy(self, session, data, result):
        """Process extended attributes for l3_policy update.

        :param session: database session
        :param data: dictionary of incoming l3_policy data
        :param result: l3_policy dictionary to extend

        Called inside transaction context on session to validate and
        update any extended l3_policy attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_l3_policy_dict(self, session, result):
        """Add extended attributes to l3_policy dictionary.

        :param session: database session
        :param result: l3_policy dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a l3_policy
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a l3_policy operation.
        """
        pass

    def process_create_policy_classifier(self, session, data, result):
        """Process extended attributes for policy_classifier creation.

        :param session: database session
        :param data: dictionary of incoming policy_classifier data
        :param result: policy_classifier dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_classifier attributes defined by
        this driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_classifier(self, session, data, result):
        """Process extended attributes for policy_classifier update.

        :param session: database session
        :param data: dictionary of incoming policy_classifier data
        :param result: policy_classifier dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_classifier attributes defined by
        this driver. Extended attribute values, whether updated or
        not, must also be added to result.
        """
        pass

    def extend_policy_classifier_dict(self, session, result):
        """Add extended attributes to policy_classifier dictionary.

        :param session: database session
        :param result: policy_classifier dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        policy_classifier dictionary to be used for mechanism driver
        calls and/or returned as the result of a policy_classifier
        operation.
        """
        pass

    def process_create_policy_action(self, session, data, result):
        """Process extended attributes for policy_action creation.

        :param session: database session
        :param data: dictionary of incoming policy_action data
        :param result: policy_action dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_action attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_action(self, session, data, result):
        """Process extended attributes for policy_action update.

        :param session: database session
        :param data: dictionary of incoming policy_action data
        :param result: policy_action dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_action attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_policy_action_dict(self, session, result):
        """Add extended attributes to policy_action dictionary.

        :param session: database session
        :param result: policy_action dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a policy_action
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a policy_action operation.
        """
        pass

    def process_create_policy_rule(self, session, data, result):
        """Process extended attributes for policy_rule creation.

        :param session: database session
        :param data: dictionary of incoming policy_rule data
        :param result: policy_rule dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_rule attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_rule(self, session, data, result):
        """Process extended attributes for policy_rule update.

        :param session: database session
        :param data: dictionary of incoming policy_rule data
        :param result: policy_rule dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_rule attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_policy_rule_dict(self, session, result):
        """Add extended attributes to policy_rule dictionary.

        :param session: database session
        :param result: policy_rule dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a policy_rule
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a policy_rule operation.
        """
        pass

    def process_create_policy_rule_set(self, session, data, result):
        """Process extended attributes for policy_rule_set creation.

        :param session: database session
        :param data: dictionary of incoming policy_rule_set data
        :param result: policy_rule_set dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended policy_rule_set attributes defined by
        this driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_policy_rule_set(self, session, data, result):
        """Process extended attributes for policy_rule_set update.

        :param session: database session
        :param data: dictionary of incoming policy_rule_set data
        :param result: policy_rule_set dictionary to extend

        Called inside transaction context on session to validate and
        update any extended policy_rule_set attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_policy_rule_set_dict(self, session, result):
        """Add extended attributes to policy_rule_set dictionary.

        :param session: database session
        :param result: policy_rule_set dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        policy_rule_set dictionary to be used for mechanism driver
        calls and/or returned as the result of a policy_rule_set
        operation.
        """
        pass

    def process_create_network_service_policy(self, session, data, result):
        """Process extended attributes for network_service_policy creation.

        :param session: database session
        :param data: dictionary of incoming network_service_policy data
        :param result: network_service_policy dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended network_service_policy attributes defined
        by this driver. Extended attribute values must also be added
        to result.
        """
        pass

    def process_update_network_service_policy(self, session, data, result):
        """Process extended attributes for network_service_policy update.

        :param session: database session
        :param data: dictionary of incoming network_service_policy data
        :param result: network_service_policy dictionary to extend

        Called inside transaction context on session to validate and
        update any extended network_service_policy attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_network_service_policy_dict(self, session, result):
        """Add extended attributes to network_service_policy dictionary.

        :param session: database session
        :param result: network_service_policy dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        network_service_policy dictionary to be used for mechanism
        driver calls and/or returned as the result of a
        network_service_policy operation.
        """
        pass

    def process_create_external_segment(self, session, data, result):
        """Process extended attributes for external_segment creation.

        :param session: database session
        :param data: dictionary of incoming external_segment data
        :param result: external_segment dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended external_segment attributes defined
        by this driver. Extended attribute values must also be added
        to result.
        """
        pass

    def process_update_external_segment(self, session, data, result):
        """Process extended attributes for external_segment update.

        :param session: database session
        :param data: dictionary of incoming external_segment data
        :param result: external_segment dictionary to extend

        Called inside transaction context on session to validate and
        update any extended external_segment attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_external_segment_dict(self, session, result):
        """Add extended attributes to external_segment dictionary.

        :param session: database session
        :param result: external_segment dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        external_segment dictionary to be used for mechanism
        driver calls and/or returned as the result of a
        external_segment operation.
        """
        pass

    def process_create_external_policy(self, session, data, result):
        """Process extended attributes for external_policy creation.

        :param session: database session
        :param data: dictionary of incoming external_policy data
        :param result: external_policy dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended external_policy attributes defined
        by this driver. Extended attribute values must also be added
        to result.
        """
        pass

    def process_update_external_policy(self, session, data, result):
        """Process extended attributes for external_policy update.

        :param session: database session
        :param data: dictionary of incoming external_policy data
        :param result: external_policy dictionary to extend

        Called inside transaction context on session to validate and
        update any extended external_policy attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_external_policy_dict(self, session, result):
        """Add extended attributes to external_policy dictionary.

        :param session: database session
        :param result: external_policy dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        external_policy dictionary to be used for mechanism
        driver calls and/or returned as the result of a
        external_policy operation.
        """
        pass

    def process_create_nat_pool(self, session, data, result):
        """Process extended attributes for nat_pool creation.

        :param session: database session
        :param data: dictionary of incoming nat_pool data
        :param result: nat_pool dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended nat_pool attributes defined
        by this driver. Extended attribute values must also be added
        to result.
        """
        pass

    def process_update_nat_pool(self, session, data, result):
        """Process extended attributes for nat_pool update.

        :param session: database session
        :param data: dictionary of incoming nat_pool data
        :param result: nat_pool dictionary to extend

        Called inside transaction context on session to validate and
        update any extended nat_pool attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_nat_pool_dict(self, session, result):
        """Add extended attributes to nat_pool dictionary.

        :param session: database session
        :param result: nat_pool dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a
        nat_pool dictionary to be used for mechanism
        driver calls and/or returned as the result of a
        nat_pool operation.
        """
        pass

    def _default_process_create(self, session, data, result, type=None,
                                table=None, keys=None):
        """Default process create behavior.

        Gives a default data storing behavior in order to avoid code
        duplication across drivers. Use multiple times to fill multiple
        tables if needed.
        """
        kwargs = dict((x, data[type][x] if
                       attributes.is_attr_set(data[type][x]) else None)
                      for x in keys)
        kwargs[type + '_' + 'id'] = result['id']
        record = table(**kwargs)
        session.add(record)
        del kwargs[type + '_' + 'id']
        result.update(kwargs)

    def _default_process_update(self, session, data, result, type=None,
                                table=None, keys=None):
        """Default process update behavior.

        Gives a default data storing behavior in order to avoid code
        duplication across drivers. Use multiple times to fill multiple
        tables if needed.
        """
        try:
            record = (session.query(table).filter_by(**{type + '_' + 'id':
                                                        result['id']}).one())
        except orm_exc.NoResultFound:
            # TODO(ivar) This is a preexisting object. For now just ignore
            # this and return. Each extension driver should be able to specify
            # a default behavior in case this happens.
            return
        for key in keys:
            value = data[type].get(key)
            if attributes.is_attr_set(value) and value != getattr(record, key):
                setattr(record, key, value)
            result[key] = getattr(record, key)

    def _default_extend_dict(self, session, result, type=None,
                             table=None, keys=None):
        """Default dictionary extension behavior.

        Gives a default dictionary extension behavior in order to avoid code
        duplication across drivers. Use multiple times to fill from multiple
        tables if needed.
        """
        try:
            record = (session.query(table).filter_by(**{type + '_' + 'id':
                                                        result['id']}).one())
        except orm_exc.NoResultFound:
            # TODO(ivar) This is a preexisting object. For now just ignore
            # this and return. Each extension driver should be able to specify
            # a default behavior in case this happens.
            return
        for key in keys:
            result[key] = getattr(record, key)


def default_extension_behavior(table, keys=None):
    def wrap(func):
        def inner(inst, *args):

            def filter_keys(inst, data, type):
                plural = utils.get_resource_plural(type)
                if keys:
                    return keys
                definition = inst._extension_dict[plural]
                return [x for x in definition if (x in data[type] if data else
                                                  True)]

            name = func.__name__
            if name.startswith('process_create_'):
                # call default process create
                type = name[len('process_create_'):]
                inst._default_process_create(*args, type=type, table=table,
                    keys=filter_keys(inst, args[1], type))
                # Complete result dictionary with unfiltered attributes
                inst._default_extend_dict(args[0], args[2], type=type,
                                          table=table,
                    keys=filter_keys(inst, None, type))
            elif name.startswith('process_update_'):
                # call default process update
                type = name[len('process_update_'):]
                inst._default_process_update(*args, type=type, table=table,
                    keys=filter_keys(inst, args[1], type))

                # Complete result dictionary with unfiltered attributes
                inst._default_extend_dict(args[0], args[2], type=type,
                                          table=table,
                    keys=filter_keys(inst, None, type))
            elif name.startswith('extend_') and name.endswith('_dict'):
                # call default extend dict
                type = name[len('extend_'):-len('_dict')]
                inst._default_extend_dict(*args, type=type, table=table,
                    keys=filter_keys(inst, None, type))
            # Now exec the actual function for postprocessing
            func(inst, *args)
        return inner
    return wrap
