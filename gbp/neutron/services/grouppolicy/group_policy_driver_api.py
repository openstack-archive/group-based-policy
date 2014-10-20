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
class EndpointContext(object):
    """Context passed to policy engine for endpoint resource changes.

    An EndpointContext instance wraps an endpoint resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the endpoint.

        Return the current state of the endpoint, as defined by
        GroupPolicyPlugin.create_endpoint.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the endpoint.

        Return the original state of the endpoint, prior to a call to
        update_endpoint. Method is only valid within calls to
        update_endpoint_precommit and update_endpoint_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_port_id(self, port_id):
        """Set the port for the endpoint.

        :param port_id: Port to which endpoint is mapped.

        Set the neutron port to which the endpoint is mapped.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class EndpointGroupContext(object):
    """Context passed to policy engine for endpoint_group resource changes.

    An EndpointContext instance wraps an endpoint_group resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the endpoint_group.

        Return the current state of the endpoint_group, as defined by
        GroupPolicyPlugin.create_endpoint_group.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the endpoint_group.

        Return the original state of the endpoint_group, prior to a call to
        update_endpoint_group. Method is only valid within calls to
        update_endpoint_group_precommit and update_endpoint_group_postcommit.
        """
        pass

    @abc.abstractmethod
    def set_l2_policy_id(self, l2_policy_id):
        """Set the l2_policy for the endpoint_group.

        :param l2_policy_id: l2_policy for the endpoint_group.

        Set the l2_policy for the endpoint_group.
        """
        pass

    @abc.abstractmethod
    def set_network_service_policy_id(self, network_service_policy_id):
        """Set the network_service_policy for the endpoint_group.

        :param network_service_policy_id: network_service_policy for the epg.

        Set the network_service_policy for the endpoint_group.
        """
        pass

    @abc.abstractmethod
    def add_subnet(self, subnet_id):
        """Add the subnet to the endpoint_group.

        :param subnet_id: Subnet to which endpoint_group is mapped.

        Add a neutron subnet to the set of subnets to which the
        endpoint_group is mapped.
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

    An PolicyClassifierContext instance wraps an policy_classifier resource.
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

    An PolicyActionContext instance wraps an policy_action resource.
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

    An PolicyRuleContext instance wraps an policy_rule resource.
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
class ContractContext(object):
    """Context passed to policy engine for changes to contract resources.

    An ContractContext instance wraps an contract resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the contract.

        Return the current state of the contract, as defined by
        GroupPolicyPlugin.create_contract.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the contract.

        Return the original state of the contract, prior to a call to
        update_contract. Method is only valid within calls to
        update_contract_precommit and update_contract_postcommit.
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

    def create_endpoint_precommit(self, context):
        """Allocate resources for a new endpoint.

        :param context: EndpointContext instance describing the new
        endpoint.
        """
        pass

    def create_endpoint_postcommit(self, context):
        """Create a endpoint.

        :param context: EndpointContext instance describing the new
        endpoint.
        """
        pass

    def update_endpoint_precommit(self, context):
        """Update resources of a endpoint.

        :param context: EndpointContext instance describing the new
        state of the endpoint, as well as the original state prior
        to the update_endpoint call.
        """
        pass

    def update_endpoint_postcommit(self, context):
        """Update a endpoint.

        :param context: EndpointContext instance describing the new
        state of the endpoint, as well as the original state prior
        to the update_endpoint call.
        """
        pass

    def delete_endpoint_precommit(self, context):
        """Delete resources for a endpoint.

        :param context: EndpointContext instance describing the current
        state of the endpoint, prior to the call to delete it.
        """
        pass

    def delete_endpoint_postcommit(self, context):
        """Delete a endpoint.

        :param context: EndpointContext instance describing the current
        state of the endpoint, prior to the call to delete it.
        """
        pass

    def create_endpoint_group_precommit(self, context):
        """Allocate resources for a new endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        endpoint_group.
        """
        pass

    def create_endpoint_group_postcommit(self, context):
        """Create a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        endpoint_group.
        """
        pass

    def update_endpoint_group_precommit(self, context):
        """Update resources of a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        state of the endpoint_group, as well as the original state prior
        to the update_endpoint_group call.
        """
        pass

    def update_endpoint_group_postcommit(self, context):
        """Update a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        state of the endpoint_group, as well as the original state prior
        to the update_endpoint_group call.
        """
        pass

    def delete_endpoint_group_precommit(self, context):
        """Delete resources for a endpoint_group.

        :param context: EndpointGroupContext instance describing the current
        state of the endpoint_group, prior to the call to delete it.
        """
        pass

    def delete_endpoint_group_postcommit(self, context):
        """Delete a endpoint_group.

        :param context: EndpointGroupContext instance describing the current
        state of the endpoint_group, prior to the call to delete it.
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

    def create_contract_precommit(self, context):
        """Allocate resources for a new contract.

        :param context: ContractContext instance describing the new
        contract.
        """
        pass

    def create_contract_postcommit(self, context):
        """Create a contract.

        :param context: ContractContext instance describing the new
        contract.
        """
        pass

    def update_contract_precommit(self, context):
        """Update resources of a contract.

        :param context: ContractContext instance describing the new
        state of the contract, as well as the original state prior
        to the update_contract call.
        """
        pass

    def update_contract_postcommit(self, context):
        """Update a contract.

        :param context: ContractContext instance describing the new
        state of the contract, as well as the original state prior
        to the update_contract call.
        """
        pass

    def delete_contract_precommit(self, context):
        """Delete resources for a contract.

        :param context: ContractContext instance describing the current
        state of the contract, prior to the call to delete it.
        """
        pass

    def delete_contract_postcommit(self, context):
        """Delete a contract.

        :param context: ContractContext instance describing the current
        state of the contract, prior to the call to delete it.
        """
        pass
