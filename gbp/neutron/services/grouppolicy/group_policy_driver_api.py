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
