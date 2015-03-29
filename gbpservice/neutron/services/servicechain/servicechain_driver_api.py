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
class ServiceChainNodeContext(object):
    """Context passed to policy engine for servicechain_node resource changes.

    A ServiceChainNodeContext instance wraps a servicechain_node resource. It
    provides helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the servicechain_node.

        Return the current state of the servicechain_node, as defined by
        ServiceChainPlugin.create_servicechain_node.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the servicechain_node.

        Return the original state of the servicechain_node, prior to a call to
        update_servicechain_node. Method is only valid within calls to
        update_servicechain_node_precommit and
        update_servicechain_node_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ServiceChainSpecContext(object):
    """Context passed to policy engine for servicechain_spec resource changes.

    A ServiceChainSpecContext instance wraps a servicechain_spec resource. It
    provides helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the servicechain_spec.

        Return the current state of the servicechain_spec, as defined by
        ServiceChainPlugin.create_servicechain_spec.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the servicechain_spec.

        Return the original state of the servicechain_spec, prior to a call to
        update_servicechain_spec. Method is only valid within calls to
        update_servicechain_spec_precommit and
        update_servicechain_spec_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ServiceChainInstanceContext(object):
    """Context passed to policy engine for servicechain_instance resource
    changes.

    A ServiceChainInstanceContext instance wraps a servicechain_instance
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached for convenient
    access.
    """

    @abc.abstractproperty
    def current(self):
        """Return the current state of the servicechain_instance.

        Return the current state of the servicechain_instance, as defined by
        ServiceChainPlugin.create_servicechain_instance.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the original state of the servicechain_instance.

        Return the original state of the servicechain_instance, prior to a
        call to update_servicechain_instance. Method is only valid within
        calls to update_servicechain_instance_precommit and
        update_servicechain_instance_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ServiceChainDriver(object):
    """Define stable abstract interface for Service Chain drivers.

    A Service Chain driver is called on the creation, update, and deletion
    of all Service Chain resources. For every event, there are two methods
    that get called - one within the database transaction (method suffix of
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

    def create_servicechain_node_precommit(self, context):
        """Allocate resources for a new servicechain_node.

        :param context: ServiceChainNodeContext instance describing the new
        servicechain_node.
        """
        pass

    def create_servicechain_node_postcommit(self, context):
        """Create a servicechain_node.

        :param context: ServiceChainNodeContext instance describing the new
        servicechain_node.
        """
        pass

    def update_servicechain_node_precommit(self, context):
        """Update resources of a servicechain_node.

        :param context: ServiceChainNodeContext instance describing the new
        state of the servicechain_node, as well as the original state prior
        to the update_servicechain_node call.
        """
        pass

    def update_servicechain_node_postcommit(self, context):
        """Update a servicechain_node.

        :param context: ServiceChainNodeContext instance describing the new
        state of the servicechain_node, as well as the original state prior
        to the update_servicechain_node call.
        """
        pass

    def delete_servicechain_node_precommit(self, context):
        """Delete resources for a servicechain_node.

        :param context: ServiceChainNodeContext instance describing the
        current state of the servicechain_node,
        prior to the call to delete it.
        """
        pass

    def delete_servicechain_node_postcommit(self, context):
        """Delete a servicechain_node.

        :param context: ServiceChainNodeContext instance describing the
        current state of the servicechain_node,
        prior to the call to delete it.
        """
        pass

    def create_servicechain_spec_precommit(self, context):
        """Allocate resources for a new servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the new
        servicechain_spec.
        """
        pass

    def create_servicechain_spec_postcommit(self, context):
        """Create a servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the new
        servicechain_spec.
        """
        pass

    def update_servicechain_spec_precommit(self, context):
        """Update resources of a servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the new
        state of the servicechain_spec, as well as the original state prior
        to the update_servicechain_spec call.
        """
        pass

    def update_servicechain_spec_postcommit(self, context):
        """Update a servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the new
        state of the servicechain_spec, as well as the original state prior
        to the update_servicechain_spec call.
        """
        pass

    def delete_servicechain_spec_precommit(self, context):
        """Delete resources for a servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the
        current state of the servicechain_spec,
        prior to the call to delete it.
        """
        pass

    def delete_servicechain_spec_postcommit(self, context):
        """Delete a servicechain_spec.

        :param context: ServiceChainSpecContext instance describing the
        current state of the servicechain_spec,
        prior to the call to delete it.
        """
        pass

    def create_servicechain_instance_precommit(self, context):
        """Allocate resources for a new servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the new
        servicechain_instance.
        """
        pass

    def create_servicechain_instance_postcommit(self, context):
        """Create a servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the
        new servicechain_instance.
        """
        pass

    def update_servicechain_instance_precommit(self, context):
        """Update resources of a servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the
        new state of the servicechain_instance, as well as the original state
        prior to the update_servicechain_instance call.
        """
        pass

    def update_servicechain_instance_postcommit(self, context):
        """Update a servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the
        new state of the servicechain_instance, as well as the original state
        prior to the update_servicechain_instance call.
        """
        pass

    def delete_servicechain_instance_precommit(self, context):
        """Delete resources for a servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the
        current state of the servicechain_instance,
        prior to the call to delete it.
        """
        pass

    def delete_servicechain_instance_postcommit(self, context):
        """Delete a servicechain_instance.

        :param context: ServiceChainInstanceContext instance describing the
        current state of the servicechain_instance,
        prior to the call to delete it.
        """
        pass