# Copyright 2015, Instituto de Telecomunicacoes - Polo de Aveiro - ATNoG.
# All rights reserved.
#
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
class SteeringDriver(object):

    """Define stable abstract interface for Traffic Steering drivers.

    A steering driver is called on the creation, update, and deletion
    of all Traffic Steering resources. For every event, there are two methods
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

    def create_port_chain_precommit(self, context):
        """Allocate resources for a new port chain.

        :param context: PortChainContext instance describing the new
        port chain.

        Create a new port chain, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_port_chain_postcommit(self, context):
        """Create a port_chain.

        :param context: PortChainContext instance describing the new
        port chain.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_port_chain_precommit(self, context):
        """Update resources of a port chain.

        :param context: PortChainContext instance describing the new
        state of the port chain, as well as the original state prior
        to the update_port_chain call.

        Update values of a port chain, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_port_chain_precommit is called for all changes to the
        port chain state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_port_chain_postcommit(self, context):
        """Update a port chain.

        :param context: PortChainContext instance describing the new
        state of the port chain, as well as the original state prior
        to the update_port_chain call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_port_chain_postcommit is called for all changes to the
        port chain state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_port_chain_precommit(self, context):
        """Delete resources for a port chain.

        :param context: PortChainContext instance describing the current
        state of the port chain, prior to the call to delete it.

        Delete port chain resources previously allocated by this
        mechanism driver for a port chain. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_port_chain_postcommit(self, context):
        """Delete a port chain.

        :param context: PortChainContext instance describing the current
        state of the port chain, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass
