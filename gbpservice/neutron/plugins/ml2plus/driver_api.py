# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
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

from neutron_lib.plugins.ml2 import api as driver_api

BULK_EXTENDED = 'ml2plus:_bulk_extended'


@six.add_metaclass(abc.ABCMeta)
class SubnetPoolContext(object):
    """Context passed to MechanismDrivers for changes to subnet pool
    resources.

    A SubnetPoolContext instance wraps a subnet pool resource. It
    provides helper methods for accessing other relevant
    information. Results from expensive operations are cached so that
    other MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the subnet pool in its current configuration.

        Return the subnet pool with all its properties 'current' at
        the time the context was established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the subnet pool in its original configuration.

        Return the subnet pool, with all its properties set to their
        original values prior to a call to update_address_scope. Method is
        only valid within calls to update_address_scope_precommit and
        update_address_scope_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class AddressScopeContext(object):
    """Context passed to MechanismDrivers for changes to address scope
    resources.

    An AddressScopeContext instance wraps an address scope
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached so that
    other MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the address scope in its current configuration.

        Return the address scope with all its properties 'current' at
        the time the context was established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the address scope in its original configuration.

        Return the address scope, with all its properties set to their
        original values prior to a call to update_address_scope. Method is
        only valid within calls to update_address_scope_precommit and
        update_address_scope_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class SecurityGroupContext(object):
    """Context passed to MechanismDrivers for changes to security group
    resources.

    A SecurityGroupContext instance wraps a security group
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached so that
    other MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the security group in its current configuration.

        Return the security group with all its properties 'current' at
        the time the context was established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the security group in its original configuration.

        Return the security group, with all its properties set to their
        original values prior to a call to update_security_group. Method is
        only valid within calls to update_security_group_precommit and
        update_security_group_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class SecurityGroupRuleContext(object):
    """Context passed to MechanismDrivers for changes to security group
    rule resources.

    A SecurityGroupRuleContext instance wraps a security group rule
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached so that
    other MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the security group rule in its current configuration.

        Return the security group rule with all its properties 'current' at
        the time the context was established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the security group rule in its original configuration.

        Return the security group rule, with all its properties set to their
        original values prior to a call to update_security_group. Method is
        only valid within calls to update_security_group_rule_precommit and
        update_security_group_rule_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class MechanismDriver(driver_api.MechanismDriver):

    # REVISIT(rkukura): Is this needed for all operations, or just for
    # create operations? If its needed for all operations, should the
    # method be specific to the resource and operation, and include
    # the request data (i.e. update_network_pretransaction(self,
    # data))?
    def ensure_tenant(self, plugin_context, tenant_id):
        """Ensure tenant known before creating resource.

        :param plugin_context: Plugin request context.
        :param tenant_id: Tenant owning resource about to be created.

        Called before the start of a transaction creating any new core
        resource, allowing any needed tenant-specific processing to be
        performed.
        """
        pass

    def create_subnetpool_precommit(self, context):
        """Allocate resources for a new subnet pool.

        :param context: SubnetPoolContext instance describing the new
        subnet pool.

        Create a new subnet pool, allocating resources as necessary in
        the database. Called inside transaction context on
        session. Call cannot block.  Raising an exception will result
        in a rollback of the current transaction.
        """
        pass

    def create_subnetpool_postcommit(self, context):
        """Create a subnet pool.

        :param context: SubnetPoolContext instance describing the new
        subnet pool.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_subnetpool_precommit(self, context):
        """Update resources of a subnet pool.

        :param context: SubnetPoolContext instance describing the new
        state of the subnet pool, as well as the original state prior
        to the update_subnetpool call.

        Update values of a subnet pool, updating the associated
        resources in the database. Called inside transaction context
        on session.  Raising an exception will result in rollback of
        the transaction.

        update_subnetpool_precommit is called for all changes to the
        subnet pool state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_subnetpool_postcommit(self, context):
        """Update a subnet pool.

        :param context: SubnetPoolContext instance describing the new
        state of the subnet pool, as well as the original state prior
        to the update_subnetpool call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_subnetpool_postcommit is called for all changes to the
        subnet pool state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_subnetpool_precommit(self, context):
        """Delete resources for a subnet pool.

        :param context: SubnetPoolContext instance describing the
        current state of the subnet pool, prior to the call to delete
        it.

        Delete subnet pool resources previously allocated by this
        mechanism driver for a subnet pool. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_subnetpool_postcommit(self, context):
        """Delete a subnet pool.

        :param context: SubnetPoolContext instance describing the
        current state of the subnet pool, prior to the call to delete
        it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_address_scope_precommit(self, context):
        """Allocate resources for a new address scope.

        :param context: AddressScopeContext instance describing the
        new address scope.

        Create a new address scope, allocating resources as necessary
        in the database. Called inside transaction context on
        session. Call cannot block.  Raising an exception will result
        in a rollback of the current transaction.
        """
        pass

    def create_address_scope_postcommit(self, context):
        """Create an address scope.

        :param context: AddressScopeContext instance describing the
        new address scope.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_address_scope_precommit(self, context):
        """Update resources of an address scope.

        :param context: AddressScopeContext instance describing the
        new state of the address scope, as well as the original state
        prior to the update_address_scope call.

        Update values of an address scope, updating the associated
        resources in the database. Called inside transaction context
        on session.  Raising an exception will result in rollback of
        the transaction.

        update_address_scope_precommit is called for all changes to
        the address scope state. It is up to the mechanism driver to
        ignore state or state changes that it does not know or care
        about.
        """
        pass

    def update_address_scope_postcommit(self, context):
        """Update an address scope.

        :param context: AddressScopeContext instance describing the
        new state of the address scope, as well as the original state
        prior to the update_address_scope call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_address_scope_postcommit is called for all changes to
        the address scope state.  It is up to the mechanism driver to
        ignore state or state changes that it does not know or care
        about.
        """
        pass

    def delete_address_scope_precommit(self, context):
        """Delete resources for an address scope.

        :param context: AddressScopeContext instance describing the
        current state of the address scope, prior to the call to
        delete it.

        Delete address scope resources previously allocated by this
        mechanism driver for an address scope. Called inside
        transaction context on session. Runtime errors are not
        expected, but raising an exception will result in rollback of
        the transaction.
        """
        pass

    def delete_address_scope_postcommit(self, context):
        """Delete an address scope.

        :param context: AddressScopeContext instance describing the
        current state of the address scope, prior to the call to
        delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_security_group_precommit(self, context):
        """Allocate resources for a new security group.

        :param context: SecurityGroupContext instance describing the
        new security group.

        Create a new security group, allocating resources as necessary
        in the database. Called inside transaction context on
        session. Call cannot block.  Raising an exception will result
        in a rollback of the current transaction.
        """
        pass

    def create_security_group_postcommit(self, context):
        """Create a security group.

        :param context: SecurityGroupContext instance describing the
        new security group.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        This API is not being implemented at this moment.
        """
        pass

    def update_security_group_precommit(self, context):
        """Update resources of a security group.

        :param context: SecurityGroupContext instance describing the
        new state of the security group, as well as the original state
        prior to the update_security_group call.

        Update values of an security group, updating the associated
        resources in the database. Called inside transaction context
        on session.  Raising an exception will result in rollback of
        the transaction.

        update_security_group_precommit is called for all changes to
        the security group state. It is up to the mechanism driver to
        ignore state or state changes that it does not know or care
        about.
        """
        pass

    def update_security_group_postcommit(self, context):
        """Update a security group.

        :param context: SecurityGroupContext instance describing the
        new state of the security group, as well as the original state
        prior to the update_security_group call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_security_group_postcommit is called for all changes to
        the security group state.  It is up to the mechanism driver to
        ignore state or state changes that it does not know or care
        about.

        This API is not being implemented at this moment.
        """
        pass

    def delete_security_group_precommit(self, context):
        """Delete resources for a security group.

        :param context: SecurityGroupContext instance describing the
        current state of the security group, prior to the call to
        delete it.

        Delete security group resources previously allocated by this
        mechanism driver for an security group. Called inside
        transaction context on session. Runtime errors are not
        expected, but raising an exception will result in rollback of
        the transaction.
        """
        pass

    def delete_security_group_postcommit(self, context):
        """Delete a security group.

        :param context: SecurityGroupContext instance describing the
        current state of the security group, prior to the call to
        delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.

        This API is not being implemented at this moment.
        """
        pass

    def create_security_group_rule_precommit(self, context):
        """Allocate resources for a new security group.

        :param context: SecurityGroupRuleContext instance describing the
        new security group rule.

        Create a new security group rule, allocating resources as necessary
        in the database. Called inside transaction context on
        session. Call cannot block.  Raising an exception will result
        in a rollback of the current transaction.
        """
        pass

    def create_security_group_rule_postcommit(self, context):
        """Create a security group rule.

        :param context: SecurityGroupRuleContext instance describing the
        new security group rule.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        This API is not being implemented at this moment.
        """
        pass

    # Security group rule updates are not supported by the Neutron API.

    def delete_security_group_rule_precommit(self, context):
        """Delete resources for a security group rule.

        :param context: SecurityGroupRuleContext instance describing the
        current state of the security group rule, prior to the call to
        delete it.

        Delete security group rule resources previously allocated by this
        mechanism driver for an security group rule. Called inside
        transaction context on session. Runtime errors are not
        expected, but raising an exception will result in rollback of
        the transaction.
        """
        pass

    def delete_security_group_rule_postcommit(self, context):
        """Delete a security group rule.

        :param context: SecurityGroupRuleContext instance describing the
        current state of the security group rule, prior to the call to
        delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.

        This API is not being implemented at this moment.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ExtensionDriver(driver_api.ExtensionDriver):

    def process_create_subnetpool(self, plugin_context, data, result):
        """Process extended attributes for create subnet pool.

        :param plugin_context: plugin request context
        :param data: dictionary of incoming subnet pool data
        :param result: subnet pool dictionary to extend

        Called inside transaction context on plugin_context.session to
        validate and persist any extended subnet pool attributes
        defined by this driver. Extended attribute values must also be
        added to result.
        """
        pass

    def process_update_subnetpool(self, plugin_context, data, result):
        """Process extended attributes for update subnet pool.

        :param plugin_context: plugin request context
        :param data: dictionary of incoming subnet pool data
        :param result: subnet pool dictionary to extend

        Called inside transaction context on plugin_context.session to
        validate and update any extended subnet pool attributes
        defined by this driver. Extended attribute values, whether
        updated or not, must also be added to result.
        """
        pass

    def extend_subnetpool_dict(self, session, base_model, result):
        """Add extended attributes to subnet pool dictionary.

        :param session: database session
        :param base_model: subnet pool model data
        :param result: subnet pool dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a subnet pool
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a subnet pool operation.
        """
        pass

    def process_create_address_scope(self, plugin_context, data, result):
        """Process extended attributes for create address scope.

        :param plugin_context: plugin request context
        :param data: dictionary of incoming address scope data
        :param result: address scope dictionary to extend

        Called inside transaction context on plugin_context.session to
        validate and persist any extended address scope attributes
        defined by this driver. Extended attribute values must also be
        added to result.
        """
        pass

    def process_update_address_scope(self, plugin_context, data, result):
        """Process extended attributes for update address scope.

        :param plugin_context: plugin request context
        :param data: dictionary of incoming address scope data
        :param result: address scope dictionary to extend

        Called inside transaction context on plugin_context.session to
        validate and update any extended address scope attributes
        defined by this driver. Extended attribute values, whether
        updated or not, must also be added to result.
        """
        pass

    def extend_address_scope_dict(self, session, base_model, result):
        """Add extended attributes to address scope dictionary.

        :param session: database session
        :param base_model: address scope model data
        :param result: address scope dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to an address scope
        dictionary to be used for mechanism driver calls and/or
        returned as the result of an address scope operation.
        """
        pass
