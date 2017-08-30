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

from neutron.plugins.ml2 import driver_context as ml2_context

from gbpservice.neutron.plugins.ml2plus import driver_api as api


class SubnetPoolContext(ml2_context.MechanismDriverContext,
                        api.SubnetPoolContext):

    def __init__(self, plugin, plugin_context, subnetpool,
                 original_subnetpool=None):
        super(SubnetPoolContext, self).__init__(plugin, plugin_context)
        self._subnetpool = subnetpool
        self._original_subnetpool = original_subnetpool

    @property
    def current(self):
        return self._subnetpool

    @property
    def original(self):
        return self._original_subnetpool


class AddressScopeContext(ml2_context.MechanismDriverContext,
                          api.AddressScopeContext):

    def __init__(self, plugin, plugin_context, address_scope,
                 original_address_scope=None):
        super(AddressScopeContext, self).__init__(plugin, plugin_context)
        self._address_scope = address_scope
        self._original_address_scope = original_address_scope

    @property
    def current(self):
        return self._address_scope

    @property
    def original(self):
        return self._original_address_scope


class SecurityGroupContext(ml2_context.MechanismDriverContext,
                           api.SecurityGroupContext):

    def __init__(self, plugin, plugin_context, security_group,
                 original_security_group=None):
        super(SecurityGroupContext, self).__init__(plugin, plugin_context)
        self._security_group = security_group
        self._original_security_group = original_security_group

    @property
    def current(self):
        return self._security_group

    @property
    def original(self):
        return self._original_security_group


class SecurityGroupRuleContext(ml2_context.MechanismDriverContext,
                               api.SecurityGroupRuleContext):

    def __init__(self, plugin, plugin_context, security_group_rule,
                 original_security_group_rule=None):
        super(SecurityGroupRuleContext, self).__init__(plugin, plugin_context)
        self._security_group_rule = security_group_rule
        self._original_security_group_rule = original_security_group_rule

    @property
    def current(self):
        return self._security_group_rule

    @property
    def original(self):
        return self._original_security_group_rule
