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

from neutron.plugins.ml2 import driver_api


@six.add_metaclass(abc.ABCMeta)
class MechanismDriver(driver_api.MechanismDriver):

    # REVISIT(rkukura): Should this be a general pre-transaction
    # callout for all operations/resources?
    def ensure_tenant(self, plugin_context, tenant_id):
        """Ensure tenant known before creating resource.

        :param plugin_context: Plugin request context.
        :param tenant_id: Tenant owning resource about to be created.

        Called before the start of a transaction creating any new core
        resource, allowing any needed tenant-specific processing to be
        performed.
        """
        pass

    # TODO(rkukura): Add precommit/postcommit calls for address_scope,
    # subnet_pool, and other resources.


# TODO(rkukura): Extend ExtensionDriver for address_scope,
# subnet_pool, and other resources.
