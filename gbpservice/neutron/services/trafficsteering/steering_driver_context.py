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


class TrafficSteeringContext(object):

    """Context passed to steering engine for TS-related resource changes.

    A TrafficSteeringContext instance generically wraps a Traffic Steering
    resource. It provides helper methods for accessing other relevant
    information. Results from expensive operations are cached for
    convenient access.
    """

    def __init__(self, plugin, plugin_context,
                 updated_resource, original_resource):
        self._plugin = plugin
        self._plugin_context = plugin_context
        self._resource = updated_resource
        self._original_resource = original_resource

    @property
    def current(self):
        """Return the current state of the resource"""

        return self._resource

    @property
    def original(self):
        """Return the original state of the resource.

        Return the original state of the resource, prior to an update call.
        Method is only valid within calls to update_precommit and _postcommit.
        """
        return self._original_resource


class PortChainContext(TrafficSteeringContext):

    def __init__(self, plugin, plugin_context, updated_port_chain,
                 original_port_chain=None):
        super(PortChainContext, self).__init__(plugin, plugin_context,
                                               updated_port_chain,
                                               original_port_chain)
