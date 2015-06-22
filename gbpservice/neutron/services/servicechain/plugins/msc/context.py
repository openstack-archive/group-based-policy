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


class ServiceChainContext(object):
    """ServiceChain context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class ServiceChainNodeContext(ServiceChainContext):

    def __init__(self, plugin, plugin_context, sc_node,
                 original_sc_node=None):
        super(ServiceChainNodeContext, self).__init__(plugin, plugin_context)
        self._sc_node = sc_node
        self._profile = None
        if self._sc_node['service_profile_id']:
            self._profile = self._plugin.get_service_profile(
                self._plugin_context, self._sc_node['service_profile_id'])

        self._original_sc_node = original_sc_node
        self._original_profile = None
        if (self._original_sc_node and
                self._original_sc_node['service_profile_id']):
            self._original_profile = self._plugin.get_service_profile(
                self._plugin_context,
                self._original_sc_node['service_profile_id'])

    @property
    def current(self):
        return self._sc_node

    @property
    def original(self):
        return self._original_sc_node

    @property
    def current_profile(self):
        return self._profile

    @property
    def original_profile(self):
        return self._original_profile


class ServiceChainSpecContext(ServiceChainContext):

    def __init__(self, plugin, plugin_context, sc_spec,
                 original_sc_spec=None):
        super(ServiceChainSpecContext, self).__init__(plugin, plugin_context)
        self._sc_spec = sc_spec
        self._original_sc_spec = original_sc_spec

    @property
    def current(self):
        return self._sc_spec

    @property
    def original(self):
        return self._original_sc_spec


class ServiceChainInstanceContext(ServiceChainContext):

    def __init__(self, plugin, plugin_context, sc_instance,
                 original_sc_instance=None):
        super(ServiceChainInstanceContext, self).__init__(plugin,
                                                          plugin_context)
        self._sc_instance = sc_instance
        self._original_sc_instance = original_sc_instance

    @property
    def current(self):
        return self._sc_instance

    @property
    def original(self):
        return self._original_sc_instance


class ServiceProfileContext(ServiceChainContext):

    def __init__(self, plugin, plugin_context, profile,
                 original_profile=None):
        super(ServiceProfileContext, self).__init__(plugin, plugin_context)
        self._profile = profile
        self._original_profile = original_profile

    @property
    def current(self):
        return self._profile

    @property
    def original(self):
        return self._original_profile
