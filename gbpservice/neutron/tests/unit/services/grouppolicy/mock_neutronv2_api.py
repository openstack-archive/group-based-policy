# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import mock

from gbpservice.neutron.services.grouppolicy.drivers import resource_mapping


# Based on the resource types, Neutron REST API calls need to be patched to
# different neutron-plugins,
PLUGIN_MAP = {
    'network': '_core_plugin',
    'subnet': '_core_plugin',
    'port': '_core_plugin',
    'security_group': '_core_plugin',
    'security_group_rule': '_core_plugin',
    'router': '_l3_plugin',
}


# Rather than patching all the test methods with these mocked API calls,
# use a meta_mock instead
def meta_mock(func):
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_create_neutron_resource',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_get_neutron_resource',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_get_neutron_resources',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_update_neutron_resource',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_delete_neutron_resource',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_add_router_interface',
                       autospec=True)
    @mock.patch.object(resource_mapping.ResourceMappingDriver,
                       '_remove_router_interface',
                       autospec=True)
    def inner(*args):
        #obj = args[0]
        args[-1].side_effect = _patched_create_resource
        args[-2].side_effect = _patched_get_resource
        args[-3].side_effect = _patched_get_resources
        args[-4].side_effect = _patched_update_resource
        args[-5].side_effect = _patched_delete_resource
        args[-6].side_effect = _patched_add_router_interface
        args[-7].side_effect = _patched_remove_router_interface
        return func(*args[:-7])

    return inner


# Indirect calls through Neutron REST APIs are patched as direct calls
# with using neutron core plugin or l3 plugin
def _patched_create_resource(obj, context, resource, attrs):
    return obj._create_resource(
        getattr(obj, PLUGIN_MAP[resource]), context, resource, attrs
    )


def _patched_get_resource(obj, context, resource, resource_id):
    return obj._get_resource(
        getattr(obj, PLUGIN_MAP[resource]), context, resource, resource_id
    )


def _patched_get_resources(obj, context, resource, filters={}):
    return obj._get_resources(
        getattr(obj, PLUGIN_MAP[resource]), context, resource, filters
    )


def _patched_update_resource(obj, context,
                             resource, resource_id, attrs):
    return obj._update_resource(getattr(obj, PLUGIN_MAP[resource]),
                                context,
                                resource,
                                resource_id,
                                attrs)


def _patched_delete_resource(obj, context, resource, resource_id):
    obj._delete_resource(
        getattr(obj, PLUGIN_MAP[resource]), context, resource, resource_id
    )


def _patched_add_router_interface(obj, context, router_id, interface):
    obj._l3_plugin.add_router_interface(context, router_id, interface)


def _patched_remove_router_interface(obj, context, router_id, interface):
    obj._l3_plugin.remove_router_interface(context, router_id, interface)