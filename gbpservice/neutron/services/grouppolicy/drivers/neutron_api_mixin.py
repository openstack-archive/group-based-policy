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

import itertools

from neutron.api.v2 import attributes
from neutron.openstack.common import log as logging

from gbpservice.neutron.tests.unit import common as cm


LOG = logging.getLogger(__name__)
MESSAGE_SG_RULE_EXISTS = "Security group rule already exists."


# Not all attributes are allowed in PUT or POST,
# Remove them if they are not allowed
def remove_not_allowed_attrs(resource, attrs, action):
    allowed_action = 'allow_%s' % action
    resources = cm.get_resource_plural(resource)
    attr_map = attributes.RESOURCE_ATTRIBUTE_MAP[resources]
    not_allowed = []
    for key in attrs:
        if not attr_map[key][allowed_action]:
            not_allowed.append(key)
    for key in not_allowed:
        del attrs[key]
    return attrs


# Unspecified attributes should not be sent over REST or WSGI.
def remove_not_specified_attrs(attrs):
    unspecified = []
    for key in attrs:
        if attrs[key] == attributes.ATTR_NOT_SPECIFIED:
            unspecified.append(key)
    for key in unspecified:
        del attrs[key]
    return attrs


# While plugin APIs support ORing filters, they are not supported in REST APIs
# or WSGI. A combination of these filters have to be generated to emulate the
# ORing behavior.
# For example, filters = {'foo': [a1, a2], 'bar': [b1, b2]} will be mapped to
# a list of filters
# [{'foo': a1, 'bar': b1},
#  {'foo': a1, 'bar': b2},
#  {'foo': a2, 'bar': b1},
#  {'foo': a2, 'bar': b2}]
def get_filter_combinations(filters):
    formatted_filters = {}
    for key, value in filters.iteritems():
        formatted_filters[key] = value if isinstance(value, list) else [value]
    keys = sorted(formatted_filters)
    return [dict(zip(keys, prod)) for prod in
            itertools.product(*(formatted_filters[key] for key in keys))]


class NeutronAPIMixin(object):
    """A Wrapper class of Neutronv2 Client APIs.

    Ideally, we want to call Neutronv2 Client APIs directly in resource mapping
    and other drivers. But there are some existing APIs as previously plugin
    APIs were used, and we need to keep these APIs so we don't need to touch
    too many codes. Later when we clean up the resource mappings, this Mixin
    wrapper should be removed as well.
    """

    def _create_port(self, plugin_context, attrs):
        return self._create_neutron_resource(plugin_context, 'port', attrs)

    def _get_port(self, plugin_context, port_id):
        return self._get_neutron_resource(plugin_context, 'port', port_id)

    def _update_port(self, plugin_context, port_id, attrs):
        return self._update_neutron_resource(
            plugin_context, 'port', port_id, attrs)

    def _delete_port(self, plugin_context, port_id):
        self._delete_neutron_resource(plugin_context, 'port', port_id)

    def _create_subnet(self, plugin_context, attrs):
        return self._create_neutron_resource(plugin_context, 'subnet', attrs)

    def _get_subnet(self, plugin_context, subnet_id):
        return self._get_neutron_resource(plugin_context, 'subnet', subnet_id)

    def _get_subnets(self, plugin_context, filters={}):
        return self._get_neutron_resources(plugin_context, 'subnet', filters)

    def _update_subnet(self, plugin_context, subnet_id, attrs):
        return self._update_neutron_resource(
            plugin_context, 'subnet', subnet_id, attrs)

    def _delete_subnet(self, plugin_context, subnet_id):
        self._delete_neutron_resource(plugin_context, 'subnet', subnet_id)

    def _create_network(self, plugin_context, attrs):
        return self._create_neutron_resource(plugin_context, 'network', attrs)

    def _get_network(self, plugin_context, network_id):
        return self._get_neutron_resource(
            plugin_context, 'network', network_id)

    def _delete_network(self, plugin_context, network_id):
        self._delete_neutron_resource(plugin_context, 'network', network_id)

    def _create_router(self, plugin_context, attrs):
        return self._create_neutron_resource(plugin_context, 'router', attrs)

    def _get_router(self, plugin_context, router_id):
        return self._get_neutron_resource(plugin_context, 'router', router_id)

    def _update_router(self, plugin_context, router_id, attrs):
        return self._update_neutron_resource(
            plugin_context, 'router', router_id, attrs)

    def _delete_router(self, plugin_context, router_id):
        self._delete_neutron_resource(plugin_context, 'router', router_id)

    def _add_router_interface(self, plugin_context, router_id, interface):
        self._neutron.add_router_interface(
            plugin_context, router_id, interface)

    def _remove_router_interface(self, plugin_context, router_id, interface):
        self._neutron.remove_router_interface(
            plugin_context, router_id, interface)

    def _add_router_gw_interface(self, plugin_context, router_id, gw_info):
        return self._update_router(
            plugin_context, router_id, {'external_gateway_info': gw_info})

    def _remove_router_gw_interface(
            self, plugin_context, router_id, interface_info):
        # TODO(yi): the logic is wrong. should do a - operation and
        # update the router with the rest of the GW interfaces
        self._update_router(
            plugin_context, router_id, {'external_gateway_info': None})

    def _create_sg(self, plugin_context, attrs):
        return self._create_neutron_resource(
            plugin_context, 'security_group', attrs)

    def _get_sg(self, plugin_context, sg_id):
        return self._get_neutron_resource(
            plugin_context, 'security_group', sg_id)

    def _get_sgs(self, plugin_context, filters={}):
        return self._get_neutron_resources(
            plugin_context, 'security_group', filters)

    def _update_sg(self, plugin_context, sg_id, attrs):
        return self._update_neutron_resource(
            plugin_context, 'security_group', sg_id, attrs)

    def _delete_sg(self, plugin_context, sg_id):
        self._delete_neutron_resource(
            plugin_context, 'security_group', sg_id)

    def _create_sg_rule(self, plugin_context, attrs):
        return self._create_neutron_resource(
            plugin_context, 'security_group_rule', attrs)

    def _get_sg_rule(self, plugin_context, sg_rule_id):
        return self._get_neutron_resource(
            plugin_context, 'security_group_rule', sg_rule_id)

    def _get_sg_rules(self, plugin_context, filters={}):
        return self._get_neutron_resources(
            plugin_context, 'security_group_rule', filters)

    # REVISIT(yi): update_security_group_rule not supported in neutron yet
    # def _update_security_group_rule(self, plugin_context, sg_rule_id, attrs):
    #     return self._update_neutron_resource(
    #         plugin_context, 'security_group_rule', sg_rule_id, attrs)

    def _delete_sg_rule(self, plugin_context, sg_rule_id):
        self._delete_neutron_resource(
            plugin_context, 'security_group_rule', sg_rule_id)

    def _create_neutron_resource(self, context, resource, attrs):
        attrs = remove_not_specified_attrs(attrs)
        attrs = remove_not_allowed_attrs(resource, attrs, 'post')
        action = 'create_' + resource
        obj_creator = getattr(self._neutron, action)
        obj = obj_creator(context, {resource: attrs})
        return obj

    def _get_neutron_resource(self, context, resource, resource_id):
        obj_getter = getattr(self._neutron, 'show_' + resource)
        obj = obj_getter(context, resource_id)
        return obj

    def _get_neutron_resources(self, context, resource, filters={}):
        # REST APIs does not support ORing filtering
        # Has to handle the combination of filters instead
        filter_list = get_filter_combinations(filters)
        resources = cm.get_resource_plural(resource)
        obj_getter = getattr(self._neutron, 'list_' + resources)
        res = []
        for filter in filter_list:
            obj = obj_getter(context, filter)
            # merge the result and remove the duplicate
            res.extend(x for x in obj if x not in res)
        return res

    def _update_neutron_resource(self, context, resource, resource_id, attrs):
        attrs = remove_not_specified_attrs(attrs)
        attrs = remove_not_allowed_attrs(resource, attrs, 'put')
        action = 'update_' + resource
        obj_updater = getattr(self._neutron, action)
        obj = obj_updater(context, resource_id, {resource: attrs})
        return obj

    def _delete_neutron_resource(self, context, resource, resource_id):
        action = 'delete_' + resource
        obj_deleter = getattr(self._neutron, action)
        obj_deleter(context, resource_id)