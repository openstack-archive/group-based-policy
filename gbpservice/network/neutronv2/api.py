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

from gbpservice.network.neutronv2 import client


class API(object):
    """API for interacting with the neutron 2.x API."""

    def _create_resource(self, context, resource, attrs):
        action = 'create_' + resource
        neutron = client.get_client(context)
        obj_creator = getattr(neutron, action)
        return obj_creator(attrs)[resource]

    def _show_resource(self, context, resource, resource_id):
        action = 'show_' + resource
        neutron = client.get_client(context)
        obj_method = getattr(neutron, action)
        return obj_method(resource_id)[resource]

    def _list_resources(self, context, resource, filters=None):
        filters = filters or {}
        resources = resource + 's'
        action = 'list_' + resources
        neutron = client.get_client(context)
        obj_lister = getattr(neutron, action)
        return obj_lister(**filters)[resources]

    def _update_resource(self, context, resource, resource_id, attrs):
        action = 'update_' + resource
        neutron = client.get_client(context)
        obj_updater = getattr(neutron, action)
        return obj_updater(resource_id, attrs)[resource]

    def _delete_resource(self, context, resource, resource_id):
        action = 'delete_' + resource
        neutron = client.get_client(context)
        obj_deleter = getattr(neutron, action)
        obj_deleter(resource_id)

    def create_network(self, context, network):
        return self._create_resource(context, 'network', network)

    def show_network(self, context, net_id):
        return self._show_resource(context, 'network', net_id)

    def list_networks(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'network', filters)

    def update_network(self, context, net_id, network):
        return self._update_resource(context, 'network', net_id, network)

    def delete_network(self, context, net_id):
        self._delete_resource(context, 'network', net_id)

    def create_subnet(self, context, subnet):
        return self._create_resource(context, 'subnet', subnet)

    def show_subnet(self, context, subnet_id):
        return self._show_resource(context, 'subnet', subnet_id)

    def list_subnets(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'subnet', filters)

    def update_subnet(self, context, subnet_id, subnet):
        return self._update_resource(context, 'subnet', subnet_id, subnet)

    def delete_subnet(self, context, subnet_id):
        self._delete_resource(context, 'subnet', subnet_id)

    def create_port(self, context, port):
        return self._create_resource(context, 'port', port)

    def show_port(self, context, port_id):
        return self._show_resource(context, 'port', port_id)

    def list_ports(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'port', filters)

    def update_port(self, context, port_id, port):
        return self._update_resource(context, 'port', port_id, port)

    def delete_port(self, context, port_id):
        self._delete_resource(context, 'port', port_id)

    def create_security_group(self, context, sg):
        return self._create_resource(context, 'security_group', sg)

    def show_security_group(self, context, sg_id):
        return self._show_resource(context, 'security_group', sg_id)

    def list_security_groups(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'security_group', filters)

    def update_security_group(self, context, sg_id, sg):
        return self._update_resource(context, 'security_group', sg_id, sg)

    def delete_security_group(self, context, sg_id):
        self._delete_resource(context, 'security_group', sg_id)

    def create_security_group_rule(self, context, rule):
        return self._create_resource(context, 'security_group_rule', rule)

    def show_security_group_rule(self, context, rule_id):
        return self._show_resource(context, 'security_group_rule', rule_id)

    def list_security_group_rules(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'security_group_rule', filters)

    # REVISIT(yi): update_security_group_rule not supported in neutron yet
    # def update_security_group_rule(self, context, rule_id, rule):
    #     return self._update_resource(context,
    #                                  'security_group_rule',
    #                                  rule_id,
    #                                  rule)

    def delete_security_group_rule(self, context, rule_id):
        self._delete_resource(context, 'security_group_rule', rule_id)

    def create_router(self, context, router):
        return self._create_resource(context, 'router', router)

    def show_router(self, context, router_id):
        return self._show_resource(context, 'router', router_id)

    def list_routers(self, context, filters=None):
        filters = filters or {}
        return self._list_resources(context, 'router', filters)

    def update_router(self, context, router_id, router):
        return self._update_resource(context, 'router', router_id, router)

    def delete_router(self, context, router_id):
        self._delete_resource(context, 'router', router_id)

    def add_router_interface(self, context, router_id, interface):
        return client.get_client(context).add_interface_router(router_id,
                                                               interface)

    def remove_router_interface(self, context, router_id, interface):
        return client.get_client(context).remove_interface_router(router_id,
                                                                  interface)
