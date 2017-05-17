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

from neutron_lib import constants
from neutron_lib.plugins import directory

from gbpservice.common import utils
from gbpservice.neutron.services.grouppolicy.drivers import resource_mapping
from gbpservice.neutron.services.servicechain.plugins.ncp import model


def get_gbp_plugin():
    return directory.get_plugin("GROUP_POLICY")


def get_node_driver_context(sc_plugin, context, sc_instance,
                            current_node, original_node=None,
                            management_group=None, service_targets=None):
    admin_context = utils.admin_context(context)
    specs = sc_plugin.get_servicechain_specs(
        admin_context, filters={'id': sc_instance['servicechain_specs']})
    position = _calculate_node_position(specs, current_node['id'])
    provider, _ = _get_ptg_or_ep(
        admin_context, sc_instance['provider_ptg_id'])
    consumer, is_consumer_external = _get_ptg_or_ep(
        admin_context, sc_instance['consumer_ptg_id'])
    management, _ = _get_ptg_or_ep(admin_context,
                                   sc_instance['management_ptg_id'])
    classifier = get_gbp_plugin().get_policy_classifier(
        admin_context, sc_instance['classifier_id'])
    current_profile = sc_plugin.get_service_profile(
        admin_context, current_node['service_profile_id'])
    original_profile = sc_plugin.get_service_profile(
        admin_context,
        original_node['service_profile_id']) if original_node else None
    if not service_targets:
        service_targets = model.get_service_targets(
            admin_context.session, servicechain_instance_id=sc_instance['id'],
            position=position, servicechain_node_id=current_node['id'])

    return NodeDriverContext(sc_plugin=sc_plugin,
                             context=context,
                             service_chain_instance=sc_instance,
                             service_chain_specs=specs,
                             current_service_chain_node=current_node,
                             current_service_profile=current_profile,
                             provider_group=provider,
                             consumer_group=consumer,
                             management_group=management,
                             original_service_chain_node=original_node,
                             original_service_profile=original_profile,
                             service_targets=service_targets,
                             position=position,
                             classifier=classifier,
                             is_consumer_external=is_consumer_external)


def _get_ptg_or_ep(context, group_id):
    if group_id == resource_mapping.SCI_CONSUMER_NOT_AVAILABLE:
        return None, False
    group = None
    is_group_external = False
    # skipping policy target group status call to avoid loop while
    # getting servicechain instance status
    fields = ['consumed_policy_rule_sets', 'description',
              'enforce_service_chains', 'id', 'l2_policy_id', 'name',
              'network_service_policy_id', 'policy_targets',
              'provided_policy_rule_sets', 'proxied_group_id',
              'proxy_group_id', 'proxy_type', 'service_management', 'shared',
              'subnets', 'tenant_id']
    if group_id:
        groups = get_gbp_plugin().get_policy_target_groups(
                                    context, filters = {'id': [group_id]},
                                    fields = fields)
        if not groups:
            groups = get_gbp_plugin().get_external_policies(
                                    context, filters = {'id': [group_id]})
            if groups:
                is_group_external = True
        if groups:
            group = groups[0]

    return (group, is_group_external)


def _calculate_node_position(specs, node_id):
    for spec in specs:
        pos = 0
        for node in spec['nodes']:
            pos += 1
            if node_id == node:
                return pos


class NodeDriverContext(object):
    """Context passed down to NCP Node Drivers."""

    def __init__(self, sc_plugin, context, service_chain_instance,
                 service_chain_specs, current_service_chain_node, position,
                 current_service_profile, provider_group, consumer_group=None,
                 management_group=None, original_service_chain_node=None,
                 original_service_profile=None, service_targets=None,
                 classifier=None, is_consumer_external=False):
        self._gbp_plugin = get_gbp_plugin()
        self._sc_plugin = sc_plugin
        self._plugin_context = context
        self._admin_context = None
        self._service_chain_instance = service_chain_instance
        self._current_service_chain_node = current_service_chain_node
        self._current_service_profile = current_service_profile
        self._original_service_chain_node = original_service_chain_node
        self._original_service_profile = original_service_profile
        self._service_targets = service_targets
        self._service_chain_specs = service_chain_specs
        self._provider_group = provider_group
        self._consumer_group = consumer_group
        self._management_group = management_group
        self._classifier = classifier
        self._is_consumer_external = is_consumer_external
        self._relevant_specs = None
        self._core_plugin = directory.get_plugin()
        self._l3_plugin = directory.get_plugin(constants.L3)
        self._position = position

    @property
    def gbp_plugin(self):
        return self._gbp_plugin

    @property
    def sc_plugin(self):
        return self._sc_plugin

    @property
    def core_plugin(self):
        return self._core_plugin

    @property
    def l3_plugin(self):
        return self._l3_plugin

    @property
    def plugin_context(self):
        return self._plugin_context

    @property
    def plugin_session(self):
        return self._plugin_context.session

    @property
    def session(self):
        return self.plugin_session

    @property
    def admin_context(self):
        if not self._admin_context:
            self._admin_context = utils.admin_context(self.plugin_context)
        return self._admin_context

    @property
    def admin_session(self):
        return self.admin_context.session

    @property
    def instance(self):
        return self._service_chain_instance

    @property
    def current_node(self):
        return self._current_service_chain_node

    @property
    def current_profile(self):
        return self._current_service_profile

    @property
    def current_position(self):
        return self._position

    @property
    def original_node(self):
        return self._original_service_chain_node

    @property
    def original_profile(self):
        return self._original_service_profile

    @property
    def is_consumer_external(self):
        return self._is_consumer_external

    @property
    def relevant_specs(self):
        """Get specs on the SCI containing this particular Node."""
        if not self._relevant_specs:
            self._relevant_specs = [x for x in self._service_chain_specs if
                                    self.current_node['id'] in x['nodes']]
        return self._relevant_specs

    @property
    def provider(self):
        return self._provider_group

    @property
    def consumer(self):
        return self._consumer_group

    @property
    def management(self):
        return self._management_group

    @property
    def classifier(self):
        return self._classifier

    def get_service_targets(self, update=False):
        """ Returns the service targets assigned for this service if any.
        The result looks like the following:
        {
            "provider": [pt_uuids],
            "consumer": [pt_uuids],
            "management": [pt_uuids],
        }
        """
        if update:
            self._service_targets = model.get_service_targets(
                self.session, servicechain_instance_id=self.instance['id'],
                position=self.current_position,
                servicechain_node_id=self.current_node['id'])
        return self._service_targets
