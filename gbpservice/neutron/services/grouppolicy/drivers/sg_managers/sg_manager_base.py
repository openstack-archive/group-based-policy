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

import netaddr
from neutron.common import constants as const
from neutron import context as ncontext
from neutron import manager

from gbpservice.common import utils
from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.extensions import group_policy as gpolicy


class SecurityGroupManagerBase(object):
    """Manages PRS mapping to Security Groups.

    Rule composition is the most critical component of the GBP Resource Mapping
    Driver. Translating the user intent into Security Group rules require
    a great automation effort. This class defines an API that exposes
    APIs used to react to certain events by modifying the Security Groups
    properly.
    """
    valid_ops = ('create', 'update', 'delete')
    valid_prefixes = ('handle', 'validate')

    @property
    def _core_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _gbp_plugin(self):
        return manager.NeutronManager.get_service_plugins().get("GROUP_POLICY")

    @property
    def _admin_context(self):
        return ncontext.get_admin_context()

    def __getattr__(self, item):
        """ Default method behavior.

        To avoid managers implementing all the methods even when not needed,
        as well as avoiding code replication whenever a new resource is added
        to GBP.
        """
        def _is_gbp_resource(resource):
            return (utils.get_resource_plural(resource) in
                    gpolicy.RESOURCE_ATTRIBUTE_MAP)
        split = item.split('_')
        if split and (split[0] in self.valid_prefixes) and (split[-1] in
                                                            self.valid_ops):
            resource = '_'.join(split[1:-1])
            if _is_gbp_resource(resource):
                return self.default

        raise AttributeError

    def default(self, *args, **kwargs):
        pass

    def initialize(self, gbp_driver):
        """ Initialization Method

        None of the below methods will be called before this one.
        """
        self._gbp_driver = gbp_driver

    def _sg_rule(self, plugin_context, tenant_id, sg_id, direction,
                 protocol=None, port_range=None, cidr=None, remote_sg=None,
                 unset=False, ethertype=None):
        versions = {4: const.IPv4, 6: const.IPv6}
        if port_range:
            port_min, port_max = (gpdb.GroupPolicyDbPlugin.
                                  _get_min_max_ports_from_range(port_range))
        else:
            port_min, port_max = None, None

        attrs = {'tenant_id': tenant_id,
                 'security_group_id': sg_id,
                 'direction': direction,
                 'ethertype': str(ethertype or versions[
                     netaddr.IPNetwork(cidr).version]),
                 'protocol': protocol,
                 'port_range_min': port_min,
                 'port_range_max': port_max,
                 'remote_ip_prefix': cidr,
                 'remote_group_id': remote_sg}
        if unset:
            filters = {}
            for key in attrs:
                value = attrs[key]
                if value:
                    filters[key] = [value]
            rule = self._core_plugin.get_security_group_rules(
                plugin_context, filters)
            if rule:
                self._gbp_driver._delete_sg_rule(plugin_context, rule[0]['id'])
        else:
            return self._gbp_driver._create_sg_rule(plugin_context, attrs)

    def _get_enforced_prs_rules(self, context, prs, subset=None):
        subset = subset or prs['policy_rules']
        if prs['parent_id']:
            parent = context._plugin.get_policy_rule_set(
                context._plugin_context, prs['parent_id'])
            parent_policy_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': parent['policy_rules']})
            subset_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': subset})
            parent_classifier_ids = [x['policy_classifier_id']
                                     for x in parent_policy_rules]
            policy_rules = [x['id'] for x in subset_rules
                            if x['policy_classifier_id']
                            in set(parent_classifier_ids)]
            return context._plugin.get_policy_rules(
                context._plugin_context,
                {'id': policy_rules})
        else:
            return context._plugin.get_policy_rules(
                context._plugin_context, {'id': set(subset)})

    def _recompute_policy_rule_sets(self, context, children):
        # Rules in child but not in parent shall be removed
        # Child rules will be set after being filtered by the parent
        for child in children:
            child = context._plugin.get_policy_rule_set(
                context._plugin_context, child)
            child_rule_ids = set(child['policy_rules'])
            if child['parent_id']:
                parent = context._plugin.get_policy_rule_set(
                    context._plugin_context, child['parent_id'])
                parent_policy_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': parent['policy_rules']})
                child_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': child['policy_rules']})
                parent_classifier_ids = [x['policy_classifier_id']
                                     for x in parent_policy_rules]
                delta_rules = [x['id'] for x in child_rules
                               if x['policy_classifier_id']
                               not in set(parent_classifier_ids)]
                delta_rules = context._plugin.get_policy_rules(
                                context._plugin_context, {'id': delta_rules})
                self._remove_policy_rule_set_rules(context, child, delta_rules)
            # Old parent may have filtered some rules, need to add them again.
            # Being the l3p_id not specified, this will affect all the SGs
            # associated with the child.
            child_rules = context._plugin.get_policy_rules(
                context._plugin_context, filters={'id': child_rule_ids})
            cidr_mapping = self._get_cidrs_mapping(context, child)
            self._apply_policy_rule_set_rules(context, child, child_rules,
                                              cidr_mapping)

    def _create_policy_rule_set_sg(self, plugin_context, prs, sg_name_prefix,
                                   l3p_id, tenant_id):
        # This method sets up the attributes of security group
        attrs = {'tenant_id': tenant_id or prs['tenant_id'],
                 'name': sg_name_prefix + '_' + prs['name'] + (
                     '_' + l3p_id) if l3p_id else '',
                 'description': '',
                 'security_group_rules': ''}
        sg = self._gbp_driver._create_sg(plugin_context, attrs)
        # Cleanup default rules
        for rule in self._core_plugin.get_security_group_rules(
                plugin_context, filters={'security_group_id': [sg['id']]}):
            self._core_plugin.delete_security_group_rule(
                plugin_context, rule['id'])
        return sg
