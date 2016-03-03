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

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.extensions import l3
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.plugins.common import constants as pconst
from oslo_config import cfg
from oslo_log import log as logging

from gbpservice.common import utils
from gbpservice.neutron.extensions import group_policy as gp_ext
from gbpservice.neutron.extensions import servicechain as sc_ext
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc

LOG = logging.getLogger(__name__)


class LocalAPI(object):
    """API for interacting with the neutron Plugins directly."""

    @property
    def _nova_notifier(self):
        return nova.Notifier()

    @property
    def _core_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _l3_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        l3_plugin = plugins.get(pconst.L3_ROUTER_NAT)
        if not l3_plugin:
            LOG.error(_("No L3 router service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return l3_plugin

    @property
    def _group_policy_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        group_policy_plugin = plugins.get(pconst.GROUP_POLICY)
        if not group_policy_plugin:
            LOG.error(_("No GroupPolicy service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return group_policy_plugin

    @property
    def _servicechain_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        if not servicechain_plugin:
            LOG.error(_("No Servicechain service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return servicechain_plugin

    @property
    def _dhcp_agent_notifier(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store notifier.
        if not self._cached_agent_notifier:
            agent_notifiers = getattr(self._core_plugin, 'agent_notifiers', {})
            self._cached_agent_notifier = (
                agent_notifiers.get(const.AGENT_TYPE_DHCP) or
                dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        return self._cached_agent_notifier

    def _create_resource(self, plugin, context, resource, attrs,
                         do_notify=True):
        # REVISIT(rkukura): Do create.start notification?
        # REVISIT(rkukura): Check authorization?
        # REVISIT(rkukura): Do quota?
        with utils.clean_session(context.session):
            action = 'create_' + resource
            obj_creator = getattr(plugin, action)
            obj = obj_creator(context, {resource: attrs})
            if do_notify:
                self._nova_notifier.send_network_change(action, {},
                                                        {resource: obj})
                # REVISIT(rkukura): Do create.end notification?
                if cfg.CONF.dhcp_agent_notification:
                    self._dhcp_agent_notifier.notify(context,
                                                     {resource: obj},
                                                     resource + '.create.end')
        return obj

    def _update_resource(self, plugin, context, resource, resource_id, attrs,
                         do_notify=True):
        # REVISIT(rkukura): Do update.start notification?
        # REVISIT(rkukura): Check authorization?
        with utils.clean_session(context.session):
            obj_getter = getattr(plugin, 'get_' + resource)
            orig_obj = obj_getter(context, resource_id)
            action = 'update_' + resource
            obj_updater = getattr(plugin, action)
            obj = obj_updater(context, resource_id, {resource: attrs})
            if do_notify:
                self._nova_notifier.send_network_change(action, orig_obj,
                                                        {resource: obj})
                # REVISIT(rkukura): Do update.end notification?
                if cfg.CONF.dhcp_agent_notification:
                    self._dhcp_agent_notifier.notify(context,
                                                     {resource: obj},
                                                     resource + '.update.end')
        return obj

    def _delete_resource(self, plugin, context, resource, resource_id,
                         do_notify=True):
        # REVISIT(rkukura): Do delete.start notification?
        # REVISIT(rkukura): Check authorization?
        with utils.clean_session(context.session):
            obj_getter = getattr(plugin, 'get_' + resource)
            obj = obj_getter(context, resource_id)
            action = 'delete_' + resource
            obj_deleter = getattr(plugin, action)
            obj_deleter(context, resource_id)
            if do_notify:
                self._nova_notifier.send_network_change(action, {},
                                                        {resource: obj})
                # REVISIT(rkukura): Do delete.end notification?
                if cfg.CONF.dhcp_agent_notification:
                    self._dhcp_agent_notifier.notify(context,
                                                     {resource: obj},
                                                     resource + '.delete.end')

    def _get_resource(self, plugin, context, resource, resource_id):
        with utils.clean_session(context.session):
            obj_getter = getattr(plugin, 'get_' + resource)
            obj = obj_getter(context, resource_id)
        return obj

    def _get_resources(self, plugin, context, resource_plural, filters=None):
        with utils.clean_session(context.session):
            obj_getter = getattr(plugin, 'get_' + resource_plural)
            obj = obj_getter(context, filters)
        return obj

    # The following methods perform the necessary subset of
    # functionality from neutron.api.v2.base.Controller.
    #
    # REVISIT(rkukura): Can we just use the WSGI Controller?  Using
    # neutronclient is also a possibility, but presents significant
    # issues to unit testing as well as overhead and failure modes.

    def _get_port(self, plugin_context, port_id):
        return self._get_resource(self._core_plugin, plugin_context, 'port',
                                  port_id)

    def _get_ports(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context, 'ports',
                                   filters)

    def _create_port(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context, 'port',
                                     attrs)

    def _update_port(self, plugin_context, port_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context, 'port',
                                     port_id, attrs)

    def _delete_port(self, plugin_context, port_id):
        try:
            self._delete_resource(self._core_plugin,
                                  plugin_context, 'port', port_id)
        except n_exc.PortNotFound:
            LOG.warn(_('Port %s already deleted'), port_id)

    def _get_subnet(self, plugin_context, subnet_id):
        return self._get_resource(self._core_plugin, plugin_context, 'subnet',
                                  subnet_id)

    def _get_subnets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context,
                                   'subnets', filters)

    def _create_subnet(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'subnet', attrs)

    def _update_subnet(self, plugin_context, subnet_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'subnet', subnet_id, attrs)

    def _delete_subnet(self, plugin_context, subnet_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context, 'subnet',
                                  subnet_id)
        except n_exc.SubnetNotFound:
            LOG.warn(_('Subnet %s already deleted'), subnet_id)

    def _get_network(self, plugin_context, network_id):
        return self._get_resource(self._core_plugin, plugin_context, 'network',
                                  network_id)

    def _get_networks(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'networks', filters)

    def _create_network(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'network', attrs)

    def _delete_network(self, plugin_context, network_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'network', network_id)
        except n_exc.NetworkNotFound:
            LOG.warn(_('Network %s already deleted'), network_id)

    def _get_router(self, plugin_context, router_id):
        return self._get_resource(self._l3_plugin, plugin_context, 'router',
                                  router_id)

    def _get_routers(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._l3_plugin, plugin_context, 'routers',
                                   filters)

    def _create_router(self, plugin_context, attrs):
        return self._create_resource(self._l3_plugin, plugin_context, 'router',
                                     attrs)

    def _update_router(self, plugin_context, router_id, attrs):
        return self._update_resource(self._l3_plugin, plugin_context, 'router',
                                     router_id, attrs)

    def _add_router_interface(self, plugin_context, router_id, interface_info):
        self._l3_plugin.add_router_interface(plugin_context,
                                             router_id, interface_info)

    def _remove_router_interface(self, plugin_context, router_id,
                                 interface_info):
        # To detach Router interface either port ID or Subnet ID is mandatory
        key = 'port_id' if 'port_id' in interface_info else 'subnet_id'
        fixed_ips_filter = {key: [interface_info.get(key)]}
        filters = {'device_id': [router_id],
                   'fixed_ips': fixed_ips_filter}
        ports = self._get_ports(plugin_context, filters=filters)

        try:
            self._l3_plugin.remove_router_interface(plugin_context, router_id,
                                                    interface_info)
        except l3.RouterInterfaceNotFoundForSubnet:
            LOG.warn(_('Router interface already deleted for subnet %s'),
                     interface_info)
            return
        else:
            # The DHCP agent is not getting this event for the router
            # interface port delete triggered by L3 Plugin. So we are
            # sending the notification here
            if cfg.CONF.dhcp_agent_notification and ports:
                self._dhcp_agent_notifier.notify(plugin_context,
                                                 {'port': ports[0]},
                                                 'port' + '.delete.end')

    def _add_router_gw_interface(self, plugin_context, router_id, gw_info):
        return self._l3_plugin.update_router(
            plugin_context, router_id,
            {'router': {'external_gateway_info': gw_info}})

    def _remove_router_gw_interface(self, plugin_context, router_id,
                                    interface_info):
        self._l3_plugin.update_router(
            plugin_context, router_id,
            {'router': {'external_gateway_info': None}})

    def _delete_router(self, plugin_context, router_id):
        try:
            self._delete_resource(self._l3_plugin, plugin_context, 'router',
                                  router_id)
        except l3.RouterNotFound:
            LOG.warn(_('Router %s already deleted'), router_id)

    def _get_sg(self, plugin_context, sg_id):
        return self._get_resource(
            self._core_plugin, plugin_context, 'security_group', sg_id)

    def _get_sgs(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'security_groups', filters)

    def _create_sg(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'security_group', attrs)

    def _update_sg(self, plugin_context, sg_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'security_group', sg_id, attrs)

    def _delete_sg(self, plugin_context, sg_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'security_group', sg_id)
        except ext_sg.SecurityGroupNotFound:
            LOG.warn(_('Security Group %s already deleted'), sg_id)

    def _get_sg_rule(self, plugin_context, sg_rule_id):
        return self._get_resource(
            self._core_plugin, plugin_context, 'security_group_rule',
            sg_rule_id)

    def _get_sg_rules(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'security_group_rules', filters)

    def _create_sg_rule(self, plugin_context, attrs):
        try:
            return self._create_resource(self._core_plugin, plugin_context,
                                         'security_group_rule', attrs)
        except ext_sg.SecurityGroupRuleExists as ex:
            LOG.warn(_('Security Group already exists %s'), ex.message)
            return

    def _update_sg_rule(self, plugin_context, sg_rule_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'security_group_rule', sg_rule_id,
                                     attrs)

    def _delete_sg_rule(self, plugin_context, sg_rule_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'security_group_rule', sg_rule_id)
        except ext_sg.SecurityGroupRuleNotFound:
            LOG.warn(_('Security Group Rule %s already deleted'), sg_rule_id)

    def _get_fip(self, plugin_context, fip_id):
        return self._get_resource(
            self._l3_plugin, plugin_context, 'floatingip', fip_id)

    def _get_fips(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._l3_plugin, plugin_context, 'floatingips', filters)

    def _create_fip(self, plugin_context, attrs):
        return self._create_resource(self._l3_plugin, plugin_context,
                                     'floatingip', attrs)

    def _update_fip(self, plugin_context, fip_id, attrs):
        return self._update_resource(self._l3_plugin, plugin_context,
                                     'floatingip', fip_id, attrs)

    def _delete_fip(self, plugin_context, fip_id):
        try:
            self._delete_resource(self._l3_plugin, plugin_context,
                                  'floatingip', fip_id)
        except l3.FloatingIPNotFound:
            LOG.warn(_('Floating IP %s Already deleted'), fip_id)

    def _get_l2_policy(self, plugin_context, l2p_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'l2_policy', l2p_id)

    def _get_l2_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'l2_policies', filters)

    def _create_l2_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'l2_policy', attrs, False)

    def _update_l2_policy(self, plugin_context, l2p_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'l2_policy', l2p_id, attrs, False)

    def _delete_l2_policy(self, plugin_context, l2p_id):
        try:
            self._delete_resource(self._group_policy_plugin,
                                  plugin_context, 'l2_policy', l2p_id, False)
        except gp_ext.L2PolicyNotFound:
            LOG.warn(_('L2 Policy %s already deleted'), l2p_id)

    def _get_l3_policy(self, plugin_context, l3p_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'l3_policy', l3p_id)

    def _get_l3_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'l3_policies', filters)

    def _create_l3_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'l3_policy', attrs, False)

    def _update_l3_policy(self, plugin_context, l3p_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'l3_policy', l3p_id, attrs, False)

    def _delete_l3_policy(self, plugin_context, l3p_id):
        try:
            self._delete_resource(self._group_policy_plugin,
                                  plugin_context, 'l3_policy', l3p_id, False)
        except gp_ext.L3PolicyNotFound:
            LOG.warn(_('L3 Policy %s already deleted'), l3p_id)

    def _get_external_segment(self, plugin_context, es_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'external_segment', es_id)

    def _get_external_segments(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'external_segments', filters)

    def _create_external_segment(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'external_segment', attrs, False)

    def _update_external_segment(self, plugin_context, es_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'external_segment', es_id, attrs, False)

    def _delete_external_segment(self, plugin_context, es_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'external_segment', es_id, False)
        except gp_ext.ExternalSegmentNotFound:
            LOG.warn(_('External Segment %s already deleted'), es_id)

    def _get_external_policy(self, plugin_context, ep_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'external_policy', ep_id)

    def _get_external_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'external_policies', filters)

    def _create_external_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'external_policy', attrs, False)

    def _update_external_policy(self, plugin_context, ep_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'external_policy', ep_id, attrs, False)

    def _delete_external_policy(self, plugin_context, ep_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'external_policy', ep_id, False)
        except gp_ext.ExternalPolicyNotFound:
            LOG.warn(_('External Policy %s already deleted'), ep_id)

    def _get_policy_rule_set(self, plugin_context, prs_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_rule_set', prs_id)

    def _get_policy_rule_sets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_rule_sets', filters)

    def _create_policy_rule_set(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_rule_set', attrs, False)

    def _update_policy_rule_set(self, plugin_context, prs_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_rule_set', prs_id, attrs, False)

    def _delete_policy_rule_set(self, plugin_context, prs_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_rule_set', prs_id, False)
        except gp_ext.PolicyRuleSetNotFound:
            LOG.warn(_('Policy Rule Set %s already deleted'), prs_id)

    def _get_servicechain_instance(self, plugin_context, sci_id):
        return self._get_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_instance', sci_id)

    def _get_servicechain_instances(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._servicechain_plugin, plugin_context,
                                   'servicechain_instances', filters)

    def _create_servicechain_instance(self, plugin_context, attrs):
        return self._create_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_instance', attrs, False)

    def _update_servicechain_instance(self, plugin_context, sci_id, attrs):
        return self._update_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_instance', sci_id, attrs,
                                     False)

    def _delete_servicechain_instance(self, plugin_context, sci_id):
        try:
            self._delete_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_instance', sci_id, False)
        except sc_ext.ServiceChainInstanceNotFound:
            LOG.warn(_("servicechain %s already deleted"), sci_id)

    def _get_servicechain_spec(self, plugin_context, scs_id):
        return self._get_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_spec', scs_id)

    def _get_servicechain_specs(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._servicechain_plugin, plugin_context,
                                   'servicechain_specs', filters)

    def _create_servicechain_spec(self, plugin_context, attrs):
        return self._create_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_spec', attrs, False)

    def _update_servicechain_spec(self, plugin_context, scs_id, attrs):
        return self._update_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_spec', scs_id, attrs, False)

    def _delete_servicechain_spec(self, plugin_context, scs_id):
        try:
            self._delete_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_spec', scs_id)
        except sc_ext.ServiceChainSpecNotFound:
            LOG.warn(_("servicechain spec %s already deleted"), scs_id)

    def _get_policy_target(self, plugin_context, pt_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target', pt_id)

    def _get_policy_targets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_targets', filters)

    def _create_policy_target(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target', attrs, False)

    def _update_policy_target(self, plugin_context, pt_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target', pt_id, attrs, False)

    def _delete_policy_target(self, plugin_context, pt_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target', pt_id, False)
        except gp_ext.PolicyTargetNotFound:
            LOG.warn(_('Policy Rule Set %s already deleted'), pt_id)

    def _get_policy_target_group(self, plugin_context, ptg_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target_group', ptg_id)

    def _get_policy_target_groups(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_target_groups', filters)

    def _create_policy_target_group(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target_group', attrs, False)

    def _update_policy_target_group(self, plugin_context, ptg_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target_group', ptg_id, attrs,
                                     False)

    def _delete_policy_target_group(self, plugin_context, ptg_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target_group', ptg_id)
        except sc_ext.ServiceChainSpecNotFound:
            LOG.warn(_("Policy Target Group %s already deleted"), ptg_id)
