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

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.common import log
from neutron import context as n_context
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from oslo.config import cfg
import sqlalchemy as sa

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db import servicechain_db  # noqa
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc


LOG = logging.getLogger(__name__)


class OwnedPort(model_base.BASEV2):
    """A Port owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_ports'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        nullable=False, primary_key=True)


class OwnedSubnet(model_base.BASEV2):
    """A Subnet owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_subnets'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class OwnedNetwork(model_base.BASEV2):
    """A Network owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_networks'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           nullable=False, primary_key=True)


class OwnedRouter(model_base.BASEV2):
    """A Router owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_routers'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class PolicyRuleSetSGsMapping(model_base.BASEV2):
    """PolicyRuleSet to SGs mapping DB."""

    __tablename__ = 'gpm_policy_rule_set_sg_mapping'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id',
                                                 ondelete='CASCADE'),
                                   nullable=False, primary_key=True)
    provided_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))
    consumed_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))


class PtgServiceChainInstanceMapping(model_base.BASEV2):
    """Policy Target Group to ServiceChainInstance mapping DB."""

    __tablename__ = 'gpm_ptgs_servicechain_mapping'
    provider_ptg_id = sa.Column(sa.String(36),
                                sa.ForeignKey('gp_policy_target_groups.id',
                                              ondelete='CASCADE'),
                                nullable=False)
    consumer_ptg_id = sa.Column(sa.String(36),
                                sa.ForeignKey('gp_policy_target_groups.id',
                                              ondelete='CASCADE'),
                                nullable=False)
    servicechain_instance_id = sa.Column(sa.String(36),
                                         sa.ForeignKey('sc_instances.id',
                                                       ondelete='CASCADE'),
                                         primary_key=True)


class ServicePolicyPTGIpAddressMapping(model_base.BASEV2):
    """Service Policy to IP Address mapping DB."""

    __tablename__ = 'gpm_service_policy_ipaddress_mappings'
    service_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_network_service_policies.id'),
        nullable=False, primary_key=True)
    policy_target_group = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id'),
        nullable=False, primary_key=True)
    ipaddress = sa.Column(sa.String(36))


class ResourceMappingDriver(api.PolicyDriver):
    """Resource Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources.
    """

    @log.log
    def initialize(self):
        self._cached_agent_notifier = None
        self._nova_notifier = nova.Notifier()

    def _reject_shared(self, object, type):
        if object.get('shared'):
            raise exc.InvalidSharedResource(type=type,
                                            driver='resource_mapping')

    def _reject_cross_tenant_ptg_l2p(self, context):
        if context.current['l2_policy_id']:
            l2p = context._plugin.get_l2_policy(
                context._plugin_context, context.current['l2_policy_id'])
            if l2p['tenant_id'] != context.current['tenant_id']:
                raise (
                    exc.
                    CrossTenantPolicyTargetGroupL2PolicyNotSupported())

    def _reject_cross_tenant_l2p_l3p(self, context):
        # Can't create non shared L2p on a shared L3p
        if context.current['l3_policy_id']:
            l3p = context._plugin.get_l3_policy(
                context._plugin_context,
                context.current['l3_policy_id'])
            if l3p['tenant_id'] != context.current['tenant_id']:
                raise exc.CrossTenantL2PolicyL3PolicyNotSupported()

    def _reject_non_shared_net_on_shared_l2p(self, context):
        if context.current.get('shared') and context.current['network_id']:
            net = self._core_plugin.get_network(
                context._plugin_context, context.current['network_id'])
            if not net.get('shared'):
                raise exc.NonSharedNetworkOnSharedL2PolicyNotSupported()

    def _reject_invalid_network_access(self, context):
        # Validate if the explicit network belongs to the tenant.
        # Are networks shared across tenants ??
        # How to check if admin and if admin can access all networks ??
        if context.current['network_id']:
            network_id = context.current['network_id']
            plugin_context = context._plugin_context
            network = None
            try:
                network = self._core_plugin.get_network(plugin_context,
                                                        network_id)
            except n_exc.NetworkNotFound:
                raise exc.InvalidNetworkAccess(
                    msg="Can't access other tenants networks",
                    network_id=context.current['network_id'],
                    tenant_id=context.current['tenant_id'])

            if network:
                tenant_id_of_explicit_net = network['tenant_id']
                if tenant_id_of_explicit_net != context.current['tenant_id']:
                    raise exc.InvalidNetworkAccess(
                        msg="Can't access other tenants networks",
                        network_id=context.current['network_id'],
                        tenant_id=context.current['tenant_id'])

    def _reject_invalid_router_access(self, context):
        # Validate if the explicit router(s) belong to the tenant.
        # Are routers shared across tenants ??
        # How to check if admin and if admin can access all routers ??
        for router_id in context.current['routers']:
            router = None
            try:
                router = self._l3_plugin.get_router(context._plugin_context,
                                                    router_id)
            except n_exc.NotFound:
                raise exc.InvalidRouterAccess(
                    msg="Can't access other tenants router",
                    router_id=router_id,
                    tenant_id=context.current['tenant_id'])

            if router:
                tenant_id_of_explicit_router = router['tenant_id']
                curr_tenant_id = context.current['tenant_id']
                if tenant_id_of_explicit_router != curr_tenant_id:
                    raise exc.InvalidRouterAccess(
                        msg="Can't access other tenants router",
                        router_id=router_id,
                        tenant_id=context.current['tenant_id'])

    def _reject_multiple_redirects_in_rule(self, context):
        policy_actions = context._plugin.get_policy_actions(
                context._plugin_context,
                filters={'id': context.current['policy_actions'],
                         'action_type': [gconst.GP_ACTION_REDIRECT]})
        if len(policy_actions) > 1:
            raise exc.MultipleRedirectActionsNotSupportedForRule()

    def _reject_multiple_redirects_in_prs(self, context):
        policy_rules = context._plugin.get_policy_rules(
                context._plugin_context,
                filters={'id': context.current['policy_rules']})
        redirect_actions_list = []
        for policy_rule in policy_rules:
            policy_actions = context._plugin.get_policy_actions(
                    context._plugin_context,
                    filters={'id': policy_rule['policy_actions'],
                             'action_type': [gconst.GP_ACTION_REDIRECT]})
            redirect_actions_list.extend(policy_actions)
        if len(redirect_actions_list) > 1:
            raise exc.MultipleRedirectActionsNotSupportedForPRS()

    @log.log
    def create_policy_target_precommit(self, context):
        if not context.current['policy_target_group_id']:
            raise exc.PolicyTargetRequiresPolicyTargetGroup()
        if context.current['port_id']:
            # Validate if explicit port's subnet
            # is same as the subnet of PTG.
            self._validate_pt_port_subnets(context)

    @log.log
    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)

        self._assoc_ptg_sg_to_pt(context, context.current['id'],
                                 context.current['policy_target_group_id'])

    @log.log
    def update_policy_target_precommit(self, context):
        if (context.current['policy_target_group_id'] !=
            context.original['policy_target_group_id']):
            raise exc.PolicyTargetGroupUpdateOfPolicyTargetNotSupported()

    @log.log
    def update_policy_target_postcommit(self, context):
        pass

    @log.log
    def delete_policy_target_precommit(self, context):
        pass

    @log.log
    def delete_policy_target_postcommit(self, context):
        sg_list = self._generate_list_of_sg_from_ptg(
            context, context.current['policy_target_group_id'])
        self._disassoc_sgs_from_port(context._plugin_context,
                                     context.current['port_id'], sg_list)
        port_id = context.current['port_id']
        self._cleanup_port(context._plugin_context, port_id)

    @log.log
    def create_policy_target_group_precommit(self, context):
        self._reject_cross_tenant_ptg_l2p(context)
        self._validate_ptg_subnets(context)

    @log.log
    def create_policy_target_group_postcommit(self, context):
        subnets = context.current['subnets']
        if subnets:
            l2p_id = context.current['l2_policy_id']
            l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                l2p_id)
            l3p_id = l2p['l3_policy_id']
            l3p = context._plugin.get_l3_policy(context._plugin_context,
                                                l3p_id)
            router_id = l3p['routers'][0] if l3p['routers'] else None
            for subnet_id in subnets:
                self._use_explicit_subnet(context._plugin_context, subnet_id,
                                          router_id)
        else:
            self._use_implicit_subnet(context)
        self._handle_network_service_policy(context)
        self._handle_policy_rule_sets(context)
        self._update_default_security_group(context._plugin_context,
                                            context.current['id'],
                                            context.current['tenant_id'],
                                            context.current['subnets'])

    def _handle_network_service_policy(self, context):
        network_service_policy_id = context.current.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return

        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")
        if not nsp_params:
            return

        # RM Driver only supports one parameter of type ip_single and value
        # self_subnet right now. Handle the other cases when we have usecase
        if (len(nsp_params) > 1 or nsp_params[0].get("type") != "ip_single"
            or nsp_params[0].get("value") != "self_subnet"):
            return
        # TODO(Magesh):Handle concurrency issues
        free_ip = self._get_last_free_ip(context._plugin_context,
                                         context.current['subnets'])
        if not free_ip:
            LOG.error(_("Reserving IP Addresses failed for Network Service "
                        "Policy. No more IP Addresses on subnet"))
            return
        # TODO(Magesh):Fetch subnet from PTG to which NSP is attached
        self._remove_ip_from_allocation_pool(context,
                                             context.current['subnets'][0],
                                             free_ip)
        self._set_policy_ipaddress_mapping(context._plugin_context.session,
                                           network_service_policy_id,
                                           context.current['id'],
                                           free_ip)

    def _get_service_policy_ipaddress(self, context, policy_target_group):
        ipaddress = self._get_ptg_policy_ipaddress_mapping(
            context._plugin_context.session, policy_target_group)
        return ipaddress

    def _cleanup_network_service_policy(self, context, subnet, ptg_id):
        ipaddress = self._get_ptg_policy_ipaddress_mapping(
            context._plugin_context.session, ptg_id)
        if ipaddress:
            self._restore_ip_to_allocation_pool(context, subnet, ipaddress)
            self._delete_policy_ipaddress_mapping(
                context._plugin_context.session, ptg_id)

    @log.log
    def update_policy_target_group_precommit(self, context):
        # REVISIT(rkukura): We could potentially allow updates to
        # l2_policy_id when no policy targets exist. This would
        # involve removing each old subnet from the l3_policy's
        # router, deleting each old subnet, creating a new subnet on
        # the new l2_policy's network, and adding that subnet to the
        # l3_policy's router in postcommit. Its also possible that new
        # subnet[s] would be provided explicitly as part of the
        # update.
        old_l2p = context.original['l2_policy_id']
        new_l2p = context.current['l2_policy_id']
        if old_l2p and old_l2p != new_l2p:
            raise exc.L2PolicyUpdateOfPolicyTargetGroupNotSupported()

        if set(context.original['subnets']) - set(context.current['subnets']):
            raise exc.PolicyTargetGroupSubnetRemovalNotSupported()

        new_subnets = list(set(context.current['subnets']) -
                           set(context.original['subnets']))
        self._validate_ptg_subnets(context, new_subnets)
        self._reject_cross_tenant_ptg_l2p(context)
        self._validate_ptg_subnets(context, context.current['subnets'])

        #Update service chain instance when any ruleset is changed
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        orig_consumed_policy_rule_sets = context.original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        if (set(orig_provided_policy_rule_sets) !=
            set(curr_provided_policy_rule_sets)
            or set(orig_consumed_policy_rule_sets) !=
            set(curr_consumed_policy_rule_sets)):
            provider_ptg_chain_map = self._get_ptg_servicechain_mapping(
                                            context._plugin_context.session,
                                            context.current['id'],
                                            None)
            consumer_ptg_chain_map = self._get_ptg_servicechain_mapping(
                                            context._plugin_context.session,
                                            None,
                                            context.current['id'])
            context.ptg_chain_map = (provider_ptg_chain_map +
                                     consumer_ptg_chain_map)

    @log.log
    def update_policy_target_group_postcommit(self, context):
        # Three conditions where SG association needs to be changed
        # (a) list of policy_targets change
        # (b) provided_policy_rule_sets change
        # (c) consumed_policy_rule_sets change
        ptg_id = context.current['id']
        new_policy_targets = list(
            set(context.current['policy_targets']) - set(
                context.original['policy_targets']))
        if new_policy_targets:
            self._update_sgs_on_pt_with_ptg(context, ptg_id,
                                            new_policy_targets, "ASSOCIATE")
        removed_policy_targets = list(
            set(context.original['policy_targets']) - set(
                context.current['policy_targets']))
        if removed_policy_targets:
            self._update_sgs_on_pt_with_ptg(context, ptg_id,
                                            new_policy_targets, "DISASSOCIATE")
        # generate a list of policy_rule_sets (SGs) to update on the PTG
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        new_provided_policy_rule_sets = list(
            set(curr_provided_policy_rule_sets) - set(
                orig_provided_policy_rule_sets))
        orig_consumed_policy_rule_sets = context.original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        new_consumed_policy_rule_sets = list(
            set(curr_consumed_policy_rule_sets) - set(
                orig_consumed_policy_rule_sets))

        old_nsp = context.original.get("network_service_policy_id")
        new_nsp = context.current.get("network_service_policy_id")
        if old_nsp != new_nsp:
            if old_nsp:
                self._cleanup_network_service_policy(
                                        context,
                                        context.current['subnets'][0],
                                        context.current['id'])
            if new_nsp:
                self._handle_network_service_policy(context)

        # Delete old servicechain instance and create new one in case of update
        if (set(orig_provided_policy_rule_sets) !=
            set(curr_provided_policy_rule_sets)
            or set(orig_consumed_policy_rule_sets) !=
            set(curr_consumed_policy_rule_sets)):
            self._cleanup_redirect_action(context)
            if (curr_consumed_policy_rule_sets or
                curr_provided_policy_rule_sets):
                policy_rule_sets = (curr_consumed_policy_rule_sets +
                                    curr_provided_policy_rule_sets)
                self._handle_redirect_action(context, policy_rule_sets)

        # if PTG associated policy_rule_sets are updated, we need to update
        # the policy rules, then assoicate SGs to ports
        if new_provided_policy_rule_sets or new_consumed_policy_rule_sets:
            subnets = context.current['subnets']
            self._set_sg_rules_for_subnets(context, subnets,
                                  new_provided_policy_rule_sets,
                                  new_consumed_policy_rule_sets)
            self._update_sgs_on_ptg(context, ptg_id,
                                    new_provided_policy_rule_sets,
                                    new_consumed_policy_rule_sets, "ASSOCIATE")
        # generate the list of contracts (SGs) to remove from current ports
        removed_provided_prs = list(set(orig_provided_policy_rule_sets) -
                                    set(curr_provided_policy_rule_sets))
        removed_consumed_prs = list(set(orig_consumed_policy_rule_sets) -
                                    set(curr_consumed_policy_rule_sets))
        if removed_provided_prs or removed_consumed_prs:
            self._update_sgs_on_ptg(context, ptg_id,
                                    removed_provided_prs,
                                    removed_consumed_prs, "DISASSOCIATE")
            subnets = context.original['subnets']
            self._unset_sg_rules_for_subnets(
                context, subnets, removed_provided_prs, removed_consumed_prs)
        # Deal with new added subnets for default SG
        # Subnet removal not possible for now
        new_subnets = list(set(context.current['subnets']) -
                           set(context.original['subnets']))
        self._update_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'], subnets=new_subnets)

    @log.log
    def delete_policy_target_group_precommit(self, context):
        provider_ptg_chain_map = self._get_ptg_servicechain_mapping(
                                            context._plugin_context.session,
                                            context.current['id'],
                                            None)
        consumer_ptg_chain_map = self._get_ptg_servicechain_mapping(
                                            context._plugin_context.session,
                                            None,
                                            context.current['id'],)
        context.ptg_chain_map = provider_ptg_chain_map + consumer_ptg_chain_map

    @log.log
    def delete_policy_target_group_postcommit(self, context):
        self._cleanup_network_service_policy(context,
                                             context.current['subnets'][0],
                                             context.current['id'])
        self._cleanup_redirect_action(context)
        # Cleanup SGs
        self._unset_sg_rules_for_subnets(
            context, context.current['subnets'],
            context.current['provided_policy_rule_sets'],
            context.current['consumed_policy_rule_sets'])

        l2p_id = context.current['l2_policy_id']
        router_id = self._get_routerid_for_l2policy(context, l2p_id)
        for subnet_id in context.current['subnets']:
            self._cleanup_subnet(context._plugin_context, subnet_id, router_id)
        self._delete_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'])

    @log.log
    def create_l2_policy_precommit(self, context):
        self._reject_cross_tenant_l2p_l3p(context)
        self._reject_non_shared_net_on_shared_l2p(context)
        self._reject_invalid_network_access(context)

    @log.log
    def create_l2_policy_postcommit(self, context):
        if not context.current['network_id']:
            self._use_implicit_network(context)

    @log.log
    def update_l2_policy_precommit(self, context):
        self._reject_cross_tenant_l2p_l3p(context)
        self._reject_non_shared_net_on_shared_l2p(context)

    @log.log
    def update_l2_policy_postcommit(self, context):
        pass

    @log.log
    def delete_l2_policy_precommit(self, context):
        pass

    @log.log
    def delete_l2_policy_postcommit(self, context):
        network_id = context.current['network_id']
        self._cleanup_network(context._plugin_context, network_id)

    @log.log
    def create_l3_policy_precommit(self, context):
        curr = context.current
        if len(curr['routers']) > 1:
            raise exc.L3PolicyMultipleRoutersNotSupported()
        # Validate non overlapping IPs in the same tenant
        l3ps = context._plugin.get_l3_policies(
            context._plugin_context, {'tenant_id': [curr['tenant_id']]})
        subnets = [x['ip_pool'] for x in l3ps if x['id'] != curr['id']]
        current_set = netaddr.IPSet(subnets)
        if netaddr.IPSet([curr['ip_pool']]) & current_set:
            raise exc.OverlappingIPPoolsInSameTenantNotAllowed(
                ip_pool=curr['ip_pool'], overlapping_pools=subnets)
        # In Neutron, one external gateway per router is allowed. Therefore
        # we have to limit the number of ES per L3P to 1
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerL3PolicyNotSupported()
        self._reject_invalid_router_access(context)

    @log.log
    def create_l3_policy_postcommit(self, context):
        if not context.current['routers']:
            self._use_implicit_router(context)
        l3p = context.current
        if l3p['external_segments']:
            self._plug_router_to_external_segment(
                context, l3p['external_segments'])
            self._set_l3p_routes(context)
        self._process_new_l3p_ip_pool(context, context.current['ip_pool'])

    @log.log
    def update_l3_policy_precommit(self, context):
        if context.current['routers'] != context.original['routers']:
            raise exc.L3PolicyRoutersUpdateNotSupported()
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerL3PolicyNotSupported()
        # Currently there is no support for router update in l3p update.
        # Added this check just in case it is supported in future.
        self._reject_invalid_router_access(context)

    @log.log
    def update_l3_policy_postcommit(self, context):
        new, old = context.current, context.original
        if new['external_segments'] != old['external_segments']:
            added = (set(new['external_segments'].keys()) -
                     set(old['external_segments'].keys()))
            removed = (set(old['external_segments'].keys()) -
                       set(new['external_segments'].keys()))
            if context.current['routers']:
                if removed:
                    self._unplug_router_from_external_segment(
                        context, dict((x, old['external_segments'][x])
                                      for x in removed))
                if added:
                    self._plug_router_to_external_segment(
                        context, dict((x, new['external_segments'][x])
                                      for x in added))
                self._set_l3p_routes(context)

    @log.log
    def delete_l3_policy_precommit(self, context):
        pass

    @log.log
    def delete_l3_policy_postcommit(self, context):
        for router_id in context.current['routers']:
            self._cleanup_router(context._plugin_context, router_id)
        self._process_remove_l3p_ip_pool(context, context.current['ip_pool'])

    @log.log
    def create_policy_classifier_precommit(self, context):
        pass

    @log.log
    def create_policy_classifier_postcommit(self, context):
        pass

    @log.log
    def update_policy_classifier_precommit(self, context):
        pass

    @log.log
    def update_policy_classifier_postcommit(self, context):
        policy_rules = (context._plugin.get_policy_classifier(
                context._plugin_context,
                context.current['id'])['policy_rules'])
        policy_rules = context._plugin.get_policy_rules(
            context._plugin_context,
            filters={'id': policy_rules})
        policy_rulesets_to_update = []
        for policy_rule in policy_rules:
            pr_id = policy_rule['id']
            pr_sets = context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, pr_id)
            policy_rulesets_to_update.extend(pr_sets)
            self._update_policy_rule_sg_rules(context, pr_sets,
                policy_rule, context.original, context.current)
        self._handle_redirect_action(context, policy_rulesets_to_update)

    @log.log
    def delete_policy_classifier_precommit(self, context):
        pass

    @log.log
    def delete_policy_classifier_postcommit(self, context):
        pass

    @log.log
    def create_policy_action_precommit(self, context):
        spec_id = context.current['action_value']
        if spec_id:
            specs = self._servicechain_plugin.get_servicechain_specs(
                context._plugin_context, filters={'id': [spec_id]})
            for spec in specs:
                if not spec.get('shared', False):
                    self._reject_shared(context.current, 'policy_action')

    @log.log
    def create_policy_action_postcommit(self, context):
        pass

    @log.log
    def update_policy_action_precommit(self, context):
        pass

    @log.log
    def update_policy_action_postcommit(self, context):
        # TODO(ivar): Should affect related SGs
        self._handle_redirect_spec_id_update(context)

    @log.log
    def delete_policy_action_precommit(self, context):
        pass

    @log.log
    def delete_policy_action_postcommit(self, context):
        pass

    @log.log
    def create_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)

    @log.log
    def create_policy_rule_postcommit(self, context):
        pass

    @log.log
    def update_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)

    @log.log
    def update_policy_rule_postcommit(self, context):
        old_classifier_id = context.original['policy_classifier_id']
        new_classifier_id = context.current['policy_classifier_id']
        old_action_set = set(context.current['policy_actions'])
        new_action_set = set(context.original['policy_actions'])
        if (old_classifier_id != new_classifier_id or
                old_action_set != new_action_set):
            policy_rule_sets = (
                context._plugin._get_policy_rule_policy_rule_sets(
                    context._plugin_context, context.current['id']))
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context, filters={'id': policy_rule_sets}):
                self._remove_policy_rule_set_rules(context, prs,
                                                   [context.original])
                self._apply_policy_rule_set_rules(context, prs,
                                                  [context.current])
            self._handle_redirect_action(context, policy_rule_sets)

    @log.log
    def delete_policy_rule_precommit(self, context):
        # REVISIT(ivar): This will be removed once navigability issue is
        # solved (bug/1384397)
        context._rmd_policy_rule_sets_temp = (
            context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, context.current['id']))

    @log.log
    def delete_policy_rule_postcommit(self, context):
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])

    @log.log
    def create_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')
        self._reject_multiple_redirects_in_prs(context)

    @log.log
    def create_policy_rule_set_postcommit(self, context):
        # creating SGs
        policy_rule_set_id = context.current['id']
        consumed_sg = self._create_policy_rule_set_sg(context, 'consumed')
        provided_sg = self._create_policy_rule_set_sg(context, 'provided')
        consumed_sg_id = consumed_sg['id']
        provided_sg_id = provided_sg['id']
        self._set_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set_id,
            consumed_sg_id, provided_sg_id)
        rules = context._plugin.get_policy_rules(
            context._plugin_context,
            {'id': context.current['policy_rules']})
        self._apply_policy_rule_set_rules(context, context.current, rules)
        if context.current['child_policy_rule_sets']:
            self._recompute_policy_rule_sets(
                context, context.current['child_policy_rule_sets'])
            self._handle_redirect_action(
                    context, context.current['child_policy_rule_sets'])

    @log.log
    def update_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')
        self._reject_multiple_redirects_in_prs(context)

    @log.log
    def update_policy_rule_set_postcommit(self, context):
        # Update policy_rule_set rules
        old_rules = set(context.original['policy_rules'])
        new_rules = set(context.current['policy_rules'])
        to_add = context._plugin.get_policy_rules(
            context._plugin_context, {'id': new_rules - old_rules})
        to_remove = context._plugin.get_policy_rules(
            context._plugin_context, {'id': old_rules - new_rules})
        self._remove_policy_rule_set_rules(context, context.current, to_remove)
        self._apply_policy_rule_set_rules(context, context.current, to_add)
        # Update children contraint
        to_recompute = (set(context.original['child_policy_rule_sets']) ^
                        set(context.current['child_policy_rule_sets']))
        self._recompute_policy_rule_sets(context, to_recompute)
        if to_add or to_remove:
            to_recompute = (set(context.original['child_policy_rule_sets']) &
                            set(context.current['child_policy_rule_sets']))
            self._recompute_policy_rule_sets(context, to_recompute)
        # Handle any Redirects from the current Policy Rule Set
        self._handle_redirect_action(context, [context.current['id']])
        # Handle Update/Delete of Redirects for any child Rule Sets
        if (set(context.original['child_policy_rule_sets']) !=
            set(context.current['child_policy_rule_sets'])):
            if context.original['child_policy_rule_sets']:
                self._handle_redirect_action(
                    context, context.original['child_policy_rule_sets'])
            if context.current['child_policy_rule_sets']:
                self._handle_redirect_action(
                    context, context.current['child_policy_rule_sets'])

    @log.log
    def delete_policy_rule_set_precommit(self, context):
        mapping = self._get_policy_rule_set_sg_mapping(
            context._plugin_context.session, context.current['id'])
        context._rmd_sg_list_temp = [mapping['provided_sg_id'],
                                     mapping['consumed_sg_id']]

    @log.log
    def delete_policy_rule_set_postcommit(self, context):
        # Disassociate SGs
        sg_list = context._rmd_sg_list_temp
        ptg_mapping = [context.current['providing_policy_target_groups'],
                       context.current['consuming_policy_target_groups']]
        for ptgs in ptg_mapping:
            for ptg in ptgs:
                policy_target_list = ptg['policy_targets']
                for pt_id in policy_target_list:
                    self._disassoc_sgs_from_pt(context, pt_id, sg_list)
        # Delete SGs
        for sg in sg_list:
            self._delete_sg(context._plugin_context, sg)
        if context.current['child_policy_rule_sets']:
            self._handle_redirect_action(
                context, context.current['child_policy_rule_sets'])

    @log.log
    def delete_network_service_policy_postcommit(self, context):
        for ptg_id in context.current.get("policy_target_groups"):
            ptg = context._plugin.get_policy_target_group(
                context._plugin_context, ptg_id)
            subnet = ptg.get('subnets')[0]
            self._cleanup_network_service_policy(context, subnet, ptg_id)

    def create_external_segment_precommit(self, context):
        if context.current['subnet_id']:
            subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                  context.current['subnet_id'])
            network = self._core_plugin.get_network(context._plugin_context,
                                                    subnet['network_id'])
            if not network['router:external']:
                raise exc.InvalidSubnetForES(sub_id=subnet['id'],
                                             net_id=network['id'])
            db_es = context._plugin._get_external_segment(
                context._plugin_context, context.current['id'])
            db_es.cidr = subnet['cidr']
            db_es.ip_version = subnet['ip_version']
            context.current['cidr'] = db_es.cidr
            context.current['ip_version'] = db_es.ip_version
        else:
            raise exc.ImplicitSubnetNotSupported()

    def create_external_segment_postcommit(self, context):
        pass

    def update_external_segment_precommit(self, context):
        invalid = ['port_address_translation']
        for attr in invalid:
            if context.current[attr] != context.original[attr]:
                raise exc.InvalidAttributeUpdateForES(attribute=attr)

    def update_external_segment_postcommit(self, context):
        # REVISIT(ivar): concurrency issues
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            # Update SG rules for each EP
            # Get all the EP using this ES
            ep_ids = context._plugin._get_external_segment_external_policies(
                context._plugin_context, context.current['id'])
            # Process their routes
            old_cidrs = [x['destination']
                         for x in context.original['external_routes']]
            old_cidrs = self._process_external_cidrs(context, old_cidrs)
            new_cidrs = [x['destination']
                         for x in context.current['external_routes']]
            new_cidrs = self._process_external_cidrs(context, new_cidrs)
            # Recompute PRS rules
            self._recompute_external_policy_rules(context, ep_ids,
                                                  new_cidrs, old_cidrs)
            old_routes = set((x['destination'], x['nexthop'])
                             for x in context.original['external_routes'])
            new_routes = set((x['destination'], x['nexthop'])
                             for x in context.current['external_routes'])
            # Set the correct list of routes for each L3P
            self._recompute_l3_policy_routes(context, new_routes, old_routes)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        pass

    def create_external_policy_precommit(self, context):
        self._reject_shared(context.current, 'external_policy')
        # REVISIT(ivar): For security reasons, only one ES allowed per EP.
        # see bug #1398156
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerEPNotSupported()
        # REVISIT(ivar): Remove when ES update is supported for EP
        if not context.current['external_segments']:
            raise exc.ESIdRequiredWhenCreatingEP()
        # REVISIT(ivar): bug #1398156 only one EP is allowed per tenant
        ep_number = context._plugin.get_external_policies_count(
            context._plugin_context,
            filters={'tenant_id': [context.current['tenant_id']]})
        if ep_number - 1:
            raise exc.OnlyOneEPPerTenantAllowed()

    def create_external_policy_postcommit(self, context):
        # Only *North to South* rules are actually effective.
        # The rules will be calculated as the symmetric difference between
        # the union of all the Tenant's L3P supernets and the union of all the
        # ES routes.
        ep = context.current
        if ep['external_segments']:
            if (ep['provided_policy_rule_sets'] or
                    ep['consumed_policy_rule_sets']):
                # Get the full processed list of external CIDRs
                cidr_list = self._get_processed_ep_cidr_list(context, ep)
                # set the rules on the proper SGs
                self._set_sg_rules_for_cidrs(
                    context, cidr_list, ep['provided_policy_rule_sets'],
                    ep['consumed_policy_rule_sets'])

    def update_external_policy_precommit(self, context):
        if (context.current['external_segments'] !=
                context.original['external_segments']):
            raise exc.ESUpdateNotSupportedForEP()

    def update_external_policy_postcommit(self, context):
        # REVISIT(ivar): Concurrency issue, the cidr_list could be different
        # in the time from adding new PRS to removing old ones. The consequence
        # is that the rules added/removed could be completely wrong.
        prov_cons = {'provided_policy_rule_sets': [],
                     'consumed_policy_rule_sets': []}
        cidr_list = None
        # Removed PRS
        for attr in prov_cons:
            orig_policy_rule_sets = context.original[attr]
            curr_policy_rule_sets = context.current[attr]
            prov_cons[attr] = list(set(orig_policy_rule_sets) -
                                   set(curr_policy_rule_sets))
        if any(prov_cons.values()):
            cidr_list = self._get_processed_ep_cidr_list(
                context, context.current)
            self._unset_sg_rules_for_cidrs(
                context, cidr_list, prov_cons['provided_policy_rule_sets'],
                prov_cons['consumed_policy_rule_sets'])

        # Added PRS
        for attr in prov_cons:
            orig_policy_rule_sets = context.original[attr]
            curr_policy_rule_sets = context.current[attr]
            prov_cons[attr] = list(set(curr_policy_rule_sets) -
                                   set(orig_policy_rule_sets))

        if any(prov_cons.values()):
            cidr_list = cidr_list or self._get_processed_ep_cidr_list(
                context, context.current)
            self._set_sg_rules_for_cidrs(
                context, cidr_list, prov_cons['provided_policy_rule_sets'],
                prov_cons['consumed_policy_rule_sets'])
        # REVISIT(ivar): manage redirect action

    def delete_external_policy_precommit(self, context):
        pass

    def delete_external_policy_postcommit(self, context):
        if (context.current['provided_policy_rule_sets'] or
                context.current['consumed_policy_rule_sets']):
            # REVISIT(ivar): concurrency issue, ES may not exist anymore
            cidr_list = self._get_processed_ep_cidr_list(
                context, context.current)
            self._unset_sg_rules_for_cidrs(
                context, cidr_list,
                context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'])
            # REVISIT(ivar): manage redirect action

    def create_nat_pool_precommit(self, context):
        # No FIP supported right now
        # REVISIT(ivar): ignore or reject?
        pass

    def _get_routerid_for_l2policy(self, context, l2p_id):
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        return l3p['routers'][0]

    def _use_implicit_port(self, context):
        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        l2p_id = ptg['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        sg_id = self._get_default_security_group(
            context._plugin_context, ptg_id, context.current['tenant_id'])
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'pt_' + context.current['name'],
                 'network_id': l2p['network_id'],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': '',
                 'device_owner': '',
                 'security_groups': [sg_id] if sg_id else None,
                 'admin_state_up': True}
        port = self._create_port(context._plugin_context, attrs)
        port_id = port['id']
        self._mark_port_owned(context._plugin_context.session, port_id)
        context.set_port_id(port_id)

    def _cleanup_port(self, plugin_context, port_id):
        if self._port_is_owned(plugin_context.session, port_id):
            try:
                self._delete_port(plugin_context, port_id)
            except n_exc.PortNotFound:
                LOG.warn(_("Port %s is missing") % port_id)

    def _plug_router_to_external_segment(self, context, es_dict):
        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_dict.keys()})
        if context.current['routers']:
            router_id = context.current['routers'][0]
            for es in es_list:
                subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                      es['subnet_id'])
                interface_info = {
                    'network_id': subnet['network_id'],
                    'enable_snat': es['port_address_translation'],
                    'external_fixed_ips': [
                        {'subnet_id': es['subnet_id'],
                         'ip_address': x} for x in es_dict[es['id']]]
                    if es_dict[es['id']] else
                    attributes.ATTR_NOT_SPECIFIED}
                router = self._add_router_gw_interface(
                    context._plugin_context, router_id, interface_info)
                if not es_dict[es['id']] or not es_dict[es['id']][0]:
                    # Update L3P assigned address
                    efi = router['external_gateway_info']['external_fixed_ips']
                    assigned_ips = [x['ip_address'] for x in efi
                                    if x['subnet_id'] == es['subnet_id']]
                    context.set_external_fixed_ips(es['id'], assigned_ips)

    def _unplug_router_from_external_segment(self, context, es_ids):
        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_ids})
        if context.current['routers']:
            router_id = context.current['routers'][0]
            for es in es_list:
                subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                      es['subnet_id'])
                interface_info = {'network_id': subnet['network_id']}
                self._remove_router_gw_interface(context._plugin_context,
                                                 router_id, interface_info)

    def _use_implicit_subnet(self, context):
        # REVISIT(rkukura): This is a temporary allocation algorithm
        # that depends on an exception being raised when the subnet
        # being created is already in use. A DB allocation table for
        # the pool of subnets, or at lest a more efficient way to
        # test if a subnet is in-use, may be needed.
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        pool = netaddr.IPNetwork(l3p['ip_pool'])

        l2ps = context._plugin.get_l2_policies(
            context._plugin_context, filters={'l3_policy_id': [l3p['id']]})
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context,
            filters={'l2_policy_id': [x['id'] for x in l2ps]})
        subnets = []
        for ptg in ptgs:
            subnets.extend(ptg['subnets'])
        subnets = self._core_plugin.get_subnets(context._plugin_context,
                                                filters={'id': subnets})
        for cidr in pool.subnet(l3p['subnet_prefix_length']):
            if not self._validate_subnet_overlap_for_l3p(subnets,
                                                         cidr.__str__()):
                continue
            try:
                attrs = {'tenant_id': context.current['tenant_id'],
                         'name': 'ptg_' + context.current['name'],
                         'network_id': l2p['network_id'],
                         'ip_version': l3p['ip_version'],
                         'cidr': cidr.__str__(),
                         'enable_dhcp': True,
                         'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                         'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                         'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                         'host_routes': attributes.ATTR_NOT_SPECIFIED}
                subnet = self._create_subnet(context._plugin_context, attrs)
                subnet_id = subnet['id']
                try:
                    if l3p['routers']:
                        router_id = l3p['routers'][0]
                        interface_info = {'subnet_id': subnet_id}
                        self._add_router_interface(context._plugin_context,
                                                   router_id, interface_info)
                    self._mark_subnet_owned(
                        context._plugin_context.session, subnet_id)
                    context.add_subnet(subnet_id)
                    return
                except n_exc.InvalidInput:
                    # This exception is not expected. We catch this
                    # here so that it isn't caught below and handled
                    # as if the CIDR is already in use.
                    LOG.exception(_("adding subnet to router failed"))
                    self._delete_subnet(context._plugin_context, subnet['id'])
                    raise exc.GroupPolicyInternalError()
            except n_exc.BadRequest:
                # This is expected (CIDR overlap) until we have a
                # proper subnet allocation algorithm. We ignore the
                # exception and repeat with the next CIDR.
                pass
        raise exc.NoSubnetAvailable()

    def _validate_subnet_overlap_for_l3p(self, subnets, subnet_cidr):
        new_subnet_ipset = netaddr.IPSet([subnet_cidr])
        for subnet in subnets:
            if (netaddr.IPSet([subnet['cidr']]) & new_subnet_ipset):
                return False
        return True

    def _use_explicit_subnet(self, plugin_context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        if router_id:
            self._add_router_interface(plugin_context, router_id,
                                       interface_info)

    def _cleanup_subnet(self, plugin_context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        if router_id:
            self._remove_router_interface(plugin_context, router_id,
                                          interface_info)
        if self._subnet_is_owned(plugin_context.session, subnet_id):
            self._delete_subnet(plugin_context, subnet_id)

    def _create_implicit_network(self, context, **kwargs):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': context.current['name'], 'admin_state_up': True,
                 'shared': context.current.get('shared', False)}
        attrs.update(**kwargs)
        network = self._create_network(context._plugin_context, attrs)
        network_id = network['id']
        self._mark_network_owned(context._plugin_context.session, network_id)
        return network

    def _use_implicit_network(self, context):
        network = self._create_implicit_network(
            context, name='l2p_' + context.current['name'])
        context.set_network_id(network['id'])

    def _cleanup_network(self, plugin_context, network_id):
        if self._network_is_owned(plugin_context.session, network_id):
            self._delete_network(plugin_context, network_id)

    def _use_implicit_router(self, context):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'l3p_' + context.current['name'],
                 'external_gateway_info': None,
                 'admin_state_up': True}
        router = self._create_router(context._plugin_context, attrs)
        router_id = router['id']
        self._mark_router_owned(context._plugin_context.session, router_id)
        context.add_router(router_id)

    def _cleanup_router(self, plugin_context, router_id):
        if self._router_is_owned(plugin_context.session, router_id):
            self._delete_router(plugin_context, router_id)

    def _create_policy_rule_set_sg(self, context, sg_name_prefix):
        # This method sets up the attributes of security group
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': sg_name_prefix + '_' + context.current['name'],
                 'description': '',
                 'security_group_rules': ''}
        sg = self._create_sg(context._plugin_context, attrs)
        # Cleanup default rules
        for rule in self._core_plugin.get_security_group_rules(
                context._plugin_context,
                filters={'security_group_id': [sg['id']]}):
            self._core_plugin.delete_security_group_rule(
                context._plugin_context, rule['id'])
        return sg

    def _handle_policy_rule_sets(self, context):
        # This method handles policy_rule_set => SG mapping
        # context is PTG context

        # for all consumed policy_rule_sets, simply associate
        # each EP's port from the PTG
        # rules are expected to be filled out already
        consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        subnets = context.current['subnets']
        ptg_id = context.current['id']
        if provided_policy_rule_sets or consumed_policy_rule_sets:
            policy_rule_sets = (
                consumed_policy_rule_sets + provided_policy_rule_sets)
            self._handle_redirect_action(context, policy_rule_sets)
        self._set_sg_rules_for_subnets(context, subnets,
                                       provided_policy_rule_sets,
                                       consumed_policy_rule_sets)
        self._update_sgs_on_ptg(context, ptg_id, provided_policy_rule_sets,
                                consumed_policy_rule_sets, "ASSOCIATE")

    # updates sg rules corresponding to a policy rule
    def _update_policy_rule_sg_rules(self, context, policy_rule_sets,
                                     policy_rule, old_classifier=None,
                                     new_classifier=None):
        policy_rule_set_list = context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': policy_rule_sets})
        for policy_rule_set in policy_rule_set_list:
            filtered_rules = self._get_enforced_prs_rules(context,
                                                          policy_rule_set)
            if policy_rule in filtered_rules:
                policy_rule_set_sg_mappings = (
                    self._get_policy_rule_set_sg_mapping(
                        context._plugin_context.session,
                        policy_rule_set['id']))
                cidr_mapping = self._get_cidrs_mapping(
                    context, policy_rule_set)
                self._add_or_remove_policy_rule_set_rule(
                    context, policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, unset=True, unset_egress=True,
                    classifier=old_classifier)
                self._add_or_remove_policy_rule_set_rule(
                    context, policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, classifier=new_classifier)

    def _set_policy_ipaddress_mapping(self, session, service_policy_id,
                                      policy_target_group, ipaddress):
        with session.begin(subtransactions=True):
            mapping = ServicePolicyPTGIpAddressMapping(
                service_policy_id=service_policy_id,
                policy_target_group=policy_target_group, ipaddress=ipaddress)
            session.add(mapping)

    def _get_ptg_policy_ipaddress_mapping(self, session, policy_target_group):
        with session.begin(subtransactions=True):
            return (session.query(ServicePolicyPTGIpAddressMapping).
                    filter_by(policy_target_group=policy_target_group).first())

    def _delete_policy_ipaddress_mapping(self, session, policy_target_group):
        with session.begin(subtransactions=True):
            mappings = session.query(
                ServicePolicyPTGIpAddressMapping).filter_by(
                    policy_target_group=policy_target_group).first()
            for ip_map in mappings:
                session.delete(ip_map)

    def _handle_redirect_spec_id_update(self, context):
        if (context.current['action_type'] != gconst.GP_ACTION_REDIRECT
            or context.current['action_value'] ==
            context.original['action_value']):
            return
        spec = self._servicechain_plugin._get_servicechain_spec(
                    context._plugin_context, context.original['action_value'])
        for servicechain_instance in spec.instances:
            sc_instance_update_req = {
                    'servicechain_specs': [context.current['action_value']]}
            self._update_resource(
                        self._servicechain_plugin,
                        context._plugin_context,
                        'servicechain_instance',
                        servicechain_instance.servicechain_instance_id,
                        sc_instance_update_req)

    def _get_rule_ids_for_actions(self, context, action_id):
        policy_rule_qry = context.session.query(
                            gpdb.PolicyRuleActionAssociation.policy_rule_id)
        policy_rule_qry.filter_by(policy_action_id=action_id)
        return policy_rule_qry.all()

    # This method is invoked from both PTG create and classifier update
    # TODO(Magesh): Handle classifier updates gracefully by invoking service
    # chain instance update. This requires having an extra mapping between PRS
    # and service chain instance, navigating though parent-child PRS and also
    # changes in service chain implementation as no resources is directly
    # getting updated in service chain instance
    def _handle_redirect_action(self, context, policy_rule_set_ids):
        policy_rule_sets = context._plugin.get_policy_rule_sets(
                                    context._plugin_context,
                                    filters={'id': policy_rule_set_ids})
        for policy_rule_set in policy_rule_sets:
            ptgs_consuming_prs = policy_rule_set[
                                            'consuming_policy_target_groups']
            ptgs_providing_prs = policy_rule_set[
                                            'providing_policy_target_groups']

            # Create the ServiceChain Instance when we have both Provider and
            # consumer PTGs. If Labels are available, they have to be applied
            if not ptgs_consuming_prs or not ptgs_providing_prs:
                continue

            parent_classifier_id = None
            parent_spec_id = None
            if policy_rule_set['parent_id']:
                parent = context._plugin.get_policy_rule_set(
                    context._plugin_context, policy_rule_set['parent_id'])
                policy_rules = context._plugin.get_policy_rules(
                                    context._plugin_context,
                                    filters={'id': parent['policy_rules']})
                for policy_rule in policy_rules:
                    policy_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': policy_rule["policy_actions"],
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
                    if policy_actions:
                        parent_spec_id = policy_actions[0].get("action_value")
                        parent_classifier_id = policy_rule.get(
                                                    "policy_classifier_id")
                        break  # only one redirect action is supported
            policy_rules = context._plugin.get_policy_rules(
                    context._plugin_context,
                    filters={'id': policy_rule_set['policy_rules']})
            for policy_rule in policy_rules:
                classifier_id = policy_rule.get("policy_classifier_id")
                if parent_classifier_id and not set(
                                [parent_classifier_id]) & set([classifier_id]):
                    continue
                policy_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': policy_rule.get("policy_actions"),
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
                for policy_action in policy_actions:
                    for ptg_consuming_prs in ptgs_consuming_prs:
                        for ptg_providing_prs in ptgs_providing_prs:
                            ptg_chain_map = (
                                        self._get_ptg_servicechain_mapping(
                                            context._plugin_context.session,
                                            ptg_providing_prs,
                                            ptg_consuming_prs))
                            # REVISIT(Magesh): There may be concurrency
                            # issues here.
                            for ptg_chain in ptg_chain_map:
                                self._delete_servicechain_instance(
                                    context,
                                    ptg_chain.servicechain_instance_id)
                            sc_instance = self._create_servicechain_instance(
                                context, policy_action.get("action_value"),
                                parent_spec_id, ptg_providing_prs,
                                ptg_consuming_prs, classifier_id)
                            self._set_ptg_servicechain_instance_mapping(
                                context._plugin_context.session,
                                ptg_providing_prs, ptg_consuming_prs,
                                sc_instance['id'])

    def _cleanup_redirect_action(self, context):
        for ptg_chain in context.ptg_chain_map:
            self._delete_servicechain_instance(
                            context, ptg_chain.servicechain_instance_id)

    # The following methods perform the necessary subset of
    # functionality from neutron.api.v2.base.Controller.
    #
    # REVISIT(rkukura): Can we just use the WSGI Controller?  Using
    # neutronclient is also a possibility, but presents significant
    # issues to unit testing as well as overhead and failure modes.

    def _create_port(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context, 'port',
                                     attrs)

    def _update_port(self, plugin_context, port_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context, 'port',
                                     port_id, attrs)

    def _delete_port(self, plugin_context, port_id):
        self._delete_resource(self._core_plugin,
                              plugin_context, 'port', port_id)

    def _create_subnet(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'subnet', attrs)

    def _update_subnet(self, plugin_context, subnet_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'subnet', subnet_id, attrs)

    def _delete_subnet(self, plugin_context, subnet_id):
        self._delete_resource(self._core_plugin, plugin_context, 'subnet',
                              subnet_id)

    def _create_network(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'network', attrs)

    def _delete_network(self, plugin_context, network_id):
        self._delete_resource(self._core_plugin, plugin_context,
                              'network', network_id)

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
        self._l3_plugin.remove_router_interface(plugin_context, router_id,
                                                interface_info)

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
        self._delete_resource(self._l3_plugin, plugin_context, 'router',
                              router_id)

    def _create_sg(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'security_group', attrs)

    def _update_sg(self, plugin_context, sg_id, attrs):
        return self._update_resouce(self._core_plugin, plugin_context,
                                    'security_group', sg_id, attrs)

    def _delete_sg(self, plugin_context, sg_id):
        self._delete_resource(self._core_plugin, plugin_context,
                              'security_group', sg_id)

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
        self._delete_resource(self._core_plugin, plugin_context,
                              'security_group_rule', sg_rule_id)

    def _restore_ip_to_allocation_pool(self, context, subnet_id, ip_address):
        # TODO(Magesh):Pass subnets and loop on subnets. Better to add logic
        # to Merge the pools together after Fragmentation
        subnet = self._core_plugin.get_subnet(context._plugin_context,
                                              subnet_id)
        allocation_pools = subnet['allocation_pools']
        for allocation_pool in allocation_pools:
            pool_end_ip = allocation_pool.get('end')
            if ip_address == str(netaddr.IPAddress(pool_end_ip) + 1):
                new_last_ip = ip_address
                allocation_pool['end'] = new_last_ip
                del subnet['gateway_ip']
                subnet = self._update_subnet(context._plugin_context,
                                             subnet['id'], subnet)
                return
        # TODO(Magesh):Have to test this logic. Add proper unit tests
        subnet['allocation_pools'].append({"start": ip_address,
                                          "end": ip_address})
        del subnet['gateway_ip']
        subnet = self._update_subnet(context._plugin_context,
                                     subnet['id'], subnet)

    def _remove_ip_from_allocation_pool(self, context, subnet_id, ip_address):
        # TODO(Magesh):Pass subnets and loop on subnets
        subnet = self._core_plugin.get_subnet(context._plugin_context,
                                              subnet_id)
        allocation_pools = subnet['allocation_pools']
        for allocation_pool in reversed(allocation_pools):
            if ip_address == allocation_pool.get('end'):
                new_last_ip = str(netaddr.IPAddress(ip_address) - 1)
                allocation_pool['end'] = new_last_ip
                del subnet['gateway_ip']
                self._update_subnet(context._plugin_context,
                                    subnet['id'], subnet)
                break

    def _get_last_free_ip(self, context, subnets):
        # Hope lock_mode update is not needed
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool)
        for subnet_id in subnets:
            ip_range = range_qry.filter_by(subnet_id=subnet_id).first()
            if not ip_range:
                continue
            ip_address = ip_range['last_ip']
            return ip_address

    def _create_servicechain_instance(self, context, servicechain_spec,
                                      parent_servicechain_spec,
                                      provider_ptg_id, consumer_ptg_id,
                                      classifier_id,
                                      config_params=None):
        sc_spec = [servicechain_spec]
        if parent_servicechain_spec:
            sc_spec.insert(0, parent_servicechain_spec)
        config_param_values = {}
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, provider_ptg_id)
        network_service_policy_id = ptg.get("network_service_policy_id")
        if network_service_policy_id:
            nsp = context._plugin.get_network_service_policy(
                context._plugin_context, network_service_policy_id)
            service_params = nsp.get("network_service_params")
            # Supporting only one value now
            param_type = service_params[0].get("type")
            if param_type == "ip_single":
                key = service_params[0].get("name")
                servicepolicy_ptg_ip_map = self._get_service_policy_ipaddress(
                    context, provider_ptg_id)
                servicepolicy_ip = servicepolicy_ptg_ip_map.get("ipaddress")
                config_param_values[key] = servicepolicy_ip

        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'gbp_' + context.current['name'],
                 'description': "",
                 'servicechain_specs': sc_spec,
                 'provider_ptg_id': provider_ptg_id,
                 'consumer_ptg_id': consumer_ptg_id,
                 'classifier_id': classifier_id,
                 'config_param_values': jsonutils.dumps(config_param_values)}
        return self._create_resource(self._servicechain_plugin,
                                     context._plugin_context,
                                     'servicechain_instance', attrs)

    def _delete_servicechain_instance(self, context, servicechain_instance_id):
        self._delete_resource(self._servicechain_plugin,
                              context._plugin_context,
                              'servicechain_instance',
                              servicechain_instance_id)

    def _create_resource(self, plugin, context, resource, attrs):
        # REVISIT(rkukura): Do create.start notification?
        # REVISIT(rkukura): Check authorization?
        # REVISIT(rkukura): Do quota?
        action = 'create_' + resource
        obj_creator = getattr(plugin, action)
        obj = obj_creator(context, {resource: attrs})
        self._nova_notifier.send_network_change(action, {}, {resource: obj})
        # REVISIT(rkukura): Do create.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.create.end')
        return obj

    def _update_resource(self, plugin, context, resource, resource_id, attrs):
        # REVISIT(rkukura): Do update.start notification?
        # REVISIT(rkukura): Check authorization?
        obj_getter = getattr(plugin, 'get_' + resource)
        orig_obj = obj_getter(context, resource_id)
        action = 'update_' + resource
        obj_updater = getattr(plugin, action)
        obj = obj_updater(context, resource_id, {resource: attrs})
        self._nova_notifier.send_network_change(action, orig_obj,
                                                {resource: obj})
        # REVISIT(rkukura): Do update.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.update.end')
        return obj

    def _delete_resource(self, plugin, context, resource, resource_id):
        # REVISIT(rkukura): Do delete.start notification?
        # REVISIT(rkukura): Check authorization?
        obj_getter = getattr(plugin, 'get_' + resource)
        obj = obj_getter(context, resource_id)
        action = 'delete_' + resource
        obj_deleter = getattr(plugin, action)
        obj_deleter(context, resource_id)
        self._nova_notifier.send_network_change(action, {}, {resource: obj})
        # REVISIT(rkukura): Do delete.end notification?
        if cfg.CONF.dhcp_agent_notification:
            self._dhcp_agent_notifier.notify(context,
                                             {resource: obj},
                                             resource + '.delete.end')

    def _get_resource(self, plugin, context, resource, resource_id):
        obj_getter = getattr(plugin, 'get_' + resource)
        obj = obj_getter(context, resource_id)
        return obj

    def _get_resources(self, plugin, context, resource, filters=[]):
        obj_getter = getattr(plugin, 'get_' + resource + 's')
        obj = obj_getter(context, filters)
        return obj

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

    def _mark_port_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            owned = OwnedPort(port_id=port_id)
            session.add(owned)

    def _port_is_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedPort).
                    filter_by(port_id=port_id).
                    first() is not None)

    def _mark_subnet_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            owned = OwnedSubnet(subnet_id=subnet_id)
            session.add(owned)

    def _subnet_is_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedSubnet).
                    filter_by(subnet_id=subnet_id).
                    first() is not None)

    def _mark_network_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            owned = OwnedNetwork(network_id=network_id)
            session.add(owned)

    def _network_is_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedNetwork).
                    filter_by(network_id=network_id).
                    first() is not None)

    def _mark_router_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            owned = OwnedRouter(router_id=router_id)
            session.add(owned)

    def _router_is_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedRouter).
                    filter_by(router_id=router_id).
                    first() is not None)

    def _set_policy_rule_set_sg_mapping(
        self, session, policy_rule_set_id, consumed_sg_id, provided_sg_id):
        with session.begin(subtransactions=True):
            mapping = PolicyRuleSetSGsMapping(
                policy_rule_set_id=policy_rule_set_id,
                consumed_sg_id=consumed_sg_id, provided_sg_id=provided_sg_id)
            session.add(mapping)

    @staticmethod
    def _get_policy_rule_set_sg_mapping(session, policy_rule_set_id):
        with session.begin(subtransactions=True):
            return (session.query(PolicyRuleSetSGsMapping).
                    filter_by(policy_rule_set_id=policy_rule_set_id).one())

    def _sg_rule(self, plugin_context, tenant_id, sg_id, direction,
                 protocol=None, port_range=None, cidr=None,
                 ethertype=const.IPv4, unset=False):
        if port_range:
            port_min, port_max = (gpdb.GroupPolicyDbPlugin.
                                  _get_min_max_ports_from_range(port_range))
        else:
            port_min, port_max = None, None

        attrs = {'tenant_id': tenant_id,
                 'security_group_id': sg_id,
                 'direction': direction,
                 'ethertype': ethertype,
                 'protocol': protocol,
                 'port_range_min': port_min,
                 'port_range_max': port_max,
                 'remote_ip_prefix': cidr,
                 'remote_group_id': None}
        if unset:
            filters = {}
            for key in attrs:
                value = attrs[key]
                if value:
                    filters[key] = [value]
            rule = self._core_plugin.get_security_group_rules(
                plugin_context, filters)
            if rule:
                self._delete_sg_rule(plugin_context, rule[0]['id'])
        else:
            return self._create_sg_rule(plugin_context, attrs)

    def _sg_ingress_rule(self, context, sg_id, protocol, port_range, cidr,
                         unset=False):
        return self._sg_rule(
            context._plugin_context, context.current['tenant_id'], sg_id,
            'ingress', protocol, port_range, cidr, unset=unset)

    def _sg_egress_rule(self, context, sg_id, protocol, port_range,
                        cidr, unset=False):
        return self._sg_rule(
            context._plugin_context, context.current['tenant_id'], sg_id,
            'egress', protocol, port_range, cidr, unset=unset)

    def _assoc_sgs_to_pt(self, context, pt_id, sg_list):
        pt = context._plugin.get_policy_target(context._plugin_context, pt_id)
        port_id = pt['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        cur_sg_list = port[ext_sg.SECURITYGROUPS]
        new_sg_list = cur_sg_list + sg_list
        port[ext_sg.SECURITYGROUPS] = new_sg_list
        self._update_port(context._plugin_context, port_id, port)

    def _disassoc_sgs_from_pt(self, context, pt_id, sg_list):
        pt = context._plugin.get_policy_target(context._plugin_context, pt_id)
        port_id = pt['port_id']
        self._disassoc_sgs_from_port(context._plugin_context, port_id, sg_list)

    def _disassoc_sgs_from_port(self, plugin_context, port_id, sg_list):
        try:
            port = self._core_plugin.get_port(plugin_context, port_id)
            cur_sg_list = port[ext_sg.SECURITYGROUPS]
            new_sg_list = list(set(cur_sg_list) - set(sg_list))
            port[ext_sg.SECURITYGROUPS] = new_sg_list
            self._update_port(plugin_context, port_id, port)
        except n_exc.PortNotFound:
            LOG.warn(_("Port %s is missing") % port_id)

    def _generate_list_of_sg_from_ptg(self, context, ptg_id):
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        provided_policy_rule_sets = ptg['provided_policy_rule_sets']
        consumed_policy_rule_sets = ptg['consumed_policy_rule_sets']
        return(self._generate_list_sg_from_policy_rule_set_list(
            context, provided_policy_rule_sets, consumed_policy_rule_sets))

    def _generate_list_sg_from_policy_rule_set_list(self, context,
                                                    provided_policy_rule_sets,
                                                    consumed_policy_rule_sets):
        ret_list = []
        for policy_rule_set_id in provided_policy_rule_sets:
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set_id)
            provided_sg_id = policy_rule_set_sg_mappings['provided_sg_id']
            ret_list.append(provided_sg_id)

        for policy_rule_set_id in consumed_policy_rule_sets:
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set_id)
            consumed_sg_id = policy_rule_set_sg_mappings['consumed_sg_id']
            ret_list.append(consumed_sg_id)
        return ret_list

    def _assoc_ptg_sg_to_pt(self, context, pt_id, ptg_id):
        sg_list = self._generate_list_of_sg_from_ptg(context, ptg_id)
        self._assoc_sgs_to_pt(context, pt_id, sg_list)

    def _update_sgs_on_pt_with_ptg(self, context, ptg_id, new_pt_list, op):
        sg_list = self._generate_list_of_sg_from_ptg(context, ptg_id)
        for pt_id in new_pt_list:
            if op == "ASSOCIATE":
                self._assoc_sgs_to_pt(context, pt_id, sg_list)
            else:
                self._disassoc_sgs_from_pt(context, pt_id, sg_list)

    def _update_sgs_on_ptg(self, context, ptg_id, provided_policy_rule_sets,
                           consumed_policy_rule_sets, op):
        sg_list = self._generate_list_sg_from_policy_rule_set_list(
            context, provided_policy_rule_sets, consumed_policy_rule_sets)
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        policy_target_list = ptg['policy_targets']
        for pt_id in policy_target_list:
            if op == "ASSOCIATE":
                self._assoc_sgs_to_pt(context, pt_id, sg_list)
            else:
                self._disassoc_sgs_from_pt(context, pt_id, sg_list)

    def _set_or_unset_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=False):
        if not provided_policy_rule_sets and not consumed_policy_rule_sets:
            return

        cidr_list = []
        for subnet_id in subnets:
            subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                  subnet_id)
            cidr = subnet['cidr']
            cidr_list.append(cidr)
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=unset)

    # context should be PTG
    def _set_sg_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets):
        self._set_or_unset_rules_for_subnets(
            context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets)

    def _unset_sg_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets):
        self._set_or_unset_rules_for_subnets(
            context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=True)

    def _set_sg_rules_for_cidrs(self, context, cidr_list,
                                provided_policy_rule_sets,
                                consumed_policy_rule_sets):
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets)

    def _unset_sg_rules_for_cidrs(self, context, cidr_list,
                                  provided_policy_rule_sets,
                                  consumed_policy_rule_sets):
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=True)

    def _set_or_unset_rules_for_cidrs(self, context, cidr_list,
                                      provided_policy_rule_sets,
                                      consumed_policy_rule_sets, unset=False):
        prov_cons = ['providing_cidrs', 'consuming_cidrs']
        for pos, policy_rule_sets in enumerate(
                [provided_policy_rule_sets, consumed_policy_rule_sets]):
            for policy_rule_set_id in policy_rule_sets:
                policy_rule_set = context._plugin.get_policy_rule_set(
                    context._plugin_context, policy_rule_set_id)
                policy_rule_set_sg_mappings = (
                    self._get_policy_rule_set_sg_mapping(
                        context._plugin_context.session, policy_rule_set_id))
                cidr_mapping = {prov_cons[pos]: cidr_list,
                                prov_cons[pos - 1]: []}
                if not unset:
                    policy_rules = self._get_enforced_prs_rules(
                        context, policy_rule_set)
                else:
                    # Not need to filter when removing rules
                    policy_rules = context._plugin.get_policy_rules(
                        context._plugin_context,
                        {'id': policy_rule_set['policy_rules']})
                for policy_rule in policy_rules:
                    self._add_or_remove_policy_rule_set_rule(
                        context, policy_rule, policy_rule_set_sg_mappings,
                        cidr_mapping, unset=unset)

    def _manage_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, unset=False,
                                      unset_egress=False):
        policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set['id'])
        policy_rule_set = context._plugin.get_policy_rule_set(
            context._plugin_context, policy_rule_set['id'])
        cidr_mapping = self._get_cidrs_mapping(context, policy_rule_set)
        for policy_rule in policy_rules:
            self._add_or_remove_policy_rule_set_rule(
                context, policy_rule, policy_rule_set_sg_mappings,
                cidr_mapping, unset=unset, unset_egress=unset_egress)

    def _add_or_remove_policy_rule_set_rule(self, context, policy_rule,
                                            policy_rule_set_sg_mappings,
                                            cidr_mapping, unset=False,
                                            unset_egress=False,
                                            classifier=None):
        in_out = [gconst.GP_DIRECTION_IN, gconst.GP_DIRECTION_OUT]
        prov_cons = [policy_rule_set_sg_mappings['provided_sg_id'],
                     policy_rule_set_sg_mappings['consumed_sg_id']]
        cidr_prov_cons = [cidr_mapping['providing_cidrs'],
                          cidr_mapping['consuming_cidrs']]

        if not classifier:
            classifier_id = policy_rule['policy_classifier_id']
            classifier = context._plugin.get_policy_classifier(
                context._plugin_context, classifier_id)

        protocol = classifier['protocol']
        port_range = classifier['port_range']

        for pos, sg in enumerate(prov_cons):
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos]]:
                for cidr in cidr_prov_cons[pos - 1]:
                    self._sg_ingress_rule(context, sg, protocol, port_range,
                                          cidr, unset=unset)
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos - 1]]:
                # TODO(ivar): IPv6 support
                self._sg_egress_rule(context, sg, protocol, port_range,
                                     '0.0.0.0/0', unset=unset_egress)

    def _apply_policy_rule_set_rules(self, context, policy_rule_set,
                                     policy_rules):
        policy_rules = self._get_enforced_prs_rules(
            context, policy_rule_set, subset=[x['id'] for x in policy_rules])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules)

    def _remove_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            unset_egress=True)

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
            # Old parent may have filtered some rules, need to add them again
            child_rules = context._plugin.get_policy_rules(
                context._plugin_context, filters={'id': child_rule_ids})
            self._apply_policy_rule_set_rules(context, child, child_rules)

    def _get_default_security_group(self, plugin_context, ptg_id,
                                    tenant_id):
        port_name = 'gbp_%s' % ptg_id
        filters = {'name': [port_name], 'tenant_id': [tenant_id]}
        default_group = self._core_plugin.get_security_groups(
            plugin_context, filters)
        return default_group[0]['id'] if default_group else None

    def _update_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id, subnets=None):

        sg_id = self._get_default_security_group(plugin_context, ptg_id,
                                                 tenant_id)
        ip_v = {4: const.IPv4, 6: const.IPv6}
        if not sg_id:
            port_name = 'gbp_%s' % ptg_id
            attrs = {'name': port_name, 'tenant_id': tenant_id,
                     'description': 'default'}
            sg_id = self._create_sg(plugin_context, attrs)['id']

        for subnet in self._core_plugin.get_subnets(
                plugin_context, filters={'id': subnets or []}):
            self._sg_rule(plugin_context, tenant_id, sg_id,
                          'ingress', cidr=subnet['cidr'],
                          ethertype=ip_v[subnet['ip_version']])
        return sg_id

    def _delete_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id):
        sg_id = self._get_default_security_group(plugin_context, ptg_id,
                                                 tenant_id)
        if sg_id:
            self._delete_sg(plugin_context, sg_id)

    def _get_ptgs_by_id(self, context, ids):
        if ids:
            filters = {'id': ids}
            return context._plugin.get_policy_target_groups(
                context._plugin_context, filters)
        else:
            return []

    def _get_ptg_cidrs(self, context, ptgs):
        cidrs = []
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context, filters={'id': ptgs})
        for ptg in ptgs:
            cidrs.extend([self._core_plugin.get_subnet(
                context._plugin_context, x)['cidr'] for x in ptg['subnets']])
        return cidrs

    def _get_ep_cidrs(self, context, eps):
        cidrs = []
        eps = context._plugin.get_external_policies(
            context._plugin_context, filters={'id': eps})
        for ep in eps:
            cidrs.extend(self._get_processed_ep_cidr_list(context, ep))
        return cidrs

    def _get_cidrs_mapping(self, context, policy_rule_set):
        providing_eps = policy_rule_set['providing_external_policies']
        consuming_eps = policy_rule_set['consuming_external_policies']
        providing_ptgs = policy_rule_set['providing_policy_target_groups']
        consuming_ptgs = policy_rule_set['consuming_policy_target_groups']
        return {
            'providing_cidrs': self._get_ptg_cidrs(
                context, providing_ptgs) + self._get_ep_cidrs(context,
                                                              providing_eps),
            'consuming_cidrs': self._get_ptg_cidrs(
                context, consuming_ptgs) + self._get_ep_cidrs(context,
                                                              consuming_eps)}

    def _set_ptg_servicechain_instance_mapping(self, session, provider_ptg_id,
                                               consumer_ptg_id,
                                               servicechain_instance_id):
        with session.begin(subtransactions=True):
            mapping = PtgServiceChainInstanceMapping(
                provider_ptg_id=provider_ptg_id,
                consumer_ptg_id=consumer_ptg_id,
                servicechain_instance_id=servicechain_instance_id)
            session.add(mapping)

    def _get_ptg_servicechain_mapping(self, session, provider_ptg_id,
                                      consumer_ptg_id):
        with session.begin(subtransactions=True):
            query = session.query(PtgServiceChainInstanceMapping)
            if provider_ptg_id:
                query = query.filter_by(provider_ptg_id=provider_ptg_id)
            if consumer_ptg_id:
                query = query.filter_by(consumer_ptg_id=consumer_ptg_id)
            return query.all()

    def _get_ep_cidr_list(self, context, ep):
        es_list = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': ep['external_segments']})
        cidr_list = []
        for es in es_list:
            cidr_list += [x['destination'] for x in es['external_routes']]
        return cidr_list

    def _process_external_cidrs(self, context, cidrs, exclude=None):
        # Get all the tenant's L3P
        exclude = exclude or []
        l3ps = context._plugin.get_l3_policies(
            context._plugin_context,
            filters={'tenant_id': [context.current['tenant_id']]})

        ip_pool_list = [x['ip_pool'] for x in l3ps if
                        x['ip_pool'] not in exclude]
        l3p_set = netaddr.IPSet(ip_pool_list)
        return [str(x) for x in (netaddr.IPSet(cidrs) - l3p_set).iter_cidrs()]

    def _get_processed_ep_cidr_list(self, context, ep):
        cidr_list = self._get_ep_cidr_list(context, ep)
        return self._process_external_cidrs(context, cidr_list)

    def _recompute_external_policy_rules(self, context, ep_ids, new_cidrs,
                                         old_cidrs):
        # the EPs could belong to different tenants, need admin context
        admin_context = n_context.get_admin_context()
        ep_list = context._plugin.get_external_policies(admin_context,
                                                        filters={'id': ep_ids})
        for ep in ep_list:
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _recompute_l3_policy_routes(self, context, new_routes, old_routes):
        # the L3Ps could belong to different tenants, need admin context
        admin_context = n_context.get_admin_context()
        added_routes = new_routes - old_routes
        removed_routes = old_routes - new_routes
        l3ps = context._plugin.get_l3_policies(
            admin_context, filters={'id': context.current['l3_policies']})
        for l3p in l3ps:
            router = self._l3_plugin.get_routes(
                admin_context, l3p['router_id'])
            current_routes = set((x['destination'], x['nexthop']) for x in
                                 router['routes'])
            current_routes = (current_routes - removed_routes |
                              added_routes)
            current_routes = [{'destination': x[0], 'nexthop': x[1]} for x
                              in current_routes if x[1]]
            self._update_router(admin_context, l3p['router_id'],
                                {'routes': current_routes})

    def _refresh_ep_cidrs_rules(self, context, ep, new_cidrs, old_cidrs):
        # REVISIT(ivar): calculate cidrs delta to minimize disruption
        # Unset old rules
        self._unset_sg_rules_for_cidrs(
            context, old_cidrs, ep['provided_policy_rule_sets'],
            ep['consumed_policy_rule_sets'])
        # Set new rules
        self._set_sg_rules_for_cidrs(
            context, new_cidrs, ep['provided_policy_rule_sets'],
            ep['consumed_policy_rule_sets'])

    def _process_new_l3p_ip_pool(self, context, ip_pool):
        # Get all the EP for this tenant
        ep_list = context._plugin.get_external_policies(
            context._plugin_context,
            filters={'tenant_id': context.current['tenant_id']})
        for ep in ep_list:
            # Remove rules before the new ip_pool came
            cidr_list = self._get_ep_cidr_list(context, ep)
            old_cidrs = self._process_external_cidrs(context, cidr_list,
                                                     exclude=[ip_pool])
            new_cidrs = [str(x) for x in
                         (netaddr.IPSet(old_cidrs) -
                          netaddr.IPSet([ip_pool])).iter_cidrs()]
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _process_remove_l3p_ip_pool(self, context, ip_pool):
        # Get all the EP for this tenant
        ep_list = context._plugin.get_external_policies(
            context._plugin_context,
            filters={'tenant_id': context.current['tenant_id']})
        for ep in ep_list:
            # Cidrs before the ip_pool removal
            cidr_list = self._get_ep_cidr_list(context, ep)
            new_cidrs = self._process_external_cidrs(context, cidr_list,
                                                     exclude=[ip_pool])
            # Cidrs after the ip_pool removal
            old_cidrs = [str(x) for x in
                         (netaddr.IPSet(new_cidrs) |
                          netaddr.IPSet([ip_pool])).iter_cidrs()]
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _set_l3p_routes(self, context, es_ids=None):
        es_ids = es_ids or context.current['external_segments'].keys()
        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_ids})
        routes = []
        for es in es_list:
            routes += es['external_routes']
        # NOTE(ivar): the context needs to be elevated because the external
        # gateway port is created by Neutron without any tenant_id! Which makes
        # it visible only from an admin context.
        self._update_router(context._plugin_context.elevated(),
                            context.current['routers'][0],
                            {'routes': [x for x in routes if x['nexthop']]})

    def _validate_ptg_subnets(self, context, subnets=None):
        if subnets or context.current['subnets']:
            l2p_id = context.current['l2_policy_id']
            l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                l2p_id)
            # Validate explicit subnet belongs to L2P's network
            network_id = l2p['network_id']
            network = self._core_plugin.get_network(context._plugin_context,
                                                    network_id)
            for subnet_id in subnets or context.current['subnets']:
                if subnet_id not in network['subnets']:
                    raise exc.InvalidSubnetForPTG(subnet_id=subnet_id,
                                                  network_id=network_id,
                                                  l2p_id=l2p['id'],
                                                  ptg_id=context.current['id'])

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

    def _validate_pt_port_subnets(self, context, subnets=None):
        # Validate if explicit port's subnet
        # is same as the subnet of PTG.
        port_id = context.current['port_id']
        core_plugin = self._core_plugin
        port = core_plugin.get_port(context._plugin_context, port_id)

        port_subnet_id = None
        fixed_ips = port['fixed_ips']
        if fixed_ips:
            # TODO(krishna-sunitha): Check if there is a case when
            # there is more than one fixed_ip?
            port_subnet_id = fixed_ips[0]['subnet_id']

        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
                                context._plugin_context,
                                ptg_id)
        for subnet in ptg.get('subnets') or subnets:
            if subnet == port_subnet_id:
                break
        else:
            raise exc.InvalidPortForPTG(port_id=port_id,
                                ptg_subnet_id=",".join(ptg.get('subnets')),
                                port_subnet_id=port_subnet_id,
                                policy_target_group_id=ptg_id)
