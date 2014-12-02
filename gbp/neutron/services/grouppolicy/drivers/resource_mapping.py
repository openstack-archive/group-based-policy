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
from sqlalchemy.orm import exc as sql_exc

from gbp.neutron.db.grouppolicy import group_policy_db as gpdb
from gbp.neutron.db import servicechain_db  # noqa
from gbp.neutron.services.grouppolicy.common import constants as gconst
from gbp.neutron.services.grouppolicy.common import exceptions as exc
from gbp.neutron.services.grouppolicy import group_policy_driver_api as api


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

    @log.log
    def create_policy_target_precommit(self, context):
        if not context.current['policy_target_group_id']:
            raise exc.PolicyTargetRequiresPolicyTargetGroup()

    @log.log
    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        else:
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
            for subnet in ptg.get('subnets'):
                if subnet == port_subnet_id:
                    break
            else:
                raise exc.InvalidPortForPTG(port_id=port_id,
                                    ptg_subnet_id=",".join(ptg.get('subnets')),
                                    port_subnet_id=port_subnet_id,
                                    policy_target_group_id=ptg_id)

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

    @log.log
    def create_policy_target_group_postcommit(self, context):
        # TODO(rkukura): Validate explicit subnet belongs to L2P's
        # network.
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
        if set(context.original['subnets']) - set(context.current['subnets']):
            raise exc.PolicyTargetGroupSubnetRemovalNotSupported()
        self._reject_cross_tenant_ptg_l2p(context)

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
        # if PTG associated policy_rule_sets are updated, we need to update
        # the policy rules, then assoicate SGs to ports
        if new_provided_policy_rule_sets or new_consumed_policy_rule_sets:
            subnets = context.current['subnets']
            self._assoc_sg_to_ptg(context, subnets,
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

    @log.log
    def create_l3_policy_postcommit(self, context):
        if not context.current['routers']:
            self._use_implicit_router(context)

    @log.log
    def update_l3_policy_precommit(self, context):
        if context.current['routers'] != context.original['routers']:
            raise exc.L3PolicyRoutersUpdateNotSupported()

    @log.log
    def update_l3_policy_postcommit(self, context):
        pass

    @log.log
    def delete_l3_policy_precommit(self, context):
        pass

    @log.log
    def delete_l3_policy_postcommit(self, context):
        for router_id in context.current['routers']:
            self._cleanup_router(context._plugin_context, router_id)

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
        policy_rules = (context._plugin._get_policy_classifier(
                context._plugin_context,
                context.current['id'])['policy_rules'])
        for policy_rule in policy_rules:
            pr_id = policy_rule['id']
            pr_sets = context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, pr_id)
            self._update_policy_rule_sg_rules(context, pr_sets,
                policy_rule, None, context.original, context.current)

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
        pass

    @log.log
    def create_policy_rule_postcommit(self, context):
        pass

    @log.log
    def update_policy_rule_precommit(self, context):
        pass

    @log.log
    def update_policy_rule_postcommit(self, context):
        old_classifier_id = context.original['policy_classifier_id']
        new_classifier_id = context.current['policy_classifier_id']
        old_action_set = set(context.current['policy_actions'])
        new_action_set = set(context.original['policy_actions'])
        if old_classifier_id != new_classifier_id or \
                old_action_set != new_action_set:
            policy_rule_sets =\
                context._plugin._get_policy_rule_policy_rule_sets(
                    context._plugin_context, context.current['id'])
            self._update_policy_rule_sg_rules(context, policy_rule_sets,
                    context.original, context.current)

    @log.log
    def delete_policy_rule_precommit(self, context):
        # REVISIT(ivar): This will be removed once navigability issue is
        # solved (bug/1384397)
        context._rmd_policy_rule_sets_temp = (
            context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, context.current['id']))

    @log.log
    def delete_policy_rule_postcommit(self, context):
        for policy_rule_set_id in context._rmd_policy_rule_sets_temp:
            policy_rule_set = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set_id)
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set['id'])
            cidr_mapping = self._get_ptg_cidrs_mapping(
                context, policy_rule_set)
            self._add_or_remove_policy_rule_set_rule(
                context, context.current, policy_rule_set_sg_mappings,
                cidr_mapping, unset=True)

    @log.log
    def create_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

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
        self._apply_policy_rule_set_rules(
            context, context.current, context.current['policy_rules'])

    @log.log
    def update_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

    @log.log
    def update_policy_rule_set_postcommit(self, context):
        # Update policy_rule_set rules
        old_rules = set(context.original['policy_rules'])
        new_rules = set(context.current['policy_rules'])
        to_add = new_rules - old_rules
        to_remove = old_rules - new_rules
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

    @log.log
    def delete_network_service_policy_postcommit(self, context):
        for ptg_id in context.current.get("policy_target_groups"):
            ptg = context._plugin.get_policy_target_group(
                context._plugin_context, ptg_id)
            subnet = ptg.get('subnets')[0]
            self._cleanup_network_service_policy(context, subnet, ptg_id)

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
            self._delete_port(plugin_context, port_id)

    def _use_implicit_subnet(self, context):
        # REVISIT(rkukura): This is a temporary allocation algorithm
        # that depends on an exception being raised when the subnet
        # being created is already in use. A DB allocation table for
        # the pool of subnets, or at least a more efficient way to
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

    def _use_implicit_network(self, context):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'l2p_' + context.current['name'],
                 'admin_state_up': True,
                 'shared': context.current.get('shared', False)}
        network = self._create_network(context._plugin_context, attrs)
        network_id = network['id']
        self._mark_network_owned(context._plugin_context.session, network_id)
        context.set_network_id(network_id)

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
        return self._create_sg(context._plugin_context, attrs)

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
        self._assoc_sg_to_ptg(context, subnets, provided_policy_rule_sets,
                              consumed_policy_rule_sets)
        self._update_sgs_on_ptg(context, ptg_id, provided_policy_rule_sets,
                                consumed_policy_rule_sets, "ASSOCIATE")

    def _get_ptgs_providing_policy_rule_set(self, session, policy_rule_set_id):
        with session.begin(subtransactions=True):
            return (session.query(
                gpdb.PTGToPRSProvidingAssociation).filter_by(
                    policy_rule_set_id=policy_rule_set_id).first())

    def _get_ptgs_consuming_policy_rule_set(self, session, policy_rule_set_id):
        try:
            with session.begin(subtransactions=True):
                return (session.query(
                    gpdb.PTGToPRSConsumingAssociation).filter_by(
                        policy_rule_set_id=policy_rule_set_id).all())
        except sql_exc.NoResultFound:
            return None

    # updates sg rules corresponding to a policy rule
    def _update_policy_rule_sg_rules(self, context, policy_rule_sets,
                                    old_policy_rule, new_policy_rule,
                                    old_classifier=None, new_classifier=None):
        """
        for policy_rule_set_id in policy_rule_sets:
            policy_rule_set = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set_id)
        """
        policy_rule_set_list = context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': policy_rule_sets})
        for policy_rule_set in policy_rule_set_list:
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set['id'])
            cidr_mapping = self._get_ptg_cidrs_mapping(
                context, policy_rule_set)
            if old_classifier:
                self._add_or_remove_policy_rule_set_rule(
                    context, old_policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, unset=True, classifier=old_classifier)
                self._add_or_remove_policy_rule_set_rule(
                    context, old_policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, classifier=new_classifier)
            else:
                self._add_or_remove_policy_rule_set_rule(
                    context, old_policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, unset=True)
                self._add_or_remove_policy_rule_set_rule(
                    context, new_policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping)

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
        servicechain_instances = spec.instances
        for servicechain_instance in servicechain_instances:
            sc_instance_update = {
                        'servicechain_spec': context.current['action_value']}
            self._update_resource(self._servicechain_plugin,
                                  context._plugin_context,
                                  'servicechain_instance',
                                  servicechain_instance['id'],
                                  sc_instance_update)

    def _get_rule_ids_for_actions(self, context, action_id):
        policy_rule_qry = context.session.query(
                            gpdb.PolicyRuleActionAssociation.policy_rule_id)
        policy_rule_qry.filter_by(policy_action_id=action_id)
        return policy_rule_qry.all()

    def _handle_redirect_action(self, context, policy_rule_sets):
        for policy_rule_set_id in policy_rule_sets:
            ptgs_consuming_policy_rule_set = (
                self._get_ptgs_consuming_policy_rule_set(
                    context._plugin_context._session, policy_rule_set_id))
            ptg_providing_prs = (
                self._get_ptgs_providing_policy_rule_set(
                    context._plugin_context._session, policy_rule_set_id))

            # Create the ServiceChain Instance when we have both Provider and
            # consumer PTGs. If Labels are available, they have to be applied
            # here. For now we support a single provider
            if not ptgs_consuming_policy_rule_set or (
                not ptg_providing_prs):
                continue

            policy_rule_set = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set_id)
            for rule_id in policy_rule_set.get('policy_rules'):
                policy_rule = context._plugin.get_policy_rule(
                    context._plugin_context, rule_id)
                classifier_id = policy_rule.get("policy_classifier_id")
                for action_id in policy_rule.get("policy_actions"):
                    policy_action = context._plugin.get_policy_action(
                        context._plugin_context, action_id)
                    if policy_action['action_type'].upper() == "REDIRECT":
                        for ptg_consuming_prs in (
                            ptgs_consuming_policy_rule_set):
                            ptg_chain_map = self._get_ptg_servicechain_mapping(
                                    context._plugin_context.session,
                                    ptg_providing_prs.policy_target_group_id,
                                    ptg_consuming_prs.policy_target_group_id)
                            if ptg_chain_map:
                                break  # one chain between a pair of PTGs
                            sc_instance = self._create_servicechain_instance(
                                context, policy_action.get("action_value"),
                                ptg_providing_prs.policy_target_group_id,
                                ptg_consuming_prs.policy_target_group_id,
                                classifier_id)
                            chain_instance_id = sc_instance['id']
                            self._set_ptg_servicechain_instance_mapping(
                                context._plugin_context.session,
                                ptg_providing_prs.policy_target_group_id,
                                ptg_consuming_prs.policy_target_group_id,
                                chain_instance_id)
                            break

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

    def _add_router_interface(self, plugin_context, router_id, interface_info):
        self._l3_plugin.add_router_interface(plugin_context,
                                             router_id, interface_info)

    def _remove_router_interface(self, plugin_context, router_id,
                                 interface_info):
        self._l3_plugin.remove_router_interface(plugin_context, router_id,
                                                interface_info)

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
                                      provider_ptg_id, consumer_ptg_id,
                                      classifier_id, config_params=None):
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
                 'servicechain_spec': servicechain_spec,
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

    def _get_policy_rule_set_sg_mapping(self, session, policy_rule_set_id):
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
        port = self._core_plugin.get_port(plugin_context, port_id)
        cur_sg_list = port[ext_sg.SECURITYGROUPS]
        new_sg_list = list(set(cur_sg_list) - set(sg_list))
        port[ext_sg.SECURITYGROUPS] = new_sg_list
        self._update_port(plugin_context, port_id, port)

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

    # context should be PTG
    def _assoc_sg_to_ptg(self, context, subnets, provided_policy_rule_sets,
                         consumed_policy_rule_sets):
        if not provided_policy_rule_sets and not consumed_policy_rule_sets:
            return

        cidr_list = []
        for subnet_id in subnets:
            subnet = self._core_plugin.get_subnet(context._plugin_context,
                                                  subnet_id)
            cidr = subnet['cidr']
            cidr_list.append(cidr)

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
                policy_rules = policy_rule_set['policy_rules']
                for policy_rule_id in policy_rules:
                    policy_rule = context._plugin.get_policy_rule(
                        context._plugin_context, policy_rule_id)
                    self._add_or_remove_policy_rule_set_rule(
                        context, policy_rule, policy_rule_set_sg_mappings,
                        cidr_mapping)

    def _manage_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, unset=False):
        policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set['id'])
        policy_rule_set = context._plugin.get_policy_rule_set(
            context._plugin_context, policy_rule_set['id'])
        cidr_mapping = self._get_ptg_cidrs_mapping(context, policy_rule_set)
        for policy_rule_id in policy_rules:
            policy_rule = context._plugin.get_policy_rule(
                context._plugin_context, policy_rule_id)

            self._add_or_remove_policy_rule_set_rule(
                context, policy_rule, policy_rule_set_sg_mappings,
                cidr_mapping, unset=unset)

    def _add_or_remove_policy_rule_set_rule(self, context, policy_rule,
                                            policy_rule_set_sg_mappings,
                                            cidr_mapping, unset=False,
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
                self._sg_egress_rule(context, sg, protocol, port_range,
                                     '0.0.0.0/0', unset=unset)

    def _apply_policy_rule_set_rules(self, context, policy_rule_set,
                                     policy_rules):
        if policy_rule_set['parent_id']:
            parent = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set['parent_id'])
            policy_rules = policy_rules & set(parent['policy_rules'])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules)

    def _remove_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True)

    def _recompute_policy_rule_sets(self, context, children):
        # Rules in child but not in parent shall be removed
        # Child rules will be set after being filtered by the parent
        for child in children:
            child = context._plugin.get_policy_rule_set(
                context._plugin_context, child)
            child_rules = set(child['policy_rules'])
            if child['parent_id']:
                parent = context._plugin.get_policy_rule_set(
                    context._plugin_context, child['parent_id'])
                parent_rules = set(parent['policy_rules'])
                self._remove_policy_rule_set_rules(
                    context, child, child_rules - parent_rules)
            # Old parent may have filtered some rules, need to add them again
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

    def _get_ptg_cidrs_mapping(self, context, policy_rule_set):
        return {
            'providing_cidrs': self._get_ptg_cidrs(
                context, policy_rule_set['providing_policy_target_groups']),
            'consuming_cidrs': self._get_ptg_cidrs(
                context, policy_rule_set['consuming_policy_target_groups'])}

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
