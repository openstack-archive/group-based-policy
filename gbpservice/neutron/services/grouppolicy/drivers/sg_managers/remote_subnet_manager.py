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
from neutron.common import exceptions as n_exc
from neutron import context as n_context
from neutron.db import model_base
from neutron.extensions import securitygroup as ext_sg
from oslo_log import log as logging
import sqlalchemy as sa

from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.grouppolicy.drivers.sg_managers import (
    sg_manager_base as base)

LOG = logging.getLogger(__name__)


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


def set_policy_rule_set_sg_mapping(session, policy_rule_set_id, consumed_sg_id,
                                   provided_sg_id):
    with session.begin(subtransactions=True):
        mapping = PolicyRuleSetSGsMapping(
            policy_rule_set_id=policy_rule_set_id,
            consumed_sg_id=consumed_sg_id, provided_sg_id=provided_sg_id)
        session.add(mapping)


def get_policy_rule_set_sg_mapping(session, policy_rule_set_id):
    with session.begin(subtransactions=True):
        return (session.query(PolicyRuleSetSGsMapping).
                filter_by(policy_rule_set_id=policy_rule_set_id).one())


class RemoteSubnetManager(base.SecurityGroupManagerBase):

    def handle_policy_target_create(self, context):
        self._assoc_ptg_sg_to_pt(context, context.current['id'],
                                 context.current['policy_target_group_id'])

    def handle_policy_target_delete(self, context):
        sg_list = self._generate_list_of_sg_from_ptg(
            context, context.current['policy_target_group_id'])
        self._disassoc_sgs_from_port(context._plugin_context,
                                     context.current['port_id'], sg_list)

    def handle_policy_target_group_create(self, context):
        consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        subnets = context.current['subnets']
        ptg_id = context.current['id']
        self._set_sg_rules_for_subnets(context, subnets,
                                       provided_policy_rule_sets,
                                       consumed_policy_rule_sets)
        self._update_sgs_on_ptg(context, ptg_id, provided_policy_rule_sets,
                                consumed_policy_rule_sets, "ASSOCIATE")

    def handle_policy_target_group_update(self, context):
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
            self._set_sg_rules_for_subnets(
                context, subnets, new_provided_policy_rule_sets,
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

    def handle_policy_target_group_delete(self, context):
        # Cleanup SGs
        self._unset_sg_rules_for_subnets(
            context, context.current['subnets'],
            context.current['provided_policy_rule_sets'],
            context.current['consumed_policy_rule_sets'])

    def validate_l3_policy_create(self, context):
        # Validate non overlapping IPs in the same tenant
        curr = context.current
        l3ps = context._plugin.get_l3_policies(
            context._plugin_context, {'tenant_id': [curr['tenant_id']]})
        subnets = [x['ip_pool'] for x in l3ps if x['id'] != curr['id']]
        current_set = netaddr.IPSet(subnets)
        if netaddr.IPSet([curr['ip_pool']]) & current_set:
            raise exc.OverlappingIPPoolsInSameTenantNotAllowed(
                ip_pool=curr['ip_pool'], overlapping_pools=subnets)

    def handle_l3_policy_create(self, context):
        self._process_new_l3p_ip_pool(context, context.current['ip_pool'])

    def handle_l3_policy_delete(self, context):
        self._process_remove_l3p_ip_pool(context, context.current['ip_pool'])

    def handle_policy_classifier_update(self, context):
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

    def handle_policy_rule_update(self, context):
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

    def handle_policy_rule_delete(self, context):
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])

    def validate_policy_rule_set_create(self, context):
        self._gbp_driver._reject_shared(context.current, 'policy_rule_set')

    def handle_policy_rule_set_create(self, context):
        # creating SGs
        policy_rule_set_id = context.current['id']
        consumed_sg = self._create_policy_rule_set_sg(
            context._plugin_context, context.current, 'consumed', None, None)
        provided_sg = self._create_policy_rule_set_sg(
            context._plugin_context, context.current, 'provided', None, None)
        consumed_sg_id = consumed_sg['id']
        provided_sg_id = provided_sg['id']
        set_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set_id,
            consumed_sg_id, provided_sg_id)
        rules = context._plugin.get_policy_rules(
            context._plugin_context,
            {'id': context.current['policy_rules']})
        self._apply_policy_rule_set_rules(context, context.current, rules)
        if context.current['child_policy_rule_sets']:
            self._recompute_policy_rule_sets(
                context, context.current['child_policy_rule_sets'])

    def validate_policy_rule_set_update(self, context):
        self._gbp_driver._reject_shared(context.current, 'policy_rule_set')

    def handle_policy_rule_set_update(self, context):
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

    def validate_policy_rule_set_delete(self, context):
        mapping = get_policy_rule_set_sg_mapping(
            context._plugin_context.session, context.current['id'])
        context._rmd_sg_list_temp = [mapping['provided_sg_id'],
                                     mapping['consumed_sg_id']]

    def handle_policy_rule_set_delete(self, context):
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
            self._gbp_driver._delete_sg(context._plugin_context, sg)

    def handle_external_segment_update(self, context):
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

    def validate_external_policy_create(self, context):
        ep_number = context._plugin.get_external_policies_count(
            context._plugin_context,
            filters={'tenant_id': [context.current['tenant_id']]})
        if ep_number > 1:
            raise exc.OnlyOneEPPerTenantAllowed()

    def handle_external_policy_create(self, context):
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

    def handle_external_policy_update(self, context):
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

    def handle_external_policy_delete(self, context):
        if (context.current['provided_policy_rule_sets'] or
            context.current['consumed_policy_rule_sets']):
            # REVISIT(ivar): concurrency issue, ES may not exist anymore
            cidr_list = self._get_processed_ep_cidr_list(
                context, context.current)
            self._unset_sg_rules_for_cidrs(
                context, cidr_list,
                context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'])

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
                    get_policy_rule_set_sg_mapping(
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
        self._gbp_driver._update_port(context._plugin_context, port_id, port)

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
            self._gbp_driver._update_port(plugin_context, port_id, port)
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
            policy_rule_set_sg_mappings = get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set_id)
            provided_sg_id = policy_rule_set_sg_mappings['provided_sg_id']
            ret_list.append(provided_sg_id)

        for policy_rule_set_id in consumed_policy_rule_sets:
            policy_rule_set_sg_mappings = get_policy_rule_set_sg_mapping(
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
                    get_policy_rule_set_sg_mapping(
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
        policy_rule_set_sg_mappings = get_policy_rule_set_sg_mapping(
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
                                     policy_rules, *args):
        policy_rules = self._get_enforced_prs_rules(
            context, policy_rule_set, subset=[x['id'] for x in policy_rules])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules)

    def _remove_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, *args):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            unset_egress=True)

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
