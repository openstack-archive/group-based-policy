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
from neutron.api.v2 import attributes as attr
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron import context as ncontext
from neutron.db import model_base
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from oslo_concurrency import lockutils
from oslo_log import log as logging
import sqlalchemy as sa

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as gconst

LOG = logging.getLogger(__name__)


class PolicyRuleSetSGsMapping(model_base.BASEV2):
    """PolicyRuleSet to SGs mapping DB."""

    __tablename__ = 'gpm_policy_rule_set_sg_mapping'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id',
                                                 ondelete='CASCADE'),
                                   nullable=False, primary_key=True)
    # Scope Security Groups by L3 Policy
    l3_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l3_policies.id',
                                           ondelete='CASCADE'),
                             nullable=False, primary_key=True)
    # Not using HasTenant because we need this to be a Primary Key
    tenant_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN), primary_key=True)
    provided_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id',
                                             ondelete='CASCADE'))
    consumed_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id',
                                             ondelete='CASCADE'))
    # For easier cleanup of unused PRSs
    reference_count = sa.Column(sa.Integer)


def set_policy_rule_set_sg_mapping(session, policy_rule_set_id, consumed_sg_id,
                                   provided_sg_id, l3_policy_id, tenant_id):
    with session.begin(subtransactions=True):
        mapping = PolicyRuleSetSGsMapping(
            policy_rule_set_id=policy_rule_set_id,
            consumed_sg_id=consumed_sg_id, provided_sg_id=provided_sg_id,
            l3_policy_id=l3_policy_id, reference_count=0, tenant_id=tenant_id)
        session.add(mapping)
        return mapping


def get_policy_rule_set_sg_mapping(session, policy_rule_set_id=None,
                                   l3_policy_id=None, tenant_id=None,
                                   consumed_sg_id=None, provided_sg_id=None,
                                   l3_policy_ids=None):
    with session.begin(subtransactions=True):
        query = session.query(PolicyRuleSetSGsMapping)
        if policy_rule_set_id:
            query = query.filter_by(policy_rule_set_id=policy_rule_set_id)
        if l3_policy_id:
            query = query.filter_by(l3_policy_id=l3_policy_id)
        if l3_policy_ids is not None:
            query = query.filter(PolicyRuleSetSGsMapping.l3_policy_id.in_(
                l3_policy_ids))
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        if provided_sg_id:
            query = query.filter_by(provided_sg_id=provided_sg_id)
        if consumed_sg_id:
            query = query.filter_by(consumed_sg_id=consumed_sg_id)
        return query.all()


def incrase_mapping_count(session, policy_rule_set_id, l3_policy_id,
                          tenant_id):
    with session.begin(subtransactions=True):
        mapping = get_policy_rule_set_sg_mapping(session, policy_rule_set_id,
                                                 l3_policy_id, tenant_id)
        if mapping:
            mapping[0].reference_count += 1
            session.merge(mapping[0])


def decrase_mapping_count(session, policy_rule_set_id, l3_policy_id,
                          tenant_id):
    with session.begin(subtransactions=True):
        mapping = get_policy_rule_set_sg_mapping(session, policy_rule_set_id,
                                                 l3_policy_id, tenant_id)
        if mapping:
            mapping[0].reference_count -= 1
            session.merge(mapping[0])


class SecurityGroupManager(object):
    """Manages PRS mapping to Security Groups.

    Rule composition is the most critical component of the GBP Resource Mapping
    Driver. Translating the user intent into Security Group rules require
    a great automation effort. This class defines an API that mirrors the
    typical GBP driver API, but is uniquely used to react to certain events by
    modifying the Security Groups properly.
    """

    def __init__(self, gbp_driver):
        self._gbp_driver = gbp_driver

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

    def handle_policy_target_create(self, context):
        """Policy target creation.
        Depending on the provided/consumed PRSs of the hosting PTG, this newly
        created PT must take part of the proper security groups.
        """
        self._assoc_ptg_sg_to_pt(context, context.current)
        pass

    def handle_policy_target_delete(self, context):
        """Policy Target deletion.
        For explicit ports (not owned by the RMD) all the PRS security groups
        have to be removed.
        """
        plugin_context = context._plugin_context
        port_id = context.current['port_id']
        if not self._gbp_driver._port_is_owned(plugin_context.session,
                                               port_id):
            # REVISIT(ivar): Naming convention or some port metadata in the DB
            # could make this operation faster and more reliable.
            sg_list = self._generate_list_of_sg_from_ptg(
                context, context.current['policy_target_group_id'],
                context.current['tenant_id'])
            self._disassoc_sgs_from_pt(context, context.current, sg_list)

    def handle_policy_target_group_create(self, context):
        pass

    def handle_policy_target_group_update(self, context):
        """Policy Target Group update.
        - Added PRS may need SG pair creation based on L3P;
        - Removed PRS may need SG pair deletion based on L3P;
        - Newly created SG pairs have to be enriched with the proper rules.
          depending on remote SG for internal connectivity, and external CIDRs
          for the existing EPs
        - Disassociate all the PTs SGs from removed contracts;
        - Associate SGs from added contracts to PTs
        """
        # if PTG associated policy_rule_sets are updated, we need to update
        # the policy rules, then assoicate SGs to ports
        new, rem = self._get_ptg_prs_diff(context.original, context.current)
        new_p, new_c = new
        rem_p, rem_c = rem
        if new_p or new_c:
            self._update_sgs_on_ptg(context, context.current, new_p, new_c,
                                    "ASSOCIATE")
        # generate the list of contracts (SGs) to remove from current ports
        if rem_p or rem_c:
            self._update_sgs_on_ptg(context, context.current, rem_p, rem_c,
                                    "DISASSOCIATE")

    def handle_policy_target_group_delete(self, context):
        pass

    def handle_l3_policy_update(self, context):
        """L3P updated.
        - Newly added External Segments modify the external subnet calculation;
        - Removed External Segments modify the external subnet calculation.
        """
        new, rem = self._get_l3p_es_diff(context.original, context.current)
        if rem:
            self._handle_es_removed_from_l3p(context, rem)
        if new:
            self._handle_es_added_to_l3p(context, new)

    def handle_policy_classifier_update(self, context):
        """Policy Classifier Updated.
        The update of a policy classifier causes all the rules using it to
        change in their meaning. This could trigger a huge chain of changes
        on PRSs using those rules:
        - Modify all the SGs associated to all the PRSs using the rules
          pointing to this classifier.
        """
        policy_rules = context.current['policy_rules']
        policy_rules = context._plugin.get_policy_rules(
            context._plugin_context,
            filters={'id': policy_rules})
        for policy_rule in policy_rules:
            pr_id = policy_rule['id']
            pr_sets = context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, pr_id)
            self._update_policy_rule_sg_rules(
                context, pr_sets, policy_rule, context.original,
                context.current)

    def handle_policy_rule_update(self, context):
        """Policy Rule Updated.
        - For all the PRS using this rule, modify the SG when the classifier
          is updated. This has to consider hierarchical PRSs.
        """
        old_classifier_id = context.original['policy_classifier_id']
        new_classifier_id = context.current['policy_classifier_id']
        if old_classifier_id != new_classifier_id:
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context,
                    filters={'id': context.current['policy_rule_sets']}):
                self._remove_policy_rule_set_rules(context, prs,
                                                   [context.original])
                self._apply_policy_rule_set_rules(context, prs,
                                                  [context.current])

    def handle_policy_rule_delete(self, context):
        """ Policy rule deleted.
        Needs to be removed in all the using PRSs
        """
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])

    def handle_policy_rule_set_create(self, context):
        """Policy Rule Set created.
        A newly create PRS isn't provided/consumed by any group yet. However,
        it may affect existing PRSs being a parent of one or more of them.
        - For any child PRS, set up their SG rules properly.
        """
        if context.current['child_policy_rule_sets']:
            self._recompute_policy_rule_sets(
                context, context.current['child_policy_rule_sets'])

    def handle_policy_rule_set_update(self, context):
        """Policy Rule Set created.
        - New rules to be set on this PRS SGs;
        - Old rules to be unset from this PRS SGs;
        - Restrict child PRSs if any;
        - Unrestrict child PRSs if removed.
        """
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

    def handle_policy_rule_set_delete(self, context):
        """Policy Rule Set Deleted.
        When deleted, the PRS is unused. At this point no SG should be left
        on his behalf. However, children PRS should be unrestrained.
        """
        if context.current['child_policy_rule_sets']:
            self._recompute_policy_rule_sets(
                context, context.current['child_policy_rule_sets'])

    def handle_external_segment_update(self, context):
        """External Segment Updated.
        - If the ES routes are updated, all the SGs for the proper L3Ps need
          to be updated.
        """
        curr = context.current
        orig = context.original

        def stream_routes(external_route):
            return set([x['destination'] for x in external_route])

        if curr['l3_policies'] and (curr['external_routes'] !=
                                    orig['external_routes']):
            add = (stream_routes(curr['external_routes']) -
                   stream_routes(orig['external_routes']))
            rem = (stream_routes(orig['external_routes']) -
                   stream_routes(curr['external_routes']))
            eps = self._gbp_plugin.get_external_policies(
                context._plugin_context, {'id': curr['external_policies']})
            l3p_ids = curr['l3_policies']
            processed_new_p = dict(
                (x, {'providing_cidrs': self._process_external_cidrs(
                    context, add, l3p_id=x)}) for x in l3p_ids)
            processed_new_c = dict(
                (x, {'consuming_cidrs': self._process_external_cidrs(
                    context, add, l3p_id=x)}) for x in l3p_ids)
            processed_rem_p = dict(
                (x, {'providing_cidrs': self._process_external_cidrs(
                    context, rem, l3p_id=x)}) for x in l3p_ids)
            processed_rem_c = dict(
                (x, {'consuming_cidrs': self._process_external_cidrs(
                    context, rem, l3p_id=x)}) for x in l3p_ids)

            for ep in eps:
                prov = ep['provided_policy_rule_sets']
                cons = ep['consumed_policy_rule_sets']

                if prov:
                    # Pass down the correct cidr mapping depending on the
                    # PRS role
                    for prs in self._gbp_plugin.get_policy_rule_sets(
                            context._plugin_context, {'id': prov}):
                        # Add/Remove this ES rules
                        rules = self._gbp_plugin.get_policy_rules(
                            context._plugin_context,
                            {'id': prs['policy_rules']})
                        self._apply_policy_rule_set_rules(
                            context, prs, rules, processed_new_p, l3p_ids,
                            external_only=True)
                        self._remove_policy_rule_set_rules(
                            context, prs, rules, processed_rem_p, l3p_ids,
                            external_only=True)

                if cons:
                    # Pass down the correct cidr mapping depending on the
                    # PRS role
                    for prs in self._gbp_plugin.get_policy_rule_sets(
                            context._plugin_context, {'id': prov}):
                        # Add/Remove this ES rules
                        rules = self._gbp_plugin.get_policy_rules(
                            context._plugin_context,
                            {'id': prs['policy_rules']})
                        self._apply_policy_rule_set_rules(
                            context, prs, rules, processed_new_c, l3p_ids,
                            external_only=True)
                        self._remove_policy_rule_set_rules(
                            context, prs, rules, processed_rem_c, l3p_ids,
                            external_only=True)

    def handle_external_policy_create(self, context):
        """External Policy Created.
        Just like the PTG creation. The difference is that this may affect
        more than one L3P at a time. Also, no Port association is usually
        needed since EPs can't host Policy Targets.
        """
        prov = context.current['provided_policy_rule_sets']
        cons = context.current['consumed_policy_rule_sets']
        self._handle_ep_added_prs(context, prov, cons)

    def handle_external_policy_update(self, context):
        """External Policy Created.
        - PRS provided/consumed may need new external rules
        - PRS removed may need deleted external rules
        """
        prov_n = set(context.current['provided_policy_rule_sets'])
        cons_n = set(context.current['consumed_policy_rule_sets'])
        prov_o = set(context.original['provided_policy_rule_sets'])
        cons_o = set(context.original['consumed_policy_rule_sets'])
        added_p = prov_n - prov_o
        added_c = cons_n - cons_o
        removed_p = prov_o - prov_n
        removed_c = cons_o - cons_n
        self._handle_ep_added_prs(context, added_p, added_c)
        self._handle_ep_removed_prs(context, removed_p, removed_c)

    def handle_external_policy_delete(self, context):
        """External Policy Created.
        Just like the PTG creation. The difference is that this may affect
        more than one L3P at a time. Also, no Port association is usually
        needed since EPs can't host Policy Targets.
        """
        prov = context.current['provided_policy_rule_sets']
        cons = context.current['consumed_policy_rule_sets']
        self._handle_ep_removed_prs(context, prov, cons)

    def _assoc_ptg_sg_to_pt(self, context, pt):
        sg_list = self._generate_list_of_sg_from_ptg(
            context, context.current['policy_target_group_id'],
            context.current['tenant_id'])
        self._assoc_sgs_to_pt(context, pt, sg_list)

    def _generate_list_of_sg_from_ptg(self, context, ptg_id, tenant_id):
        ptg = self._gbp_plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        provided_policy_rule_sets = ptg['provided_policy_rule_sets']
        consumed_policy_rule_sets = ptg['consumed_policy_rule_sets']
        l3_policy_id = self._get_ptg_l3p_id(context, ptg)
        return(self._generate_list_sg_from_policy_rule_set_list(
            context, provided_policy_rule_sets, consumed_policy_rule_sets,
            l3_policy_id, tenant_id))

    def _generate_list_sg_from_policy_rule_set_list(
            self, context, provided, consumed, l3_policy_id, tenant_id):
        """Returns SG list scoped by L3 Policy."""
        ret_list = []
        for policy_rule_set in self._gbp_plugin.get_policy_rule_sets(
                context._plugin_context, {'id': provided}):
            policy_rule_set_sg_mappings = self._create_sg_pair(
                context, policy_rule_set, l3_policy_id, tenant_id)
            provided_sg_id = policy_rule_set_sg_mappings['provided_sg_id']
            ret_list.append(provided_sg_id)

        for policy_rule_set in self._gbp_plugin.get_policy_rule_sets(
                context._plugin_context, {'id': consumed}):
            policy_rule_set_sg_mappings = self._create_sg_pair(
                context, policy_rule_set, l3_policy_id, tenant_id)
            consumed_sg_id = policy_rule_set_sg_mappings['consumed_sg_id']
            ret_list.append(consumed_sg_id)
        return ret_list

    def _assoc_sgs_to_pt(self, context, pt, sg_list):
        plugin_context = context._plugin_context
        port_id = pt['port_id']
        port = self._core_plugin.get_port(plugin_context, port_id)
        cur_sg_list = port[ext_sg.SECURITYGROUPS]
        new_sg_list = cur_sg_list + sg_list
        port[ext_sg.SECURITYGROUPS] = new_sg_list
        self._gbp_driver._update_port(plugin_context, port_id, port)
        for sg in sg_list:
            self._mark_sg_usage(context, sg)

    def _disassoc_sgs_from_pt(self, context, pt, sg_list):
        plugin_context = context._plugin_context
        port_id = pt['port_id']
        try:
            port = self._core_plugin.get_port(plugin_context, port_id)
            cur_sg_list = port[ext_sg.SECURITYGROUPS]
            new_sg_list = list(set(cur_sg_list) - set(sg_list))
            port[ext_sg.SECURITYGROUPS] = new_sg_list
            self._gbp_driver._update_port(plugin_context, port_id, port)
        except n_exc.PortNotFound:
            LOG.warn(_("Port %s is missing") % port_id)
        finally:
            # Need to decrase count and eventually delete the SG pair
            for sg in sg_list:
                self._delete_sg_pair_from_sg_id(context, sg)

    def _create_sg_pair(self, context, prs, l3p_id, tenant_id):
        # REVISIT(ivar): Multiple servers?
        with lockutils.lock('%s-%s-%s' % (prs['id'], l3p_id, tenant_id),
                            'gbp-', True):
            plugin_context = self._admin_context
            mapping = get_policy_rule_set_sg_mapping(
                    plugin_context.session, prs['id'], l3p_id, tenant_id)
            if not mapping:
                consumed_sg = self._create_policy_rule_set_sg(
                    plugin_context, prs, 'consumed', l3p_id, tenant_id)
                provided_sg = self._create_policy_rule_set_sg(
                    plugin_context, prs, 'provided', l3p_id, tenant_id)
                consumed_sg_id = consumed_sg['id']
                provided_sg_id = provided_sg['id']
                mapping = set_policy_rule_set_sg_mapping(
                    plugin_context.session, prs['id'], consumed_sg_id,
                    provided_sg_id, l3p_id, tenant_id)
                rules = self._gbp_plugin.get_policy_rules(
                    plugin_context, {'id': prs['policy_rules']})
                cidr_mapping = self._get_cidrs_mapping(context, prs)
                self._apply_policy_rule_set_rules(context, prs, rules,
                                                  cidr_mapping, [l3p_id])
                return mapping
            else:
                return mapping[0]

    def _mark_sg_usage(self, context, sg_id):
        # This is a new PRS user for this L3P
        mapping = get_policy_rule_set_sg_mapping(
            context._plugin_context.session, provided_sg_id=sg_id)
        if not mapping:
            mapping = get_policy_rule_set_sg_mapping(
                context._plugin_context.session, consumed_sg_id=sg_id)
        if mapping:
            prs_id = mapping[0].policy_rule_set_id
            l3p_id = mapping[0].l3_policy_id
            tenant_id = mapping[0].tenant_id
            with lockutils.lock('%s-%s-%s' % (prs_id, l3p_id, tenant_id),
                                'gbp-', True):
                incrase_mapping_count(
                    context._plugin_context.session, prs_id, l3p_id,
                    tenant_id)

    def _delete_sg_pair(self, context, prs_id, l3p_id, tenant_id):
        # REVISIT(ivar): Multiple servers?
        with lockutils.lock('%s-%s-%s' % (prs_id, l3p_id, tenant_id),
                            'gbp-', True):
            plugin_context = self._admin_context
            decrase_mapping_count(plugin_context.session, prs_id, l3p_id,
                                  tenant_id)
            mapping = get_policy_rule_set_sg_mapping(
                plugin_context.session, prs_id, l3p_id, tenant_id)
            if not mapping or mapping[0].reference_count < 1:
                try:
                    self._gbp_driver._delete_sg(plugin_context,
                                                mapping[0].provided_sg_id)
                except ext_sg.SecurityGroupNotFound:
                    pass
                try:
                    self._gbp_driver._delete_sg(plugin_context,
                                                mapping[0].consumed_sg_id)
                except ext_sg.SecurityGroupNotFound:
                    pass
                return True
            else:
                return False

    def _delete_sg_pair_from_sg_id(self, context, sg_id):
        mapping = get_policy_rule_set_sg_mapping(
            context._plugin_context.session, provided_sg_id=sg_id)
        if not mapping:
            mapping = get_policy_rule_set_sg_mapping(
                context._plugin_context.session, consumed_sg_id=sg_id)
        if mapping:
            self._delete_sg_pair(context, mapping[0].policy_rule_set_id,
                                 mapping[0].l3_policy_id,
                                 mapping[0].tenant_id)

    def _prs_in_l3p(self, context, prs, l3p_id):
        with lockutils.lock(prs['id'] + '-' + l3p_id, 'gbp-', True):
            return get_policy_rule_set_sg_mapping(
                context._plugin_context.session, prs['id'], l3p_id)

    def _create_policy_rule_set_sg(self, plugin_context, prs, sg_name_prefix,
                                   l3p_id, tenant_id):
        # This method sets up the attributes of security group
        attrs = {'tenant_id': tenant_id,
                 'name': sg_name_prefix + '_' + prs['name'] + '_' + l3p_id,
                 'description': '',
                 'security_group_rules': ''}
        sg = self._gbp_driver._create_sg(plugin_context, attrs)
        # Cleanup default rules
        for rule in self._core_plugin.get_security_group_rules(
                plugin_context, filters={'security_group_id': [sg['id']]}):
            self._core_plugin.delete_security_group_rule(
                plugin_context, rule['id'])
        return sg

    def _apply_policy_rule_set_rules(self, context, policy_rule_set,
                                     policy_rules, cidr_mapping=None,
                                     l3p_ids=None, external_only=False):
        cidr_mapping = cidr_mapping or self._get_cidrs_mapping(
            context, policy_rule_set)
        policy_rules = self._gbp_driver._get_enforced_prs_rules(
            context, policy_rule_set, subset=[x['id'] for x in policy_rules])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, cidr_mapping,
            l3p_ids=l3p_ids, external_only=external_only)

    def _remove_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, cidr_mapping=None,
                                      l3p_ids=None, external_only=False):
        cidr_mapping = cidr_mapping or self._get_cidrs_mapping(
            context, policy_rule_set)
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, cidr_mapping, unset=True,
            unset_egress=True, l3p_ids=l3p_ids, external_only=external_only)

    def _manage_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, cidr_mapping, unset=False,
                                      unset_egress=False, l3p_ids=None,
                                      external_only=False):
        policy_rule_set_sg_mappings = get_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set['id'],
            l3_policy_ids=l3p_ids)
        for mapping in policy_rule_set_sg_mappings:
            for policy_rule in policy_rules:
                self._add_or_remove_policy_rule_set_rule(
                    context, policy_rule, mapping,
                    cidr_mapping.get(mapping.l3_policy_id, {}), unset=unset,
                    unset_egress=unset_egress, external_only=external_only)

    def _get_cidrs_mapping(self, context, policy_rule_set):
        """ Organize CIDRs participating a given PRS.

        retrieve EPs CIDRs participating a given PRS grouped by L3 Policy
        ID.
        """
        result = dict()
        providing_eps = self._ep_by_l3p(
            context, policy_rule_set['providing_external_policies'])
        consuming_eps = self._ep_by_l3p(
            context, policy_rule_set['consuming_external_policies'])
        for l3p_id in (set(providing_eps.keys()) | set(consuming_eps.keys())):
            result[l3p_id] = {
                'providing_cidrs': self._get_processed_ep_routes(
                    context, providing_eps.get(l3p_id, []), l3p_id),
                'consuming_cidrs': self._get_processed_ep_routes(
                    context, consuming_eps.get(l3p_id, []), l3p_id)}
        return result

    def _get_processed_ep_routes(self, context, eps, l3p_id=None):
        cidrs = []
        for ep in eps:
            route_list = self._get_ep_route_list(context, ep, l3p_id=l3p_id)
            cidrs.extend(self._process_external_cidrs(context, route_list,
                                                      l3p_id=l3p_id))
        return cidrs

    def _get_ep_route_list(self, context, ep, l3p_id=None):
        es_list = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': ep['external_segments']})
        cidr_list = []
        for es in es_list:
            if not l3p_id or l3p_id in es['l3_policies']:
                cidr_list += [x['destination'] for x in es['external_routes']]
        return cidr_list

    def _process_external_cidrs(self, context, cidrs, l3p_id=None):
        default = ['0.0.0.0/0', '::']
        if not l3p_id:
            # Get all the tenant's L3P
            l3ps = context._plugin.get_l3_policies(
                context._plugin_context,
                filters={'tenant_id': [context.current['tenant_id']]})
        else:
            l3ps = [context._plugin.get_l3_policy(context._plugin_context,
                                                  l3p_id)]

        ip_pool_list = [x['ip_pool'] for x in l3ps]
        l3p_set = netaddr.IPSet(ip_pool_list)
        result = []
        for cidr in cidrs:
            if cidr in default:
                result.extend([str(x) for x in
                               (netaddr.IPSet([cidr]) - l3p_set).iter_cidrs()])
            else:
                result.append(cidr)
        return result

    def _get_per_l3p_ep_cidrs(self, context, ep):
        # Given a EP, returns its CIDRs grouped by L3P
        result = {}
        for es in self._gbp_plugin.get_external_segments(
                context._plugin_context, {'id': ep['external_segments']}):
            routes = [x['destination'] for x in es['external_routes']]
            for l3p_id in es['l3_policies']:
                cidrs = self._process_external_cidrs(
                    context, routes, l3p_id=l3p_id)
                if not l3p_id in result:
                    result[l3p_id] = set()
                result[l3p_id] |= set(cidrs)
        return result

    def _add_or_remove_policy_rule_set_rule(
            self, context, policy_rule, policy_rule_set_sg_mappings,
            cidr_mapping, unset=False, unset_egress=False, classifier=None,
            external_only=False):
        """ Add or remove a rule to a PRS.
        A PRS can have multiple SGs associated, depending on the L3P in which
        it is used. Infra PTG associations will use the remote_sg notation,
        cidr_mapping is used for external connectivity purposes.
        """
        in_out = [gconst.GP_DIRECTION_IN, gconst.GP_DIRECTION_OUT]
        prov_cons = [policy_rule_set_sg_mappings['provided_sg_id'],
                     policy_rule_set_sg_mappings['consumed_sg_id']]
        cidr_prov_cons = [cidr_mapping.get('providing_cidrs', []),
                          cidr_mapping.get('consuming_cidrs', [])]
        prs = self._gbp_plugin.get_policy_rule_set(
            context._plugin_context,
            policy_rule_set_sg_mappings['policy_rule_set_id'])
        if not classifier:
            classifier_id = policy_rule['policy_classifier_id']
            classifier = self._gbp_plugin.get_policy_classifier(
                context._plugin_context, classifier_id)

        protocol = classifier['protocol']
        port_range = classifier['port_range']

        for pos, sg in enumerate(prov_cons):
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos]]:
                # External rules
                for cidr in cidr_prov_cons[pos - 1]:
                    self._sg_ingress_rule(prs, sg, protocol,
                                          port_range, remote_cidr=cidr,
                                          unset=unset)
                # Internal rule
                if not external_only:
                    self._sg_ingress_rule(prs, sg, protocol, port_range,
                                          remote_sg=prov_cons[pos - 1],
                                          unset=unset)
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos - 1]]:
                # External rules
                for cidr in cidr_prov_cons[pos - 1]:
                    self._sg_egress_rule(prs, sg, protocol,
                                         port_range, remote_cidr=cidr,
                                         unset=unset_egress)
                # Internal rule
                if not external_only:
                    self._sg_egress_rule(prs, sg, protocol, port_range,
                                         remote_sg=prov_cons[pos - 1],
                                         unset=unset_egress)

    def _sg_ingress_rule(self, prs, sg_id, protocol, port_range,
                         remote_cidr=None, remote_sg=None, unset=False):
        return self._sg_rule(
            self._admin_context, prs['tenant_id'], sg_id,
            'ingress', protocol, port_range, remote_cidr, remote_sg,
            unset=unset)

    def _sg_egress_rule(self, prs, sg_id, protocol, port_range,
                        remote_cidr=None, remote_sg=None, unset=False):
        return self._sg_rule(
            self._admin_context, prs['tenant_id'], sg_id,
            'egress', protocol, port_range, remote_cidr, remote_sg,
            unset=unset)

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
                 'ethertype': ethertype or versions[
                     netaddr.IPNetwork(cidr).version] if cidr else None,
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

    def _get_ptg_prs_diff(self, original, current):
        orig_provided_policy_rule_sets = original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = current[
            'provided_policy_rule_sets']
        orig_consumed_policy_rule_sets = original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = current[
            'consumed_policy_rule_sets']

        new_p = list(set(curr_provided_policy_rule_sets) -
                     set(orig_provided_policy_rule_sets))
        new_c = list(set(curr_consumed_policy_rule_sets) -
                     set(orig_consumed_policy_rule_sets))
        rem_p = list(set(orig_provided_policy_rule_sets) -
                     set(curr_provided_policy_rule_sets))
        rem_c = list(set(orig_consumed_policy_rule_sets) -
                     set(curr_consumed_policy_rule_sets))
        return (new_p, new_c), (rem_p, rem_c)

    def _get_l3p_es_diff(self, original, current):
        added = removed = set()
        if current['external_segments'] != original['external_segments']:
            added = (set(current['external_segments'].keys()) -
                     set(original['external_segments'].keys()))
            removed = (set(original['external_segments'].keys()) -
                       set(current['external_segments'].keys()))
        return added, removed

    def _update_sgs_on_ptg(self, context, ptg, provided_policy_rule_sets,
                           consumed_policy_rule_sets, op):
        l3_policy_id = self._get_ptg_l3p_id(context, ptg)
        policy_target_list = ptg['policy_targets']
        for pt in self._gbp_plugin.get_policy_targets(
                self._admin_context, {'id': policy_target_list}):
            sg_list = self._generate_list_sg_from_policy_rule_set_list(
                context, provided_policy_rule_sets, consumed_policy_rule_sets,
                l3_policy_id, pt['tenant_id'])
            if op == "ASSOCIATE":
                self._assoc_sgs_to_pt(context, pt, sg_list)
            else:
                self._disassoc_sgs_from_pt(context, pt, sg_list)

    # Expected l3p context
    def _handle_es_added_to_l3p(self, context, segments):
        self._handle_es_added_or_removed_from_l3p(context, segments)

    # Expected l3p context
    def _handle_es_removed_from_l3p(self, context, segments):
        self._handle_es_added_or_removed_from_l3p(context, segments, False)

    # Expected l3p context
    def _handle_es_added_or_removed_from_l3p(self, context, segments,
                                             added=True):
        apply_remove = {True: self._apply_policy_rule_set_rules,
                        False: self._remove_policy_rule_set_rules}
        l3p_id = context.current['id']

        def process_prs(prss, mapping):
            prss = self._gbp_plugin.get_policy_rule_sets(
                context._plugin_context, {'id': prss})
            for prs in prss:
                # If no SG exist for this L3P no operations needed
                if not self._prs_in_l3p(context, prs, l3p_id):
                    continue
                # Add/Remove this ES rules
                rules = self._gbp_plugin.get_policy_rules(
                    context._plugin_context,
                    {'id': prs['policy_rules']})
                apply_remove[added](context, prs, rules, mapping, [l3p_id],
                                    external_only=True)

        for es in self._gbp_plugin.get_external_segments(
                context._plugin_context, {'id': segments}):
            if not es['external_policies'] or not es['external_routes']:
                continue
            eps = self._gbp_plugin.get_external_policies(
                context._plugin_context, {'id': es['external_policies']})
            cidrs = [x['destination'] for x in es['external_routes']]

            for ep in eps:
                prov = ep['provided_policy_rule_sets']
                cons = ep['consumed_policy_rule_sets']

                if prov:
                    # Pass down the correct cidr mapping depending on the
                    # PRS role
                    mapping = {l3p_id: {
                        'providing_cidrs': self._process_external_cidrs(
                            context, cidrs, l3p_id=l3p_id)}}
                    process_prs(prov, mapping)

                if cons:
                    # Pass down the correct cidr mapping depending on the
                    # PRS role
                    mapping = {l3p_id: {
                        'consuming_cidrs': self._process_external_cidrs(
                            context, cidrs, l3p_id=l3p_id)}}
                    process_prs(cons, mapping)

    # updates sg rules corresponding to a policy rule
    def _update_policy_rule_sg_rules(self, context, policy_rule_sets,
                                     policy_rule, old_classifier=None,
                                     new_classifier=None):
        policy_rule_set_list = context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': policy_rule_sets})
        for policy_rule_set in policy_rule_set_list:
            filtered_rules = self._gbp_driver._get_enforced_prs_rules(
                context, policy_rule_set)
            if policy_rule in filtered_rules:
                policy_rule_set_sg_mappings = (get_policy_rule_set_sg_mapping(
                    context._plugin_context.session, policy_rule_set['id']))
                cidr_mapping = self._get_cidrs_mapping(context,
                                                       policy_rule_set)
                for prs_map in policy_rule_set_sg_mappings:
                    l3p_id = prs_map.l3_policy_id
                    self._add_or_remove_policy_rule_set_rule(
                        context, policy_rule, prs_map,
                        cidr_mapping.get(l3p_id, {}), unset=True,
                        unset_egress=True, classifier=old_classifier)
                    self._add_or_remove_policy_rule_set_rule(
                        context, policy_rule, prs_map,
                        cidr_mapping.get(l3p_id, {}),
                        classifier=new_classifier)

    # EP context expected
    def _handle_ep_added_prs(self, context, prov, cons):
        if prov or cons:
            routes = self._get_per_l3p_ep_cidrs(context, context.current)
            for l3p_id in routes.keys():
                prov_mapping = {l3p_id: {'providing_cidrs': routes[l3p_id]}}
                cons_mapping = {l3p_id: {'consuming_cidrs': routes[l3p_id]}}
                for prs in self._gbp_plugin.get_policy_rule_sets(
                        context._plugin_context,
                        {'id': set(prov) | set(cons)}):
                    # The PRS clould be new to this L3P
                    if not self._prs_in_l3p(context, prs, l3p_id):
                        continue
                    # Add rules for this EP CIDRs
                    rules = self._gbp_plugin.get_policy_rules(
                        context._plugin_context, {'id': prs['policy_rules']})
                    if prs['id'] in prov and prov_mapping[l3p_id].values():
                        self._apply_policy_rule_set_rules(
                            context, prs, rules, prov_mapping,
                            external_only=True)
                    if prs['id'] in cons and cons_mapping[l3p_id].values():
                        self._apply_policy_rule_set_rules(
                            context, prs, rules, cons_mapping,
                            external_only=True)

    def _handle_ep_removed_prs(self, context, prov, cons):
        if prov or cons:
            routes = self._get_per_l3p_ep_cidrs(context, context.current)
            for prs in self._gbp_plugin.get_policy_rule_sets(
                    context._plugin_context, {'id': set(prov) | set(cons)}):
                actual_mapping = self._get_cidrs_mapping(context, prs)
                for l3p_id in routes.keys():
                    prov_mapping = {l3p_id: {
                        'providing_cidrs': (
                            set(routes[l3p_id]) - actual_mapping.get(
                                l3p_id, {}).get('providing_cidrs', set()))}}
                    cons_mapping = {l3p_id: {
                        'consuming_cidrs': (
                            set(routes[l3p_id]) - actual_mapping.get(
                                l3p_id, {}).get('consuming_cidrs', set()))}}
                    if not self._prs_in_l3p(context, prs, l3p_id):
                        continue
                    # Remove rules for this EP CIDRs
                    rules = self._gbp_plugin.get_policy_rules(
                        context._plugin_context, {'id': prs['policy_rules']})
                    if prs['id'] in prov and prov_mapping[l3p_id].values():
                        self._remove_policy_rule_set_rules(
                            context, prs, rules, prov_mapping,
                            external_only=True)
                    if prs['id'] in cons and cons_mapping[l3p_id].values():
                        self._remove_policy_rule_set_rules(
                            context, prs, rules, cons_mapping,
                            external_only=True)

    def _get_ptg_l3p_id(self, context, ptg):
        l2p = context._plugin._get_l2_policy(
            context._plugin_context, ptg['l2_policy_id'])
        return l2p['l3_policy_id']

    def _ep_by_l3p(self, context, ep_ids):
        result = dict()
        eps = []
        if ep_ids:
            eps = context._plugin.get_external_policies(
                context._plugin_context, filters={'id': ep_ids})
        for ep in eps:
            ess = []
            l3ps = set()
            if ep['external_segments']:
                ess = context._plugin.get_external_segments(
                    context._plugin_context,
                    filters={'id': ep['external_segments']})
            for es in ess:
                l3ps |= set(es['l3_policies'])
            for l3p_id in l3ps:
                if l3p_id not in result:
                    result[l3p_id] = []
                result[l3p_id].append(ep)
        return result