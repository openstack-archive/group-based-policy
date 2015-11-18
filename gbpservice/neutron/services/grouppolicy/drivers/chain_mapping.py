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

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as k_client
from neutron.common import log
from neutron.db import model_base
from neutron.db import models_v2
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
import sqlalchemy as sa

from gbpservice.common import utils
from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.db import servicechain_db  # noqa
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.grouppolicy.drivers import nsp_manager
from gbpservice.neutron.services.grouppolicy import sc_notifications


LOG = logging.getLogger(__name__)
SCI_CONSUMER_NOT_AVAILABLE = 'N/A'

chain_mapping_opts = [
    cfg.StrOpt('chain_owner_user',
               help=_("Chain owner username. If set, will be used in "
                      "place of the Neutron service admin for retrieving "
                      "tenant owner information through Keystone."),
               default=''),
    cfg.StrOpt('chain_owner_password',
               help=_("Chain owner password."), default='',
               secret=True),
    cfg.StrOpt('chain_owner_tenant_name',
               help=_("Name of the Tenant that will own the service chain "
                      "instances for this driver. Leave empty for provider "
                      "owned chains."), default=''),

]

cfg.CONF.register_opts(chain_mapping_opts, "chain_mapping")


class PtgServiceChainInstanceMapping(model_base.BASEV2, models_v2.HasTenant):
    """Policy Target Group to ServiceChainInstance mapping DB."""

    __tablename__ = 'gpm_ptgs_servicechain_mapping'
    provider_ptg_id = sa.Column(sa.String(36),
                                sa.ForeignKey('gp_policy_target_groups.id',
                                              ondelete='CASCADE'),
                                nullable=False)
    # Consumer PTG could be an External Policy
    consumer_ptg_id = sa.Column(sa.String(36), nullable=False)
    servicechain_instance_id = sa.Column(sa.String(36),
                                         sa.ForeignKey('sc_instances.id',
                                                       ondelete='CASCADE'),
                                         primary_key=True)


class ChainMappingDriver(api.PolicyDriver, local_api.LocalAPI,
                         nsp_manager.NetworkServicePolicyMappingMixin,
                         sc_notifications.ServiceChainNotificationsMixin):
    """Resource Mapping driver for Group Policy plugin.

    This driver implements service chain semantics by mapping group
    policy resources to various service chain constructs.
    """

    @log.log
    def initialize(self):
        self._cached_agent_notifier = None
        self.chain_owner = ChainMappingDriver.chain_tenant_id(reraise=True)

    @staticmethod
    def chain_tenant_id(reraise=False):
        keystone = ChainMappingDriver.chain_tenant_keystone_client()
        if keystone:
            tenant = cfg.CONF.chain_mapping.chain_owner_tenant_name
            try:
                # Can it be retrieved directly, without a further keystone
                # call?
                tenant = keystone.tenants.find(name=tenant)
                return tenant.id
            except k_exceptions.NotFound:
                with excutils.save_and_reraise_exception(reraise=reraise):
                    LOG.error(_('No tenant with name %s exists.'), tenant)
            except k_exceptions.NoUniqueMatch:
                with excutils.save_and_reraise_exception(reraise=reraise):
                    LOG.error(_('Multiple tenants matches found for %s'),
                              tenant)

    @staticmethod
    def chain_tenant_keystone_client():
        chain_user = cfg.CONF.chain_mapping.chain_owner_user
        user, pwd, tenant, auth_url = utils.get_keystone_creds()
        user = (chain_user or user)
        pwd = (cfg.CONF.chain_mapping.chain_owner_password or
               (pwd if not chain_user else ''))

        # Tenant must be configured in the resource_mapping section, provider
        # owner will be used otherwise.
        tenant = cfg.CONF.chain_mapping.chain_owner_tenant_name

        if tenant:
            return k_client.Client(username=user, password=pwd,
                                   auth_url=auth_url)

    @log.log
    def create_policy_target_postcommit(self, context):
        if not context._plugin._is_service_target(context._plugin_context,
                                                  context.current['id']):
            mappings = self._get_ptg_servicechain_mapping(
                context._plugin_context.session,
                provider_ptg_id=context.current['policy_target_group_id'])
            for mapping in mappings:
                chain_context = self._get_chain_admin_context(
                    context._plugin_context,
                    instance_id=mapping.servicechain_instance_id)
                self._notify_sc_plugin_pt_added(
                    chain_context, context.current,
                    mapping.servicechain_instance_id)

    @log.log
    def delete_policy_target_precommit(self, context):
        context._is_service_target = context._plugin._is_service_target(
            context._plugin_context, context.current['id'])

    @log.log
    def delete_policy_target_postcommit(self, context):
        if not context._is_service_target:
            mappings = self._get_ptg_servicechain_mapping(
                context._plugin_context.session,
                provider_ptg_id=context.current['policy_target_group_id'])
            for mapping in mappings:
                chain_context = self._get_chain_admin_context(
                    context._plugin_context,
                    instance_id=mapping.servicechain_instance_id)
                self._notify_sc_plugin_pt_removed(
                    chain_context, context.current,
                    mapping.servicechain_instance_id)

    @log.log
    def create_policy_target_group_precommit(self, context):
        self._validate_ptg_prss(context, context.current)

    @log.log
    def create_policy_target_group_postcommit(self, context):
        if (context.current['provided_policy_rule_sets'] and not
            context.current.get('proxied_group_id')):
            self._handle_redirect_action(
                context, context.current['provided_policy_rule_sets'],
                providing_ptg=context.current)
        self._handle_prs_added(context)

    @log.log
    def update_policy_target_group_precommit(self, context):
        self._validate_ptg_prss(context, context.current)
        self._stash_ptg_modified_chains(context)

    @log.log
    def update_policy_target_group_postcommit(self, context):
        #Update service chain instance when any ruleset is changed
        orig = context.original
        curr = context.current

        new_provided_policy_rule_sets = list(
            set(curr['provided_policy_rule_sets']) - set(
                orig['provided_policy_rule_sets']))

        # Only the ones set in context in precommit operation will be deleted
        self._cleanup_redirect_action(context)
        # If the spec is changed, then update the chain with new spec
        # If redirect is newly added, create the chain
        if self._is_redirect_in_policy_rule_sets(
                context, new_provided_policy_rule_sets) and not (
                    context.current.get('proxied_group_id')):
            self._handle_redirect_action(
                context, curr['provided_policy_rule_sets'],
                providing_ptg=context.current)
        self._handle_prs_updated(context)

    @log.log
    def delete_policy_target_group_precommit(self, context):
        pass

    @log.log
    def delete_policy_target_group_postcommit(self, context):
        self._handle_prs_removed(context)

    @log.log
    def update_policy_classifier_postcommit(self, context):
        self._handle_classifier_update_notification(context)

    @log.log
    def create_policy_action_precommit(self, context):
        spec_id = context.current['action_value']
        if spec_id:
            specs = self._get_servicechain_specs(
                context._plugin_context, filters={'id': [spec_id]})
            for spec in specs:
                if not spec.get('shared', False):
                    self._reject_shared(context.current, 'policy_action')

    @log.log
    def update_policy_action_postcommit(self, context):
        self._handle_redirect_spec_id_update(context)

    @log.log
    def create_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)

    @log.log
    def update_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)
        old_redirect = self._get_redirect_action(context, context.original)
        new_redirect = self._get_redirect_action(context, context.current)
        if not old_redirect and new_redirect:
            # If redirect action is added, check that there's no contract that
            # already has a redirect action
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context,
                    {'id': context.current['policy_rule_sets']}):
                # Make sure the PRS can have a new redirect action
                self._validate_new_prs_redirect(context, prs)

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

            old_redirect_policy_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': context.original['policy_actions'],
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
            new_redirect_policy_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': context.current['policy_actions'],
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
            if old_redirect_policy_actions or new_redirect_policy_actions:
                self._handle_redirect_action(context, policy_rule_sets)

    @log.log
    def create_policy_rule_set_precommit(self, context):
        self._reject_multiple_redirects_in_prs(context)

    @log.log
    def create_policy_rule_set_postcommit(self, context):
        if context.current['child_policy_rule_sets']:
            self._handle_redirect_action(
                context, context.current['child_policy_rule_sets'])

    @log.log
    def update_policy_rule_set_precommit(self, context):
        self._reject_multiple_redirects_in_prs(context)
        # If a redirect action is added (from 0 to one) we have to validate
        # the providing and consuming PTGs. Not needed at creation time since
        # no PTG could be possibly providing or consuming it
        old_red_count = self._multiple_pr_redirect_action_number(
            context._plugin_context.session, context.original['policy_rules'])
        new_red_count = self._multiple_pr_redirect_action_number(
            context._plugin_context.session, context.current['policy_rules'])
        if new_red_count > old_red_count:
            self._validate_new_prs_redirect(context, context.current)

    @log.log
    def update_policy_rule_set_postcommit(self, context):
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
    def delete_policy_rule_set_postcommit(self, context):
        if context.current['child_policy_rule_sets']:
            self._handle_redirect_action(
                context, context.current['child_policy_rule_sets'])

    @log.log
    def create_external_policy_postcommit(self, context):
        self._handle_prs_added(context)

    @log.log
    def update_external_policy_postcommit(self, context):
        self._handle_prs_updated(context)

    @log.log
    def delete_external_policy_postcommit(self, context):
        self._handle_prs_removed(context)

    def _handle_prs_added(self, context):
        # Expecting either a PTG or EP context
        if context.current['consumed_policy_rule_sets']:
            for sci in self._get_chains_by_prs(
                    context, context.current['consumed_policy_rule_sets']):
                chain_context = self._get_chain_admin_context(
                    context._plugin_context, instance_id=sci)
                self._notify_sc_consumer_added(
                    chain_context, context.current, sci)

    def _handle_prs_removed(self, context):
        # Expecting either a PTG or EP context
        if context.current['consumed_policy_rule_sets']:
            for sci in self._get_chains_by_prs(
                    context, context.current['consumed_policy_rule_sets']):
                chain_context = self._get_chain_admin_context(
                    context._plugin_context, instance_id=sci)
                self._notify_sc_consumer_removed(
                    chain_context, context.current, sci)

    def _handle_prs_updated(self, context):
        # Expecting either a PTG or EP context
        if (context.current['consumed_policy_rule_sets'] !=
                context.original['consumed_policy_rule_sets']):
            added, removed = utils.set_difference(
                context.current['consumed_policy_rule_sets'],
                context.original['consumed_policy_rule_sets'])
            if removed:
                for sci in self._get_chains_by_prs(context, removed):
                    chain_context = self._get_chain_admin_context(
                        context._plugin_context, instance_id=sci)
                    self._notify_sc_consumer_removed(
                        chain_context, context.current, sci)
            if added:
                for sci in self._get_chains_by_prs(context, added):
                    chain_context = self._get_chain_admin_context(
                        context._plugin_context, instance_id=sci)
                    self._notify_sc_consumer_removed(
                        chain_context, context.current, sci)

    def _handle_redirect_spec_id_update(self, context):
        if (context.current['action_type'] != gconst.GP_ACTION_REDIRECT
            or context.current['action_value'] ==
            context.original['action_value']):
            return

        spec = self._servicechain_plugin._get_servicechain_spec(
                    context._plugin_context, context.original['action_value'])
        for servicechain_instance in spec.instances:
            sc_instance_id = servicechain_instance.servicechain_instance_id
            sc_instance = self._servicechain_plugin.get_servicechain_instance(
                    context._plugin_context, sc_instance_id)
            old_specs = sc_instance['servicechain_specs']
            # Use the parent/child redirect spec as it is. Only replace the
            # current one
            new_specs = [context.current['action_value'] if
                         x == context.original['action_value'] else
                         x for x in old_specs]
            self._update_servicechain_instance(
                context._plugin_context,
                servicechain_instance.servicechain_instance_id,
                sc_specs=new_specs)

    def _update_servicechain_instance(self, plugin_context, sc_instance_id,
                                      classifier_id=None, sc_specs=None):
        sc_instance_update_data = {}
        if sc_specs:
            sc_instance_update_data.update({'servicechain_specs': sc_specs})
        if classifier_id:
            sc_instance_update_data.update({'classifier_id': classifier_id})
        super(ChainMappingDriver, self)._update_servicechain_instance(
            self._get_chain_admin_context(
                plugin_context, instance_id=sc_instance_id),
            sc_instance_id, sc_instance_update_data)

    # This method would either update an existing chain instance, or creates a
    # new chain instance or delete the existing instance. In case of updates,
    # the parameters that can be updated are service chain spec and
    # classifier ID.
    def _handle_redirect_action(self, context, policy_rule_set_ids,
                                providing_ptg=None):
        policy_rule_sets = context._plugin.get_policy_rule_sets(
            context._plugin_context, filters={'id': policy_rule_set_ids})
        for policy_rule_set in policy_rule_sets:
            if providing_ptg:
                ptgs_providing_prs = [providing_ptg]
            else:
                if not policy_rule_set['providing_policy_target_groups']:
                    continue
                ptgs_providing_prs = context._plugin.get_policy_target_groups(
                    context._plugin_context.elevated(),
                    {'id': policy_rule_set['providing_policy_target_groups']})
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
                hierarchial_classifier_mismatch = False
                classifier_id = policy_rule.get("policy_classifier_id")
                if parent_classifier_id and (parent_classifier_id !=
                                             classifier_id):
                    hierarchial_classifier_mismatch = True
                policy_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': policy_rule.get("policy_actions"),
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
                # Only one Redirect action per PRS. The chain may belong to
                # another PRS in which case the chain should not be deleted
                if (self._is_redirect_in_policy_rule_sets(
                    context, policy_rule_set_ids) and not policy_actions):
                    continue
                spec_id = (policy_actions and policy_actions[0]['action_value']
                           or None)
                for ptg_providing_prs in ptgs_providing_prs:
                    # REVISIT(Magesh): There are concurrency issues here with
                    # concurrent updates to the same PRS, Policy Rule or Action
                    # value
                    if not ptg_providing_prs.get('proxied_group_id'):
                        self._create_or_update_chain(
                            context, ptg_providing_prs['id'],
                            SCI_CONSUMER_NOT_AVAILABLE, spec_id,
                            parent_spec_id, classifier_id,
                            hierarchial_classifier_mismatch,
                            policy_rule_set)

    def _create_or_update_chain(self, context, provider, consumer, spec_id,
                                parent_spec_id, classifier_id,
                                hierarchial_classifier_mismatch, prs_id):
        ptg_chain_map = self._get_ptg_servicechain_mapping(
            context._plugin_context.session, provider)
        if ptg_chain_map:
            if hierarchial_classifier_mismatch or not spec_id:
                ctx = self._get_chain_admin_context(
                    context._plugin_context,
                    tenant_id=ptg_chain_map[0].tenant_id)
                self._delete_servicechain_instance(
                    ctx, ptg_chain_map[0].servicechain_instance_id)
            else:
                sc_specs = [spec_id]
                if parent_spec_id:
                    sc_specs.insert(0, parent_spec_id)
                # One chain per providing PTG
                self._update_servicechain_instance(
                    context._plugin_context,
                    ptg_chain_map[0].servicechain_instance_id,
                    classifier_id=classifier_id,
                    sc_specs=sc_specs)
        elif spec_id and not hierarchial_classifier_mismatch:
            self._create_servicechain_instance(
                context, spec_id, parent_spec_id, provider,
                SCI_CONSUMER_NOT_AVAILABLE, classifier_id, prs_id)

    def _cleanup_redirect_action(self, context):
        for ptg_chain in context.ptg_chain_map:
            ctx = self._get_chain_admin_context(context._plugin_context,
                                                tenant_id=ptg_chain.tenant_id)
            self._delete_servicechain_instance(
                ctx, ptg_chain.servicechain_instance_id)

    def _create_servicechain_instance(self, context, servicechain_spec,
                                      parent_servicechain_spec,
                                      provider_ptg_id, consumer_ptg_id,
                                      classifier_id, policy_rule_set):
        sc_spec = [servicechain_spec]
        if parent_servicechain_spec:
            sc_spec.insert(0, parent_servicechain_spec)
        config_param_values = {}
        provider_ptg = context._plugin.get_policy_target_group(
            utils.admin_context(context._plugin_context), provider_ptg_id)
        p_ctx = self._get_chain_admin_context(
            context._plugin_context,
            provider_tenant_id=provider_ptg['tenant_id'])
        session = context._plugin_context.session
        network_service_policy_id = provider_ptg.get(
            "network_service_policy_id")
        if network_service_policy_id:
            nsp = context._plugin.get_network_service_policy(
                p_ctx, network_service_policy_id)
            service_params = nsp.get("network_service_params")
            for service_parameter in service_params:
                param_type = service_parameter.get("type")
                param_value = service_parameter.get("value")
                if param_type == "ip_single" and param_value == "self_subnet":
                    key = service_parameter.get("name")
                    servicepolicy_ptg_ip_map = (
                        self._get_ptg_policy_ipaddress_mapping(
                            session, provider_ptg_id))
                    servicepolicy_ip = servicepolicy_ptg_ip_map.get(
                                                        "ipaddress")
                    config_param_values[key] = servicepolicy_ip
                elif param_type == "ip_single" and param_value == "nat_pool":
                    key = service_parameter.get("name")
                    fip_maps = (
                        self._get_ptg_policy_fip_mapping(
                            context._plugin_context.session,
                            provider_ptg_id))
                    servicepolicy_fip_ids = []
                    for fip_map in fip_maps:
                        servicepolicy_fip_ids.append(fip_map.floatingip_id)
                    config_param_values[key] = servicepolicy_fip_ids
        name = 'gbp_%s_%s' % (policy_rule_set['name'], provider_ptg['name'])

        attrs = {'tenant_id': p_ctx.tenant,
                 'name': name,
                 'description': "",
                 'servicechain_specs': sc_spec,
                 'provider_ptg_id': provider_ptg_id,
                 'consumer_ptg_id': SCI_CONSUMER_NOT_AVAILABLE,
                 'management_ptg_id': None,
                 'classifier_id': classifier_id,
                 'config_param_values': jsonutils.dumps(config_param_values)}
        sc_instance = super(
            ChainMappingDriver, self)._create_servicechain_instance(
                p_ctx, attrs)
        self._set_ptg_servicechain_instance_mapping(
            session, provider_ptg_id, SCI_CONSUMER_NOT_AVAILABLE,
            sc_instance['id'], p_ctx.tenant)
        return sc_instance

    def _set_ptg_servicechain_instance_mapping(self, session, provider_ptg_id,
                                               consumer_ptg_id,
                                               servicechain_instance_id,
                                               provider_tenant_id):
        with session.begin(subtransactions=True):
            mapping = PtgServiceChainInstanceMapping(
                provider_ptg_id=provider_ptg_id,
                consumer_ptg_id=consumer_ptg_id,
                servicechain_instance_id=servicechain_instance_id,
                tenant_id=provider_tenant_id)
            session.add(mapping)

    def _get_ptg_servicechain_mapping(self, session, provider_ptg_id=None,
                                      consumer_ptg_id=None, tenant_id=None,
                                      servicechain_instance_id=None,
                                      provider_ptg_ids=None):
        with session.begin(subtransactions=True):
            query = session.query(PtgServiceChainInstanceMapping)
            if provider_ptg_id:
                query = query.filter_by(provider_ptg_id=provider_ptg_id)
            elif provider_ptg_ids:
                query = query.filter(
                    PtgServiceChainInstanceMapping.provider_ptg_id.in_(
                        list(provider_ptg_ids)))
            if consumer_ptg_id:
                query = query.filter_by(consumer_ptg_id=consumer_ptg_id)
            if servicechain_instance_id:
                query = query.filter_by(
                    servicechain_instance_id=servicechain_instance_id)
            if tenant_id:
                query = query.filter_by(consumer_ptg_id=tenant_id)
            all = query.all()
            return [utils.DictClass([('provider_ptg_id', x.provider_ptg_id),
                                     ('consumer_ptg_id', x.consumer_ptg_id),
                                     ('servicechain_instance_id',
                                      x.servicechain_instance_id),
                                     ('tenant_id', x.tenant_id)])
                    for x in all]

    def _get_chain_admin_context(self, plugin_context, tenant_id=None,
                                 provider_tenant_id=None, instance_id=None):
        ctx = plugin_context.elevated()
        # REVISIT(Ivar): Any particular implication when a provider owned PT
        # exist in the consumer PTG? Especially when the consumer PTG belongs
        # to another tenant? We may want to consider a strong convention
        # for reference plumbers to absolutely avoid this kind of inter tenant
        # object creation when the owner is the provider (in which case, the
        # context can as well be a normal context without admin capabilities).
        ctx.tenant_id = None
        if instance_id:
            cmap = self._get_ptg_servicechain_mapping(
                ctx.session, servicechain_instance_id=instance_id)
            if cmap:
                ctx.tenant_id = cmap[0].tenant_id
        if not ctx.tenant_id:
            ctx.tenant_id = tenant_id or self.chain_owner or provider_tenant_id
        if self.chain_owner == ctx.tenant_id:
            ctx.auth_token = self.chain_tenant_keystone_client().get_token(
                self.chain_owner)
        return ctx

    def _is_redirect_in_policy_rule_sets(self, context, policy_rule_sets):
        policy_rule_ids = []
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': policy_rule_sets}):
            policy_rule_ids.extend(prs['policy_rules'])
        for rule in context._plugin.get_policy_rules(
                context._plugin_context, filters={'id': policy_rule_ids}):
            redirect_actions = context._plugin.get_policy_actions(
                        context._plugin_context,
                        filters={'id': rule["policy_actions"],
                                 'action_type': [gconst.GP_ACTION_REDIRECT]})
            if redirect_actions:
                return True
        return False

    def _get_redirect_action(self, context, policy_rule):
        for action in context._plugin.get_policy_actions(
                context._plugin_context,
                filters={'id': policy_rule['policy_actions']}):
            if action['action_type'] == gconst.GP_ACTION_REDIRECT:
                return action

    def _validate_new_prs_redirect(self, context, prs):
        if self._prss_redirect_rules(context._plugin_context.session,
                                     [prs['id']]) > 1:
            raise exc.MultipleRedirectActionsNotSupportedForPRS()
        for ptg in context._plugin.get_policy_target_groups(
                context._plugin_context,
                {'id': prs['providing_policy_target_groups']}):
            self._validate_ptg_prss(context, ptg)

    def _prss_redirect_rules(self, session, prs_ids):
        if len(prs_ids) == 0:
            # No result will be found in this case
            return 0
        query = (session.query(gpdb.gpdb.PolicyAction).
                 join(gpdb.gpdb.PolicyRuleActionAssociation).
                 join(gpdb.gpdb.PolicyRule).
                 join(gpdb.gpdb.PRSToPRAssociation).
                 filter(
                 gpdb.gpdb.PRSToPRAssociation.policy_rule_set_id.in_(prs_ids)).
                 filter(gpdb.gpdb.PolicyAction.action_type ==
                        gconst.GP_ACTION_REDIRECT))
        return query.count()

    def _multiple_pr_redirect_action_number(self, session, pr_ids):
        # Given a set of rules, gives the total number of redirect actions
        # found
        if len(pr_ids) == 0:
            # No result will be found in this case
            return 0
        return (session.query(gpdb.gpdb.PolicyAction).
                join(gpdb.gpdb.PolicyRuleActionAssociation).
                filter(
                gpdb.gpdb.PolicyRuleActionAssociation.policy_rule_id.in_(
                    pr_ids)).
                filter(gpdb.gpdb.PolicyAction.action_type ==
                       gconst.GP_ACTION_REDIRECT)).count()

    def _reject_shared(self, object, type):
        if object.get('shared'):
            raise exc.InvalidSharedResource(type=type,
                                            driver='chain_mapping')

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

    def _validate_ptg_prss(self, context, ptg):
        # If the PTG is providing a redirect PRS, it can't provide any more
        # redirect rules
        if self._prss_redirect_rules(context._plugin_context.session,
                                     ptg['provided_policy_rule_sets']) > 1:
                raise exc.PTGAlreadyProvidingRedirectPRS(ptg_id=ptg['id'])

    def _handle_classifier_update_notification(self, context):
        # Invoke Service chain update notify hook if protocol or port or
        # direction is updated. The SC side will have to reclassify the chain
        # and update the traffic steering programming
        if (context.original['port_range'] != context.current['port_range'] or
            context.original['protocol'] != context.current['protocol'] or
            context.original['direction'] != context.current['direction']):
            sc_instances = (
                self._servicechain_plugin.get_servicechain_instances(
                    context._plugin_context.elevated(),
                    filters={'classifier_id': [context.current['id']]}))
            for sc_instance in sc_instances:
                cmap = self._get_ptg_servicechain_mapping(
                    context._plugin_context.session,
                    servicechain_instance_id=sc_instance['id'])
                ctx = self._get_chain_admin_context(context._plugin_context,
                                                    cmap[0].tenant_id)
                self._servicechain_plugin.notify_chain_parameters_updated(
                    ctx, sc_instance['id'])

    def _stash_ptg_modified_chains(self, context):
        #Update service chain instance when any ruleset is changed
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']

        removed_provided_prs = (set(orig_provided_policy_rule_sets) -
                                set(curr_provided_policy_rule_sets))
        added_provided_prs = (set(curr_provided_policy_rule_sets) -
                              set(orig_provided_policy_rule_sets))
        context.ptg_chain_map = []
        # If the Redirect is removed, delete the chain. If the spec is
        # changed, then update the existing instance with new spec
        if (self._is_redirect_in_policy_rule_sets(
                context, removed_provided_prs) and not
            self._is_redirect_in_policy_rule_sets(
                context, added_provided_prs)):
            context.ptg_chain_map += self._get_ptg_servicechain_mapping(
                context._plugin_context.session, context.current['id'])

    def _get_chains_by_prs(self, context, prs_ids):
        # REVISIT(ivar): only works under the assumption that only -one- chain
        # can be provided by a given group. A more direct way of retrieving
        # this info must be implemented before we drop this limitation
        result = set()
        for prs in self._get_policy_rule_sets(
                context._plugin_context.elevated(), {'id': prs_ids}):
            if prs['providing_policy_target_groups']:
                result |= set(
                    [x.servicechain_instance_id for x in
                     self._get_ptg_servicechain_mapping(
                         context._plugin_context.session,
                         provider_ptg_ids=prs[
                             'providing_policy_target_groups'])])
        return result
