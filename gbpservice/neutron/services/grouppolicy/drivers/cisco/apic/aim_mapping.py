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

from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron._i18n import _LI
from neutron import manager
from oslo_concurrency import lockutils
from oslo_log import helpers as log
from oslo_log import log as logging

from gbpservice.neutron.extensions import aim_driver_ext as aim_ext
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as aim_md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim.extensions import (
    cisco_apic)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.services.grouppolicy import plugin as gbp_plugin


LOG = logging.getLogger(__name__)
FORWARD = 'Forward'
REVERSE = 'Reverse'
FILTER_DIRECTIONS = {FORWARD: False, REVERSE: True}
FORWARD_FILTER_ENTRIES = 'Forward-FilterEntries'
REVERSE_FILTER_ENTRIES = 'Reverse-FilterEntries'

# Definitions duplicated from apicapi lib
APIC_OWNED = 'apic_owned_'


class ExplicitSubnetAssociationNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Explicit subnet association not supported by APIC driver.")


class AIMMappingDriver(nrd.CommonNeutronBase):
    """AIM Mapping Orchestration driver.

    This driver maps GBP resources to the ACI-Integration-Module (AIM).
    """

    @log.log_method_call
    def initialize(self):
        LOG.info(_LI("APIC AIM Policy Driver initializing"))
        self.db = model.DbModel()
        super(AIMMappingDriver, self).initialize()
        self._apic_aim_mech_driver = None

    @property
    def aim_mech_driver(self):
        if not self._apic_aim_mech_driver:
            ml2plus_plugin = manager.NeutronManager.get_plugin()
            self._apic_aim_mech_driver = (
                ml2plus_plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
        return self._apic_aim_mech_driver

    @property
    def aim(self):
        return self.aim_mech_driver.aim

    @property
    def name_mapper(self):
        return self.aim_mech_driver.name_mapper

    @log.log_method_call
    def ensure_tenant(self, plugin_context, tenant_id):
        self.aim_mech_driver.ensure_tenant(plugin_context, tenant_id)

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        if context.current['subnets']:
            raise ExplicitSubnetAssociationNotSupported()

        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])

        if not context.current['l2_policy_id']:
            self._create_implicit_l2_policy(context, clean_session=False)
            ptg_db['l2_policy_id'] = l2p_id = context.current['l2_policy_id']
        else:
            l2p_id = context.current['l2_policy_id']

        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, l2p_id)

        net = self._get_network(
            context._plugin_context, l2p_db['network_id'],
            clean_session=False)

        self._use_implicit_subnet(context)

        aim_ctx = self._get_aim_context(context)

        session = context._plugin_context.session

        bd_name = str(self.name_mapper.network(
            session, net['id'], net['name']))
        bd_tenant_name = str(self._aim_tenant_name(
            session, context.current['tenant_id']))

        epg = self._aim_endpoint_group(session, context.current, bd_name,
                                       bd_tenant_name)
        self.aim.create(aim_ctx, epg)

    @log.log_method_call
    def update_policy_target_group_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def delete_policy_target_group_precommit(self, context):
        plugin_context = context._plugin_context
        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])
        session = context._plugin_context.session

        aim_ctx = self._get_aim_context(context)
        epg = self._aim_endpoint_group(session, context.current)
        self.aim.delete(aim_ctx, epg)
        self.name_mapper.delete_apic_name(session, context.current['id'])

        subnet_ids = [assoc['subnet_id'] for assoc in ptg_db['subnets']]

        context._plugin._remove_subnets_from_policy_target_group(
            context._plugin_context, ptg_db['id'])
        if subnet_ids:
            for subnet_id in subnet_ids:
                if not context._plugin._get_ptgs_for_subnet(
                    context._plugin_context, subnet_id):
                    self._cleanup_subnet(plugin_context, subnet_id,
                                         clean_session=False)

        if ptg_db['l2_policy_id']:
            l2p_id = ptg_db['l2_policy_id']
            ptg_db.update({'l2_policy_id': None})
            l2p_db = context._plugin._get_l2_policy(
                context._plugin_context, l2p_id)
            if not l2p_db['policy_target_groups']:
                self._cleanup_l2_policy(context, l2p_id, clean_session=False)

    @log.log_method_call
    def extend_policy_target_group_dict(self, session, result):
        epg = self._get_aim_endpoint_group(session, result)
        if epg:
            result[cisco_apic.DIST_NAMES] = {cisco_apic.EPG: epg.dn}

    @log.log_method_call
    def get_policy_target_group_status(self, context):
        session = context._plugin_context.session
        epg = self._get_aim_endpoint_group(session, context.current)
        context.current['status'] = self._map_aim_status(session, epg)

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        if not context.current['port_id']:
            ptg = self._db_plugin(
                context._plugin).get_policy_target_group(
                    context._plugin_context,
                    context.current['policy_target_group_id'])
            subnets = self._get_subnets(
                context._plugin_context, {'id': ptg['subnets']},
                clean_session=False)

            self._use_implicit_port(context, subnets=subnets,
                                    clean_session=False)

    @log.log_method_call
    def update_policy_target_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def delete_policy_target_precommit(self, context):
        pt_db = context._plugin._get_policy_target(
            context._plugin_context, context.current['id'])
        if pt_db['port_id']:
            self._cleanup_port(context._plugin_context, pt_db['port_id'])

    @log.log_method_call
    def delete_l3_policy_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def create_policy_rule_precommit(self, context):
        entries = alib.get_filter_entries_for_policy_rule(context)
        if entries['forward_rules']:
            session = context._plugin_context.session
            aim_ctx = self._get_aim_context(context)
            aim_filter = self._aim_filter(session, context.current)
            self.aim.create(aim_ctx, aim_filter)
            self._create_aim_filter_entries(session, aim_ctx, aim_filter,
                                            entries['forward_rules'])
            if entries['reverse_rules']:
                # Also create reverse rule
                aim_filter = self._aim_filter(session, context.current,
                                              reverse_prefix=True)
                self.aim.create(aim_ctx, aim_filter)
                self._create_aim_filter_entries(session, aim_ctx, aim_filter,
                                                entries['reverse_rules'])

    @log.log_method_call
    def update_policy_rule_precommit(self, context):
        self.delete_policy_rule_precommit(context)
        self.create_policy_rule_precommit(context)

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = self._get_aim_context(context)
        aim_filter = self._aim_filter(session, context.current)
        aim_filter_entries = self.aim.find(
            aim_ctx, aim_resource.FilterEntry,
            tenant_name=aim_filter.tenant_name,
            filter_name=aim_filter.name)
        for entry in aim_filter_entries:
            self.aim.delete(aim_ctx, entry)
        self.aim.delete(aim_ctx, aim_filter)
        aim_reverse_filter = self._aim_filter(
            session, context.current, reverse_prefix=True)
        if aim_reverse_filter:
            aim_reverse_filter_entries = self.aim.find(
                aim_ctx, aim_resource.FilterEntry,
                tenant_name=aim_reverse_filter.tenant_name,
                filter_name=aim_reverse_filter.name)
            for entry in aim_reverse_filter_entries:
                self.aim.delete(aim_ctx, entry)
            self.aim.delete(aim_ctx, aim_reverse_filter)
        self.name_mapper.delete_apic_name(session, context.current['id'])

    @log.log_method_call
    def extend_policy_rule_dict(self, session, result):
        result[cisco_apic.DIST_NAMES] = {}
        aim_filter_entries = self._get_aim_filter_entries(session, result)
        for k, v in aim_filter_entries.iteritems():
            dn_list = []
            for entry in v:
                dn_list.append(entry.dn)
            if k == FORWARD:
                result[cisco_apic.DIST_NAMES].update(
                    {aim_ext.FORWARD_FILTER_ENTRIES: dn_list})
            else:
                result[cisco_apic.DIST_NAMES].update(
                    {aim_ext.REVERSE_FILTER_ENTRIES: dn_list})

    @log.log_method_call
    def get_policy_rule_status(self, context):
        session = context._plugin_context.session
        aim_filters = self._get_aim_filters(session, context.current)
        aim_filter_entries = self._get_aim_filter_entries(
            session, context.current)
        context.current['status'] = self._merge_aim_status(
            session, aim_filters.values() + aim_filter_entries.values())

    @log.log_method_call
    def create_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise alib.HierarchicalContractsNotSupported()
        aim_ctx = self._get_aim_context(context)
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        self.aim.create(aim_ctx, aim_contract)
        rules = self._db_plugin(context._plugin).get_policy_rules(
            context._plugin_context,
            filters={'id': context.current['policy_rules']})
        self._populate_aim_contract_subject(context, aim_contract, rules)

    @log.log_method_call
    def update_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise alib.HierarchicalContractsNotSupported()
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        rules = self._db_plugin(context._plugin).get_policy_rules(
            context._plugin_context,
            filters={'id': context.current['policy_rules']})
        self._populate_aim_contract_subject(
            context, aim_contract, rules, create=False)

    @log.log_method_call
    def delete_policy_rule_set_precommit(self, context):
        aim_ctx = self._get_aim_context(context)
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        aim_contract_subject = self._aim_contract_subject(aim_contract)
        self.aim.delete(aim_ctx, aim_contract_subject)
        self.aim.delete(aim_ctx, aim_contract)

    @log.log_method_call
    def extend_policy_rule_set_dict(self, session, result):
        result[cisco_apic.DIST_NAMES] = {}
        aim_contract_fetched = self._get_aim_contract(session, result)
        aim_contract_subject_fetched = self._get_aim_contract_subject(
            session, result)
        result[cisco_apic.DIST_NAMES].update(
            {aim_ext.CONTRACT: aim_contract_fetched.dn,
             aim_ext.CONTRACT_SUBJECT: aim_contract_subject_fetched.dn})

    @log.log_method_call
    def get_policy_rule_set_status(self, context):
        session = context._plugin_context.session
        aim_contract_fetched = self._get_aim_contract(session, context.current)
        aim_contract_subject_fetched = self._get_aim_contract_subject(
            session, context.current)
        context.current['status'] = self._merge_aim_status(
            session, [aim_contract_fetched, aim_contract_subject_fetched])

    def _aim_tenant_name(self, session, tenant_id):
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(apic_name)s",
                  {'id': tenant_id, 'apic_name': tenant_name})
        return tenant_name

    def _aim_endpoint_group(self, session, ptg, bd_name=None,
                            bd_tenant_name=None):
        # This returns a new AIM EPG resource
        tenant_id = ptg['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id)
        id = ptg['id']
        name = ptg['name']
        epg_name = self.name_mapper.policy_target_group(session, id, name)
        LOG.debug("Mapped ptg_id %(id)s with name %(name)s to %(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': epg_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(epg_name),
                  'app_profile_name': aim_md.AP_NAME}
        if bd_name:
            kwargs['bd_name'] = bd_name
        if bd_tenant_name:
            kwargs['bd_tenant_name'] = bd_tenant_name

        epg = aim_resource.EndpointGroup(**kwargs)
        return epg

    def _get_aim_endpoint_group(self, session, ptg):
        # This gets an EPG from the AIM DB
        epg = self._aim_endpoint_group(session, ptg)
        aim_ctx = aim_context.AimContext(session)
        epg_fetched = self.aim.get(aim_ctx, epg)
        if not epg_fetched:
            LOG.debug("No EPG found in AIM DB")
        else:
            LOG.debug("Got epg: %s", epg_fetched.__dict__)
        return epg_fetched

    def _aim_filter(self, session, pr, reverse_prefix=False):
        # This returns a new AIM Filter resource
        tenant_id = pr['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id)
        id = pr['id']
        name = pr['name']
        if reverse_prefix:
            filter_name = self.name_mapper.policy_rule(
                session, id, resource_name=name, prefix=alib.REVERSE_PREFIX)
        else:
            filter_name = self.name_mapper.policy_rule(session, id,
                                                       resource_name=name)
        LOG.debug("Mapped policy_rule_id %(id)s with name %(name)s to",
                  "%(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': filter_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(filter_name)}

        aim_filter = aim_resource.Filter(**kwargs)
        return aim_filter

    def _aim_filter_entry(self, session, aim_filter, filter_entry_name,
                          filter_entry_attrs):
        # This returns a new AIM FilterEntry resource
        tenant_name = aim_filter.tenant_name
        filter_name = aim_filter.name
        kwargs = {'tenant_name': tenant_name,
                  'filter_name': filter_name,
                  'name': filter_entry_name}
        kwargs.update(filter_entry_attrs)

        aim_filter_entry = aim_resource.FilterEntry(**kwargs)
        return aim_filter_entry

    def _create_aim_filter_entries(self, session, aim_ctx, aim_filter,
                                   filter_entries):
        for k, v in filter_entries.iteritems():
            aim_filter_entry = self._aim_filter_entry(
                session, aim_filter, k, v)
            self.aim.create(aim_ctx, aim_filter_entry)

    def _get_aim_filters(self, session, policy_rule):
        # This gets the Forward and Reverse Filters from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = {}
        for k, v in FILTER_DIRECTIONS.iteritems():
            aim_filter = self._aim_filter(session, policy_rule, v)
            aim_filter_fetched = self.aim.get(aim_ctx, aim_filter)
            if not aim_filter_fetched:
                LOG.debug("No %s Filter found in AIM DB", k)
            else:
                LOG.debug("Got %s Filter: %s",
                          (aim_filter_fetched.__dict__, k))
            filters[k] = aim_filter_fetched
        return filters

    def _get_aim_filter_names(self, session, policy_rule):
        # Forward and Reverse AIM Filter names for a Policy Rule
        aim_filters = self._get_aim_filters(session, policy_rule)
        aim_filter_names = [f.name for f in aim_filters.values()]
        return aim_filter_names

    def _get_aim_filter_entries(self, session, policy_rule):
        # This gets the Forward and Reverse FilterEntries from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = self._get_aim_filters(session, policy_rule)
        filters_entries = {}
        for k, v in filters.iteritems():
            aim_filter_entries = self.aim.find(
                aim_ctx, aim_resource.FilterEntry,
                tenant_name=v.tenant_name, filter_name=v.name)
            if not aim_filter_entries:
                LOG.debug("No %s FilterEntry found in AIM DB", k)
            else:
                LOG.debug("Got %s FilterEntry: %s",
                          (aim_filter_entries, k))
            filters_entries[k] = aim_filter_entries
        return filters_entries

    def _aim_contract(self, session, policy_rule_set):
        # This returns a new AIM Contract resource
        tenant_id = policy_rule_set['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id)
        id = policy_rule_set['id']
        name = policy_rule_set['name']
        contract_name = self.name_mapper.policy_rule_set(session, id,
                                                         resource_name=name)
        LOG.debug("Mapped policy_rule_set_id %(id)s with name %(name)s to",
                  "%(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': contract_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(contract_name)}

        aim_contract = aim_resource.Contract(**kwargs)
        return aim_contract

    def _aim_contract_subject(self, aim_contract, in_filters=None,
                              out_filters=None, bi_filters=None):
        # This returns a new AIM ContractSubject resource
        if not in_filters:
            in_filters = []
        if not out_filters:
            out_filters = []
        if not bi_filters:
            bi_filters = []
        # Since we create one ContractSubject per Contract,
        # ContractSubject is given the Contract name
        kwargs = {'tenant_name': aim_contract.tenant_name,
                  'contract_name': aim_contract.name,
                  'name': aim_contract.name,
                  'in_filters': in_filters,
                  'out_filters': out_filters,
                  'bi_filters': bi_filters}

        aim_contract_subject = aim_resource.ContractSubject(**kwargs)
        return aim_contract_subject

    def _populate_aim_contract_subject(self, context, aim_contract,
                                       policy_rules, create=True):
        in_filters, out_filters, bi_filters = [], [], []
        session = context._plugin_context.session
        for rule in policy_rules:
            aim_filters = self._get_aim_filter_names(session, rule)
            classifier = context._plugin.get_policy_classifier(
                context._plugin_context, rule['policy_classifier_id'])
            if classifier['direction'] == g_const.GP_DIRECTION_IN:
                in_filters += aim_filters
            elif classifier['direction'] == g_const.GP_DIRECTION_OUT:
                out_filters += aim_filters
            else:
                bi_filters += aim_filters
        aim_ctx = self._get_aim_context(context)
        if create:
            # We create one ContractSubject per Contract
            aim_contract_subject = self._aim_contract_subject(
                aim_contract, in_filters, out_filters, bi_filters)
            self.aim.create(aim_ctx, aim_contract_subject)
        else:
            aim_contract_subject = self._aim_contract_subject(aim_contract)
            self.aim.update(aim_ctx, aim_contract_subject,
                            **{'in_filters': in_filters,
                               'out_filters': out_filters,
                               'bi_filters': bi_filters})

    def _get_aim_contract(self, session, policy_rule_set):
        # This gets a Contract from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        contract = self._aim_contract(session, policy_rule_set)
        contract_fetched = self.aim.get(aim_ctx, contract)
        if not contract_fetched:
            LOG.debug("No Contract found in AIM DB")
        else:
            LOG.debug("Got Contract: %s", contract_fetched.__dict__)
        return contract_fetched

    def _get_aim_contract_subject(self, session, policy_rule_set):
        # This gets a ContractSubject from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        contract = self._aim_contract(session, policy_rule_set)
        contract_subject = self._aim_contract_subject(contract)
        contract_subject_fetched = self.aim.get(aim_ctx, contract_subject)
        if not contract_subject_fetched:
            LOG.debug("No Contract found in AIM DB")
        else:
            LOG.debug("Got ContractSubject: %s",
                      contract_subject_fetched.__dict__)
        return contract_subject_fetched

    def _aim_bridge_domain(self, session, tenant_id, network_id, network_name):
        # This returns a new AIM BD resource
        tenant_name = self._aim_tenant_name(session, tenant_id)
        bd_name = self.name_mapper.network(session, network_id, network_name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': network_id, 'name': network_name,
                  'apic_name': bd_name})

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(bd_name))
        return bd

    def _get_l2p_subnets(self, context, l2p_id, clean_session=False):
        plugin_context = context._plugin_context
        l2p = context._plugin.get_l2_policy(plugin_context, l2p_id)
        # REVISIT: The following should be a get_subnets call via local API
        return self._core_plugin.get_subnets_by_network(
            plugin_context, l2p['network_id'])

    def _sync_ptg_subnets(self, context, l2p):
        l2p_subnets = [x['id'] for x in
                       self._get_l2p_subnets(context, l2p['id'])]
        ptgs = context._plugin._get_policy_target_groups(
            context._plugin_context.elevated(), {'l2_policy_id': [l2p['id']]})
        for sub in l2p_subnets:
            # Add to PTG
            for ptg in ptgs:
                if sub not in ptg['subnets']:
                    try:
                        (context._plugin.
                         _add_subnet_to_policy_target_group(
                             context._plugin_context.elevated(),
                             ptg['id'], sub))
                    except gpolicy.PolicyTargetGroupNotFound as e:
                        LOG.warning(e)

    def _use_implicit_subnet(self, context, force_add=False,
                             clean_session=False):
        """Implicit subnet for AIM.

        The first PTG in a L2P will allocate a new subnet from the L3P.
        Any subsequent PTG in the same L2P will use the same subnet.
        Additional subnets will be allocated as and when the currently used
        subnet runs out of IP addresses.
        """
        l2p_id = context.current['l2_policy_id']
        with lockutils.lock(l2p_id, external=True):
            subs = self._get_l2p_subnets(context, l2p_id)
            subs = set([x['id'] for x in subs])
            added = []
            if not subs or force_add:
                l2p = context._plugin.get_l2_policy(
                    context._plugin_context, l2p_id)
                name = APIC_OWNED + l2p['name']
                added = super(
                    AIMMappingDriver, self)._use_implicit_subnet(
                        context, subnet_specifics={'name': name},
                        is_proxy=False, clean_session=clean_session)
            context.add_subnets(subs - set(context.current['subnets']))
            for subnet in added:
                self._sync_ptg_subnets(context, l2p)

    def _map_aim_status(self, session, aim_resource_obj):
        # Note that this implementation assumes that this driver
        # is the only policy driver configured, and no merging
        # with any previous status is required.
        aim_ctx = aim_context.AimContext(session)
        aim_status = self.aim.get_status(aim_ctx, aim_resource_obj)
        if not aim_status:
            # REVIST(Sumit)
            return gp_const.STATUS_BUILD
        if aim_status.is_error():
            return gp_const.STATUS_ERROR
        elif aim_status.is_build():
            return gp_const.STATUS_BUILD
        else:
            return gp_const.STATUS_ACTIVE

    def _merge_aim_status(self, session, aim_resource_obj_list):
        # Note that this implementation assumes that this driver
        # is the only policy driver configured, and no merging
        # with any previous status is required.
        # When merging states of multiple AIM objects, the status
        # priority is ERROR > BUILD > ACTIVE.
        merged_status = gp_const.STATUS_ACTIVE
        for aim_obj in aim_resource_obj_list:
            status = self._map_aim_status(session, aim_obj)
            if status != gp_const.STATUS_ACTIVE:
                merged_status = status
            if merged_status == gp_const.STATUS_ERROR:
                break
        return merged_status

    def _db_plugin(self, plugin_obj):
            return super(gbp_plugin.GroupPolicyPlugin, plugin_obj)

    def _get_aim_context(self, context):
        session = context._plugin_context.session
        return aim_context.AimContext(session)
