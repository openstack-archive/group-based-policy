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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron._i18n import _LI
from neutron import context as nctx
from neutron import manager
from oslo_concurrency import lockutils
from oslo_log import helpers as log
from oslo_log import log as logging

from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as aim_md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim.extensions import (
    cisco_apic)
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)


LOG = logging.getLogger(__name__)
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
        self.aim = aim_manager.AimManager()
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
    def name_mapper(self):
        return self.aim_mech_driver.name_mapper

    def _aim_tenant_name(self, context):
        session = context._plugin_context.session
        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})
        return tenant_name

    def _aim_endpoint_group(self, context, bd_name=None, bd_tenant_name=None):
        session = context._plugin_context.session
        tenant_name = self._aim_tenant_name(context)
        id = context.current['id']
        name = context.current['name']
        epg_name = self.name_mapper.policy_target_group(session, id, name)
        LOG.info(_LI("Mapped ptg_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': id, 'name': name, 'apic_name': epg_name})

        epg = aim_resource.EndpointGroup(tenant_name=str(tenant_name),
                                         name=str(epg_name),
                                         app_profile_name=aim_md.AP_NAME,
                                         bd_name=bd_name,
                                         bd_tenant_name=bd_tenant_name)
        return epg

    def _aim_bridge_domain(self, context, network_id, network_name):
        session = context._plugin_context.session
        tenant_name = self._aim_tenant_name(context)
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
        ptgs = context._plugin.get_policy_target_groups(
            nctx.get_admin_context(), {'l2_policy_id': [l2p['id']]})
        for sub in l2p_subnets:
            # Add to PTG
            for ptg in ptgs:
                if sub not in ptg['subnets']:
                    try:
                        (context._plugin.
                         _add_subnet_to_policy_target_group(
                             nctx.get_admin_context(), ptg['id'], sub))
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
                l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                    l2p_id)
                name = APIC_OWNED + l2p['name']
                added = super(
                    AIMMappingDriver, self)._use_implicit_subnet(
                        context, subnet_specifics={'name': name},
                        is_proxy=False, clean_session=clean_session)
            context.add_subnets(subs - set(context.current['subnets']))
            for subnet in added:
                self._sync_ptg_subnets(context, l2p)

    @log.log_method_call
    def ensure_tenant(self, plugin_context, tenant_id):
        self.aim_mech_driver.ensure_tenant(plugin_context, tenant_id)

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        if context.current['subnets']:
            raise ExplicitSubnetAssociationNotSupported()

        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])

        session = context._plugin_context.session

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

        aim_ctx = aim_context.AimContext(session)

        bd_name = str(self.name_mapper.network(
            session, net['id'], net['name']))
        bd_tenant_name = str(self._aim_tenant_name(context))

        epg = self._aim_endpoint_group(context, bd_name, bd_tenant_name)
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

        aim_ctx = aim_context.AimContext(session)
        epg = self._aim_endpoint_group(context)
        self.aim.delete(aim_ctx, epg)
        self.name_mapper.delete_apic_name(session, context.current['id'])

        # REVISIT(Sumit): Delete app_profile if this is last PTG

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

    def extend_policy_target_group_dict(self, session, result):
        LOG.info(_LI("AIM Mapping Driver extending dict for PTG: %s"), result)

        tenant_id = result['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})

        id = result['id']
        name = result['name']

        aim_ctx = aim_context.AimContext(session)
        epg_name = self.name_mapper.policy_target_group(session, id, name)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_name,
                                         name=epg_name,
                                         app_profile_name=aim_md.AP_NAME)
        epg = self.aim.get(aim_ctx, epg)
        if epg:
            LOG.debug("got EPG with DN: %s", epg.dn)

            result[cisco_apic.DIST_NAMES] = {cisco_apic.EPG: epg.dn}

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        if not context.current['port_id']:
            ptg = context._plugin.get_policy_target_group(
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
        pass
        # TODO(sumit): uncomment the following when AIM supports TenantFilter
        # aim_context = aim_manager.AimContext(context._plugin_context.session)
        # tenant = context.current['tenant_id']
        # pr_id = context.current['id']
        # pr_name = context.current['name']
        # rn = self.mapper.tenant_filter(tenant, pr_id, name=pr_name)
        # tf = aim_resource.TenantFilter(tenant_rn=tenant, rn=rn)
        # self.aim.create(aim_context, tf)
        # pr_db = context._plugin_context.session.query(
        #    gpdb.PolicyRule).get(context.current['id'])
        # context._plugin_context.session.expunge(pr_db)
        # TODO(sumit): uncomment the following line when the GBP resource
        # is appropriately extended to hold AIM references
        # pr_db['aim_id'] = rn
        # context._plugin_context.session.add(pr_db)

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        pass
        # TODO(sumit): uncomment the following when AIM supports TenantFilter
        # aim_context = aim_manager.AimContext(context._plugin_context.session)
        # tenant = context.current['tenant_id']
        # pr_id = context.current['id']
        # rn = self.mapper.tenant_filter(tenant, pr_id)
        # tf = aim_resource.TenantFilter(tenant_rn=tenant, rn=rn)
        # self.aim.delete(aim_context, tf)
