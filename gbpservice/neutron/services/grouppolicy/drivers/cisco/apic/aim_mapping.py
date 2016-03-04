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
from keystoneclient.v2_0 import client as keyclient
from neutron._i18n import _LI
from oslo_config import cfg
from oslo_log import helpers as log
from oslo_log import log as logging

# from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model


LOG = logging.getLogger(__name__)


class AIMMappingDriver(nrd.CommonNeutronBase):
    """AIM Mapping Orchestration driver.

    This driver maps GBP resources to the ACI-Integration-Module (AIM).
    """

    @log.log_method_call
    def initialize(self):
        LOG.info(_LI("APIC AIM Policy Driver initializing"))
        self.db = model.DbModel()
        self.name_mapper = apic_mapper.APICNameMapper(
            self.db, logging, keyclient, cfg.CONF.keystone_authtoken)
        self.aim = aim_manager.AimManager()
        super(AIMMappingDriver, self).initialize()

    # TODO(Sumit): Ensure tenant, check if it can be shared with
    # ML2PLUS MD

    def _aim_tenant_name(self, context):
        session = context._plugin_context.session
        tenant_id = context.current['tenant_id']
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.info(_LI("Mapped tenant_id %(id)s to %(apic_name)s"),
                 {'id': tenant_id, 'apic_name': tenant_name})
        return tenant_name

    def _aim_app_profile_name(self, context):
        tenant_name = self._aim_tenant_name(context)
        # REVISIT(Sumit): Check if app_profile name needs to be something else
        return tenant_name

    def _aim_app_profile(self, context):
        tenant_name = self._aim_tenant_name(context)
        app_profile_name = self._aim_app_profile_name(context)
        LOG.info(_LI("Assigned name %(name)s to app_profile for tenant"
                     "%(tenant_name)s"),
                 {'name': app_profile_name, 'tenant_name': tenant_name})

        app_profile = aim_resource.ApplicationProfile(
            tenant_name=str(tenant_name), name=str(app_profile_name))
        return app_profile

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
                                         app_profile_name=
                                         str(self._aim_app_profile_name(
                                             context)),
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

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
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

        aim_ctx = aim_context.AimContext(session)

        app_profile = self._aim_app_profile(context)
        # REVISIT(Sumit): Assuming here that recreating each time is fine
        self.aim.create(aim_ctx, app_profile, overwrite=True)

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
        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])
        session = context._plugin_context.session

        aim_ctx = aim_context.AimContext(session)
        epg = self._aim_endpoint_group(context)
        self.aim.delete(aim_ctx, epg)
        self.name_mapper.delete_apic_name(session, context.current['id'])

        # REVISIT(Sumit): Delete app_profile if this is last PTG

        if ptg_db['l2_policy_id']:
            l2p_id = ptg_db['l2_policy_id']
            ptg_db.update({'l2_policy_id': None})
            self._cleanup_l2_policy(context, l2p_id, clean_session=False)

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
