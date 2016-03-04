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
# from aim.api import resource as aim_resource
from oslo_log import helpers as log
from oslo_log import log as logging

# from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)


LOG = logging.getLogger(__name__)


class APICNameMapper(object):

    def tenant_filter(self, tenant, resource_id, name=None):
        # REVISIT(sumit): Temporary implementation
        return 'TF_' + resource_id


class AIMMappingDriver(nrd.CommonNeutronBase):
    """AIM Mapping Orchestration driver.

    This driver maps GBP resources to the ACI-Integration-Module (AIM).
    """

    @log.log_method_call
    def initialize(self):
        self.aim = aim_manager.AimManager()
        self.mapper = APICNameMapper()
        super(AIMMappingDriver, self).initialize()

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
