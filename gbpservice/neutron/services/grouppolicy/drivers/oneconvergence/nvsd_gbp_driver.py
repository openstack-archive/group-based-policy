# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
#
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

from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as res_map)
from gbpservice.neutron.services.grouppolicy.drivers.oneconvergence import (
    nvsd_gbp_api as api)

from neutron.common import log
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class NvsdGbpDriver(res_map.ResourceMappingDriver):
    """One Convergence NVSD Group Policy Driver for Group Policy Service Plugin

    This class inherits from ResourceMappingDriver and overrides the implicit
    Subnet creation for an EndPointGroup. One Convergence NVSD only supports
    REDIRECT to an L2 Service at present and the Provider and Consumer PTGs
    have to be on the same network and subnet. Hence, One Convergence NVSD
    Group Policy Driver creates only one default L2 Policy for a tenant.
    Further, the PTGs do not have a one-to-one mapping to a subnet, but rather
    multiple PTGs are mapped to one subnet. One Convergence NVSD maps an PTG to
    a NVSD Port Group.
    """
    def __init__(self):
        self.nvsd_api = api.NVSDServiceApi()

    @log.log
    def create_policy_target_postcommit(self, context):
        super(NvsdGbpDriver, self).create_policy_target_postcommit(context)
        try:
            self.nvsd_api.create_endpoint(context._plugin_context,
                                          context.current)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NvsdGbpDriver,
                      self).delete_policy_target_postcommit(context)

    @log.log
    def update_policy_target_postcommit(self, context):
        super(NvsdGbpDriver, self).update_policy_target_postcommit(context)
        self.nvsd_api.update_endpoint(context._plugin_context,
                                      context.current)

    @log.log
    def delete_policy_target_postcommit(self, context):
        self.nvsd_api.delete_endpoint(context._plugin_context,
                                      context.current['id'])
        super(NvsdGbpDriver, self).delete_policy_target_postcommit(context)

    @log.log
    def create_policy_target_group_precommit(self, context):
        # Reuse the previously created implicit L2 Policy for the tenant
        if not context.current['l2_policy_id']:
            l2ps = context._plugin.get_l2_policies(
                context._plugin_context,
                filters=({'description': ["Implicitly created L2 policy"],
                          "tenant_id": [context.current['tenant_id']]}))
            if l2ps:
                context.set_l2_policy_id(l2ps[0]['id'])
        super(NvsdGbpDriver, self).create_policy_target_group_precommit(
                                                                    context)

    @log.log
    def create_policy_target_group_postcommit(self, context):
        subnets = context.current['subnets']
        if not subnets:
            if self._use_implicit_subnet(context) is True:
                subnets = context.current['subnets']
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context,
                                            l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context,
                                            l3p_id)
        router_id = l3p['routers'][0]
        for subnet_id in subnets:
            self._plug_router_to_subnet(context._plugin_context,
                                        subnet_id, router_id)
        self.nvsd_api.create_endpointgroup(context._plugin_context,
                                           context.current)
        self._handle_network_service_policy(context)
        self._handle_policy_rule_sets(context)
        self._update_default_security_group(context._plugin_context,
                                            context.current['id'],
                                            context.current['tenant_id'],
                                            context.current['subnets'])

    @log.log
    def update_policy_target_group_postcommit(self, context):
        super(NvsdGbpDriver,
              self).update_policy_target_group_postcommit(context)
        self.nvsd_api.update_endpointgroup(context._plugin_context,
                                           context.current)

    @log.log
    def delete_policy_target_group_precommit(self, context):
        super(NvsdGbpDriver,
              self).delete_policy_target_group_precommit(context)
        l2p_id = context.current['l2_policy_id']
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context,
            filters=({'l2_policy_id': [l2p_id]}))
        for ptg in ptgs:
            if ptg['id'] != context.current['id']:
                context.current['l2_policy_id'] = None
                return

    @log.log
    def delete_policy_target_group_postcommit(self, context):
        try:
            self._cleanup_network_service_policy(context,
                                                 context.current,
                                                 context.nsp_cleanup_ipaddress,
                                                 context.nsp_cleanup_fips)
            self._cleanup_redirect_action(context)
            # Cleanup SGs
            self._unset_sg_rules_for_subnets(
                context, context.current['subnets'],
                context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'])
        except Exception as err:
            LOG.error(_("Cleanup of Redirect Action failed. "
                        "Error : %s"), err)
        try:
            l2p_id = context.current['l2_policy_id']
            l3p = self._get_l3p_for_l2policy(context, l2p_id)
            router_id = l3p['routers'][0]
            for subnet_id in context.current['subnets']:
                self._cleanup_subnet(context, subnet_id, router_id)
            self._delete_default_security_group(
                context._plugin_context, context.current['id'],
                context.current['tenant_id'])
        except Exception as err:
            LOG.error(_("Cleanup of Policy target group failed. "
                        "Error : %s"), err)
        self.nvsd_api.delete_endpointgroup(context._plugin_context,
                                           context.current['id'])

    @log.log
    def create_l2_policy_postcommit(self, context):
        super(NvsdGbpDriver, self).create_l2_policy_postcommit(context)

    @log.log
    def delete_l2_policy_postcommit(self, context):
        super(NvsdGbpDriver, self).delete_l2_policy_postcommit(context)

    @log.log
    def create_policy_classifier_postcommit(self, context):
        super(NvsdGbpDriver, self).create_policy_classifier_postcommit(context)
        self.nvsd_api.create_policy_classifier(context._plugin_context,
                                               context.current)

    @log.log
    def update_policy_classifier_postcommit(self, context):
        super(NvsdGbpDriver, self).update_policy_classifier_postcommit(context)
        self.nvsd_api.update_policy_classifier(context._plugin_context,
                                               context.current)

    @log.log
    def delete_policy_classifier_postcommit(self, context):
        self.nvsd_api.delete_policy_classifier(context._plugin_context,
                                               context.current['id'])
        super(NvsdGbpDriver, self).delete_policy_classifier_postcommit(context)

    def _use_implicit_subnet(self, context):
        # One Convergence NVSD does not support REDIRECT to a different Subnet
        # at present. So restricting to use same subnet for a given L2 Policy
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context, filters=(
                {'l2_policy_id': [context.current['l2_policy_id']]}))
        for ptg in ptgs:
            if ptg['subnets']:
                context.add_subnet(ptg['subnets'][0])
                return False
        # Create a new Subnet for first PTG using the L2 Policy
        super(NvsdGbpDriver, self)._use_implicit_subnet(context)
        return True

    def _cleanup_subnet(self, context, subnet_id, router_id):
        # Cleanup is performed only when the last PTG on subnet is removed
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context)
        for ptg in ptgs:
            ptg_subnets = ptg['subnets']
            if subnet_id in ptg_subnets:
                return
        super(NvsdGbpDriver, self)._cleanup_subnet(context._plugin_context,
                                                   subnet_id, router_id)
