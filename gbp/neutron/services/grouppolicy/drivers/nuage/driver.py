# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from oslo.config import cfg

from gbp.neutron.services.grouppolicy.drivers.nuage.common import config
from gbp.neutron.services.grouppolicy.drivers import resource_mapping as api

LOG = logging.getLogger(__name__)


class NuageGBPDriver(api.ResourceMappingDriver):

    def initialize(self):
        LOG.debug('Initializing Nuage GBP driver')
        config.nuage_register_cfg_opts()
        self.nuageclient_init()
        LOG.debug('Initialization of Nuage GBP is complete')

    def nuageclient_init(self):
        server = cfg.CONF.RESTPROXY.server
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        base_uri = cfg.CONF.RESTPROXY.base_uri
        auth_resource = cfg.CONF.RESTPROXY.auth_resource
        organization = cfg.CONF.RESTPROXY.organization
        nuageclient = importutils.import_module('nuagenetlib.nuageclient')
        self.nuageclient = nuageclient.NuageClient(server, base_uri,
                                                   serverssl, serverauth,
                                                   auth_resource,
                                                   organization)
        self.nuageclient.create_application(
            cfg.CONF.RESTPROXY.application)

    def create_policy_target_group_postcommit(self, context):
        self.nuageclient.create_ptg_postcommit(context)

    def update_policy_target_group_postcommit(self, context):
        curr_provided_prs = context.current[
            'provided_policy_rule_sets']
        curr_consumed_prs = context.current[
            'consumed_policy_rule_sets']

        if curr_provided_prs and not curr_consumed_prs:
            prs = context._plugin.get_policy_rule_set(
                context._plugin_context, curr_provided_prs[0])
        elif curr_consumed_prs and not curr_provided_prs:
            prs = context._plugin.get_policy_rule_set(
                context._plugin_context, curr_consumed_prs[0])

        if (prs and prs['providing_policy_target_groups'] and
            prs['consuming_policy_target_groups']):
            self.nuageclient.update_ptg_postcommit(context,
                                                   prs)

    def delete_policy_target_group_postcommit(self, context):
        self.nuageclient.delete_ptg_postcommit(context)

    def create_policy_rule_postcommit(self, context):
        action = context._plugin.get_policy_action(
            context._plugin_context, context.current['policy_actions'][0])
        classifier = context._plugin.get_policy_classifier(
            context._plugin_context,
            context.current['policy_classifier_id'])
        self.nuageclient.create_policyrule_postcommit(context, action,
                                                      classifier)

    def delete_policy_rule_postcommit(self, context):
        self.nuageclient.delete_policyrule_postcommit(context)
