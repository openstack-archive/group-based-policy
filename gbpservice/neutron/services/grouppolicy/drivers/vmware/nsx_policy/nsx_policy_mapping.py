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

from neutron import manager
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.db import db as nsx_db

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import resources as nsx_resources

from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI


LOG = logging.getLogger(__name__)

SINGLE_ENTRY_ID = 'GBP'
DRIVER_NAME = 'NSX Policy driver'
DRIVER_OPT_GROUP = 'NSX_POLICY'
NSX_V3_GROUP = 'nsx_v3'

policy_opts = [
    cfg.StrOpt('nsx_policy_manager',
               help=_("Nsx Policy manager IP address or host.")),
    cfg.StrOpt('nsx_policy_username',
               help=_("Nsx Policy username.")),
    cfg.StrOpt('nsx_policy_password',
               help=_("Nsx Policy password.")),
    cfg.StrOpt('nsx_manager_thumbprint',
               help=_("Thumbprint of nsx manager"))
]

cfg.CONF.register_opts(policy_opts, DRIVER_OPT_GROUP)


class HierarchicalContractsNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Hierarchy in rule sets is not supported with %s." %
               DRIVER_NAME)


class UpdateOperationNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Update operation on this object is not supported with %s." %
               DRIVER_NAME)


def in_name(name):
    return name + '_I'


def out_name(name):
    return name + '_O'


#TODO(annak): Catch exceptions and rollback previous changes
#TODO(annak): Use DB to reduce backend calls
#TODO(annak): Update support
#TODO(annak): Failure recovery
class NsxPolicyMappingDriver(api.ResourceMappingDriver):
    """Nsx Policy Mapping driver for Group Policy plugin.

    This mapping driver is only supported with nsxv3 core plugin.
    NSX Manager is the network virtualization appliance configured by the core
    plugin.
    NSX Policy is a separate appliance that provides grouping API. Behind the
    scenes, NSX Policy configures same NSX manager.

    At current phase of development, security is configured via NSX Policy,
    while connectivity functionality is inherited from neutron mapping.
    """
    def get_nsxpolicy_lib(self):
        nsxlib_config = config.NsxLibConfig(
            nsx_api_managers=[cfg.CONF.NSX_POLICY.nsx_policy_manager],
            username=cfg.CONF.NSX_POLICY.nsx_policy_username,
            password=cfg.CONF.NSX_POLICY.nsx_policy_password)

        return v3.NsxPolicyLib(nsxlib_config)

    def get_nsxmanager_client(self):
        nsxlib_config = config.NsxLibConfig(
                nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
                username=cfg.CONF.nsx_v3.nsx_api_user,
                password=cfg.CONF.nsx_v3.nsx_api_password)

        return v3.NsxLib(nsxlib_config).client

    def initialize(self):
        super(NsxPolicyMappingDriver, self).initialize()
        self._gbp_plugin = None
        self.nsx_policy = self.get_nsxpolicy_lib()
        self.policy_api = self.nsx_policy.policy_api

        nsx_manager_client = self.get_nsxmanager_client()
        self.nsx_port = nsx_resources.LogicalPort(nsx_manager_client)
        self._verify_enforcement_point()

        # TODO(annak): add validation for core plugin (can only be nsxv3)

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    def _verify_enforcement_point(self):
        # TODO(annak): optimize using DB
        nsx_manager_ip = cfg.CONF.nsx_v3.nsx_api_managers[0]
        nsx_manager_username = cfg.CONF.nsx_v3.nsx_api_user
        nsx_manager_password = cfg.CONF.nsx_v3.nsx_api_password
        nsx_manager_thumbprint = cfg.CONF.NSX_POLICY.nsx_manager_thumbprint
        epoints = self.nsx_policy.enforcement_point.list()
        for ep in epoints:
            for conn in ep['connection_info']:
                if conn['ip_address'] == nsx_manager_ip:
                    LOG.debug('Enforcement point for %s already exists (%s)',
                              nsx_manager_ip, ep['id'])
                    return

        LOG.info(_LI('Creating enforcement point for %s'), nsx_manager_ip)
        self.nsx_policy.enforcement_point.create_or_overwrite(
            name=nsx_manager_ip,
            ep_id=SINGLE_ENTRY_ID,
            ip_address=nsx_manager_ip,
            username=nsx_manager_username,
            password=nsx_manager_password,
            thumbprint=nsx_manager_thumbprint)

    def _generate_nsx_name(self, object_id, object_name):
        if object_name:
            return object_name + '_' + object_id
        return object_id

    def _create_domain(self, context):
        project_id = context.current['project_id']
        tenant_name = context._plugin_context.tenant_name
        domain_name = self._generate_nsx_name(project_id, tenant_name)

        LOG.info(_LI('Creating domain %(domain)s for project %(project)s'),
                {'domain': domain_name,
                 'project': project_id})

        self.nsx_policy.domain.create_or_overwrite(
            name=domain_name,
            domain_id=project_id,
            description=_('Domain for tenant %s') % tenant_name)

        self.nsx_policy.deployment_map.create_or_overwrite(
            name=domain_name,
            map_id=project_id,
            domain_id=project_id,
            ep_id=SINGLE_ENTRY_ID)

    def _delete_domain(self, project_id):
        try:
            self.nsx_policy.domain.delete(project_id)

            self.nsx_policy.deployment_map.delete(project_id)
        except nsxlib_exc.ResourceNotFound:
            LOG.error(_LE('Domain %s was not found on backend'), project_id)

    def create_policy_action_precommit(self, context):
        pass

    def create_policy_classifier_precommit(self, context):
        pass

    def create_policy_classifier_postcommit(self, context):
        classifier = context.current

        port_range = classifier['port_range'].split(':', 1)
        lower = int(port_range[0])
        upper = int(port_range[-1]) + 1
        ports = [str(p) for p in range(lower, upper)]

        # service entry in nsx policy has single direction
        # directions will be enforced on communication profile level
        self.nsx_policy.service.create_or_overwrite(
            name=classifier['name'],
            service_id=classifier['id'],
            description=classifier['description'],
            protocol=classifier['protocol'],
            dest_ports=ports)

    def create_policy_rule_precommit(self, context):
        pass

    def create_policy_rule_postcommit(self, context, transaction=None):
        pass

    def create_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise HierarchicalContractsNotSupported()

    def _create_or_update_communication_profile(self, profile_id, name,
                                                description, rules,
                                                update_flow=False):

        services = [rule['policy_classifier_id']
                    for rule in rules]

        self.nsx_policy.comm_profile.create_or_overwrite(
                name=name,
                profile_id=profile_id,
                description=description,
                services=services)

    def _split_rules_by_direction(self, context, rules):
        in_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_IN]
        out_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_OUT]

        in_rules = []
        out_rules = []

        for rule in rules:
            classifier = context._plugin.get_policy_classifier(
                                             context._plugin_context,
                                             rule['policy_classifier_id'])
            direction = classifier['direction']
            if direction in in_dir:
                in_rules.append(rule)

            if direction in out_dir:
                out_rules.append(rule)

        return in_rules, out_rules

    def _delete_comm_profile(self, comm_profile_id):
        # TODO(annak): check existance in DB
        try:
            self.nsx_policy.comm_profile.delete(comm_profile_id)
        except nsxlib_exc.ResourceNotFound:
            LOG.error(_LE('Communication profile %s not found on backend'),
                      comm_profile_id)

    def _create_or_update_policy_rule_set(self, context, update_flow=False):

        rule_set_id = context.current['id']

        rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': context.current['policy_rules']})

        in_rules, out_rules = self._split_rules_by_direction(context, rules)

        if in_rules:
            self._create_or_update_communication_profile(
                in_name(rule_set_id),
                in_name(context.current['name']),
                context.current['description'] + '(ingress)',
                in_rules)
        elif update_flow:
            self._delete_comm_profile(in_name(rule_set_id))

        if out_rules:
            self._create_or_update_communication_profile(
                out_name(rule_set_id),
                out_name(context.current['name']),
                context.current['description'] + '(egress)',
                out_rules)
        elif update_flow:
            self._delete_comm_profile(out_name(rule_set_id))

    def create_policy_rule_set_postcommit(self, context):
        self._create_or_update_policy_rule_set(context)

    def create_policy_target_precommit(self, context):
        super(NsxPolicyMappingDriver,
              self).create_policy_target_precommit(context)

    def _tag_port(self, context, port_id, tag):
        # Translate neutron port id to nsx port id
        _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                 context._plugin_context.session, port_id)
        self.nsx_port.update(nsx_port_id, None,
                             tags_update=[{'scope': 'gbp',
                                           'tag': tag}])

    def _get_project_ptgs(self, context, project_id):
        ptgs = context._plugin.get_policy_target_groups(
                context._plugin_context)

        return [ptg for ptg in ptgs if ptg['project_id'] == project_id]

    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        self._tag_port(context,
                       context.current['port_id'],
                       context.current['policy_target_group_id'])

        # Below is inherited behaviour
        self._update_cluster_membership(
                context, new_cluster_id=context.current['cluster_id'])
        self._associate_fip_to_pt(context)
        if context.current.get('proxy_gateway'):
            self._set_proxy_gateway_routes(context, context.current)

    def create_policy_target_group_precommit(self, context):
        super(NsxPolicyMappingDriver,
              self).create_policy_target_group_precommit(context)

    def _filter_ptgs_by_ruleset(self, ptgs, ruleset_id):
        providing_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['provided_policy_rule_sets']]
        consuming_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['consumed_policy_rule_sets']]
        return providing_ptgs, consuming_ptgs

    def _map_rule_set(self, ptgs, profiles, project_id,
                      group_id, ruleset_id, delete_flow):

        providing_ptgs, consuming_ptgs = self._filter_ptgs_by_ruleset(
            ptgs, ruleset_id)

        ruleset_in = in_name(ruleset_id)
        ruleset_out = out_name(ruleset_id)
        if not consuming_ptgs or not providing_ptgs:
            if not delete_flow:
                return
            if not consuming_ptgs and not providing_ptgs:
                return

            # we need to delete map entry if exists
            for ruleset in (ruleset_in, ruleset_out):
                if ruleset in profiles:
                    try:
                        self.nsx_policy.comm_map.delete(project_id, ruleset)
                    except nsxlib_exc.ResourceNotFound:
                        pass
            return

        if ruleset_in in profiles:
            self.nsx_policy.comm_map.create_or_overwrite(
                    name = ruleset_in,
                    domain_id=project_id,
                    map_id=ruleset_in,
                    description="GBP ruleset ingress",
                    profile_id=ruleset_in,
                    source_groups=consuming_ptgs,
                    dest_groups=providing_ptgs)

        if ruleset_out in profiles:
            self.nsx_policy.comm_map.create_or_overwrite(
                    name=ruleset_out,
                    domain_id=project_id,
                    map_id=ruleset_out,
                    description="GBP ruleset egress",
                    profile_id=ruleset_out,
                    source_groups=providing_ptgs,
                    dest_groups=consuming_ptgs)

    def _map_group_rule_sets(self, context, group_id,
                             provided_policy_rule_sets,
                             consumed_policy_rule_sets,
                             delete_flow=False):

        project_id = context.current['project_id']

        # TODO(annak): optimize with db
        profiles = self.nsx_policy.comm_profile.list()
        profiles = [p['id'] for p in profiles]

        # create communication maps
        ptgs = context._plugin.get_policy_target_groups(
                                context._plugin_context)
        for ruleset in provided_policy_rule_sets:
            self._map_rule_set(ptgs, profiles, project_id,
                               group_id, ruleset, delete_flow)

        for ruleset in consumed_policy_rule_sets:
            self._map_rule_set(ptgs, profiles, project_id,
                               group_id, ruleset, delete_flow)

    # overrides base class, called from base group_create_postcommit
    def _set_sg_rules_for_subnets(self, context, subnets,
                                  provided_policy_rule_sets,
                                  consumed_policy_rule_sets):
        pass

    # overrides base class, called from base group_delete_postcommit
    def _unset_sg_rules_for_subnets(self, context, subnets,
                                    provided_policy_rule_sets,
                                    consumed_policy_rule_sets):
        pass

    # Overrides base class
    def _update_sgs_on_ptg(self, context, ptg_id,
                           provided_policy_rule_sets,
                           consumed_policy_rule_sets, op):

        group_id = context.current['id']

        self._map_group_rule_sets(
             context, group_id,
             provided_policy_rule_sets,
             consumed_policy_rule_sets,
             delete_flow=(op == "DISASSOCIATE"))

    def create_policy_target_group_postcommit(self, context):
        # create the group on backend
        group_id = context.current['id']
        project_id = context.current['project_id']

        # create the domain for this project if needed
        project_ptgs = self._get_project_ptgs(context, project_id)
        if len(project_ptgs) == 1:
            # we've just created the first group for this project
            # need to create a domain for the project on backend
            self._create_domain(context)

        self.nsx_policy.group.create_or_overwrite(
            name=context.current['name'],
            domain_id=project_id,
            group_id=group_id,
            description=context.current['description'],
            cond_val=group_id)

        # This will take care of connectivity and invoke overriden
        # callbacks defined above for security
        super(NsxPolicyMappingDriver,
              self).create_policy_target_group_postcommit(context)

    def delete_policy_target_group_postcommit(self, context):
        group_id = context.current['id']
        project_id = context.current['project_id']
        self.nsx_policy.group.delete(project_id, group_id)

        # create the domain for this project if needed
        project_ptgs = self._get_project_ptgs(context, project_id)
        if len(project_ptgs) == 0:
            # we've just deleted the last group for this project
            # need to clean up the project domain on backend
            self._delete_domain(project_id)

        # This will take care of connectivity and invoke overriden
        # callbacks defined above for security
        super(NsxPolicyMappingDriver,
              self).delete_policy_target_group_postcommit(context)

    def delete_policy_classifier_precommit(self, context):
        pass

    def delete_policy_classifier_postcommit(self, context):
        classifier_id = context.current['id']
        self.nsx_policy.service.delete(classifier_id)

    def delete_policy_rule_set_precommit(self, context):
        pass

    def delete_policy_rule_set_postcommit(self, context):
        ruleset_id = context.current['id']
        rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': context.current['policy_rules']})

        in_rules, out_rules = self._split_rules_by_direction(context, rules)
        if in_rules:
            self._delete_comm_profile(in_name(ruleset_id))

        if out_rules:
            self._delete_comm_profile(out_name(ruleset_id))

    def delete_policy_target_postcommit(self, context):
        # Inherited behavior without sg disassociation
        port_id = context.current['port_id']
        for fip in context.fips:
            self._delete_fip(context._plugin_context,
                             fip.floatingip_id)
        if context.current.get('proxy_gateway'):
            self._unset_proxy_gateway_routes(context, context.current)
        self._cleanup_port(context._plugin_context, port_id)

    def update_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

    def update_policy_rule_set_postcommit(self, context):
        self._create_or_update_policy_rule_set(context, update_flow=True)

    def update_policy_target_precommit(self, context):
        # Parent call verifies change of PTG is not supported
        super(NsxPolicyMappingDriver,
              self).update_policy_target_precommit(context)

    def update_policy_target_postcommit(self, context):
        # Since change of PTG is not supported, nothing to add here
        super(NsxPolicyMappingDriver,
              self).update_policy_target_postcommit(context)

    def update_policy_rule_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_rule_postcommit(self, context):
        pass

    def update_policy_action_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_classifier_precommit(self, context):
        pass

    def update_policy_classifier_postcommit(self, context):
        self.create_policy_classifier_postcommit(context)
