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

from vmware_nsx.db import db as nsx_db

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import policy_defs as policy
from vmware_nsxlib.v3 import resources as nsx_resources

from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)


policy_opts = [
    cfg.StrOpt('nsx_policy_manager',
               help=_("Nsx Policy manager IP address or host.")),
    cfg.StrOpt('nsx_policy_username',
               help=_("Nsx Policy username.")),
    cfg.StrOpt('nsx_policy_password',
               help=_("Nsx Policy password."))
]

cfg.CONF.register_opts(policy_opts, 'NSX_POLICY')

nsx_opts = [
    cfg.StrOpt('nsx_managers',
               help=_("Nsx manager IP address or host.")),
    cfg.StrOpt('nsx_username',
               help=_("Nsx manager username.")),
    cfg.StrOpt('nsx_password',
               help=_("Nsx manager password."))
]

cfg.CONF.register_opts(nsx_opts, 'nsx_v3')

SINGLE_ENTRY_ID = "GBP"
DRIVER_NAME = "NSX Policy driver"


class HierarchicalContractsNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Hierarchy in rule sets is not supported with %s." %
               DRIVER_NAME)


class ActionTypeNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Action types other than allow are not supported with %s." %
               DRIVER_NAME)


class UpdateOperationNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Update operation on this object is not supported with %s." %
               DRIVER_NAME)


#TODO(annak): Catch exceptions and rollback previous changes
#TODO(annak): Use DB to eliminate backend calls
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
    def get_nsxpolicy_api(self):
        nsxlib_config = config.NsxLibConfig(
            nsx_api_managers=[cfg.CONF.NSX_POLICY.nsx_policy_manager],
            username=cfg.CONF.NSX_POLICY.nsx_policy_username,
            password=cfg.CONF.NSX_POLICY.nsx_policy_password)

        return v3.NsxPolicyLib(nsxlib_config).policy_api

    def get_nsxmanager_client(self):
        nsxlib_config = config.NsxLibConfig(
                nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
                username=cfg.CONF.nsx_v3.nsx_api_user,
                password=cfg.CONF.nsx_v3.nsx_api_password)

        return v3.NsxLib(nsxlib_config).client

    def initialize(self):
        super(NsxPolicyMappingDriver, self).initialize()
        self._gbp_plugin = None
        self.policy_api = self.get_nsxpolicy_api()
        nsx_manager_client = self.get_nsxmanager_client()
        self.nsx_port = nsx_resources.LogicalPort(nsx_manager_client)
        self._verify_enforcement_point()
        # TODO(annak) temporary solution for communictaion map seq numbers
        self.cmap_seq = 1

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
        result = self.policy_api.list(policy.EnforcementPointDef())
        epoints = result['results']
        for ep in epoints:
            for conn in ep['connection_info']:
                if conn['ip_address'] == nsx_manager_ip:
                    return

        ep = policy.EnforcementPointDef(SINGLE_ENTRY_ID,
                                        ip_address=nsx_manager_ip,
                                        username=nsx_manager_username,
                                        password=nsx_manager_password,
                                        name=nsx_manager_ip)
        self.policy_api.create(ep)

    def _verify_project(self, project_id):
        # TODO(annak): optimize using DB
        domain = policy.DomainDef(project_id)
        try:
            self.policy_api.get(domain)
        except nsxlib_exc.ResourceNotFound:
            # create domain and domain deployment map
            self.policy_api.create(domain)

            deployment_map = policy.DeploymentMapDef(project_id,
                                                     domain_id=project_id,
                                                     ep_id=SINGLE_ENTRY_ID)
            self.policy_api.create(deployment_map)

    def create_policy_action_precommit(self, context):
        action = context.current
        if action['action_type'] == 'allow':
            return

        raise ActionTypeNotSupported()

    def create_policy_classifier_precommit(self, context):
        pass

    def create_policy_classifier_postcommit(self, context):
        classifier = context.current
        self._verify_project(classifier['project_id'])
        service = policy.ServiceDef(classifier['id'],
                                    name=classifier['name'],
                                    description=classifier['description'])
        ports = [port for port in classifier['port_range'].split(':', 1)]

        # service entry in nsx policy has single direction
        # directions will be enforced on communication profile level
        service_entry = policy.L4ServiceEntryDef(
            classifier['id'],
            SINGLE_ENTRY_ID,
            name=classifier['name'],
            description=classifier['description'],
            protocol=classifier['protocol'],
            dest_ports=ports)

        self.policy_api.create_with_parent(service, service_entry)

    def create_policy_rule_precommit(self, context):
        pass

    def create_policy_rule_postcommit(self, context, transaction=None):
        pass

    def create_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise HierarchicalContractsNotSupported()

    def _create_communication_profile(self, profile_id, description, rules):

        profile = policy.CommunicationProfileDef(profile_id,
                                                 description=description)
        services = [rule['policy_classifier_id']
                    for rule in rules]

        entry = policy.CommunicationProfileEntryDef(
                profile_id,
                SINGLE_ENTRY_ID,
                description=rule['description'],
                services=services)

        self.policy_api.create_with_parent(profile, entry)

    def in_name(self, name):
        return name + '_I'

    def out_name(self, name):
        return name + '_O'

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

    def create_policy_rule_set_postcommit(self, context):

        rule_set_id = context.current['id']
        self._verify_project(context.current['project_id'])

        rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': context.current['policy_rules']})

        in_rules, out_rules = self._split_rules_by_direction(context, rules)

        self._create_communication_profile(
                self.in_name(rule_set_id),
                context.current['description'] + '(ingress)',
                in_rules)

        self._create_communication_profile(
                self.out_name(rule_set_id),
                context.current['description'] + '(egress)',
                out_rules)

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

    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        self._tag_port(context,
                       context.current['port_id'],
                       context.current['policy_target_group_id'])
        self._update_cluster_membership(
                context, new_cluster_id=context.current['cluster_id'])
        self._associate_fip_to_pt(context)
        if context.current.get('proxy_gateway'):
            self._set_proxy_gateway_routes(context, context.current)

    def create_policy_target_group_precommit(self, context):
        super(NsxPolicyMappingDriver,
              self).create_policy_target_group_precommit(context)

    def _map_provided_rule_set(self, project_id, ptgs, group_id, ruleset_id):
        consuming_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['consumed_policy_rule_sets']]

        if not consuming_ptgs:
            return

        # TODO(annak): support update
        ruleset_in = self.in_name(ruleset_id)
        ruleset_out = self.out_name(ruleset_id)
        communication_maps = []
        if ruleset_in:
            self.cmap_seq += 1
            cm = policy.CommunicationMapDef(project_id,
                                            communicationmap_id=ruleset_in,
                                            description="GBP ruleset",
                                            sequence_number=self.cmap_seq,
                                            profile_id=ruleset_in,
                                            source_groups=consuming_ptgs,
                                            dest_groups=[group_id])
            communication_maps.append(cm)

        if ruleset_out:
            self.cmap_seq += 1
            cm = policy.CommunicationMapDef(project_id,
                                            communicationmap_id=ruleset_out,
                                            description="GBP ruleset",
                                            sequence_number=self.cmap_seq,
                                            profile_id=ruleset_out,
                                            source_groups=[group_id],
                                            dest_groups=consuming_ptgs)
            communication_maps.append(cm)

        return communication_maps

    def _map_consumed_rule_set(self, project_id, ptgs,
                               group_id, ruleset_id):

        providing_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['provided_policy_rule_sets']]

        if not providing_ptgs:
            return

        # TODO(annak): support update
        ruleset_in = self.in_name(ruleset_id)
        ruleset_out = self.out_name(ruleset_id)
        communictaion_maps = []
        if ruleset_in:
            self.cmap_seq += 1
            cm = policy.CommunicationMapDef(project_id,
                                            communicationmap_id=ruleset_in,
                                            description="GBP ruleset",
                                            sequence_number=self.cmap_seq,
                                            profile_id=ruleset_in,
                                            source_groups=[group_id],
                                            dest_groups=providing_ptgs)
            communictaion_maps.append(cm)

        if ruleset_out:
            self.cmap_seq += 1
            cm = policy.CommunicationMapDef(project_id,
                                            communicationmap_id=ruleset_out,
                                            description="GBP ruleset",
                                            sequence_number=self.cmap_seq,
                                            profile_id=ruleset_out,
                                            source_groups=providing_ptgs,
                                            dest_groups=[group_id])
            communictaion_maps.append(cm)

        return communictaion_maps

    def _map_group_rule_sets(self, context, group_id,
                             provided_policy_rule_sets,
                             consumed_policy_rule_sets):

        project_id = context.current['project_id']
        self._verify_project(project_id)

        # create communication maps
        communictaion_maps = []
        ptgs = context._plugin.get_policy_target_groups(
                                context._plugin_context)
        for ruleset in provided_policy_rule_sets:
            cms = self._map_provided_rule_set(project_id, ptgs,
                                              group_id, ruleset)
            if cms:
                communictaion_maps.extend(cms)

        for ruleset in consumed_policy_rule_sets:
            cms = self._map_consumed_rule_set(project_id, ptgs,
                                              group_id, ruleset)
            if cms:
                communictaion_maps.extend(cms)

        return communictaion_maps

    # handles policy rule sets upon assication with group
    # overrides base class, called from base group_create_postcommit
    # TODO(annak): suggest a helping design on base class level(divide
    # security and connectivity)
    def _set_sg_rules_for_subnets(self, context, subnets,
                                  provided_policy_rule_sets,
                                  consumed_policy_rule_sets):
        # create the group on backend
        group_id = context.current['id']
        project_id = context.current['project_id']
        group = policy.GroupDef(domain_id=project_id,
                                group_id=group_id,
                                name=context.current['name'],
                                description=context.current['description'],
                                conditions=[policy.Condition(group_id)])

        self.policy_api.create(group)

        # TODO(annak) optimize to one backend call if possible
        communictaion_maps = self._map_group_rule_sets(
                context, group_id,
                provided_policy_rule_sets,
                consumed_policy_rule_sets)

        for cm in communictaion_maps:
            self.policy_api.create(cm)

    # overrides base class, called from base group_create_postcommit
    # TODO(annak): suggest a better design on base class level
    def _unset_sg_rules_for_subnets(self, context, subnets,
                                    provided_policy_rule_sets,
                                    consumed_policy_rule_sets):
        # TODO(annak): verify this is allways called from group context
        group_id = context.current['id']

        communictaion_maps = self._map_group_rule_sets(
                context, group_id,
                provided_policy_rule_sets,
                consumed_policy_rule_sets)

        for cm in communictaion_maps:
            self.policy_api.delete(cm)

        group = policy.GroupDef(group_id)
        self.policy_api.delete(group)

    # Overrides base class
    # This would be a better match for creating group and communication
    # profiles, but it is not invoked from base class delete group
    def _update_sgs_on_ptg(self, context, ptg_id, provided_policy_rule_sets,
                           consumed_policy_rule_sets, op):
        pass

    def delete_policy_classifier_precommit(self, context):
        pass

    def delete_policy_classifier_postcommit(self, context):
        classifier_id = context.current['id']
        service = policy.ServiceDef(classifier_id)

        self.policy_api.delete(service)

    def delete_policy_rule_set_precommit(self, context):
        pass

    def delete_policy_rule_set_postcommit(self, context):
        ruleset_id = context.current['id']
        in_profile = policy.CommunicationProfileEntryDef(
                self.in_name(ruleset_id))
        out_profile = policy.CommunicationProfileEntryDef(
                self.out_name(ruleset_id))

        self.policy_api.delete(in_profile)
        self.policy_api.delete(out_profile)

    def delete_policy_target_postcommit(self, context):
        port_id = context.current['port_id']
        for fip in context.fips:
            self._delete_fip(context._plugin_context,
                             fip.floatingip_id)

        if context.current.get('proxy_gateway'):
            self._unset_proxy_gateway_routes(context, context.current)

        self._cleanup_port(context._plugin_context, port_id)
        # delete tag is challenging in current version, so we change
        # tag value in order to remove membership
        self._tag_port(context, port_id, '')

    def update_policy_rule_set_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_rule_set_postcommit(self, context):
        pass

    def update_policy_target_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_target_postcommit(self, context):
        pass

    def update_policy_rule_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_rule_postcommit(self, context):
        pass

    def update_policy_action_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_target_group_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_target_group_postcommit(self, context):
        pass

    def update_policy_classifier_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_classifier_postcommit(self, context):
        pass
