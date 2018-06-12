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

from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources

from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import utils as nsx_utils

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import resources as nsx_resources

from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)


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


class ProxyGroupsNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Proxy groups are not supported with %s." % DRIVER_NAME)


#TODO(annak): remove when ipv6 is supported + add support for ICMPv6 service
class Ipv6NotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Ipv6 not supported with %s" % DRIVER_NAME)


class UpdateClassifierProtocolNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Update operation on classifier protocol is not supported "
               "with %s" % DRIVER_NAME)


class UpdateClassifierDirectionNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Update operation on classifier direction is not supported "
               "with %s" % DRIVER_NAME)


class ProtocolNotSupported(gpexc.GroupPolicyBadRequest):
    message = ("Unsupported classifier protocol. Only icmp, tcp and udp are "
               "supported with %s" % DRIVER_NAME)


def append_in_dir(name):
    return name + '_I'


def append_out_dir(name):
    return name + '_O'


def generate_nsx_name(uuid, name, tag=None, maxlen=80):
    short_uuid = '_' + uuid[:5] + '...' + uuid[-5:]
    maxlen = maxlen - len(short_uuid)
    if not name:
        name = ''
    if tag:
        maxlen = maxlen - len(tag) - 1
        return name[:maxlen] + '_' + tag + short_uuid
    else:
        return name[:maxlen] + short_uuid


class NsxPolicyMappingDriver(api.ResourceMappingDriver):
    """Nsx Policy Mapping driver for Group Policy plugin.

    This mapping driver is only supported with nsxv3 core plugin.
    NSX Manager is the network virtualization appliance configured by the core
    plugin.
    NSX Policy is a separate appliance that provides grouping API. Behind the
    scenes, NSX Policy configures same NSX manager.

    At current phase of development, security is achieved via NSX Policy,
    while connectivity functionality is inherited from resource mapping driver.

    This driver configures services, connectivity rules and grouping objects
    on NSX Policy. In addition, it configures logical port tag directly on
    NSX manager, in order to provide port membership in the desired group.

    The driver does not maintain state of its own (no db extension). This is
    for sake of reducing failure recovery problems, at cost of making few more
    backend roundtrips.
    """
    def get_nsxpolicy_lib(self):
        """ Prepare agent for NSX Policy API calls"""
        nsxlib_config = config.NsxLibConfig(
            nsx_api_managers=[cfg.CONF.NSX_POLICY.nsx_policy_manager],
            username=cfg.CONF.NSX_POLICY.nsx_policy_username,
            password=cfg.CONF.NSX_POLICY.nsx_policy_password)

        return v3.NsxPolicyLib(nsxlib_config)

    def get_nsxmanager_lib(self):
        """Prepare agent for NSX Manager API calls"""
        return nsx_utils.get_nsxlib_wrapper()

    def initialize(self):
        super(NsxPolicyMappingDriver, self).initialize()
        self._gbp_plugin = None
        self.nsx_policy = self.get_nsxpolicy_lib()
        # reinitialize the cluster upon fork for api workers to ensure each
        # process has its own keepalive loops + state
        registry.subscribe(
            self.nsx_policy.reinitialize_cluster,
            resources.PROCESS, events.AFTER_INIT)
        self.policy_api = self.nsx_policy.policy_api

        self.nsx_manager = self.get_nsxmanager_lib()
        registry.subscribe(
            self.nsx_manager.reinitialize_cluster,
            resources.PROCESS, events.AFTER_INIT)

        self.nsx_port = nsx_resources.LogicalPort(self.nsx_manager.client)

        self._verify_enforcement_point()

        # TODO(annak): add validation for core plugin (can only be nsxv3)

    def _verify_enforcement_point(self):
        """Configure NSX Policy to enforce grouping rules on NSX Manager"""

        # We only support a single NSX manager at this point
        nsx_manager_ip = cfg.CONF.nsx_v3.nsx_api_managers[0]
        nsx_manager_username = cfg.CONF.nsx_v3.nsx_api_user[0]
        nsx_manager_password = cfg.CONF.nsx_v3.nsx_api_password[0]
        nsx_manager_thumbprint = cfg.CONF.NSX_POLICY.nsx_manager_thumbprint
        epoints = self.nsx_policy.enforcement_point.list()
        for ep in epoints:
            conn = ep['connection_info']
            if conn and conn['enforcement_point_address'] == nsx_manager_ip:
                LOG.debug('Enforcement point for %s already exists (%s)',
                          nsx_manager_ip, ep['id'])
                return

        LOG.info('Creating enforcement point for %s', nsx_manager_ip)
        self.nsx_policy.enforcement_point.create_or_overwrite(
            name=nsx_manager_ip,
            ep_id=SINGLE_ENTRY_ID,
            ip_address=nsx_manager_ip,
            username=nsx_manager_username,
            password=nsx_manager_password,
            thumbprint=nsx_manager_thumbprint)

    def _create_domain(self, context):
        project_id = context.current['project_id']
        tenant_name = context._plugin_context.tenant_name
        domain_name = generate_nsx_name(project_id, tenant_name)

        LOG.info('Creating domain %(domain)s for project %(project)s',
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
            self.nsx_policy.deployment_map.delete(project_id,
                                                  domain_id=project_id)
        except nsxlib_exc.ManagerError:
            LOG.warning('Domain %s is not deployed on backend',
                        project_id)

        try:
            self.nsx_policy.domain.delete(project_id)
        except nsxlib_exc.ManagerError:
            LOG.warning('Domain %s was not found on backend',
                        project_id)

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

    def _get_services_from_rule_set(self, context, rule_set_id):

        ruleset = self.gbp_plugin.get_policy_rule_set(
                context._plugin_context, rule_set_id)
        rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': ruleset['policy_rules']})

        in_rules, out_rules = self._split_rules_by_direction(context, rules)
        in_services = set()
        for rule in in_rules:
            in_services.add(rule['policy_classifier_id'])
        out_services = set()
        for rule in out_rules:
            out_services.add(rule['policy_classifier_id'])

        return sorted(list(in_services)), sorted(list(out_services))

    def _filter_ptgs_by_ruleset(self, ptgs, ruleset_id):
        providing_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['provided_policy_rule_sets']]
        consuming_ptgs = [ptg['id'] for ptg in ptgs
                          if ruleset_id in ptg['consumed_policy_rule_sets']]
        return providing_ptgs, consuming_ptgs

    def _map_rule_set(self, context, ptgs, project_id,
                      ruleset_id, delete_flow):

        def delete_map_if_exists(ruleset):
            try:
                self.nsx_policy.comm_map.delete(project_id, ruleset)
            except nsxlib_exc.ManagerError:
                # TODO(annak) - narrow this exception down
                pass

        providing_ptgs, consuming_ptgs = self._filter_ptgs_by_ruleset(
            ptgs, ruleset_id)

        ruleset_in = append_in_dir(ruleset_id)
        ruleset_out = append_out_dir(ruleset_id)
        if not consuming_ptgs or not providing_ptgs:
            if not delete_flow:
                return
            if not consuming_ptgs and not providing_ptgs:
                return

            # we need to delete map entry if exists
            for ruleset in (ruleset_in, ruleset_out):
                delete_map_if_exists(ruleset)

            return

        services_in, services_out = self._get_services_from_rule_set(
            context, ruleset_id)

        if services_in:
            self.nsx_policy.comm_map.create_or_overwrite(
                name=ruleset_in,
                domain_id=project_id,
                map_id=ruleset_in,
                description="GBP ruleset ingress",
                service_ids=services_in,
                source_groups=consuming_ptgs,
                dest_groups=providing_ptgs)
        else:
            delete_map_if_exists(ruleset_in)

        if services_out:
            self.nsx_policy.comm_map.create_or_overwrite(
                name=ruleset_out,
                domain_id=project_id,
                map_id=ruleset_out,
                description="GBP ruleset egress",
                service_ids=services_out,
                source_groups=providing_ptgs,
                dest_groups=consuming_ptgs)
        else:
            delete_map_if_exists(ruleset_out)

    def _map_group_rule_sets(self, context,
                             provided_policy_rule_sets,
                             consumed_policy_rule_sets,
                             delete_flow=False):

        project_id = context.current['project_id']

        # create communication maps
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context)
        for ruleset in provided_policy_rule_sets:
            self._map_rule_set(context, ptgs, project_id,
                               ruleset, delete_flow)

        for ruleset in consumed_policy_rule_sets:
            self._map_rule_set(context, ptgs, project_id,
                               ruleset, delete_flow)

    # overrides base class, called from base group_create_postcommit
    # REVISIT(annak): Suggest a better design for driver-specific callbacks,
    # based on connectivity vs. security
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

        self._map_group_rule_sets(
             context,
             provided_policy_rule_sets,
             consumed_policy_rule_sets,
             delete_flow=(op == "DISASSOCIATE"))

    def create_policy_action_precommit(self, context):
        pass

    def create_policy_action_postcommit(self, context):
        super(NsxPolicyMappingDriver,
              self).create_policy_action_postcommit(context)

    def create_policy_classifier_precommit(self, context):
        if context.current['protocol'] not in ('icmp', 'tcp', 'udp'):
            raise ProtocolNotSupported()

    def create_policy_classifier_postcommit(self, context):
        classifier = context.current

        if classifier['protocol'] == 'icmp':
            self.nsx_policy.icmp_service.create_or_overwrite(
                name=classifier['name'],
                service_id=classifier['id'],
                description=classifier['description'])
            return

        ports = []
        if classifier['port_range']:
            port_range = classifier['port_range'].split(':', 1)
            lower = int(port_range[0])
            upper = int(port_range[-1]) + 1
            ports = [str(p) for p in range(lower, upper)]

        # service entry in nsx policy has single direction
        # directions will be enforced on communication map level
        self.nsx_policy.service.create_or_overwrite(
            name=generate_nsx_name(classifier['id'], classifier['name']),
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

    def create_policy_rule_set_postcommit(self, context):
        pass

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

    def create_policy_target_group_precommit(self, context):
        if context.current.get('proxied_group_id'):
            raise ProxyGroupsNotSupported()

        super(NsxPolicyMappingDriver,
              self).create_policy_target_group_precommit(context)

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
            name=generate_nsx_name(group_id, context.current['name']),
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

        # delete the domain for this project if needed
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
        if context.current['protocol'] == 'icmp':
            self.nsx_policy.icmp_service.delete(classifier_id)
        else:
            self.nsx_policy.service.delete(classifier_id)

    def delete_policy_rule_set_precommit(self, context):
        pass

    def delete_policy_rule_set_postcommit(self, context):
        pass

    def delete_policy_target_postcommit(self, context):
        # This is inherited behavior without:
        # 1. sg disassociation
        # 2. proxy handling
        port_id = context.current['port_id']
        for fip in context.fips:
            self._delete_fip(context._plugin_context,
                             fip.floatingip_id)
        self._cleanup_port(context._plugin_context, port_id)

    def update_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

    def update_policy_rule_set_postcommit(self, context):
        if (context.current['policy_rules'] !=
            context.original['policy_rules']):
            self._on_policy_rule_set_updated(context, context.current)

    def update_policy_target_precommit(self, context):
        # Parent call verifies change of PTG is not supported
        super(NsxPolicyMappingDriver,
              self).update_policy_target_precommit(context)

    def update_policy_target_postcommit(self, context):
        # Since change of PTG is not supported, nothing to add here
        super(NsxPolicyMappingDriver,
              self).update_policy_target_postcommit(context)

    def update_policy_rule_precommit(self, context):
        super(NsxPolicyMappingDriver,
              self).update_policy_rule_precommit(context)

    def _on_policy_rule_set_updated(self, context, prs):
        ptgs = context._plugin.get_policy_target_groups(
            context._plugin_context)

        self._map_rule_set(context, ptgs, prs['project_id'],
                           prs['id'], False)

    def update_policy_rule_postcommit(self, context):
        if (context.current['policy_classifier_id'] !=
            context.original['policy_classifier_id']):
            # All groups using this rule need to be updated
            prs_ids = (
                context._plugin._get_policy_rule_policy_rule_sets(
                    context._plugin_context, context.current['id']))
            policy_rule_sets = context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': prs_ids})
            for prs in policy_rule_sets:
                self._on_policy_rule_set_updated(context, prs)

    def update_policy_action_precommit(self, context):
        raise UpdateOperationNotSupported()

    def update_policy_classifier_precommit(self, context):
        if context.current['protocol'] != context.original['protocol']:
            raise UpdateClassifierProtocolNotSupported()

        # TODO(annak): support this
        if context.current['direction'] != context.original['direction']:
            raise UpdateClassifierDirectionNotSupported()

    def update_policy_classifier_postcommit(self, context):
        self.create_policy_classifier_postcommit(context)

    def create_l3_policy_precommit(self, context):
        if context.current['ip_version'] != 4:
            raise Ipv6NotSupported()

        super(NsxPolicyMappingDriver,
              self).create_l3_policy_precommit(context)
