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

import netaddr

from apicapi import apic_manager
from keystoneclient.v2_0 import client as keyclient
from neutron.common import exceptions as n_exc
from neutron.extensions import providernet as pn
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers.cisco.apic import config
from neutron.plugins.ml2 import models
from oslo.config import cfg

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)

LOG = logging.getLogger(__name__)


class L2PolicyMultiplePolicyTargetGroupNotSupportedOnApicDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("An L2 policy can't have multiple policy target groups on "
                "APIC GBP driver.")


class RedirectActionNotSupportedOnApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Redirect action is currently not supported for APIC GBP "
                "driver.")


class PolicyRuleUpdateNotSupportedOnApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule update is not supported on APIC GBP"
                "driver.")


class ExactlyOneActionPerRuleIsSupportedOnApicDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Exactly one action per rule is supported on APIC GBP driver.")


class OnlyOneL3PolicyIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one L3 Policy per ES is supported on APIC GBP driver.")


class OnlyOneAddressIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one ip address on each ES is supported on "
                "APIC GBP driver.")


class NoAddressConfiguredOnExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("L3 Policy %(l3p_id)s has no address configured on "
                "External Segment %(es_id)s")


class PATNotSupportedByApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Port address translation is not supported by APIC driver.")


class SharedAttributeUpdateNotSupportedOnApic(gpexc.GroupPolicyBadRequest):
    message = _("Resource shared attribute update not supported on APIC "
                "GBP driver for resource of type %(type)s")


class ApicMappingDriver(api.ResourceMappingDriver):
    """Apic Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources, and leverages
    Cisco APIC's backend for enforcing the policies.
    """

    me = None
    manager = None

    @staticmethod
    def get_apic_manager(client=True):
        if not ApicMappingDriver.manager:
            apic_config = cfg.CONF.ml2_cisco_apic
            network_config = {
                'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
                'switch_dict': config.create_switch_dictionary(),
                'vpc_dict': config.create_vpc_dictionary(),
                'external_network_dict':
                    config.create_external_network_dictionary(),
            }
            apic_system_id = cfg.CONF.apic_system_id
            keyclient_param = keyclient if client else None
            keystone_authtoken = (cfg.CONF.keystone_authtoken if client else
                                  None)
            ApicMappingDriver.manager = apic_manager.APICManager(
                apic_model.ApicDbModel(), logging, network_config, apic_config,
                keyclient_param, keystone_authtoken, apic_system_id)
            ApicMappingDriver.manager.ensure_infra_created_on_apic()
            ApicMappingDriver.manager.ensure_bgp_pod_policy_created_on_apic()
        return ApicMappingDriver.manager

    def initialize(self):
        super(ApicMappingDriver, self).initialize()
        self.apic_manager = ApicMappingDriver.get_apic_manager()
        self.name_mapper = self.apic_manager.apic_mapper
        self._gbp_plugin = None
        ApicMappingDriver.me = self

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    @staticmethod
    def get_initialized_instance():
        return ApicMappingDriver.me

    def get_gbp_details(self, context, **kwargs):
        port_id = (kwargs.get('port_id') or
                   self._core_plugin._device_to_port_id(kwargs['device']))
        port = self._core_plugin.get_port(context, port_id)
        # retrieve PTG and network from a given Port
        if not kwargs.get('policy_target'):
            ptg, network = self._port_to_ptg_network(context, port,
                                                     kwargs['host'])
            if not ptg:
                return
        else:
            pt = kwargs['policy_target']
            ptg = self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id'])
            network = self._l2p_id_to_network(context, ptg['l2_policy_id'])

        return {'port_id': port_id,
                'mac_address': port['mac_address'],
                'ptg_id': ptg['id'],
                'segmentation_id': network[pn.SEGMENTATION_ID],
                'network_type': network[pn.NETWORK_TYPE],
                'l2_policy_id': ptg['l2_policy_id'],
                'tenant_id': port['tenant_id'],
                'host': port['binding:host_id'],
                'ptg_apic_tentant': (ptg['tenant_id'] if not ptg['shared'] else
                                     apic_manager.TENANT_COMMON)
                }

    def create_dhcp_policy_target_if_needed(self, plugin_context, port):
        session = plugin_context.session
        if (self._port_is_owned(session, port['id'])):
            # Nothing to do
            return
        # Retrieve PTG
        fixed_ips = port['fixed_ips']
        if fixed_ips:
            port_subnet_id = fixed_ips[0]['subnet_id']
            ptg = self._get_ptg_by_subnet(plugin_context, port_subnet_id)
            if ptg:
                # Create PolicyTarget
                attrs = {'policy_target':
                         {'tenant_id': port['tenant_id'],
                          'name': 'dhcp-%s' % ptg['id'],
                          'description': _("Implicitly created DHCP policy "
                                           "target"),
                          'policy_target_group_id': ptg['id'],
                          'port_id': port['id']}}
                self.gbp_plugin.create_policy_target(plugin_context, attrs)
                sg_id = self._get_default_security_group(plugin_context,
                                                         ptg['id'],
                                                         port['tenant_id'])
                data = {'port': {'security_groups': [sg_id]}}
                self._core_plugin.update_port(plugin_context, port['id'], data)

    def create_policy_action_precommit(self, context):
        # TODO(ivar): allow redirect for service chaining
        if context.current['action_type'] == g_const.GP_ACTION_REDIRECT:
            raise RedirectActionNotSupportedOnApicDriver()

    def create_policy_rule_precommit(self, context):
        if ('policy_actions' in context.current and
                len(context.current['policy_actions']) != 1):
            # TODO(ivar): to be fixed when redirect is supported
            raise ExactlyOneActionPerRuleIsSupportedOnApicDriver()

    def create_policy_rule_postcommit(self, context):
        action = context._plugin.get_policy_action(
            context._plugin_context, context.current['policy_actions'][0])
        classifier = context._plugin.get_policy_classifier(
            context._plugin_context,
            context.current['policy_classifier_id'])
        if action['action_type'] == g_const.GP_ACTION_ALLOW:
            port_min, port_max = (
                gpdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                    classifier['port_range']))
            attrs = {'etherT': 'ip',
                     'prot': classifier['protocol'].lower()}
            if port_min and port_max:
                attrs['dToPort'] = port_max
                attrs['dFromPort'] = port_min
            tenant = self._tenant_by_sharing_policy(context.current)
            policy_rule = self.name_mapper.policy_rule(context,
                                                       context.current['id'])
            self.apic_manager.create_tenant_filter(policy_rule, owner=tenant,
                                                   **attrs)

    def create_policy_rule_set_precommit(self, context):
        pass

    def create_policy_rule_set_postcommit(self, context):
        # Create APIC policy_rule_set
        tenant = self._tenant_by_sharing_policy(context.current)
        contract = self.name_mapper.policy_rule_set(context,
                                                    context.current['id'])
        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)
            rules = self.gbp_plugin.get_policy_rules(
                context._plugin_context,
                {'id': context.current['policy_rules']})
            self._apply_policy_rule_set_rules(
                context, context.current, rules, transaction=trs)

    def create_policy_target_postcommit(self, context):
        # The path needs to be created at bind time, this will be taken
        # care by the GBP ML2 apic driver.
        super(ApicMappingDriver, self).create_policy_target_postcommit(context)
        self._manage_policy_target_port(
            context._plugin_context, context.current)

    def create_policy_target_group_precommit(self, context):
        pass

    def create_policy_target_group_postcommit(self, context):
        super(ApicMappingDriver, self).create_policy_target_group_postcommit(
            context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l2_policy = self.name_mapper.l2_policy(context,
                                               context.current['l2_policy_id'])
        epg = self.name_mapper.policy_target_group(context,
                                                   context.current['id'])
        l2_policy_object = context._plugin.get_l2_policy(
            context._plugin_context, context.current['l2_policy_id'])
        bd_owner = self._tenant_by_sharing_policy(l2_policy_object)
        with self.apic_manager.apic.transaction(None) as trs:
            self.apic_manager.ensure_epg_created(tenant, epg,
                                                 bd_owner=bd_owner,
                                                 bd_name=l2_policy)
            subnets = self._subnet_ids_to_objects(context._plugin_context,
                                                  context.current['subnets'])
            self._manage_ptg_subnets(context._plugin_context, context.current,
                                     subnets, [], transaction=trs)
            self._manage_ptg_policy_rule_sets(
                context._plugin_context, context.current,
                context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'], [], [],
                transaction=trs)
        self._update_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'], context.current['subnets'])

    def create_l2_policy_precommit(self, context):
        self._reject_non_shared_net_on_shared_l2p(context)

    def update_l2_policy_precommit(self, context):
        self._reject_non_shared_net_on_shared_l2p(context)
        self._reject_shared_update(context, 'l2_policy')

    def create_l2_policy_postcommit(self, context):
        super(ApicMappingDriver, self).create_l2_policy_postcommit(context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context,
                                               context.current['l3_policy_id'])
        l2_policy = self.name_mapper.l2_policy(context, context.current['id'])
        l3_policy_object = context._plugin.get_l3_policy(
            context._plugin_context, context.current['l3_policy_id'])
        ctx_owner = self._tenant_by_sharing_policy(l3_policy_object)
        self.apic_manager.ensure_bd_created_on_apic(tenant, l2_policy,
                                                    ctx_owner=ctx_owner,
                                                    ctx_name=l3_policy)

    def create_l3_policy_precommit(self, context):
        self._check_l3p_es(context)

    def create_l3_policy_postcommit(self, context):
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])
        self.apic_manager.ensure_context_enforced(tenant, l3_policy)
        external_segments = context.current['external_segments']
        if external_segments:
            # Create a L3 ext for each External Segment
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': external_segments.keys()})
            for es in ess:
                self._plug_l3p_to_es(context, es)

    def delete_policy_rule_postcommit(self, context):
        # TODO(ivar): delete Contract subject entries to avoid reference leak
        tenant = self._tenant_by_sharing_policy(context.current)
        policy_rule = self.name_mapper.policy_rule(context,
                                                   context.current['id'])
        self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant)

    def delete_policy_rule_set_precommit(self, context):
        # Intercept Parent Call
        pass

    def delete_policy_rule_set_postcommit(self, context):
        # TODO(ivar): disassociate PTGs to avoid reference leak
        tenant = self._tenant_by_sharing_policy(context.current)
        contract = self.name_mapper.policy_rule_set(context,
                                                    context.current['id'])
        self.apic_manager.delete_contract(contract, owner=tenant)

    def delete_policy_target_postcommit(self, context):
        try:
            port = self._core_plugin.get_port(context._plugin_context,
                                              context.current['port_id'])
        except n_exc.PortNotFound:
            LOG.warn(_("Port %s is missing") % context.current['port_id'])
            return

        if port['binding:host_id']:
            self.process_path_deletion(context._plugin_context, port,
                                       policy_target=context.current)
        # Delete Neutron's port
        super(ApicMappingDriver, self).delete_policy_target_postcommit(context)

    def delete_policy_target_group_postcommit(self, context):
        if context.current['subnets']:
            subnets = self._subnet_ids_to_objects(context._plugin_context,
                                                  context.current['subnets'])
            self._manage_ptg_subnets(context._plugin_context, context.current,
                                     [], subnets)
        for subnet_id in context.current['subnets']:
            self._cleanup_subnet(context._plugin_context, subnet_id, None)
        tenant = self._tenant_by_sharing_policy(context.current)
        ptg = self.name_mapper.policy_target_group(context,
                                                   context.current['id'])

        self.apic_manager.delete_epg_for_network(tenant, ptg)

    def delete_l2_policy_postcommit(self, context):
        super(ApicMappingDriver, self).delete_l2_policy_postcommit(context)
        tenant = self._tenant_by_sharing_policy(context.current)
        l2_policy = self.name_mapper.l2_policy(context, context.current['id'])

        self.apic_manager.delete_bd_on_apic(tenant, l2_policy)

    def delete_l3_policy_postcommit(self, context):
        tenant = self._tenant_by_sharing_policy(context.current)
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])

        self.apic_manager.ensure_context_deleted(tenant, l3_policy)
        external_segments = context.current['external_segments']
        if external_segments:
            # Create a L3 ext for each External Segment
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': external_segments.keys()})
            for es in ess:
                self._unplug_l3p_from_es(context, es)

    def update_policy_rule_set_precommit(self, context):
        self._reject_shared_update(context, 'policy_rule_set')

    def update_policy_target_postcommit(self, context):
        # TODO(ivar): redo binding procedure if the PTG is modified,
        # not doable unless driver extension framework is in place
        pass

    def update_policy_rule_precommit(self, context):
        # TODO(ivar): add support for action update on policy rules
        raise PolicyRuleUpdateNotSupportedOnApicDriver()

    def update_policy_target_group_precommit(self, context):
        if set(context.original['subnets']) - set(context.current['subnets']):
            raise gpexc.PolicyTargetGroupSubnetRemovalNotSupported()
        self._reject_shared_update(context, 'policy_target_group')

    def update_policy_target_group_postcommit(self, context):
        # TODO(ivar): refactor parent to avoid code duplication
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        orig_consumed_policy_rule_sets = context.original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']

        new_provided_policy_rule_sets = list(
            set(curr_provided_policy_rule_sets) - set(
                orig_provided_policy_rule_sets))
        new_consumed_policy_rule_sets = list(
            set(curr_consumed_policy_rule_sets) - set(
                orig_consumed_policy_rule_sets))
        removed_provided_policy_rule_sets = list(
            set(orig_provided_policy_rule_sets) - set(
                curr_provided_policy_rule_sets))
        removed_consumed_policy_rule_sets = list(
            set(orig_consumed_policy_rule_sets) - set(
                curr_consumed_policy_rule_sets))

        orig_subnets = context.original['subnets']
        curr_subnets = context.current['subnets']
        new_subnets = list(set(curr_subnets) - set(orig_subnets))
        removed_subnets = list(set(orig_subnets) - set(curr_subnets))

        with self.apic_manager.apic.transaction(None) as trs:
            self._manage_ptg_policy_rule_sets(
                context._plugin_context, context.current,
                new_provided_policy_rule_sets, new_consumed_policy_rule_sets,
                removed_provided_policy_rule_sets,
                removed_consumed_policy_rule_sets, transaction=trs)

            new_subnets = self._subnet_ids_to_objects(
                context._plugin_context, new_subnets)
            removed_subnets = self._subnet_ids_to_objects(
                context._plugin_context, removed_subnets)

            self._manage_ptg_subnets(context._plugin_context, context.current,
                                     new_subnets, removed_subnets)
        self._update_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'], subnets=new_subnets)

    def update_l3_policy_precommit(self, context):
        self._reject_shared_update(context, 'l3_policy')
        self._check_l3p_es(context)

    def update_l3_policy_postcommit(self, context):
        old_segment_dict = context.original['external_segments']
        new_segment_dict = context.current['external_segments']
        if (context.current['external_segments'] !=
                context.original['external_segments']):
            new_segments = set(new_segment_dict.keys())
            old_segments = set(old_segment_dict.keys())
            added = new_segments - old_segments
            removed = old_segments - new_segments
            # Modified ES are treated like new ones
            modified = set(x for x in (new_segments - added) if
                        (set(old_segment_dict[x]) != set(new_segment_dict[x])))
            added |= modified
            # The following operations could be intra-tenant, can't be executed
            # in a single transaction
            if added:
                # Create a L3 ext for each External Segment
                added_ess = context._plugin.get_external_segments(
                    context._plugin_context, filters={'id': added})
                for es in added_ess:
                    self._plug_l3p_to_es(context, es)
            if removed:
                removed_ess = context._plugin.get_external_segments(
                    context._plugin_context, filters={'id': removed})
                for es in removed_ess:
                    self._unplug_l3p_from_es(context, es)

    def create_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if ext_info and ext_info.get('cidr_exposed'):
            db_es = context._plugin._get_external_segment(
                context._plugin_context, context.current['id'])
            net = netaddr.IPNetwork(ext_info.get('cidr_exposed'))
            db_es.cidr = str(net)
            db_es.ip_version = net[0].version
            context.current['cidr'] = db_es.cidr
            context.current['ip_version'] = db_es.ip_version
        else:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])

    def create_external_segment_postcommit(self, context):
        external_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not external_info:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])

    def update_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()

    def update_external_segment_postcommit(self, context):
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not ext_info:
            LOG.warn(_("External Segment %s is not managed by APIC mapping "
                       "driver.") % context.current['id'])
            return
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            new_routes_dict = self._build_routes_dict(
                context.current['external_routes'])
            new_routes = set((x['destination'], x['nexthop'])
                             for x in context.current['external_routes'])
            old_routes = set((x['destination'], x['nexthop'])
                             for x in context.original['external_routes'])
            added = new_routes - old_routes
            removed = old_routes - new_routes
            switch = ext_info['switch']
            default_gateway = ext_info['gateway_ip']
            es_name = self.name_mapper.external_segment(
                context, context.current['id'])
            es_tenant = self._tenant_by_sharing_policy(context.current)
            ep_names = [self.name_mapper.external_policy(context, x)
                        for x in context.current['external_policies']]

            nexthop = lambda h: h if h else default_gateway
            with self.apic_manager.apic.transaction() as trs:
                for route in removed:
                    if route[0] not in new_routes_dict:
                        # Remove Route completely
                        self.apic_manager.ensure_static_route_deleted(
                            es_name, switch, route[0], owner=es_tenant,
                            transaction=trs)
                        # Also from External EPG
                        del_epg = (self.apic_manager.
                                   ensure_external_epg_routes_deleted)
                        for ep in ep_names:
                            del_epg(
                                es_name, external_epg=ep, owner=es_tenant,
                                subnets=[route[0]], transaction=trs)
                    else:
                        # Only remove nexthop
                        self.apic_manager.ensure_next_hop_deleted(
                            es_name, switch, route[0], nexthop(route[1]),
                            owner=es_tenant, transaction=trs)
                for route in added:
                    # Create Static Route on External Routed Network
                    self.apic_manager.ensure_static_route_created(
                        es_name, switch, nexthop(route[1]),
                        owner=es_tenant, subnet=route[0], transaction=trs)
                    # And on the External EPGs
                    for ep in ep_names:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=route[0], external_epg=ep,
                            owner=es_tenant, transaction=trs)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        # If not in use, there's no representation of it in the APIC
        pass

    def create_external_policy_precommit(self, context):
        pass

    def create_external_policy_postcommit(self, context):
        segments = context.current['external_segments']
        provided_prs = context.current['provided_policy_rule_sets']
        consumed_prs = context.current['consumed_policy_rule_sets']
        self._plug_externa_policy_to_segment(
            context, context.current, segments, provided_prs, consumed_prs)

    def update_external_policy_precommit(self, context):
        pass

    def update_external_policy_postcommit(self, context):
        added_segments = (set(context.current['external_segments']) -
                          set(context.original['external_segments']))
        removed_segments = (set(context.original['external_segments']) -
                            set(context.current['external_segments']))
        # Remove segments
        self._unplug_external_policy_from_segment(
            context, context.current, removed_segments)
        # Add new segments
        provided_prs = context.current['provided_policy_rule_sets']
        consumed_prs = context.current['consumed_policy_rule_sets']
        self._plug_externa_policy_to_segment(
            context, context.current, added_segments, provided_prs,
            consumed_prs)
        # Manage updated PRSs
        added_p_prs = (set(context.current['provided_policy_rule_sets']) -
                       set(context.original['provided_policy_rule_sets']))
        removed_p_prs = (set(context.original['provided_policy_rule_sets']) -
                         set(context.current['provided_policy_rule_sets']))
        added_c_prs = (set(context.current['consumed_policy_rule_sets']) -
                       set(context.original['consumed_policy_rule_sets']))
        removed_c_prs = (set(context.original['consumed_policy_rule_sets']) -
                         set(context.current['consumed_policy_rule_sets']))
        # Avoid duplicating requests
        delta_segments = [x for x in context.current['external_segments']
                          if x not in added_segments]
        new_ess = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': delta_segments})
        for es in new_ess:
            self._manage_ep_policy_rule_sets(
                context._plugin_context, es, context.current, added_p_prs,
                added_c_prs, removed_p_prs, removed_c_prs)

    def delete_external_policy_precommit(self, context):
        pass

    def delete_external_policy_postcommit(self, context):
        external_segments = context.current['external_segments']
        self._unplug_external_policy_from_segment(
            context, context.current, external_segments)

    def process_subnet_changed(self, context, old, new):
        if old['gateway_ip'] != new['gateway_ip']:
            ptg = self._subnet_to_ptg(context, new['id'])
            if ptg:
                # Is GBP owned, reflect on APIC
                self._manage_ptg_subnets(context, ptg, [new], [old])

    def process_port_changed(self, context, old, new):
        # Port's EP can't change unless EP is deleted/created, therefore the
        # binding will mostly be the same except for the host
        if old['binding:host_id'] != new['binding:host_id']:
            pt = self._port_id_to_pt(context, new['id'])
            if pt:
                if old['binding:host_id']:
                    self.process_path_deletion(context, old)
                self._manage_policy_target_port(context, pt)

    def process_path_deletion(self, context, port, policy_target=None):
        port_details = self.get_gbp_details(
            context, port_id=port['id'], host=port['binding:host_id'],
            policy_target=policy_target)
        self._delete_path_if_last(context, port_details)

    def _apply_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        # TODO(ivar): refactor parent to avoid code duplication
        if policy_rule_set['parent_id']:
            parent = context._plugin.get_policy_rule_set(
                context._plugin_context, policy_rule_set['parent_id'])
            policy_rules = policy_rules & set(parent['policy_rules'])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, transaction=transaction)

    def _remove_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            transaction=transaction)

    def _manage_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, unset=False,
            transaction=None):
        # REVISIT(ivar): figure out what should be moved in apicapi instead
        if policy_rules:
            tenant = self._tenant_by_sharing_policy(policy_rule_set)
            contract = self.name_mapper.policy_rule_set(context,
                                                 context.current['id'])
            in_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_IN]
            out_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_OUT]
            for rule in policy_rules:
                policy_rule = self.name_mapper.policy_rule(context, rule['id'])
                rule_owner = self._tenant_by_sharing_policy(rule)
                classifier = context._plugin.get_policy_classifier(
                    context._plugin_context, rule['policy_classifier_id'])
                with self.apic_manager.apic.transaction(transaction) as trs:
                    if classifier['direction'] in in_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_in_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                    if classifier['direction'] in out_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_out_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)

    @lockutils.synchronized('apic-portlock')
    def _manage_policy_target_port(self, plugin_context, pt):
        port = self._core_plugin.get_port(plugin_context, pt['port_id'])
        if port.get('binding:host_id'):
            port_details = self.get_gbp_details(
                plugin_context, port_id=port['id'],
                host=port['binding:host_id'])
            if port_details:
                # TODO(ivar): change APICAPI to not expect a resource context
                plugin_context._plugin = self.gbp_plugin
                plugin_context._plugin_context = plugin_context
                ptg_object = self.gbp_plugin.get_policy_target_group(
                    plugin_context, port_details['ptg_id'])
                tenant_id = self._tenant_by_sharing_policy(ptg_object)
                epg = self.name_mapper.policy_target_group(
                    plugin_context, port_details['ptg_id'])
                bd = self.name_mapper.l2_policy(
                    plugin_context, port_details['l2_policy_id'])
                seg = port_details['segmentation_id']
                # Create a static path attachment for the host/epg/switchport
                with self.apic_manager.apic.transaction() as trs:
                    self.apic_manager.ensure_path_created_for_port(
                        tenant_id, epg, port['binding:host_id'], seg,
                        bd_name=bd,
                        transaction=trs)

    def _manage_ptg_policy_rule_sets(
            self, plugin_context, ptg, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        mapped_tenant = self._tenant_by_sharing_policy(ptg)
        mapped_ptg = self.name_mapper.policy_target_group(plugin_context,
                                                     ptg['id'])
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_epg,
                   self.apic_manager.unset_contract_for_epg]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(provided)):
                for c in self.gbp_plugin.get_policy_rule_sets(
                        plugin_context, filters={'id': provided[x]}):
                    c_owner = self._tenant_by_sharing_policy(c)
                    c = self.name_mapper.policy_rule_set(plugin_context,
                                                         c['id'])
                    methods[x](mapped_tenant, mapped_ptg, c, provider=True,
                               contract_owner=c_owner, transaction=trs)
            for x in xrange(len(consumed)):
                for c in self.gbp_plugin.get_policy_rule_sets(
                        plugin_context, filters={'id': consumed[x]}):
                    c_owner = self._tenant_by_sharing_policy(c)
                    c = self.name_mapper.policy_rule_set(plugin_context,
                                                         c['id'])
                    methods[x](mapped_tenant, mapped_ptg, c, provider=False,
                               contract_owner=c_owner, transaction=trs)

    def _manage_ep_policy_rule_sets(
            self, plugin_context, es, ep, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        mapped_tenant = self._tenant_by_sharing_policy(es)
        mapped_es = self.name_mapper.external_segment(plugin_context, es['id'])

        mapped_ep = self.name_mapper.external_policy(plugin_context,
                                                     ep['id'])
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_external_epg,
                   self.apic_manager.unset_contract_for_external_epg]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(provided)):
                for c in provided[x]:
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=True,
                               transaction=trs)
            for x in xrange(len(consumed)):
                for c in consumed[x]:
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=False,
                               transaction=trs)

    def _manage_ptg_subnets(self, plugin_context, ptg, added_subnets,
                            removed_subnets, transaction=None):
        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        l2_policy_object = self.gbp_plugin.get_l2_policy(
            plugin_context, ptg['l2_policy_id'])
        mapped_tenant = self._tenant_by_sharing_policy(l2_policy_object)
        mapped_l2p = self.name_mapper.l2_policy(plugin_context,
                                                ptg['l2_policy_id'])
        subnets = [added_subnets, removed_subnets]
        methods = [self.apic_manager.ensure_subnet_created_on_apic,
                   self.apic_manager.ensure_subnet_deleted_on_apic]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(subnets)):
                for s in subnets[x]:
                    methods[x](mapped_tenant, mapped_l2p, self._gateway_ip(s),
                               transaction=trs)

    def _get_active_path_count(self, plugin_context, port_info):
        return plugin_context.session.query(
            models.PortBinding).filter_by(
                host=port_info['host'],
                segment=port_info['segmentation_id']).filter(
                    models.PortBinding.port_id != port_info['port_id']).count()

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, ptg, port_info):
        if not self._get_active_path_count(context, port_info):
            self.apic_manager.ensure_path_deleted_for_port(
                atenant_id, ptg, port_info['host'])

    def _delete_path_if_last(self, context, port_info):
        if not self._get_active_path_count(context, port_info):
            # TODO(ivar): change APICAPI to not expect a resource context
            context._plugin = self.gbp_plugin
            context._plugin_context = context
            ptg_object = self.gbp_plugin.get_policy_target_group(
                context, port_info['ptg_id'])
            atenant_id = self._tenant_by_sharing_policy(ptg_object)
            epg = self.name_mapper.policy_target_group(context,
                                                       port_info['ptg_id'])
            self._delete_port_path(context, atenant_id, epg, port_info)

    def _get_default_security_group(self, context, ptg_id, tenant_id):
        # Default SG in APIC mapping is per tenant, and allows all the traffic
        # since the contracts will be enforced by ACI and not via SG
        filters = {'name': ['gbp_apic_default'], 'tenant_id': [tenant_id]}
        default_group = self._core_plugin.get_security_groups(
            context, filters)
        if not default_group:
            attrs = {'name': 'gbp_apic_default', 'tenant_id': tenant_id,
                     'description': 'default apic sg'}
            ret = self._create_sg(context, attrs)
            for ethertype in ext_sg.sg_supported_ethertypes:
                for direction in ['ingress', 'egress']:
                    self._sg_rule(context, tenant_id, ret['id'], direction,
                                  ethertype=ethertype)
            return ret['id']
        else:
            return default_group[0]['id']

    def _update_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id, subnets=None):
        pass

    def _assoc_ptg_sg_to_pt(self, context, pt_id, ptg_id):
        pass

    def _handle_policy_rule_sets(self, context):
        pass

    def _gateway_ip(self, subnet):
        cidr = netaddr.IPNetwork(subnet['cidr'])
        return '%s/%s' % (subnet['gateway_ip'], str(cidr.prefixlen))

    def _subnet_ids_to_objects(self, plugin_context, ids):
        return self._core_plugin.get_subnets(plugin_context,
                                             filters={'id': ids})

    def _port_to_ptg_network(self, context, port, host=None):
        ptg = self._port_id_to_ptg(context, port['id'])
        if not ptg:
            # Not GBP port
            return None, None
        network = self._l2p_id_to_network(context, ptg['l2_policy_id'])
        return ptg, network

    def _port_id_to_pt(self, context, port_id):
        pt = (context.session.query(gpdb.PolicyTargetMapping).
              filter_by(port_id=port_id).first())
        if pt:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_dict(pt)

    def _port_id_to_ptg(self, context, port_id):
        pt = self._port_id_to_pt(context, port_id)
        if pt:
            return self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id'])
        return

    def _l2p_id_to_network(self, context, l2p_id):
        l2_policy = self.gbp_plugin.get_l2_policy(context, l2p_id)
        return self._core_plugin.get_network(context, l2_policy['network_id'])

    def _network_id_to_l2p(self, context, network_id):
        l2ps = self.gbp_plugin.get_l2_policies(
            context, filters={'network_id': [network_id]})
        return l2ps[0] if l2ps else None

    def _subnet_to_ptg(self, context, subnet_id):
        ptg = (context.session.query(gpdb.PolicyTargetGroupMapping).
               join(gpdb.PolicyTargetGroupMapping.subnets).
               filter(gpdb.PTGToSubnetAssociation.subnet_id ==
                      subnet_id).
               first())
        if ptg:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_group_dict(ptg)

    def _plug_l3p_to_es(self, context, external_segment):
        l3_policy = self.name_mapper.l3_policy(context, context.current['id'])
        es = external_segment
        external_segments = context.current['external_segments']
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warn(
                _("External Segment %s is not managed by APIC mapping "
                  "driver.") % es['id'])
            return
        ip = external_segments[es['id']]
        ip = ip[0] if (ip and ip[0]) else ext_info.get('cidr_exposed',
                                                       '/').split('/')[0]
        if not ip:
            raise NoAddressConfiguredOnExternalSegment(
                l3p_id=context.current['id'], es_id=es['id'])
        context.set_external_fixed_ips(es['id'], [ip])
        encap = ext_info.get('encap')  # No encap if None
        switch = ext_info['switch']
        module, sport = ext_info['port'].split('/')
        router_id = ext_info['router_id']
        default_gateway = ext_info['gateway_ip']
        es_name = self.name_mapper.external_segment(
            context, es['id'])
        es_tenant = self._tenant_by_sharing_policy(es)
        with self.apic_manager.apic.transaction() as trs:
            # Create External Routed Network connected to the proper
            # L3 Context
            self.apic_manager.ensure_external_routed_network_created(
                es_name, owner=es_tenant, context=l3_policy,
                transaction=trs)
            self.apic_manager.ensure_logical_node_profile_created(
                es_name, switch, module, sport, encap,
                ip, owner=es_tenant, router_id=router_id,
                transaction=trs)
            for route in es['external_routes']:
                self.apic_manager.ensure_static_route_created(
                    es_name, switch, route['nexthop'] or default_gateway,
                    owner=es_tenant,
                    subnet=route['destination'], transaction=trs)

    def _unplug_l3p_from_es(self, context, es):
        es_name = self.name_mapper.external_segment(context, es['id'])
        es_tenant = self._tenant_by_sharing_policy(es)
        self.apic_manager.delete_external_routed_network(
            es_name, owner=es_tenant)

    def _build_routes_dict(self, routes):
        result = {}
        for route in routes:
            if route['destination'] not in result:
                result[route['destination']] = []
            result[route['destination']].append(route['nexthop'])
        return result

    def _plug_externa_policy_to_segment(self, context, ep, segments,
                                        provided_prs, consumed_prs):
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(
                context, ep['id'])
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(_("External Segment %s is not managed by APIC "
                             "mapping driver.") % es['id'])
                    continue
                es_name = self.name_mapper.external_segment(context, es['id'])
                es_tenant = self._tenant_by_sharing_policy(es)
                with self.apic_manager.apic.transaction() as trs:
                    # Create External EPG
                    subnets = set(x['destination'] for
                                  x in es['external_routes'])
                    for s in subnets:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=s, external_epg=ep_name,
                            owner=es_tenant, transaction=trs)
                    # Provide and consume contracts
                    self._manage_ep_policy_rule_sets(
                        context._plugin_context, es, ep,
                        provided_prs, consumed_prs, [], [], transaction=trs)

    def _unplug_external_policy_from_segment(self, context, ep, segments):
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(
                context, ep['id'])
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(_("External Segment %s is not managed by APIC "
                             "mapping driver.") % es['id'])
                    continue
                es_name = self.name_mapper.external_segment(context, es['id'])
                es_tenant = self._tenant_by_sharing_policy(es)
                self.apic_manager.ensure_external_epg_deleted(
                        es_name, external_epg=ep_name, owner=es_tenant)

    def _check_l3p_es(self, context):
        l3p = context.current
        if l3p['external_segments']:
            # Check not used
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': l3p['external_segments'].keys()})
            for es in ess:
                if [x for x in es['l3_policies'] if x != l3p['id']]:
                    raise OnlyOneL3PolicyIsAllowedPerExternalSegment()
            for allocations in l3p['external_segments'].values():
                if len(allocations) > 1:
                    raise OnlyOneAddressIsAllowedPerExternalSegment()

    def _get_ptg_by_subnet(self, plugin_context, subnet_id):
        ptgass = (plugin_context.session.query(gpdb.PTGToSubnetAssociation).
                  filter_by(subnet_id=subnet_id).first())
        if ptgass:
            return self.gbp_plugin.get_policy_target_group(
                plugin_context, ptgass['policy_target_group_id'])

    def _reject_shared_update(self, context, type):
        if context.original.get('shared') != context.current.get('shared'):
            raise SharedAttributeUpdateNotSupportedOnApic(type=type)

    def _tenant_by_sharing_policy(self, object):
        if not object.get('shared'):
            return self.name_mapper.tenant(None, object['tenant_id'])
        else:
            return apic_manager.TENANT_COMMON
