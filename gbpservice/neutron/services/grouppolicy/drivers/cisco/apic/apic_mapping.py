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
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers.cisco.apic import config
from opflexagent import constants as ofcst
from opflexagent import rpc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    name_manager as name_manager)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)
from gbpservice.neutron.services.grouppolicy import group_policy_context


LOG = logging.getLogger(__name__)
UNMANAGED_SEGMENT = _("External Segment %s is not managed by APIC mapping "
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


class ExplicitSubnetAssociationNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Explicit subnet association not supported by APIC driver.")


class HierarchicalContractsNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Hierarchical contracts not supported by APIC driver.")


class HostPoolSubnetOverlap(gpexc.GroupPolicyBadRequest):
    message = _("Host pool subnet %(host_pool_cidr)s overlaps with "
                "APIC external network subnet for %(es)s.")


class FloatingIPFromExtSegmentInUse(gpexc.GroupPolicyBadRequest):
    message = _("One or more policy targets in L3 policy %(l3p)s have "
                "floating IPs associated with external segment.")


class NatPoolOverlapsApicSubnet(gpexc.GroupPolicyBadRequest):
    message = _("NAT IP pool %(nat_pool_cidr)s overlaps with "
                "APIC external network or host-pool subnet for %(es)s.")


class CannotUpdateApicName(gpexc.GroupPolicyBadRequest):
    message = _("Objects referring to existing "
                "APIC resources can't be updated")


REVERSE_PREFIX = 'reverse-'
SHADOW_PREFIX = 'Shd-'
SERVICE_PREFIX = 'Svc-'
IMPLICIT_PREFIX = 'implicit-'
ANY_PREFIX = 'any-'
PROMISCUOUS_SUFFIX = 'promiscuous'
APIC_OWNED = 'apic_owned_'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
ALLOWING_ACTIONS = [g_const.GP_ACTION_ALLOW, g_const.GP_ACTION_REDIRECT]
REVERTIBLE_PROTOCOLS = [n_constants.PROTO_NAME_TCP.lower()]
NAT_EPG_PREFIX = "NAT-"


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
                'vni_ranges': cfg.CONF.ml2_type_vxlan.vni_ranges,
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
        self._setup_rpc_listeners()
        self._setup_rpc()
        self.apic_manager = ApicMappingDriver.get_apic_manager()
        self.name_mapper = name_manager.ApicNameManager(self.apic_manager)
        self.enable_dhcp_opt = self.apic_manager.enable_optimized_dhcp
        self._gbp_plugin = None

    def _setup_rpc_listeners(self):
        self.endpoints = [rpc.GBPServerRpcCallback(self)]
        self.topic = rpc.TOPIC_OPFLEX
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        return self.conn.consume_in_threads()

    def _setup_rpc(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    # RPC Method
    def get_vrf_details(self, context, **kwargs):
        details = {'l3_policy_id': kwargs['vrf_id']}
        self._add_vrf_details(context, details)
        return details

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        port_id = self._core_plugin._device_to_port_id(
            kwargs['device'])
        port_context = self._core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return
        port = port_context.current

        # retrieve PTG from a given Port
        ptg = self._port_id_to_ptg(context, port['id'])
        l2p = self._network_id_to_l2p(context, port['network_id'])
        if not ptg and not l2p:
            return
        context._plugin = self.gbp_plugin
        context._plugin_context = context

        l2_policy_id = l2p['id']
        ptg_tenant = self._tenant_by_sharing_policy(ptg or l2p)
        if ptg:
            endpoint_group_name = self.name_mapper.policy_target_group(
                context, ptg)
        else:
            endpoint_group_name = self.name_mapper.l2_policy(
                context, l2p, prefix=SHADOW_PREFIX)

        def is_port_promiscuous(port):
            return (port['device_owner'] in PROMISCUOUS_TYPES or
                    port['name'].endswith(PROMISCUOUS_SUFFIX))

        details = {'device': kwargs.get('device'),
                   'port_id': port_id,
                   'mac_address': port['mac_address'],
                   'app_profile_name': str(
                       self.apic_manager.app_profile_name),
                   'l2_policy_id': l2_policy_id,
                   'l3_policy_id': l2p['l3_policy_id'],
                   'tenant_id': port['tenant_id'],
                   'host': port[portbindings.HOST_ID],
                   'ptg_tenant': self.apic_manager.apic.fvTenant.name(
                       ptg_tenant),
                   'endpoint_group_name': str(endpoint_group_name),
                   'promiscuous_mode': is_port_promiscuous(port)}
        if port['device_owner'].startswith('compute:') and port['device_id']:
            vm = nclient.NovaClient().get_server(port['device_id'])
            details['vm-name'] = vm.name if vm else port['device_id']

            l3_policy = context._plugin.get_l3_policy(context,
                                                      l2p['l3_policy_id'])
            self._add_ip_mapping_details(context, port_id, l3_policy, details)
        self._add_network_details(context, port, details)
        self._add_vrf_details(context, details)
        return details

    def _add_ip_mapping_details(self, context, port_id, l3_policy, details):
        """ Add information about IP mapping for DNAT/SNAT """
        if not l3_policy['external_segments']:
            return
        fips = self._get_fips(context, filters={'port_id': [port_id]})
        ipms = []
        ess = context._plugin.get_external_segments(context._plugin_context,
                filters={'id': l3_policy['external_segments'].keys()})
        for es in ess:
            nat_epg_name = self._get_nat_epg_for_es(context, es)
            nat_epg_tenant = str(self._tenant_by_sharing_policy(es))
            fips_in_es = []

            if es['subnet_id']:
                subnet = self._get_subnet(context._plugin_context,
                                          es['subnet_id'])
                ext_net_id = subnet['network_id']
                fips_in_es = filter(
                    lambda x: x['floating_network_id'] == ext_net_id, fips)
            if not fips_in_es:
                ipms.append({'external_segment_name': es['name'],
                             'nat_epg_name': nat_epg_name,
                             'nat_epg_tenant': nat_epg_tenant})
            for f in fips_in_es:
                f['nat_epg_name'] = nat_epg_name
                f['nat_epg_tenant'] = nat_epg_tenant
        details['floating_ip'] = fips
        details['ip_mapping'] = ipms

    def _add_network_details(self, context, port, details):
        details['allowed_address_pairs'] = port['allowed_address_pairs']
        details['enable_dhcp_optimization'] = self.enable_dhcp_opt
        details['subnets'] = self._get_subnets(context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})

    def _add_vrf_details(self, context, details):
        l3p = self.gbp_plugin.get_l3_policy(context, details['l3_policy_id'])
        details['vrf_tenant'] = self.apic_manager.apic.fvTenant.name(
            self._tenant_by_sharing_policy(l3p))
        details['vrf_name'] = str(self.name_mapper.l3_policy(
            context, l3p))
        details['vrf_subnets'] = [l3p['ip_pool']]
        if l3p.get('proxy_ip_pool'):
            details['vrf_subnets'].append(l3p['proxy_ip_pool'])

    def process_port_added(self, plugin_context, port):
        pass

    def create_policy_action_precommit(self, context):
        pass

    def create_policy_rule_precommit(self, context):
        if ('policy_actions' in context.current and
                len(context.current['policy_actions']) != 1):
            # TODO(ivar): to be fixed when redirect is supported
            raise ExactlyOneActionPerRuleIsSupportedOnApicDriver()

    def create_policy_rule_postcommit(self, context, transaction=None):
        action = context._plugin.get_policy_action(
            context._plugin_context, context.current['policy_actions'][0])
        classifier = context._plugin.get_policy_classifier(
            context._plugin_context,
            context.current['policy_classifier_id'])
        if action['action_type'] in ALLOWING_ACTIONS:
            port_min, port_max = (
                gpdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                    classifier['port_range']))
            attrs = {'etherT': 'unspecified'}
            if classifier['protocol']:
                attrs['etherT'] = 'ip'
                attrs['prot'] = classifier['protocol'].lower()
                if port_min and port_max:
                    attrs['dToPort'] = port_max
                    attrs['dFromPort'] = port_min
            tenant = self._tenant_by_sharing_policy(context.current)
            policy_rule = self.name_mapper.policy_rule(context,
                                                       context.current)
            with self.apic_manager.apic.transaction(transaction) as trs:
                self.apic_manager.create_tenant_filter(
                    policy_rule, owner=tenant, transaction=trs, **attrs)
                # Also create reverse rule
                if attrs.get('prot') in REVERTIBLE_PROTOCOLS:
                    if attrs['prot'] == n_constants.PROTO_NAME_TCP.lower():
                        policy_rule = self.name_mapper.policy_rule(
                            context, context.current, prefix=REVERSE_PREFIX)
                        if attrs.get('dToPort') and attrs.get('dFromPort'):
                            attrs.pop('dToPort')
                            attrs.pop('dFromPort')
                            attrs['sToPort'] = port_max
                            attrs['sFromPort'] = port_min
                        attrs['tcpRules'] = 'est'
                        self.apic_manager.create_tenant_filter(
                            policy_rule, owner=tenant, transaction=trs,
                            **attrs)

    def create_policy_rule_set_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            if context.current['child_policy_rule_sets']:
                raise HierarchicalContractsNotSupported()
        else:
            self.name_mapper.has_valid_name(context.current)

    def create_policy_rule_set_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            # Create APIC policy_rule_set
            tenant = self._tenant_by_sharing_policy(context.current)
            contract = self.name_mapper.policy_rule_set(context,
                                                        context.current)
            with self.apic_manager.apic.transaction(None) as trs:
                self.apic_manager.create_contract(
                    contract, owner=tenant, transaction=trs)
                rules = self.gbp_plugin.get_policy_rules(
                    context._plugin_context,
                    {'id': context.current['policy_rules']})
                self._apply_policy_rule_set_rules(
                    context, context.current, rules, transaction=trs)

    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        port = self._core_plugin.get_port(context._plugin_context,
                                          context.current['port_id'])
        if self._is_port_bound(port):
            self._notify_port_update(context._plugin_context, port['id'])
        if self._may_have_fip(context):
            self._associate_fip_to_pt(context)

    def _may_have_fip(self, context):
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context,
            context.current['policy_target_group_id'])
        es = self._retrieve_es_with_nat_pools(context, ptg['l2_policy_id'])
        return reduce(lambda x, y: x and y,
                      [e['subnet_id'] for e in es], True)

    def create_policy_target_group_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            if context.current['subnets']:
                raise ExplicitSubnetAssociationNotSupported()
        else:
            self.name_mapper.has_valid_name(context.current)

    def create_policy_target_group_postcommit(self, context):
        if not context.current['subnets']:
            self._use_implicit_subnet(context)
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            l2p = self._get_l2_policy(context._plugin_context,
                                      context.current['l2_policy_id'])
            l2_policy = self.name_mapper.l2_policy(context, l2p)
            epg = self.name_mapper.policy_target_group(context,
                                                       context.current)
            l2_policy_object = context._plugin.get_l2_policy(
                context._plugin_context, context.current['l2_policy_id'])
            bd_owner = self._tenant_by_sharing_policy(l2_policy_object)
            with self.apic_manager.apic.transaction(None) as trs:
                self.apic_manager.ensure_epg_created(tenant, epg,
                                                     bd_owner=bd_owner,
                                                     bd_name=l2_policy)

                l2p = context._plugin.get_l2_policy(
                    context._plugin_context, context.current['l2_policy_id'])
                self._configure_epg_service_contract(
                    context, context.current, l2p, epg, transaction=trs)
                self._configure_epg_implicit_contract(
                    context, context.current, l2p, epg, transaction=trs)

            self._manage_ptg_policy_rule_sets(
                    context, context.current['provided_policy_rule_sets'],
                    context.current['consumed_policy_rule_sets'], [], [])

    def create_l2_policy_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_non_shared_net_on_shared_l2p(context)
        else:
            self.name_mapper.has_valid_name(context.current)

    def update_l2_policy_precommit(self, context):
        self._reject_apic_name_change(context)
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_non_shared_net_on_shared_l2p(context)
            self._reject_shared_update(context, 'l2_policy')

    def create_l2_policy_postcommit(self, context):
        super(ApicMappingDriver, self).create_l2_policy_postcommit(context)
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            l3_policy_object = self._get_l3_policy(
                context._plugin_context, context.current['l3_policy_id'])
            l3_policy = self.name_mapper.l3_policy(context, l3_policy_object)
            l2_policy = self.name_mapper.l2_policy(context, context.current)
            ctx_owner = self._tenant_by_sharing_policy(l3_policy_object)
            with self.apic_manager.apic.transaction(None) as trs:
                self.apic_manager.ensure_bd_created_on_apic(
                    tenant, l2_policy, ctx_owner=ctx_owner, ctx_name=l3_policy,
                    transaction=trs)
                # Create neutron port EPG
                self._configure_shadow_epg(context, context.current, l2_policy,
                                           transaction=trs)
                self._configure_implicit_contract(context, context.current,
                                                  transaction=trs)
                # Add existing subnets
                net_id = context.current['network_id']
                subnets = self._core_plugin.get_subnets(
                    context._plugin_context, {'network_id': [net_id]})
                self._manage_l2p_subnets(
                    context._plugin_context, context.current['id'],
                    subnets, [], transaction=trs)

    def update_l2_policy_postcommit(self, context):
        pass

    def create_l3_policy_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            self._check_l3p_es(context)
        else:
            self.name_mapper.has_valid_name(context.current)

    def create_l3_policy_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            l3_policy = self.name_mapper.l3_policy(context, context.current)
            self.apic_manager.ensure_context_enforced(tenant, l3_policy)
            external_segments = context.current['external_segments']
            if external_segments:
                # Create a L3 ext for each External Segment
                ess = context._plugin.get_external_segments(
                    context._plugin_context,
                    filters={'id': external_segments.keys()})
                self._create_and_plug_router_to_es(context, external_segments)
                for es in ess:
                    self._plug_l3p_to_es(context, es)

    def delete_policy_rule_postcommit(self, context):
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])
        self._delete_policy_rule_from_apic(context)

    def _delete_policy_rule_from_apic(self, context, transaction=None):
        tenant = self._tenant_by_sharing_policy(context.current)
        policy_rule = self.name_mapper.policy_rule(context,
                                                   context.current)
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant,
                                                   transaction=trs)
            # Delete policy reverse rule
            policy_rule = self.name_mapper.policy_rule(
                context, context.current, prefix=REVERSE_PREFIX)
            self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant,
                                                   transaction=trs)

    def delete_policy_rule_set_precommit(self, context):
        # Intercept Parent Call
        pass

    def delete_policy_rule_set_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            contract = self.name_mapper.policy_rule_set(context,
                                                        context.current)
            self.apic_manager.delete_contract(contract, owner=tenant)

    def delete_policy_target_postcommit(self, context):
        for fip in context.fips:
            self._delete_fip(context._plugin_context, fip.floatingip_id)
        try:
            if context.current['port_id']:
                port = self._core_plugin.get_port(context._plugin_context,
                                                  context.current['port_id'])
                # Delete Neutron's port
                port_id = context.current['port_id']
                self._cleanup_port(context._plugin_context, port_id)
                # Notify the agent. If the port has been deleted by the
                # parent method the notification will not be done
                self._notify_port_update(context._plugin_context, port['id'])
        except n_exc.PortNotFound:
            LOG.warn(_("Port %s is missing") % context.current['port_id'])
            return

    def delete_policy_target_group_precommit(self, context):
        pass

    def delete_policy_target_group_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            ptg = self.name_mapper.policy_target_group(context,
                                                       context.current)

            self.apic_manager.delete_epg_for_network(tenant, ptg)

    def delete_l2_policy_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            super(ApicMappingDriver, self).delete_l2_policy_precommit(context)

    def delete_l2_policy_postcommit(self, context):
        # before removing the network, remove interfaces attached to router
        self._cleanup_router_interface(context, context.current)
        super(ApicMappingDriver, self).delete_l2_policy_postcommit(context)
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            l2_policy = self.name_mapper.l2_policy(context, context.current)

            with self.apic_manager.apic.transaction(None) as trs:
                self.apic_manager.delete_bd_on_apic(
                    tenant, l2_policy, transaction=trs)
                # Delete neutron port EPG
                self._delete_shadow_epg(context, context.current,
                                        transaction=trs)
                self._delete_implicit_contract(context, context.current,
                                               transaction=trs)

    def delete_l3_policy_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            super(ApicMappingDriver, self).delete_l3_policy_precommit(context)

    def delete_l3_policy_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            l3_policy = self.name_mapper.l3_policy(context, context.current)

            self.apic_manager.ensure_context_deleted(tenant, l3_policy)
            external_segments = context.current['external_segments']
            if external_segments:
                # Create a L3 ext for each External Segment
                ess = context._plugin.get_external_segments(
                    context._plugin_context,
                    filters={'id': external_segments.keys()})
                for es in ess:
                    self._unplug_l3p_from_es(context, es)
            for router_id in context.current['routers']:
                self._cleanup_router(context._plugin_context, router_id)

    def update_policy_rule_set_precommit(self, context):
        self._reject_apic_name_change(context)
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_shared_update(context, 'policy_rule_set')
            self._reject_multiple_redirects_in_prs(context)
            if context.current['child_policy_rule_sets']:
                raise HierarchicalContractsNotSupported()
            # If a redirect action is added (from 0 to one) we have to validate
            # the providing and consuming PTGs
            old_red_count = self._multiple_pr_redirect_action_number(
                context._plugin_context.session,
                context.original['policy_rules'])
            new_red_count = self._multiple_pr_redirect_action_number(
                context._plugin_context.session,
                context.current['policy_rules'])
            if new_red_count > old_red_count:
                self._validate_new_prs_redirect(context, context.current)

    def update_policy_rule_set_postcommit(self, context):
        # Update policy_rule_set rules
        old_rules = set(context.original['policy_rules'])
        new_rules = set(context.current['policy_rules'])
        to_add = context._plugin.get_policy_rules(
            context._plugin_context, {'id': new_rules - old_rules})
        to_remove = context._plugin.get_policy_rules(
            context._plugin_context, {'id': old_rules - new_rules})
        self._remove_policy_rule_set_rules(context, context.current,
                                           to_remove)
        self._apply_policy_rule_set_rules(context, context.current, to_add)

    def update_policy_target_precommit(self, context):
        if (context.original['policy_target_group_id'] !=
                context.current['policy_target_group_id']):
            if context.current['policy_target_group_id']:
                self._validate_pt_port_subnets(context)

    def update_policy_target_postcommit(self, context):
        if (context.original['policy_target_group_id'] !=
                context.current['policy_target_group_id']):
            self._notify_port_update(context._plugin_context,
                                     context.current['port_id'])

    def update_policy_rule_precommit(self, context):
        self._reject_multiple_redirects_in_rule(context)
        old_redirect = self._get_redirect_action(context, context.original)
        new_redirect = self._get_redirect_action(context, context.current)
        if not old_redirect and new_redirect:
            # If redirect action is added, check that there's no contract that
            # already has a redirect action
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context,
                    {'id': context.current['policy_rule_sets']}):
                # Make sure the PRS can have a new redirect action
                self._validate_new_prs_redirect(context, prs)

    def update_policy_rule_postcommit(self, context):
        self._update_policy_rule_on_apic(context)

    def update_policy_action_postcommit(self, context):
        pass

    def _update_policy_rule_on_apic(self, context):
        self._delete_policy_rule_from_apic(context, transaction=None)
        # The following only creates the APIC reference
        self.create_policy_rule_postcommit(context, transaction=None)

    def update_policy_target_group_precommit(self, context):
        self._reject_apic_name_change(context)
        if not self.name_mapper._is_apic_reference(context.current):
            if set(context.original['subnets']) != set(
                    context.current['subnets']):
                raise ExplicitSubnetAssociationNotSupported()
            self._reject_shared_update(context, 'policy_target_group')

    def update_policy_target_group_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
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

            self._manage_ptg_policy_rule_sets(
                context, new_provided_policy_rule_sets,
                new_consumed_policy_rule_sets,
                removed_provided_policy_rule_sets,
                removed_consumed_policy_rule_sets)

    def update_l3_policy_precommit(self, context):
        self._reject_apic_name_change(context)
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_shared_update(context, 'l3_policy')
            self._check_l3p_es(context)
            if context.current['routers'] != context.original['routers']:
                raise gpexc.L3PolicyRoutersUpdateNotSupported()
            rmvd_es = (set(context.original['external_segments'].keys()) -
                      set(context.current['external_segments'].keys()))
            self._check_fip_in_use_in_es(context, context.original, rmvd_es)

    def update_l3_policy_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
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
                            (set(old_segment_dict[x]) !=
                             set(new_segment_dict[x])))
                added |= modified
                # The following operations could be intra-tenant, can't be
                # executed in a single transaction
                if removed:
                    removed_ess = context._plugin.get_external_segments(
                        context._plugin_context, filters={'id': removed})
                    for es in removed_ess:
                        self._unplug_l3p_from_es(context, es)
                    self._cleanup_and_unplug_router_from_es(context,
                                                            removed_ess)
                if added:
                    # Create a L3 ext for each External Segment
                    added_ess = context._plugin.get_external_segments(
                        context._plugin_context, filters={'id': added})
                    self._create_and_plug_router_to_es(context,
                                                       new_segment_dict)
                    for es in added_ess:
                        self._plug_l3p_to_es(context, es)
                self._notify_port_update_in_l3policy(context, context.current)

    def create_policy_classifier_precommit(self, context):
        pass

    def create_policy_classifier_postcommit(self, context):
        pass

    def update_policy_classifier_precommit(self, context):
        pass

    def update_policy_classifier_postcommit(self, context):
        admin_context = nctx.get_admin_context()
        if not context.current['policy_rules']:
            return
        rules = context._plugin.get_policy_rules(
                admin_context,
                filters={'id': context.current['policy_rules']})
        # Rewrite the rule on the APIC
        for rule in rules:
            rule_context = group_policy_context.PolicyRuleContext(
                context._plugin, context._plugin_context, rule)
            self._update_policy_rule_on_apic(rule_context)
            # If direction or protocol changed, the contracts should be updated
            o_dir = context.original['direction']
            c_dir = context.current['direction']
            o_prot = context.original['protocol']
            c_prot = context.current['protocol']
            # TODO(ivar): Optimize by aggregating on PRS ID
            if ((o_dir != c_dir) or
                    ((o_prot in REVERTIBLE_PROTOCOLS) !=
                        (c_prot in REVERTIBLE_PROTOCOLS))):
                for prs in context._plugin.get_policy_rule_sets(
                        admin_context,
                        filters={'id': rule['policy_rule_sets']}):
                    self._remove_policy_rule_set_rules(
                        context, prs, [(rule, context.original)])
                    self._apply_policy_rule_set_rules(context, prs, [rule])

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
            self._check_es_subnet(context, context.current)
            if 'host_pool_cidr' in ext_info:
                hp_net = netaddr.IPNetwork(ext_info['host_pool_cidr'])
                if hp_net.cidr == net.cidr:
                    raise HostPoolSubnetOverlap(host_pool_cidr=hp_net.cidr,
                                                es=context.current['name'])
        else:
            LOG.warn(UNMANAGED_SEGMENT % context.current['id'])

    def create_external_segment_postcommit(self, context):
        external_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not external_info:
            LOG.warn(UNMANAGED_SEGMENT % context.current['id'])
        elif not context.current['subnet_id']:
            self._create_nat_epg_for_es(context, context.current,
                                        external_info)
            subnet = self._use_implicit_external_subnet(
                context, context.current, external_info)
            context.add_subnet(subnet['id'])

    def update_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()
        if context.current['subnet_id'] != context.original['subnet_id']:
            raise gpexc.InvalidAttributeUpdateForES(attribute='subnet_id')

    def update_external_segment_postcommit(self, context):
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not ext_info:
            LOG.warn(UNMANAGED_SEGMENT % context.current['id'])
            return
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            self._do_external_segment_update(context, ext_info)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        # cleanup NAT EPG
        es = context.current
        self.apic_manager.ensure_nat_epg_deleted(
            self._tenant_by_sharing_policy(es),
            self._get_nat_epg_for_es(context, es),
            self._get_nat_bd_for_es(context, es),
            self._get_nat_vrf_for_es(context, es))
        self._delete_implicit_external_subnet(context, es)

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
            if es['name'] in self.apic_manager.ext_net_dict:
                # Update to the PRS of EP updates the shadow EPs only
                l3ps = context._plugin.get_l3_policies(context._plugin_context,
                    filters={'id': es['l3_policies']})
                for l3p in l3ps:
                    self._manage_ep_policy_rule_sets(
                        context._plugin_context, es, context.current,
                        added_p_prs, added_c_prs, removed_p_prs, removed_c_prs,
                        l3policy_obj=l3p)

    def delete_external_policy_precommit(self, context):
        pass

    def delete_external_policy_postcommit(self, context):
        external_segments = context.current['external_segments']
        self._unplug_external_policy_from_segment(
            context, context.current, external_segments)

    def create_nat_pool_precommit(self, context):
        self._check_nat_pool_cidr(context, context.current)
        super(ApicMappingDriver, self).create_nat_pool_precommit(context)

    def create_nat_pool_postcommit(self, context):
        super(ApicMappingDriver, self).create_nat_pool_postcommit(context)
        self._stash_es_subnet_for_nat_pool(context, context.current)
        self._manage_nat_pool_subnet(context, None, context.current)

    def update_nat_pool_precommit(self, context):
        self._check_nat_pool_cidr(context, context.current)
        super(ApicMappingDriver, self).update_nat_pool_precommit(context)

    def update_nat_pool_postcommit(self, context):
        self._stash_es_subnet_for_nat_pool(context, context.original)
        super(ApicMappingDriver, self).update_nat_pool_postcommit(context)
        self._stash_es_subnet_for_nat_pool(context, context.current)
        self._manage_nat_pool_subnet(context, context.original,
                                     context.current)

    def delete_nat_pool_postcommit(self, context):
        self._stash_es_subnet_for_nat_pool(context, context.current)
        super(ApicMappingDriver, self).delete_nat_pool_postcommit(context)
        self._manage_nat_pool_subnet(context, context.current, None)

    def process_subnet_changed(self, context, old, new):
        if old['gateway_ip'] != new['gateway_ip']:
            l2p = self._network_id_to_l2p(context, new['network_id'])
            if l2p:
                # Is GBP owned, reflect on APIC
                self._manage_l2p_subnets(context, l2p['id'], [new], [old])
        # notify ports in the subnet
        ptg_ids = self.gbp_plugin._get_ptgs_for_subnet(context, old['id'])
        pts = self.gbp_plugin.get_policy_targets(
            context, filters={'policy_target_group_id': ptg_ids})
        # REVISIT(amit): We may notify more ports than those that are
        # really affected. Consider checking the port's subnet as well.
        for pt in pts:
            self._notify_port_update(context, pt['port_id'])

    def process_subnet_added(self, context, subnet):
        l2p = self._network_id_to_l2p(context, subnet['network_id'])
        if l2p:
            self._sync_epg_subnets(context, l2p)
            self._manage_l2p_subnets(context, l2p['id'], [subnet], [])

    def process_subnet_deleted(self, context, subnet):
        l2p = self._network_id_to_l2p(context, subnet['network_id'])
        if l2p:
            self._manage_l2p_subnets(context, l2p['id'], [], [subnet])

    def process_port_changed(self, context, old, new):
        pass

    def process_pre_port_deleted(self, context, port):
        pt = self._port_id_to_pt(context, port['id'])
        if pt:
            context.policy_target_id = pt['id']

    def process_port_deleted(self, context, port):
        # do nothing for floating-ip ports
        if port['device_owner'] == n_constants.DEVICE_OWNER_FLOATINGIP:
            LOG.debug(_("Ignoring floating-ip port %s") % port['id'])
            return
        try:
            self.gbp_plugin.delete_policy_target(
                context, context.policy_target_id)
        except AttributeError:
            pass

    def create_floatingip_in_nat_pool(self, context, tenant_id, floatingip):
        """Create floating-ip in NAT pool associated with external-network"""
        fip = floatingip['floatingip']
        f_net_id = fip['floating_network_id']
        subnets = self._get_subnets(context.elevated(),
            {'network_id': [f_net_id]})
        ext_seg = self.gbp_plugin.get_external_segments(context.elevated(),
            {'subnet_id': [s['id'] for s in subnets]}) if subnets else []
        if not ext_seg:
            return None
        context._plugin = self.gbp_plugin
        context._plugin_context = context
        for es in ext_seg:
            fip_id = self._allocate_floating_ip_in_ext_seg(context,
                tenant_id, es, f_net_id, fip.get('port_id'))
            if fip_id:
                return fip_id
        raise n_exc.IpAddressGenerationFailure(net_id=f_net_id)

    def _apply_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        # TODO(ivar): parent contract filtering when supported
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, transaction=transaction)

    def _remove_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            transaction=transaction)

    def _manage_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, unset=False,
            transaction=None, classifier=None):
        # REVISIT(ivar): figure out what should be moved in apicapi instead
        if policy_rules:
            tenant = self._tenant_by_sharing_policy(policy_rule_set)
            contract = self.name_mapper.policy_rule_set(
                context, policy_rule_set)
            in_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_IN]
            out_dir = [g_const.GP_DIRECTION_BI, g_const.GP_DIRECTION_OUT]
            for rule in policy_rules:
                if isinstance(rule, tuple):
                    classifier = rule[1]
                    rule = rule[0]
                else:
                    classifier = context._plugin.get_policy_classifier(
                            context._plugin_context,
                            rule['policy_classifier_id'])
                policy_rule = self.name_mapper.policy_rule(context, rule)
                reverse_policy_rule = self.name_mapper.policy_rule(
                    context, rule, prefix=REVERSE_PREFIX)
                rule_owner = self._tenant_by_sharing_policy(rule)
                with self.apic_manager.apic.transaction(transaction) as trs:
                    if classifier['direction'] in in_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_in_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                        if (classifier['protocol'].lower() in
                                REVERTIBLE_PROTOCOLS):
                            (self.apic_manager.
                             manage_contract_subject_out_filter(
                                 contract, contract, reverse_policy_rule,
                                 owner=tenant, transaction=trs, unset=unset,
                                 rule_owner=rule_owner))
                    if classifier['direction'] in out_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_out_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                        if (classifier['protocol'].lower() in
                                REVERTIBLE_PROTOCOLS):
                            (self.apic_manager.
                             manage_contract_subject_in_filter(
                                 contract, contract, reverse_policy_rule,
                                 owner=tenant, transaction=trs, unset=unset,
                                 rule_owner=rule_owner))

    def _manage_ptg_policy_rule_sets(
            self, ptg_context, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        context = ptg_context
        plugin_context = context._plugin_context
        ptg = context.current
        ptg_params = []

        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        mapped_tenant = self._tenant_by_sharing_policy(ptg)
        mapped_ptg = self.name_mapper.policy_target_group(plugin_context, ptg)
        ptg_params.append((mapped_tenant, mapped_ptg))
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_epg,
                   self.apic_manager.unset_contract_for_epg]

        for x in xrange(len(provided)):
            for c in self.gbp_plugin.get_policy_rule_sets(
                    plugin_context, filters={'id': provided[x]}):
                c_owner = self._tenant_by_sharing_policy(c)
                c = self.name_mapper.policy_rule_set(plugin_context, c)
                for params in ptg_params:
                    methods[x](params[0], params[1], c, provider=True,
                               contract_owner=c_owner, transaction=None)
        for x in xrange(len(consumed)):
            for c in self.gbp_plugin.get_policy_rule_sets(
                    plugin_context, filters={'id': consumed[x]}):
                c_owner = self._tenant_by_sharing_policy(c)
                c = self.name_mapper.policy_rule_set(plugin_context, c)
                for params in ptg_params:
                    methods[x](params[0], params[1], c, provider=False,
                               contract_owner=c_owner, transaction=None)

    def _manage_ep_policy_rule_sets(
            self, plugin_context, es, ep, added_provided, added_consumed,
            removed_provided, removed_consumed, l3policy_obj=None,
            transaction=None):

        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warn(_("External Segment %s is not managed by APIC "
                     "mapping driver.") % es['id'])
            return
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        is_shadow = bool(l3policy_obj)
        mapped_tenant = self._get_tenant_for_shadow(is_shadow, l3policy_obj,
                                                    es)
        pfx = self._get_shadow_prefix(plugin_context, is_shadow, l3policy_obj)
        mapped_es = self.name_mapper.external_segment(plugin_context, es,
                                                      prefix=pfx)
        mapped_ep = self.name_mapper.external_policy(plugin_context, ep,
                                                     prefix=pfx)
        provided = [added_provided, removed_provided]
        consumed = [added_consumed, removed_consumed]
        methods = [self.apic_manager.set_contract_for_external_epg,
                   self.apic_manager.unset_contract_for_external_epg]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(provided)):
                for c in self._get_policy_rule_sets(plugin_context,
                                                    {'id': provided[x]}):
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=True,
                               transaction=trs)
            for x in xrange(len(consumed)):
                for c in self._get_policy_rule_sets(plugin_context,
                                                    {'id': consumed[x]}):
                    c = self.name_mapper.policy_rule_set(plugin_context, c)
                    methods[x](mapped_es, c, external_epg=mapped_ep,
                               owner=mapped_tenant, provided=False,
                               transaction=trs)

    def _manage_l2p_subnets(self, plugin_context, l2p_id, added_subnets,
                            removed_subnets, transaction=None):
        # TODO(ivar): change APICAPI to not expect a resource context
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context
        l2_policy_object = self.gbp_plugin.get_l2_policy(
            plugin_context, l2p_id)
        mapped_tenant = self._tenant_by_sharing_policy(l2_policy_object)
        mapped_l2p = self.name_mapper.l2_policy(plugin_context,
                                                l2_policy_object)
        subnets = [added_subnets, removed_subnets]
        methods = [self.apic_manager.ensure_subnet_created_on_apic,
                   self.apic_manager.ensure_subnet_deleted_on_apic]
        with self.apic_manager.apic.transaction(transaction) as trs:
            for x in xrange(len(subnets)):
                for s in subnets[x]:
                    methods[x](mapped_tenant, mapped_l2p, self._gateway_ip(s),
                               transaction=trs)

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

    def _port_to_ptg_network(self, context, port_id):
        ptg = self._port_id_to_ptg(context, port_id)
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
        for l2p in l2ps:
            if l2p['network_id'] == network_id:
                return l2p

    def _subnet_to_ptg(self, context, subnet_id):
        ptg = (context.session.query(gpdb.PolicyTargetGroupMapping).
               join(gpdb.PolicyTargetGroupMapping.subnets).
               filter(gpdb.PTGToSubnetAssociation.subnet_id ==
                      subnet_id).
               first())
        if ptg:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_group_dict(ptg)

    def _plug_l3p_to_es(self, context, es, is_shadow=False):
        l3_policy = (is_shadow and
            self.name_mapper.l3_policy(context, context.current)
            or self._get_nat_vrf_for_es(context, es))
        external_segments = context.current['external_segments']
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warn(UNMANAGED_SEGMENT % es['id'])
            return
        ip = external_segments[es['id']]
        if ip and ip[0]:
            ip = ip[0]
            exposed = ip + '/' + es['cidr'].split('/')[1]
        else:
            ip = getattr(context, 'assigned_router_ips', {}).get(es['id'], [])
            if ip and ip[0]:
                ip = ip[0]
            else:
                ip = ext_info.get('cidr_exposed', '/').split('/')[0]
            exposed = ext_info.get('cidr_exposed')

        if not ip:
            raise NoAddressConfiguredOnExternalSegment(
                l3p_id=context.current['id'], es_id=es['id'])
        context.set_external_fixed_ips(es['id'], [ip])
        encap = ext_info.get('encap')  # No encap if None
        switch = ext_info['switch']
        module, sport = ext_info['port'].split('/')
        router_id = ext_info['router_id']
        default_gateway = ext_info['gateway_ip']
        es_name = self.name_mapper.external_segment(context, es,
            prefix=self._get_shadow_prefix(context,
                is_shadow, context.current))
        es_tenant = self._get_tenant_for_shadow(is_shadow, context.current, es)
        with self.apic_manager.apic.transaction() as trs:
            # Create External Routed Network connected to the proper
            # L3 Context
            self.apic_manager.ensure_external_routed_network_created(
                es_name, owner=es_tenant, context=l3_policy,
                transaction=trs)
            if not is_shadow:
                self.apic_manager.ensure_logical_node_profile_created(
                    es_name, switch, module, sport, encap,
                    exposed, owner=es_tenant,
                    router_id=router_id, transaction=trs)
                for route in es['external_routes']:
                    self.apic_manager.ensure_static_route_created(
                        es_name, switch, route['nexthop'] or default_gateway,
                        owner=es_tenant,
                        subnet=route['destination'], transaction=trs)
        if not is_shadow:
            # create shadow external-networks
            self._plug_l3p_to_es(context, es, True)
            # create shadow external EPGs indirectly by re-plugging
            # external policies to external segment
            eps = context._plugin.get_external_policies(
                context._plugin_context,
                filters={'id': es['external_policies']})
            for ep in eps:
                self._plug_externa_policy_to_segment(context, ep,
                    [es['id']], ep['provided_policy_rule_sets'],
                    ep['consumed_policy_rule_sets'])

    def _unplug_l3p_from_es(self, context, es, is_shadow=False):
        es_name = self.name_mapper.external_segment(context, es,
            prefix=self._get_shadow_prefix(context,
                is_shadow, context.current))
        es_tenant = self._get_tenant_for_shadow(is_shadow, context.current, es)
        # remove shadow external-networks
        if not is_shadow:
            self._unplug_l3p_from_es(context, es, True)
        if (is_shadow or
            not [x for x in es['l3_policies'] if x != context.current['id']]):
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
                                        provided_prs, consumed_prs,
                                        l3policy_obj=None):
        is_shadow = bool(l3policy_obj)
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(context, ep,
                prefix=self._get_shadow_prefix(context,
                    is_shadow, l3policy_obj))
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(UNMANAGED_SEGMENT % es['id'])
                    continue
                es_name = self.name_mapper.external_segment(context,
                    es, prefix=self._get_shadow_prefix(
                        context, is_shadow, l3policy_obj))
                es_tenant = self._get_tenant_for_shadow(is_shadow,
                    l3policy_obj, es)
                with self.apic_manager.apic.transaction() as trs:
                    # Create External EPG
                    subnets = set(x['destination'] for
                                  x in es['external_routes'])
                    for s in subnets:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=s, external_epg=ep_name,
                            owner=es_tenant, transaction=trs)
                    if is_shadow:
                        # Shadow external EPGs provide and consume user
                        # specified contracts
                        self._manage_ep_policy_rule_sets(
                            context._plugin_context, es, ep,
                            provided_prs, consumed_prs, [], [],
                            l3policy_obj=l3policy_obj, transaction=trs)
                        # set up link to NAT EPG
                        self.apic_manager.associate_external_epg_to_nat_epg(
                            es_tenant, es_name, ep_name,
                            self._get_nat_epg_for_es(context, es),
                            target_owner=self._tenant_by_sharing_policy(es),
                            transaction=trs)
                    else:
                        # 'real' external EPGs provide and consume
                        # allow-all contract
                        self.apic_manager.set_contract_for_external_epg(
                            es_name, self._get_allow_all_contract_name(),
                            external_epg=ep_name, owner=es_tenant,
                            provided=True, transaction=trs)
                        self.apic_manager.set_contract_for_external_epg(
                            es_name, self._get_allow_all_contract_name(),
                            external_epg=ep_name, owner=es_tenant,
                            provided=False, transaction=trs)

                # create shadow external epgs in L3policies associated
                # with the segment
                if not is_shadow:
                    l3ps = context._plugin.get_l3_policies(
                        context._plugin_context,
                        filters={'id': es['l3_policies']})
                    for l3p in l3ps:
                        self._plug_externa_policy_to_segment(context, ep,
                            [es['id']], provided_prs, consumed_prs,
                            l3policy_obj=l3p)

    def _unplug_external_policy_from_segment(self, context, ep, segments,
                                             l3policy_obj=None):
        is_shadow = bool(l3policy_obj)
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            ep_name = self.name_mapper.external_policy(context, ep,
                prefix=self._get_shadow_prefix(context,
                    is_shadow, l3policy_obj))
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warn(UNMANAGED_SEGMENT % es['id'])
                    continue
                # remove the shadow external EPGs from L3policies
                # associated with the segment
                if not is_shadow:
                    l3ps = context._plugin.get_l3_policies(
                        context._plugin_context,
                        filters={'id': es['l3_policies']})
                    for l3p in l3ps:
                        self._unplug_external_policy_from_segment(context, ep,
                            [es['id']], l3policy_obj=l3p)

                es_name = self.name_mapper.external_segment(context, es,
                    prefix=self._get_shadow_prefix(context,
                        is_shadow, l3policy_obj))
                es_tenant = self._get_tenant_for_shadow(is_shadow,
                    l3policy_obj, es)
                self.apic_manager.ensure_external_epg_deleted(
                        es_name, external_epg=ep_name, owner=es_tenant)

    def _do_external_segment_update(self, context, ext_info,
                                    l3policy_obj=None):
        is_shadow = bool(l3policy_obj)
        es = context.current
        new_routes_dict = self._build_routes_dict(es['external_routes'])
        new_routes = set((x['destination'], x['nexthop'])
                         for x in context.current['external_routes'])
        old_routes = set((x['destination'], x['nexthop'])
                         for x in context.original['external_routes'])
        added = new_routes - old_routes
        removed = old_routes - new_routes
        switch = ext_info['switch']
        default_gateway = ext_info['gateway_ip']

        pfx = self._get_shadow_prefix(context, is_shadow, l3policy_obj)
        es_name = self.name_mapper.external_segment(context, es,
                                                    prefix=pfx)
        es_tenant = self._get_tenant_for_shadow(is_shadow, l3policy_obj, es)
        ep_names = [self.name_mapper.external_policy(
            context, self._get_external_policy(
                context._plugin_context.elevated(), x), prefix=pfx)
            for x in es['external_policies']]

        nexthop = lambda h: h if h else default_gateway
        with self.apic_manager.apic.transaction() as trs:
            for route in removed:
                if route[0] not in new_routes_dict:
                    # Remove Route completely
                    if not is_shadow:
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
                if not is_shadow:
                    self.apic_manager.ensure_static_route_created(
                        es_name, switch, nexthop(route[1]),
                        owner=es_tenant, subnet=route[0], transaction=trs)
                # And on the External EPGs
                for ep in ep_names:
                    self.apic_manager.ensure_external_epg_created(
                        es_name, subnet=route[0], external_epg=ep,
                        owner=es_tenant, transaction=trs)
        # Update the shadow external-segments
        if not is_shadow:
            l3ps = context._plugin.get_l3_policies(context._plugin_context,
                filters={'id': es['l3_policies']})
            for l3p in l3ps:
                self._do_external_segment_update(context, ext_info,
                                                 l3policy_obj=l3p)

    def _check_l3p_es(self, context):
        l3p = context.current
        if l3p['external_segments']:
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
        if object.get('shared') and not self.name_mapper._is_apic_reference(
                object):
            return apic_manager.TENANT_COMMON
        else:
            return self.name_mapper.tenant(object)

    def _get_nat_epg_for_es(self, context, es):
        return ("NAT-epg-%s" %
            self.name_mapper.external_segment(context, es))

    def _get_nat_bd_for_es(self, context, es):
        return ("NAT-bd-%s" %
            self.name_mapper.external_segment(context, es))

    def _get_nat_vrf_for_es(self, context, es):
        return ("NAT-vrf-%s" %
            self.name_mapper.external_segment(context, es))

    def _get_allow_all_contract_name(self):
        return "NAT-allow-all"

    def _get_shadow_prefix(self, context, is_shadow, l3_obj):
        return (is_shadow and
            ('%s%s-' % (SHADOW_PREFIX,
                str(self.name_mapper.l3_policy(context, l3_obj))))
            or '')

    def _get_tenant_for_shadow(self, is_shadow, shadow_obj, obj):
        return self._tenant_by_sharing_policy(
            shadow_obj if is_shadow else obj)

    def _notify_port_update(self, plugin_context, port_id):
        try:
            port = self._core_plugin.get_port(plugin_context, port_id)
            if self._is_port_bound(port):
                self.notifier.port_update(plugin_context, port)
        except n_exc.PortNotFound:
            # Notification not needed
            pass

    def _get_port_network_type(self, context, port):
        try:
            network = self._core_plugin.get_network(context,
                                                    port['network_id'])
            return network['provider:network_type']
        except n_exc.NetworkNotFound:
            pass

    def _is_apic_network_type(self, context, port):
        return (self._get_port_network_type(context, port) ==
                ofcst.TYPE_OPFLEX)

    def _is_port_bound(self, port):
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _use_implicit_subnet(self, context, force_add=False):
        """Implicit subnet for APIC driver.

        The first PTG of a given BD will allocate a new subnet from the L3P.
        Any subsequent PTG in the same BD will use the same subnet.
        More subnets will be allocated whenever the existing ones go out of
        addresses.
        """
        l2p_id = context.current['l2_policy_id']
        with lockutils.lock(l2p_id, external=True):
            subs = self._get_l2p_subnets(context._plugin_context, l2p_id)
            subs = set([x['id'] for x in subs])
            added = None
            if not subs or force_add:
                l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                    l2p_id)
                added = super(
                    ApicMappingDriver, self)._use_implicit_subnet(
                        context, mark_as_owned=False,
                        subnet_specifics={'name': APIC_OWNED + l2p['name']})
                subs.add(added['id'])
            context.add_subnets(subs - set(context.current['subnets']))
            if added:
                self.process_subnet_added(context._plugin_context, added)
                l3p_id = l2p['l3_policy_id']
                l3p = context._plugin.get_l3_policy(context._plugin_context,
                                                    l3p_id)
                for router_id in l3p['routers']:
                    # Use admin context because router and subnet may
                    # be in different tenants
                    self._plug_router_to_subnet(nctx.get_admin_context(),
                                                added['id'], router_id)

    def _sync_epg_subnets(self, plugin_context, l2p):
        l2p_subnets = [x['id'] for x in
                       self._get_l2p_subnets(plugin_context, l2p['id'])]
        epgs = self.gbp_plugin.get_policy_target_groups(
            nctx.get_admin_context(), {'l2_policy_id': [l2p['id']]})
        for sub in l2p_subnets:
            # Add to EPG
            for epg in epgs:
                if sub not in epg['subnets']:
                    try:
                        (self.gbp_plugin.
                         _add_subnet_to_policy_target_group(
                             nctx.get_admin_context(), epg['id'], sub))
                    except gpolicy.PolicyTargetGroupNotFound as e:
                        LOG.warn(e)

    def _get_l2p_subnets(self, plugin_context, l2p_id):
        l2p = self.gbp_plugin.get_l2_policy(plugin_context, l2p_id)
        return self._core_plugin.get_subnets(
            plugin_context, {'network_id': [l2p['network_id']]})

    def _configure_implicit_contract(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            # Create Service contract
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=IMPLICIT_PREFIX)
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)

            # Create ARP filter/subject
            attrs = {'etherT': 'arp'}
            self._associate_service_filter(tenant, contract, 'arp',
                                           'arp', transaction=trs, **attrs)

    def _configure_shadow_epg(self, context, l2p, bd_name, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            shadow_epg = self.name_mapper.l2_policy(
                context, l2p, prefix=SHADOW_PREFIX)
            self.apic_manager.ensure_epg_created(
                tenant, shadow_epg, bd_owner=tenant, bd_name=bd_name,
                transaction=trs)

            # Create Service contract
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=SERVICE_PREFIX)
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)

            # Shadow EPG provides this contract
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=True,
                contract_owner=tenant, transaction=trs)

            # Create DNS filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 'dns',
                     'dFromPort': 'dns'}
            self._associate_service_filter(tenant, contract, 'dns',
                                           'dns', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'sToPort': 'dns',
                     'sFromPort': 'dns'}
            self._associate_service_filter(tenant, contract, 'dns',
                                           'r-dns', transaction=trs, **attrs)

            # Create HTTP filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'tcp',
                     'dToPort': 80,
                     'dFromPort': 80}
            self._associate_service_filter(tenant, contract, 'http',
                                           'http', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'tcp',
                     'sToPort': 80,
                     'sFromPort': 80}
            self._associate_service_filter(tenant, contract, 'http',
                                           'r-http', transaction=trs, **attrs)

            attrs = {'etherT': 'ip',
                     'prot': 'icmp'}
            self._associate_service_filter(tenant, contract, 'icmp',
                                           'icmp', transaction=trs, **attrs)

            # Create DHCP filter/subject
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 68,
                     'dFromPort': 68,
                     'sToPort': 67,
                     'sFromPort': 67}
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'dhcp', transaction=trs, **attrs)
            attrs = {'etherT': 'ip',
                     'prot': 'udp',
                     'dToPort': 67,
                     'dFromPort': 67,
                     'sToPort': 68,
                     'sFromPort': 68}
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'r-dhcp', transaction=trs, **attrs)

            # Create ARP filter/subject
            attrs = {'etherT': 'arp'}
            self._associate_service_filter(tenant, contract, 'arp',
                                           'arp', transaction=trs, **attrs)

            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=IMPLICIT_PREFIX)
            # Shadow EPG provides and consumes implicit contract
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=False,
                contract_owner=tenant, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=True,
                contract_owner=tenant, transaction=trs)

    def _associate_service_filter(self, tenant, contract, filter_name,
                                  entry_name, transaction=None, **attrs):
        with self.apic_manager.apic.transaction(transaction) as trs:
            filter_name = '%s-%s' % (str(self.apic_manager.app_profile_name),
                                     filter_name)
            self.apic_manager.create_tenant_filter(
                filter_name, owner=tenant, entry=entry_name,
                transaction=trs, **attrs)
            self.apic_manager.manage_contract_subject_bi_filter(
                contract, contract, filter_name, owner=tenant,
                transaction=trs, rule_owner=tenant)

    def _delete_shadow_epg(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            shadow_epg = self.name_mapper.l2_policy(
                context, l2p, prefix=SHADOW_PREFIX)
            self.apic_manager.delete_epg_for_network(
                tenant, shadow_epg, transaction=trs)

            # Delete Service Contract
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=SERVICE_PREFIX)
            self.apic_manager.delete_contract(
                contract, owner=tenant, transaction=trs)

    def _delete_implicit_contract(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=IMPLICIT_PREFIX)
            self.apic_manager.delete_contract(
                contract, owner=tenant, transaction=trs)

    def _configure_epg_service_contract(self, context, ptg, l2p, epg_name,
                                        transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            contract_owner = self._tenant_by_sharing_policy(l2p)
            tenant = self._tenant_by_sharing_policy(ptg)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=SERVICE_PREFIX)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=False,
                contract_owner=contract_owner, transaction=trs)

    def _configure_epg_implicit_contract(self, context, ptg, l2p, epg_name,
                                         transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            contract_owner = self._tenant_by_sharing_policy(l2p)
            tenant = self._tenant_by_sharing_policy(ptg)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=IMPLICIT_PREFIX)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=False,
                contract_owner=contract_owner, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=True,
                contract_owner=contract_owner, transaction=trs)

    def _get_redirect_action(self, context, policy_rule):
        for action in context._plugin.get_policy_actions(
                context._plugin_context,
                filters={'id': policy_rule['policy_actions']}):
            if action['action_type'] == g_const.GP_ACTION_REDIRECT:
                return action

    def _validate_new_prs_redirect(self, context, prs):
        if self._prss_redirect_rules(context._plugin_context.session,
                                     [prs['id']]) > 1:
            raise gpexc.MultipleRedirectActionsNotSupportedForPRS()

    def _prss_redirect_rules(self, session, prs_ids):
        if len(prs_ids) == 0:
            # No result will be found in this case
            return 0
        query = (session.query(gpdb.gpdb.PolicyAction).
                 join(gpdb.gpdb.PolicyRuleActionAssociation).
                 join(gpdb.gpdb.PolicyRule).
                 join(gpdb.gpdb.PRSToPRAssociation).
                 filter(
                 gpdb.gpdb.PRSToPRAssociation.policy_rule_set_id.in_(prs_ids)).
                 filter(gpdb.gpdb.PolicyAction.action_type ==
                        g_const.GP_ACTION_REDIRECT))
        return query.count()

    def _multiple_pr_redirect_action_number(self, session, pr_ids):
        # Given a set of rules, gives the total number of redirect actions
        # found
        if len(pr_ids) == 0:
            # No result will be found in this case
            return 0
        return (session.query(gpdb.gpdb.PolicyAction).
                join(gpdb.gpdb.PolicyRuleActionAssociation).
                filter(
                gpdb.gpdb.PolicyRuleActionAssociation.policy_rule_id.in_(
                    pr_ids)).
                filter(gpdb.gpdb.PolicyAction.action_type ==
                       g_const.GP_ACTION_REDIRECT)).count()

    def _check_es_subnet(self, context, es):
        if es['subnet_id']:
            subnet = self._get_subnet(context._plugin_context,
                                      es['subnet_id'])
            network = self._get_network(context._plugin_context,
                                        subnet['network_id'])
            if not network['router:external']:
                raise gpexc.InvalidSubnetForES(sub_id=subnet['id'],
                                               net_id=network['id'])

    def _use_implicit_external_subnet(self, context, es, ext_info):
        # create external-network if required
        ext_net_name = "%s%s-%s" % (APIC_OWNED, es['name'], es['id'])
        networks = self._get_networks(context._plugin_context,
            filters={'name': [ext_net_name],
                     'tenant_id': [es['tenant_id']]})
        if networks:
            extnet = networks[0]
        else:
            attrs = {'tenant_id': es['tenant_id'],
                     'name': ext_net_name,
                     'admin_state_up': True,
                     'router:external': True,
                     'provider:physical_network': ext_net_name,
                     'provider:network_type': 'flat',
                     'shared': es.get('shared', False)}
            extnet = self._create_network(context._plugin_context, attrs)

        # create subnet in external-network
        sn_name = "%s%s-%s" % (APIC_OWNED, es['name'], es['id'])
        subnets = self._get_subnets(context._plugin_context,
            filters={'name': [sn_name],
                     'network_id': [extnet['id']]})
        if subnets:
            subnet = subnets[0]
        else:
            attrs = {'tenant_id': es['tenant_id'],
                     'name': sn_name,
                     'network_id': extnet['id'],
                     'ip_version': es['ip_version'],
                     'cidr': es['cidr'],
                     'enable_dhcp': False,
                     'gateway_ip': ext_info['gateway_ip'],
                     'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                     'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                     'host_routes': attributes.ATTR_NOT_SPECIFIED}
            subnet = self._create_subnet(context._plugin_context, attrs)
        return subnet

    def _delete_implicit_external_subnet(self, context, es):
        if not es['subnet_id']:
            return
        subnet = self._get_subnet(context._plugin_context, es['subnet_id'])
        network = self._get_network(context._plugin_context,
                                    subnet['network_id'])
        if subnet['name'].startswith(APIC_OWNED):
            self._delete_subnet(context._plugin_context, subnet['id'])
        if (network['name'].startswith(APIC_OWNED) and
            not [x for x in network['subnets'] if x != subnet['id']]):
            self._delete_network(context._plugin_context, network['id'])

    def _get_router_ext_subnet_for_l3p(self, context, l3policy):
        """ Get dict of external-subnets to the routers of l3 policy """
        rtr_sn = {}
        routers = self._get_routers(context._plugin_context,
                                    {'id': l3policy['routers']})
        for r in routers:
            if (not r['external_gateway_info'] or
                not r['external_gateway_info']['external_fixed_ips']):
                continue
            for ip in r['external_gateway_info']['external_fixed_ips']:
                rtr_sn[ip['subnet_id']] = r['id']
        return rtr_sn

    def _create_and_plug_router_to_es(self, context, es_dict):
        l3p = context.current
        sub_r_dict = self._get_router_ext_subnet_for_l3p(context, l3p)

        l2p_sn_ids = set()
        for l2p_id in l3p['l2_policies']:
            l2p_sn_ids.update([x['id'] for x in
                self._get_l2p_subnets(context._plugin_context, l2p_id)])

        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_dict.keys()})
        assigned_ips = {}
        for es in es_list:
            if not es['subnet_id']:
                continue
            router_id = sub_r_dict.get(es['subnet_id'])
            if router_id:   # router connecting to ES's subnet exists
                router = self._get_router(context._plugin_context, router_id)
            else:
                router_id = self._use_implicit_router(context,
                    l3p['name'] + '-' + es['name'])
                router = self._create_router_gw_for_external_segment(
                    context._plugin_context, es, es_dict, router_id)
            if not es_dict[es['id']] or not es_dict[es['id']][0]:
                # Update L3P assigned address
                efi = router['external_gateway_info']['external_fixed_ips']
                rtr_ips = [x['ip_address'] for x in efi
                           if x['subnet_id'] == es['subnet_id']]
                assigned_ips[es['id']] = rtr_ips
            # Use admin context because router and subnet may
            # be in different tenants
            self._attach_router_to_subnets(nctx.get_admin_context(),
                                           router_id, l2p_sn_ids)
        context.assigned_router_ips = assigned_ips

    def _cleanup_and_unplug_router_from_es(self, context, es_list):
        l3p = context.current
        sub_r_dict = self._get_router_ext_subnet_for_l3p(context, l3p)
        current_es = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': l3p['external_segments']})
        ext_sn_in_use = set([e['subnet_id'] for e in current_es])
        for es in es_list:
            if not es['subnet_id'] or es['subnet_id'] in ext_sn_in_use:
                continue
            router_id = sub_r_dict.get(es['subnet_id'])
            if not router_id:
                continue
            router_sn = self._get_router_interface_subnets(
                context._plugin_context, router_id)
            # Use admin context because router and subnet may be
            # in different tenants
            self._detach_router_from_subnets(nctx.get_admin_context(),
                                             router_id, router_sn)
            context.remove_router(router_id)
            self._cleanup_router(context._plugin_context, router_id)

    def _get_router_interface_subnets(self, plugin_context, router_id):
        router_ports = self._get_ports(plugin_context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'device_id': [router_id]})
        return set(y['subnet_id']
                   for x in router_ports for y in x['fixed_ips'])

    def _attach_router_to_subnets(self, plugin_context, router_id, sn_ids):
        rtr_sn = self._get_router_interface_subnets(plugin_context, router_id)
        for subnet_id in sn_ids:
            if subnet_id in rtr_sn:     # already attached
                continue
            self._plug_router_to_subnet(plugin_context, subnet_id, router_id)

    def _plug_router_to_subnet(self, plugin_context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        if router_id:
            try:
                self._add_router_interface(plugin_context, router_id,
                                           interface_info)
                return
            except n_exc.IpAddressInUse as e:
                LOG.debug(_("Will try to use create and use port - %s"), e)
            except n_exc.BadRequest:
                LOG.exception(_("Adding subnet to router failed"))
                return
            # Allocate port and use it as router interface
            subnet = self._get_subnet(plugin_context, subnet_id)
            attrs = {'tenant_id': subnet['tenant_id'],
                     'network_id': subnet['network_id'],
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': [{'subnet_id': subnet_id}],
                     'device_id': '',
                     'device_owner': '',
                     'name': "%s-%s" % (router_id, subnet_id),
                     'admin_state_up': True}
            port = self._create_port(plugin_context, attrs)
            interface_info = {'port_id': port['id']}
            try:
                self._add_router_interface(plugin_context, router_id,
                                           interface_info)
            except n_exc.BadRequest:
                self._delete_port(plugin_context, port['id'])
                LOG.exception(_("Adding subnet to router with "
                                "explicit port failed"))

    def _detach_router_from_subnets(self, plugin_context, router_id, sn_ids):
        for subnet_id in sn_ids:
            self._remove_router_interface(plugin_context, router_id,
                                          {'subnet_id': subnet_id})

    def _cleanup_router_interface(self, context, l2p):
        l3p = context._plugin.get_l3_policy(context._plugin_context,
                                            l2p['l3_policy_id'])
        network = self._get_network(context._plugin_context,
                                    l2p['network_id'])
        for router_id in l3p['routers']:
            router_sn = self._get_router_interface_subnets(
                context._plugin_context, router_id)
            router_sn.intersection_update(network['subnets'])
            # Use admin context because router and subnet may be
            # in different tenants
            self._detach_router_from_subnets(nctx.get_admin_context(),
                                             router_id, router_sn)

    def _create_nat_epg_for_es(self, context, es, ext_info, transaction=None):
        tenant_name = self._tenant_by_sharing_policy(es)
        nat_bd_name = self._get_nat_bd_for_es(context, es)
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.ensure_nat_epg_contract_created(
                tenant_name,
                self._get_nat_epg_for_es(context, es),
                nat_bd_name,
                self._get_nat_vrf_for_es(context, es),
                self._get_allow_all_contract_name(),
                transaction=trs)
            gw, plen = ext_info.get('host_pool_cidr', '/').split('/', 1)
            if gw and plen:
                self.apic_manager.ensure_subnet_created_on_apic(tenant_name,
                    nat_bd_name, gw + '/' + plen, transaction=trs)

    def _get_ports_in_l3policy(self, context, l3p):
        admin_ctx = nctx.get_admin_context()
        ptgs = context._plugin.get_policy_target_groups(
            admin_ctx, filters={'l2_policy_id': l3p['l2_policies']})
        pts = context._plugin.get_policy_targets(
            admin_ctx,
            filters={'policy_target_group_id': [g['id'] for g in ptgs]})
        return [pt['port_id'] for pt in pts]

    def _notify_port_update_in_l3policy(self, context, l3p):
        for port in self._get_ports_in_l3policy(context, l3p):
            self._notify_port_update(context._plugin_context, port)

    def _check_fip_in_use_in_es(self, context, l3p, ess_id):
        admin_ctx = nctx.get_admin_context()
        port_id = self._get_ports_in_l3policy(context, l3p)
        fips = self._get_fips(admin_ctx, filters={'port_id': port_id})
        fip_net = set([x['floating_network_id'] for x in fips])

        ess = context._plugin.get_external_segments(admin_ctx,
            filters={'id': list(ess_id)})
        sn_id = set([es['subnet_id'] for es in ess])
        subnet = self._get_subnets(admin_ctx,
            filters={'id': list(sn_id)})
        sn_net = set([sn['network_id'] for sn in subnet])
        if (fip_net & sn_net):
            raise FloatingIPFromExtSegmentInUse(l3p=l3p['name'])

    def _check_nat_pool_cidr(self, context, nat_pool):
        ext_info = None
        if nat_pool['external_segment_id']:
            es = context._plugin.get_external_segment(
                context._plugin_context, nat_pool['external_segment_id'])
            ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if ext_info:
            exposed = netaddr.IPSet([])
            if ext_info.get('cidr_exposed'):
                exposed.add(ext_info['cidr_exposed'])
            if ext_info.get('host_pool_cidr'):
                exposed.add(ext_info['host_pool_cidr'])
            np_ip_set = netaddr.IPSet([nat_pool['ip_pool']])
            if exposed & np_ip_set:
                raise NatPoolOverlapsApicSubnet(nat_pool_cidr=np_ip_set,
                                                es=es['name'])

    def _stash_es_subnet_for_nat_pool(self, context, nat_pool):
        if nat_pool['external_segment_id'] and nat_pool['subnet_id']:
            nat_pool['ext_seg'] = context._plugin.get_external_segment(
                context._plugin_context, nat_pool['external_segment_id'])
            nat_pool['subnet'] = self._get_subnet(
                context._plugin_context, nat_pool['subnet_id'])

    def _manage_nat_pool_subnet(self, context, old, new):
        if old and old.get('ext_seg') and old.get('subnet'):
            tenant_name = self._tenant_by_sharing_policy(old['ext_seg'])
            nat_bd_name = self._get_nat_bd_for_es(context, old['ext_seg'])
            self.apic_manager.ensure_subnet_deleted_on_apic(tenant_name,
                    nat_bd_name, self._gateway_ip(old['subnet']))

        if new and new.get('ext_seg') and new.get('subnet'):
            tenant_name = self._tenant_by_sharing_policy(new['ext_seg'])
            nat_bd_name = self._get_nat_bd_for_es(context, new['ext_seg'])
            self.apic_manager.ensure_subnet_created_on_apic(tenant_name,
                    nat_bd_name, self._gateway_ip(new['subnet']))

    def _reject_apic_name_change(self, context):
        if self.name_mapper._is_apic_reference(context.original):
            if context.original['name'] != context.current['name']:
                raise CannotUpdateApicName()