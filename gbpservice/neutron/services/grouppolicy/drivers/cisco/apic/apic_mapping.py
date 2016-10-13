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

import copy
import hashlib
import netaddr
import re

from apic_ml2.neutron.db import l3out_vlan_allocation as l3out_vlan_alloc
from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import apic_model
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config  # noqa
from apicapi import apic_manager
from apicapi import apic_mapper
from keystoneclient.auth.identity.generic import password as keypassword
from keystoneclient import client as keyclient
from keystoneclient import session as keysession
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.agent.linux import dhcp
from neutron.api.v2 import attributes
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.db import db_base_plugin_v2 as n_db
from neutron.db import model_base
from neutron.extensions import portbindings
from neutron.extensions import providernet
from neutron import manager
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as n_api
from neutron.plugins.ml2 import models as ml2_models
from neutron.plugins.ml2 import rpc as neu_rpc
from opflexagent import constants as ofcst
from opflexagent import rpc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
import sqlalchemy as sa

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    name_manager as name_manager)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)
from gbpservice.neutron.services.grouppolicy import group_policy_context
from gbpservice.neutron.services.grouppolicy import plugin as gbp_plugin


HOST_SNAT_POOL = 'host-snat-pool-for-internal-use'
HOST_SNAT_POOL_PORT = 'host-snat-pool-port-for-internal-use'
DEVICE_OWNER_SNAT_PORT = 'host-snat-pool-port-device-owner-internal-use'
n_db.AUTO_DELETE_PORT_OWNERS.append(DEVICE_OWNER_SNAT_PORT)

LOG = logging.getLogger(__name__)
UNMANAGED_SEGMENT = _("External Segment %s is not managed by APIC mapping "
                      "driver.")
PRE_EXISTING_SEGMENT = _("Pre-existing external segment %s not found.")
AUTO_PTG_NAME_PREFIX = 'auto-ptg-%s'
# Note that this prefix should not exceede 4 characters
AUTO_PTG_ID_PREFIX = 'auto%s'
AUTO_PTG_MUTABLE_KEYS = ['name', 'description', 'consumed_policy_rule_sets',
                         'provided_policy_rule_sets']

opts = [
    cfg.BoolOpt('create_auto_ptg',
                default=False,
                help=_("Automatically create a PTG when a L2 Policy "
                       "gets created. This is currently an apic_mapping "
                       "policy driver specific feature and may evolve "
                       "to be a broader GBP feature. As a part of the "
                       "evolution, new APIs may be added, the Auto PTG "
                       "naming, and ID format convention may change.")),
]

cfg.CONF.register_opts(opts, "apic_mapping")


class PolicyRuleUpdateNotSupportedOnApicDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule update is not supported on APIC GBP"
                "driver.")


class ExactlyOneActionPerRuleIsSupportedOnApicDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Exactly one action per rule is supported on APIC GBP driver.")


class OnlyOneL3PolicyIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one L3 Policy per ES is supported when NAT is disabled "
                "on the ES.")


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


class MultipleExternalPoliciesForL3Policy(gpexc.GroupPolicyBadRequest):
    message = _("Potential association of multiple external policies to "
                "an L3 Policy.")


class SharedExternalPolicyUnsupported(gpexc.GroupPolicyBadRequest):
    message = _("APIC mapping driver does not support sharing of "
                "external policies.")


class PreExistingL3OutNotFound(gpexc.GroupPolicyBadRequest):
    message = _("No applicable External Routed Network named %(l3out)s was "
                "found on APIC.")


class PreExistingL3OutInIncorrectTenant(gpexc.GroupPolicyBadRequest):
    message = _("APIC tenant '%(l3out_tenant)s' of existing External Routed "
                "Network '%(l3out)s' does not match the APIC tenant "
                "'%(es_tenant)s' to which external-segment '%(es)s' maps.")


class EdgeNatVlanRangeNotFound(gpexc.GroupPolicyBadRequest):
    message = _("No vlan range is specified for L3Out %(l3out)s "
                "when edge_nat is enabled.")


class EdgeNatBadVlanRange(gpexc.GroupPolicyBadRequest):
    message = _("Bad vlan range is specified for L3Out %(l3out)s "
                "when edge_nat is enabled.")


class EdgeNatWrongL3OutIFType(gpexc.GroupPolicyBadRequest):
    message = _("L3Out %(l3out)s can only support routed sub-interfaces and "
                "SVI in the interface profiles when edge_nat is enabled.")


class EdgeNatWrongL3OutAuthTypeForBGP(gpexc.GroupPolicyBadRequest):
    message = _("L3Out %(l3out)s can only support no authentication "
                "for BGP interface profile when edge_nat is enabled.")


class EdgeNatWrongL3OutAuthTypeForOSPF(gpexc.GroupPolicyBadRequest):
    message = _("L3Out %(l3out)s can only support no authentication "
                "for OSPF interface profile when edge_nat is enabled.")


class ExplicitPortInWrongNetwork(gpexc.GroupPolicyBadRequest):
    message = _('Explicit port %(port)s for PT %(pt)s is in '
                'wrong network %(net)s, expected %(exp_net)s')


class PTGChangeDisallowedWithNonOpFlexNetwork(gpexc.GroupPolicyBadRequest):
    message = _('Policy target group for policy target cannot be changed '
                'when using network of type other than %(net_type)s')


class ExplicitPortOverlap(gpexc.GroupPolicyBadRequest):
    message = _('Explicit port %(port)s, MAC address %(mac)s, IP address '
                '%(ip)s has overlapping IP or MAC address with another port '
                'in network %(net)s')


class AdminOnlyOperation(gpexc.GroupPolicyBadRequest):
    message = _("This operation is reserved to admins")


class AutoPTGAttrsUpdateNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Update of attributes: %(attrs)s for auto PTG "
                "%(id)s not supported.")


class AutoPTGDeleteNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Auto PTG %(id)s cannot be deleted.")


class TenantSpecificNatEpg(model_base.BASEV2):
    """Tenants that use a specific NAT EPG for an external segment."""
    __tablename__ = 'gp_apic_tenant_specific_nat_epg'
    external_segment_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_external_segments.id',
                                     ondelete='CASCADE'),
        primary_key=True)
    tenant_id = sa.Column(sa.String(36), primary_key=True)


SHADOW_PREFIX = 'Shd-'
AUTO_PREFIX = 'Auto-'
ANY_PREFIX = 'any-'
PROMISCUOUS_SUFFIX = 'promiscuous'
APIC_OWNED = 'apic_owned_'
APIC_OWNED_RES = 'apic_owned_res_'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
PROXY_PORT_PREFIX = "opflex_proxy:"
EOC_PREFIX = "opflex_eoc:"


class ApicMappingDriver(api.ResourceMappingDriver,
                        ha_ip_db.HAIPOwnerDbMixin):
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
            if cfg.CONF.apic.apic_username is not None:
                apic_config = cfg.CONF.apic
            else:
                apic_config = cfg.CONF.ml2_cisco_apic
            network_config = {
                'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
                'vni_ranges': cfg.CONF.ml2_type_vxlan.vni_ranges,
            }
            apic_system_id = cfg.CONF.apic_system_id
            keyclient_param = keyclient if client else None
            keystone_authtoken = None
            session = None
            if client:
                keystone_authtoken = cfg.CONF.keystone_authtoken
                pass_params = (
                    apic_mapper.APICNameMapper.get_key_password_params(
                        keystone_authtoken))
                admin_auth = keypassword.Password(
                    auth_url=pass_params[0],
                    username=pass_params[1], password=pass_params[2],
                    tenant_name=pass_params[3],
                    user_domain_id='Default', project_domain_id='Default')
                session = keysession.Session(auth=admin_auth)
            ApicMappingDriver.manager = apic_manager.APICManager(
                apic_model.ApicDbModel(), logging, network_config, apic_config,
                keyclient_param, keystone_authtoken, apic_system_id,
                default_apic_model=('apic_ml2.neutron.plugins.ml2.drivers.'
                                    'cisco.apic.apic_model'),
                keysession=session)
            ApicMappingDriver.manager.ensure_infra_created_on_apic()
            ApicMappingDriver.manager.ensure_bgp_pod_policy_created_on_apic()
        return ApicMappingDriver.manager

    def initialize(self):
        super(ApicMappingDriver, self).initialize()
        self._setup_rpc()
        self._setup_rpc_listeners()
        self.apic_manager = ApicMappingDriver.get_apic_manager()
        self.name_mapper = name_manager.ApicNameManager(self.apic_manager)
        self.enable_dhcp_opt = self.apic_manager.enable_optimized_dhcp
        self.enable_metadata_opt = self.apic_manager.enable_optimized_metadata
        self.nat_enabled = self.apic_manager.use_vmm
        self.per_tenant_nat_epg = self.apic_manager.per_tenant_nat_epg
        self._gbp_plugin = None
        self._apic_segmentation_label_driver = None
        self.l3out_vlan_alloc = l3out_vlan_alloc.L3outVlanAlloc()
        self.l3out_vlan_alloc.sync_vlan_allocations(
            self.apic_manager.ext_net_dict)
        self.create_auto_ptg = cfg.CONF.apic_mapping.create_auto_ptg
        if self.create_auto_ptg:
            LOG.info(_LI('Auto PTG creation configuration set, '
                         'this will result in automatic creation of a PTG '
                         'per L2 Policy'))

    def _setup_rpc_listeners(self):
        self.endpoints = [rpc.GBPServerRpcCallback(self, self.notifier)]
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

    @property
    def apic_segmentation_label_driver(self):
        if not self._apic_segmentation_label_driver:
            ext_drivers = self.gbp_plugin.extension_manager.ordered_ext_drivers
            for driver in ext_drivers:
                if 'apic_segmentation_label' == driver.name:
                    self._apic_segmentation_label_driver = (
                        driver.obj)
                    break
        return self._apic_segmentation_label_driver

    # HA RPC call
    def update_ip_owner(self, ip_owner_info):
        # Needs to handle proxy ports
        context = nctx.get_admin_context()
        port_id = ip_owner_info.get('port')
        if port_id:
            ptg, pt = self._port_id_to_ptg(context, port_id)
            if pt and pt['description'].startswith(PROXY_PORT_PREFIX):
                new_id = pt['description'].replace(PROXY_PORT_PREFIX,
                                                   '').rstrip(' ')
                try:
                    LOG.debug("Replace port %s with port %s", port_id,
                              new_id)
                    port = self._get_port(context, new_id)
                    ip_owner_info['port'] = port['id']
                except n_exc.PortNotFound:
                    LOG.warning(_LW("Proxied port %s could not be found"),
                                new_id)
        return super(ApicMappingDriver, self).update_ip_owner(ip_owner_info)

    # RPC Method
    def get_vrf_details(self, context, **kwargs):
        details = {'l3_policy_id': kwargs['vrf_id']}
        self._add_vrf_details(context, details)
        return details

    def request_vrf_details(self, context, **kwargs):
        return self.get_vrf_details(context, **kwargs)

    # RPC Method
    def _get_gbp_details(self, context, **kwargs):
        port_id = self._core_plugin._device_to_port_id(
            context, kwargs['device'])
        port_context = self._core_plugin.get_bound_port_context(
            context, port_id, kwargs['host'])
        if not port_context:
            LOG.warning(_LW("Device %(device)s requested by agent "
                            "%(agent_id)s not found in database"),
                        {'device': port_id,
                         'agent_id': kwargs.get('agent_id')})
            return {'device': kwargs.get('device')}
        port = port_context.current
        # retrieve PTG from a given Port
        ptg, pt = self._port_id_to_ptg(context, port['id'])
        context._plugin = self.gbp_plugin
        context._plugin_context = context
        switched = False
        if pt and pt['description'].startswith(PROXY_PORT_PREFIX):
            new_id = pt['description'].replace(
                PROXY_PORT_PREFIX, '').rstrip(' ')
            try:
                LOG.debug("Replace port %s with port %s", port_id, new_id)
                port = self._get_port(context, new_id)
                ptg, pt = self._port_id_to_ptg(context, port['id'])
                switched = True
            except n_exc.PortNotFound:
                LOG.warning(_LW("Proxied port %s could not be found"),
                            new_id)

        l2p = self._network_id_to_l2p(context, port['network_id'])
        if not l2p and self._ptg_needs_shadow_network(context, ptg):
            l2p = self._get_l2_policy(context._plugin_context,
                                      ptg['l2_policy_id'])
        if not ptg and not l2p:
            return None

        l2_policy_id = l2p['id']
        if ptg:
            ptg_tenant = self._tenant_by_sharing_policy(ptg)
            endpoint_group_name = self.name_mapper.policy_target_group(
                context, ptg)
        else:
            ptg_tenant = self._tenant_by_sharing_policy(l2p)
            endpoint_group_name = self.name_mapper.l2_policy(
                context, l2p, prefix=SHADOW_PREFIX)

        def is_port_promiscuous(port):
            if (pt and pt.get('cluster_id') and
                    pt.get('cluster_id') != pt['id']):
                master = self._get_policy_target(context, pt['cluster_id'])
                if master.get('group_default_gateway'):
                    return True
            return (port['device_owner'] in PROMISCUOUS_TYPES or
                    port['name'].endswith(PROMISCUOUS_SUFFIX)) or (
                        pt and pt.get('group_default_gateway'))
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
                   'promiscuous_mode': is_port_promiscuous(port),
                   'extra_ips': [],
                   'floating_ip': [],
                   'ip_mapping': [],
                   # Put per mac-address extra info
                   'extra_details': {}}
        if switched:
            details['fixed_ips'] = port['fixed_ips']
        if port['device_owner'].startswith('compute:') and port[
                'device_id']:
            vm = nclient.NovaClient().get_server(port['device_id'])
            details['vm-name'] = vm.name if vm else port['device_id']
        l3_policy = context._plugin.get_l3_policy(context,
                                                  l2p['l3_policy_id'])
        own_addr = set()
        if pt:
            own_addr = set(self._get_owned_addresses(context,
                                                     pt['port_id']))
        own_addr |= set(self._get_owned_addresses(context, port_id))
        (details['floating_ip'], details['ip_mapping'],
            details['host_snat_ips']) = (
                self._get_ip_mapping_details(
                    context, port['id'], l3_policy, pt=pt,
                    owned_addresses=own_addr, host=kwargs['host']))
        self._add_network_details(context, port, details, pt=pt,
                                  owned=own_addr, inject_default_route=
                                  l2p['inject_default_route'])
        self._add_vrf_details(context, details)
        if self._is_pt_chain_head(context, pt, ptg, owned_ips=own_addr,
                                  port_id=port_id):
            # is a relevant proxy_gateway, push all the addresses from this
            # chain to this PT
            extra_map = details
            master_port = self._is_master_owner(context, pt,
                                                owned_ips=own_addr)
            if master_port:
                extra_map = details['extra_details'].setdefault(
                    master_port['mac_address'],
                    {'extra_ips': [], 'floating_ip': [],
                     'ip_mapping': [], 'host_snat_ips': []})
            if bool(master_port) == bool(pt['cluster_id']):
                l3_policy = context._plugin.get_l3_policy(
                    context, l2p['l3_policy_id'])
                proxied_ptgs = []
                while ptg.get('proxied_group_id'):
                    proxied = self.gbp_plugin.get_policy_target_group(
                        context, ptg['proxied_group_id'])
                    proxied_ptgs.append(proxied)
                    ptg = proxied
                # Retrieve PTGs explicitly proxied
                descriptions = [EOC_PREFIX + port_id]
                if master_port:
                    # Also retrieve groups proxied by master of the cluster
                    descriptions.append(EOC_PREFIX + master_port['id'])
                proxied_ptgs.extend(
                    self._get_policy_target_groups(
                        context, filters={'description': descriptions}))
                for proxied in proxied_ptgs:
                    for port in self._get_ptg_ports(proxied):
                        extra_map['extra_ips'].extend(
                            [x['ip_address'] for x in port['fixed_ips'] +
                             port.get('allowed_address_pairs', [])])
                        (fips, ipms, host_snat_ips) = (
                            self._get_ip_mapping_details(
                                context, port['id'], l3_policy,
                                host=kwargs['host']))
                        extra_map['floating_ip'].extend(fips)
                        if not extra_map['ip_mapping']:
                            extra_map['ip_mapping'].extend(ipms)
                        if not extra_map['host_snat_ips']:
                            extra_map['host_snat_ips'].extend(
                                host_snat_ips)
            else:
                LOG.info(_LI("Active master has changed for PT %s"),
                         pt['id'])
                # There's no master mac even if a cluster_id is set.
                # Active chain head must have changed in a concurrent
                # operation, get out of here
                pass
        if self.apic_segmentation_label_driver and pt and (
            'segmentation_labels' in pt):
            details['segmentation_labels'] = pt['segmentation_labels']
        return details

    def get_snat_ip_for_vrf(self, context, vrf_id, network, es_name=None):
        """Allocate SNAT IP for a VRF for an external network."""
        # This API supports getting SNAT IPs per VRF and populating
        # the dictionary eithe rwith the network name, or the name
        # of the external segment
        if es_name is None:
            es_name = network.get('name')
        return self._allocate_snat_ip(context, vrf_id, network, es_name)

    # RPC Method
    def get_gbp_details(self, context, **kwargs):
        try:
            return self._get_gbp_details(context, **kwargs)
        except Exception as e:
            LOG.error(_LE(
                "An exception has occurred while retrieving device "
                "gbp details for %s"), kwargs.get('device'))
            LOG.exception(e)
            details = {'device': kwargs.get('device')}
        return details

    # RPC Method
    def request_endpoint_details(self, context, **kwargs):
        try:
            LOG.debug("Request GBP details: %s", kwargs)
            kwargs.update(kwargs['request'])
            result = {'device': kwargs['device'],
                      'timestamp': kwargs['timestamp'],
                      'request_id': kwargs['request_id'],
                      'gbp_details': None,
                      'neutron_details': None}
            result['gbp_details'] = self._get_gbp_details(context, **kwargs)
            result['neutron_details'] = neu_rpc.RpcCallbacks(
                None, None).get_device_details(context, **kwargs)
            return result
        except Exception as e:
            LOG.error(_LE("An exception has occurred while requesting device "
                          "gbp details for %s"), kwargs.get('device'))
            LOG.exception(e)
            return None

    def _allocate_snat_ip(self, context, host_or_vrf, network, es_name):
        """Allocate SNAT IP for a host for an external network."""
        snat_subnets = self._get_subnets(context,
                filters={'name': [HOST_SNAT_POOL],
                         'network_id': [network['id']]})
        if not snat_subnets:
            LOG.info(_LI("Subnet for SNAT-pool could not be found "
                       "for external network %(net_id)s. SNAT will not "
                       "function on this network"), {'net_id': network['id']})
            return {}
        else:
            snat_ports = self._get_ports(context,
                    filters={'name': [HOST_SNAT_POOL_PORT],
                             'network_id': [network['id']],
                             'device_id': [host_or_vrf]})
            snat_ip = None
            if not snat_ports:
                # Note that the following port is created for only getting
                # an IP assignment in the
                attrs = {'device_id': host_or_vrf,
                         'device_owner': DEVICE_OWNER_SNAT_PORT,
                         'binding:host_id': host_or_vrf,
                         'binding:vif_type': portbindings.VIF_TYPE_UNBOUND,
                         'tenant_id': network['tenant_id'],
                         'name': HOST_SNAT_POOL_PORT,
                         'network_id': network['id'],
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'fixed_ips': [{'subnet_id': snat_subnets[0]['id']}],
                         'admin_state_up': False}
                port = self._create_port(context, attrs)
                if port and port['fixed_ips']:
                    snat_ip = port['fixed_ips'][0]['ip_address']
                else:
                    LOG.warning(_LW("SNAT-port creation failed for subnet "
                                  "%(subnet_id)s on external network "
                                  "%(net_id)s. SNAT will not function on"
                                  "host or vrf %(host_or_vrf)s for this "
                                  "network"),
                                {'subnet_id': snat_subnets[0]['id'],
                                 'net_id': network['id'],
                                 'host_or_vrf': host_or_vrf})
                    return {}
            elif snat_ports[0]['fixed_ips']:
                snat_ip = snat_ports[0]['fixed_ips'][0]['ip_address']
            else:
                LOG.warning(_LW("SNAT-port %(port)s for external network "
                              "%(net)s on host or VRF %(host_or_vrf)s doesn't "
                              "have an IP-address"),
                            {'port': snat_ports[0]['id'],
                             'net': network['id'],
                             'host_or_vrf': host_or_vrf})
                return {}

            return {'external_segment_name': es_name,
                    'host_snat_ip': snat_ip,
                    'gateway_ip': snat_subnets[0]['gateway_ip'],
                    'prefixlen':
                    netaddr.IPNetwork(snat_subnets[0]['cidr']).prefixlen}

    def _get_ip_mapping_details(self, context, port_id, l3_policy, pt=None,
                                owned_addresses=None, host=None):
        """ Add information about IP mapping for DNAT/SNAT """
        if not l3_policy['external_segments']:
            return [], [], []
        fips_filter = [port_id]
        if pt:
            # For each owned address, we must pass the FIPs of the original
            # owning port.
            # REVISIT(ivar): should be done for allowed_address_pairs in
            # general?
            ptg_pts = self._get_policy_targets(
                context, {'policy_target_group_id':
                          [pt['policy_target_group_id']]})
            ports = self._get_ports(context,
                                    {'id': [x['port_id'] for x in ptg_pts]})
            for port in ports:
                # Whenever a owned address belongs to a port, steal its FIPs
                if owned_addresses & set([x['ip_address'] for x in
                                          port['fixed_ips'] + port.get(
                                              'allowed_address_pairs', [])]):
                    fips_filter.append(port['id'])

        fips = self._get_fips(context, filters={'port_id': fips_filter})
        ipms = []
        # Populate host_snat_ips in the format:
        # [ {'external_segment_name': <ext_segment_name1>,
        #    'host_snat_ip': <ip_addr>, 'gateway_ip': <gateway_ip>,
        #    'prefixlen': <prefix_length_of_host_snat_pool_subnet>},
        #    {..}, ... ]
        host_snat_ips = []
        ess = context._plugin.get_external_segments(context._plugin_context,
                filters={'id': l3_policy['external_segments'].keys()})
        for es in ess:
            if not self._is_nat_enabled_on_es(es):
                continue
            ext_info = self.apic_manager.ext_net_dict.get(es['name'])
            if ext_info and self._is_edge_nat(ext_info):
                continue
            nat_epg_tenant, nat_epg_name = self._determine_nat_epg_for_es(
                context, es, l3_policy)
            nat_epg_tenant = self.apic_manager.apic.fvTenant.name(
                nat_epg_tenant)
            fips_in_es = []

            if es['subnet_id']:
                subnet = self._get_subnet(context._plugin_context,
                                          es['subnet_id'])
                ext_net_id = subnet['network_id']
                fips_in_es = filter(
                    lambda x: x['floating_network_id'] == ext_net_id, fips)
                ext_network = self._get_network(context._plugin_context,
                        ext_net_id)
                if host:
                    host_snat_ip_allocation = (
                        self._allocate_snat_ip(
                            context._plugin_context, host, ext_network,
                            es['name']))
                    if host_snat_ip_allocation:
                        host_snat_ips.append(host_snat_ip_allocation)
            if not fips_in_es:
                ipms.append({'external_segment_name': es['name'],
                             'nat_epg_name': nat_epg_name,
                             'nat_epg_tenant': nat_epg_tenant,
                             'next_hop_ep_tenant': (
                                self.apic_manager.apic.fvTenant.name(
                                    self._tenant_by_sharing_policy(es)))})
            for f in fips_in_es:
                f['nat_epg_name'] = nat_epg_name
                f['nat_epg_tenant'] = nat_epg_tenant
        return fips, ipms, host_snat_ips

    def _add_network_details(self, context, port, details, pt=None,
                             owned=None, inject_default_route=True):
        details['allowed_address_pairs'] = port['allowed_address_pairs']
        if pt:
            # Set the correct address ownership for this port
            owned_addresses = owned or self._get_owned_addresses(context,
                                                                 pt['port_id'])
            for allowed in details['allowed_address_pairs']:
                if allowed['ip_address'] in owned_addresses:
                    # Signal the agent that this particular address is active
                    # on its port
                    allowed['active'] = True
        details['enable_dhcp_optimization'] = self.enable_dhcp_opt
        details['enable_metadata_optimization'] = self.enable_metadata_opt
        details['subnets'] = self._get_subnets(context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})
        for subnet in details['subnets']:
            dhcp_ips = set()
            for port in self._get_ports(
                    context, filters={
                        'network_id': [subnet['network_id']],
                        'device_owner': [n_constants.DEVICE_OWNER_DHCP]}):
                dhcp_ips |= set([x['ip_address'] for x in port['fixed_ips']
                                 if x['subnet_id'] == subnet['id']])
            dhcp_ips = list(dhcp_ips)
            if not subnet['dns_nameservers']:
                # Use DHCP namespace port IP
                subnet['dns_nameservers'] = dhcp_ips
            # Set Default & Metadata routes if needed
            default_route = metadata_route = {}
            if subnet['ip_version'] == 4:
                for route in subnet['host_routes']:
                    if route['destination'] == '0.0.0.0/0':
                        default_route = route
                    if route['destination'] == dhcp.METADATA_DEFAULT_CIDR:
                        metadata_route = route
                if not inject_default_route:
                    # In this case we do not want to send the default route
                    # and the metadata route. We also do not want to send
                    # the gateway_ip for the subnet.
                    if default_route:
                        subnet['host_routes'].remove(default_route)
                    if metadata_route:
                        subnet['host_routes'].remove(metadata_route)
                    del subnet['gateway_ip']
                else:
                    # Set missing routes
                    if not default_route:
                        subnet['host_routes'].append(
                            {'destination': '0.0.0.0/0',
                             'nexthop': subnet['gateway_ip']})
                    if not metadata_route and dhcp_ips and (
                        not self.enable_metadata_opt):
                        subnet['host_routes'].append(
                            {'destination': dhcp.METADATA_DEFAULT_CIDR,
                             'nexthop': dhcp_ips[0]})
            subnet['dhcp_server_ips'] = dhcp_ips

    def _add_vrf_details(self, context, details):
        l3p = self.gbp_plugin.get_l3_policy(context, details['l3_policy_id'])
        details['vrf_tenant'] = self.apic_manager.apic.fvTenant.name(
            self._tenant_by_sharing_policy(l3p))
        details['vrf_name'] = self.apic_manager.apic.fvCtx.name(
            str(self.name_mapper.l3_policy(context, l3p)))
        details['vrf_subnets'] = [l3p['ip_pool']]
        if l3p.get('proxy_ip_pool'):
            details['vrf_subnets'].append(l3p['proxy_ip_pool'])

    # RPC Method
    def ip_address_owner_update(self, context, **kwargs):
        if not kwargs.get('ip_owner_info'):
            return
        ports_to_update = self.update_ip_owner(kwargs['ip_owner_info'])
        pts = self._get_policy_targets(context, {'port_id': ports_to_update})
        for p in ports_to_update:
            LOG.debug("APIC ownership update for port %s", p)
            self._notify_port_update(context, p)
        for pt in pts:
            self._notify_head_chain_ports(pt['policy_target_group_id'])

    def process_port_added(self, context):
        self._handle_shadow_port_change(context)

    def create_policy_action_precommit(self, context):
        pass

    def create_policy_rule_precommit(self, context):
        pass

    def create_policy_rule_postcommit(self, context, transaction=None):
        entries = alib.get_filter_entries_for_policy_rule(context)
        if entries['forward_rules']:
            tenant = self._tenant_by_sharing_policy(context.current)
            policy_rule = self.name_mapper.policy_rule(context,
                                                       context.current)
            with self.apic_manager.apic.transaction(transaction) as trs:
                self._create_tenant_filter(policy_rule, tenant,
                                           entries['forward_rules'],
                                           transaction=trs)
                if entries['reverse_rules']:
                    # Also create reverse rule
                    policy_rule = self.name_mapper.policy_rule(
                        context, context.current, prefix=alib.REVERSE_PREFIX)
                    self._create_tenant_filter(policy_rule, tenant,
                                               entries['reverse_rules'],
                                               transaction=trs)

    def create_policy_rule_set_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            if context.current['child_policy_rule_sets']:
                raise alib.HierarchicalContractsNotSupported()
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

    def create_policy_target_precommit(self, context):
        ptg = self._get_policy_target_group(
            context._plugin_context,
            context.current['policy_target_group_id'])
        shadow_net = self._get_ptg_shadow_network(context, ptg)

        super(ApicMappingDriver, self)._check_create_policy_target(
            context, verify_port_subnet=not bool(shadow_net))
        if shadow_net and context.current['port_id']:
            self._check_explicit_port(context, ptg, shadow_net)

    def create_policy_target_postcommit(self, context):
        ptg = self.gbp_plugin.get_policy_target_group(
            context._plugin_context,
            context.current['policy_target_group_id'])
        subnets = self._get_subnets(
            context._plugin_context, {'id': ptg['subnets']})
        owned = []
        reserved = []
        for subnet in subnets:
            if not subnet['name'].startswith(APIC_OWNED_RES):
                owned.append(subnet)
            elif subnet['name'] == APIC_OWNED_RES + ptg['id']:
                reserved.append(subnet)
        self._create_implicit_and_shadow_ports(context, ptg,
            implicit_subnets=reserved or owned)

        self._update_cluster_membership(
            context, new_cluster_id=context.current['cluster_id'])
        port = self._get_port(context._plugin_context,
                              context.current['port_id'])
        if self._is_port_bound(port):
            self._notify_port_update(context._plugin_context, port['id'])
        if self._may_have_fip(context):
            self._associate_fip_to_pt(context)
        self._notify_head_chain_ports(
            context.current['policy_target_group_id'])

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
                raise alib.ExplicitSubnetAssociationNotSupported()
            if context.current.get('proxied_group_id'):
                # goes in same L2P as proxied group
                proxied = context._plugin.get_policy_target_group(
                    context._plugin_context,
                    context.current['proxied_group_id'])
                db_group = context._plugin._get_policy_target_group(
                    context._plugin_context, context.current['id'])
                db_group.l2_policy_id = proxied['l2_policy_id']
                context.current['l2_policy_id'] = proxied['l2_policy_id']
            if context.current['description']:
                if (EOC_PREFIX in context.current['description']
                        and not context._plugin_context.is_admin):
                    raise AdminOnlyOperation()
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
                if not self.name_mapper._is_apic_reference(l2_policy_object):
                    self._configure_epg_service_contract(
                        context, context.current, l2p, epg, transaction=trs)
                    self._configure_epg_implicit_contract(
                        context, context.current, l2p, epg, transaction=trs)

            l3p = context._plugin.get_l3_policy(
                context._plugin_context, l2_policy_object['l3_policy_id'])
            if context.current.get('proxied_group_id'):
                self._stitch_proxy_ptg_to_l3p(context, l3p)
            self._handle_network_service_policy(context)

            self._manage_ptg_policy_rule_sets(
                    context, context.current['provided_policy_rule_sets'],
                    context.current['consumed_policy_rule_sets'], [], [])
            self._set_proxy_any_contract(context.current)
            # Mirror Contracts
            if context.current.get('proxied_group_id'):
                proxied = context._plugin.get_policy_target_group(
                    context._plugin_context.elevated(),
                    context.current['proxied_group_id'])
                updated = context._plugin.update_policy_target_group(
                    context._plugin_context.elevated(),
                    context.current['id'], {
                        'policy_target_group': {
                            'provided_policy_rule_sets': dict(
                                (x, '') for x in proxied[
                                    'provided_policy_rule_sets']),
                            'consumed_policy_rule_sets': dict(
                                (x, '') for x in proxied[
                                    'consumed_policy_rule_sets'])}})
                context.current.update(updated)
            self._create_ptg_shadow_network(context, context.current)

    def create_l2_policy_precommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_non_shared_net_on_shared_l2p(context)
        else:
            self.name_mapper.has_valid_name(context.current)

    def update_l2_policy_precommit(self, context):
        if (context.current['l3_policy_id'] !=
                context.original['l3_policy_id']):
            raise gpexc.L3PolicyUpdateOfL2PolicyNotSupported()
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

                # query all the ESs for this VRF, connect BD to corresponding
                # (shadow) L3Outs for no-NAT and edge-NAT cases.
                if l3_policy_object['external_segments']:
                    ess = context._plugin.get_external_segments(
                        context._plugin_context,
                        filters={'id':
                                 l3_policy_object['external_segments'].keys()})
                    for es in ess:
                        ext_info = self.apic_manager.ext_net_dict.get(
                            es['name'])
                        nat_enabled = self._is_nat_enabled_on_es(es)
                        is_edge_nat = (nat_enabled and ext_info and
                                       self._is_edge_nat(ext_info))
                        if not nat_enabled or is_edge_nat:
                            es_name = self.name_mapper.external_segment(
                                context, es,
                                prefix=self._get_shadow_prefix(context,
                                    is_edge_nat, l3_policy_object,
                                    is_edge_nat=is_edge_nat))
                            if not is_edge_nat and self._is_pre_existing(es):
                                nm = self.name_mapper.name_mapper
                                es_name = nm.pre_existing(
                                    context._plugin_context, es['name'])
                            self.apic_manager.set_l3out_for_bd(tenant,
                                    l2_policy, es_name, transaction=trs)

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
                context, context.current, prefix=alib.REVERSE_PREFIX)
            self.apic_manager.delete_tenant_filter(policy_rule, owner=tenant,
                                                   transaction=trs)

    def delete_policy_rule_set_precommit(self, context):
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
            self._delete_implicit_and_shadow_ports(context)
            if context.current['port_id']:
                # Notify the agent. If the port has been deleted by the
                # parent method the notification will not be done
                self._notify_port_update(context._plugin_context,
                                         context.current['port_id'])
        except n_exc.PortNotFound:
            LOG.warning(_LW("Port %s is missing") % context.current['port_id'])
            return

    def delete_policy_target_group_precommit(self, context):
        if self.create_auto_ptg:
            auto_ptg_id = self._get_auto_ptg_id(
                context.current['l2_policy_id'])
            if context.current['id'] == auto_ptg_id:
                raise AutoPTGDeleteNotSupported(id=auto_ptg_id)

    def delete_policy_target_group_postcommit(self, context):
        if not self.name_mapper._is_apic_reference(context.current):
            tenant = self._tenant_by_sharing_policy(context.current)
            ptg = self.name_mapper.policy_target_group(context,
                                                       context.current)

            self.apic_manager.delete_epg_for_network(tenant, ptg)
            # Place back proxied PTG, if any
            if context.current.get('proxied_group_id'):
                proxied = context._plugin.get_policy_target_group(
                    context._plugin_context,
                    context.current['proxied_group_id'])
                ptg_name = self.name_mapper.policy_target_group(
                    context, proxied)
                l2_policy_object = context._plugin.get_l2_policy(
                    context._plugin_context, context.current['l2_policy_id'])
                l2_policy = self.name_mapper.l2_policy(
                    context, l2_policy_object)
                bd_owner = self._tenant_by_sharing_policy(l2_policy_object)
                tenant = self._tenant_by_sharing_policy(proxied)
                self.apic_manager.ensure_epg_created(
                    tenant, ptg_name, bd_owner=bd_owner, bd_name=l2_policy)

                # Delete shadow BD
                shadow_bd = self.name_mapper.policy_target_group(
                    context, proxied, prefix=SHADOW_PREFIX)
                self.apic_manager.delete_bd_on_apic(tenant, shadow_bd)
            # Delete PTG specific subnets
            subnets = self._core_plugin.get_subnets(
                context._plugin_context, {'name': [APIC_OWNED_RES +
                                                   context.current['id']]})
            self.gbp_plugin._remove_subnets_from_policy_target_groups(
                nctx.get_admin_context(), [x['id'] for x in subnets])
            for subnet in subnets:
                self._cleanup_subnet(context._plugin_context, subnet['id'],
                                     None)
            self._delete_ptg_shadow_network(context, context.current)
            self._unset_any_contract(context.current)

    def delete_l2_policy_precommit(self, context):
        if self.create_auto_ptg:
            auto_ptg_id = self._get_auto_ptg_id(context.current['id'])
            auto_ptg = context._plugin.get_policy_target_group(
                    context._plugin_context, auto_ptg_id)
            if auto_ptg:
                self._db_plugin(context._plugin).delete_policy_target_group(
                    context._plugin_context, auto_ptg_id)
            self.apic_manager.db.delete_apic_name(auto_ptg_id)
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
        if not self.name_mapper._is_apic_reference(context.current):
            self._reject_shared_update(context, 'policy_rule_set')
            if context.current['child_policy_rule_sets']:
                raise alib.HierarchicalContractsNotSupported()

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
        self._validate_cluster_id(context)
        if (context.original['policy_target_group_id'] !=
                context.current['policy_target_group_id']):
            if self._is_supported_non_opflex_port(context,
                                                context.current['port_id']):
                raise PTGChangeDisallowedWithNonOpFlexNetwork(
                    net_type=ofcst.TYPE_OPFLEX)
            if context.current['policy_target_group_id']:
                self._validate_pt_port_subnets(context)

    def update_policy_target_postcommit(self, context):
        curr, orig = context.current, context.original
        self._update_cluster_membership(
            context, new_cluster_id=context.current['cluster_id'],
            old_cluster_id=context.original['cluster_id'])
        if ((orig['policy_target_group_id'] != curr['policy_target_group_id'])
            or ((curr['description'] != orig['description']) and
                curr['description'].startswith(PROXY_PORT_PREFIX))):
            self._notify_port_update(context._plugin_context,
                                     context.current['port_id'])

    def update_policy_rule_precommit(self, context):
        pass

    def update_policy_rule_postcommit(self, context):
        self._update_policy_rule_on_apic(context)
        super(ApicMappingDriver, self).update_policy_rule_postcommit(context)

    def update_policy_action_postcommit(self, context):
        pass

    def _update_policy_rule_on_apic(self, context):
        self._delete_policy_rule_from_apic(context, transaction=None)
        # The following only creates the APIC reference
        self.create_policy_rule_postcommit(context, transaction=None)

    def update_policy_target_group_precommit(self, context):
        if self.create_auto_ptg:
            auto_ptg_id = self._get_auto_ptg_id(
                context.original['l2_policy_id'])
            if context.current['id'] == auto_ptg_id:
                updated_attrs = [key for key in context.current if
                                 context.original[key] != context.current[key]]
                if list(set(updated_attrs) - set(AUTO_PTG_MUTABLE_KEYS)):
                    raise AutoPTGAttrsUpdateNotSupported(
                        id=auto_ptg_id, attrs=updated_attrs)
        if not self.name_mapper._is_apic_reference(context.current):
            if set(context.original['subnets']) != set(
                 context.current['subnets']):
                raise alib.ExplicitSubnetAssociationNotSupported()
            self._reject_shared_update(context, 'policy_target_group')
            if (context.current['description'] !=
                    context.original['description']):
                if (EOC_PREFIX in context.current['description']
                        and not context._plugin_context.is_admin):
                    raise AdminOnlyOperation()

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

            self._handle_nsp_update_on_ptg(context)

            self._manage_ptg_policy_rule_sets(
                context, new_provided_policy_rule_sets,
                new_consumed_policy_rule_sets,
                removed_provided_policy_rule_sets,
                removed_consumed_policy_rule_sets)

            # Set same contracts to proxy group
            # Refresh current after the above operations took place
            current = context._plugin.get_policy_target_group(
                context._plugin_context, context.current['id'])
            if current.get('proxy_group_id'):
                proxy = context._plugin.get_policy_target_group(
                    context._plugin_context.elevated(),
                    current['proxy_group_id'])
                context._plugin.update_policy_target_group(
                    context._plugin_context.elevated(),
                    proxy['id'], {
                        'policy_target_group': {
                            'provided_policy_rule_sets': dict(
                                (x, '') for x in current[
                                    'provided_policy_rule_sets']),
                            'consumed_policy_rule_sets': dict(
                                (x, '') for x in current[
                                    'consumed_policy_rule_sets'])}})

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
                    ((o_prot in alib.REVERSIBLE_PROTOCOLS) !=
                        (c_prot in alib.REVERSIBLE_PROTOCOLS))):
                for prs in context._plugin.get_policy_rule_sets(
                        admin_context,
                        filters={'id': rule['policy_rule_sets']}):
                    self._remove_policy_rule_set_rules(
                        context, prs, [(rule, context.original)])
                    self._apply_policy_rule_set_rules(context, prs, [rule])

    def create_external_segment_precommit(self, context):
        es = context.current
        if es['port_address_translation']:
            raise PATNotSupportedByApicDriver()
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if ext_info:
            self._check_pre_existing_es(context, es)
            if ext_info.get('cidr_exposed'):
                db_es = context._plugin._get_external_segment(
                    context._plugin_context, es['id'])
                net = netaddr.IPNetwork(ext_info.get('cidr_exposed'))
                db_es.cidr = str(net)
                db_es.ip_version = net[0].version
                context.current['cidr'] = db_es.cidr
                context.current['ip_version'] = db_es.ip_version
                self._check_es_subnet(context, es)
                if (self._is_nat_enabled_on_es(es) and
                        'host_pool_cidr' in ext_info):
                    hp_net = netaddr.IPNetwork(ext_info['host_pool_cidr'])
                    if hp_net.cidr == net.cidr:
                        raise HostPoolSubnetOverlap(host_pool_cidr=hp_net.cidr,
                                                    es=es['name'])
            self._check_edge_nat_setting(es)
        else:
            LOG.warning(UNMANAGED_SEGMENT % context.current['id'])

    def create_external_segment_postcommit(self, context):
        es = context.current
        external_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not external_info:
            LOG.warning(UNMANAGED_SEGMENT % es['id'])
        else:
            if not es['subnet_id']:
                subnet = self._use_implicit_external_subnet(context, es)
                context.add_subnet(subnet['id'])
            if self._is_nat_enabled_on_es(es):
                self._create_nat_epg_for_es(context, es, external_info)

    def update_external_segment_precommit(self, context):
        if context.current['port_address_translation']:
            raise PATNotSupportedByApicDriver()
        if context.current['subnet_id'] != context.original['subnet_id']:
            raise gpexc.InvalidAttributeUpdateForES(attribute='subnet_id')

    def update_external_segment_postcommit(self, context):
        ext_info = self.apic_manager.ext_net_dict.get(
            context.current['name'])
        if not ext_info:
            LOG.warning(UNMANAGED_SEGMENT % context.current['id'])
            return
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            self._do_external_segment_update(context, ext_info)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        # cleanup NAT EPG
        es = context.current
        if self._is_nat_enabled_on_es(es):
            self._delete_nat_epg_for_es(context, es)
        self._delete_implicit_external_subnet(context, es)

    def create_external_policy_precommit(self, context):
        self._check_external_policy(context, context.current)

    def create_external_policy_postcommit(self, context):
        segments = context.current['external_segments']
        provided_prs = context.current['provided_policy_rule_sets']
        consumed_prs = context.current['consumed_policy_rule_sets']
        self._plug_external_policy_to_segment(
            context, context.current, segments, provided_prs, consumed_prs)

    def update_external_policy_precommit(self, context):
        self._check_external_policy(context, context.current)

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
        self._plug_external_policy_to_segment(
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
                if not self._is_nat_enabled_on_es(es):
                    l3ps = [None]
                else:
                    # Update to the PRS of EP should update the shadow EPs
                    l3ps = context._plugin.get_l3_policies(
                        context._plugin_context,
                        filters={'id': es['l3_policies'],
                                 'tenant_id': [context.current['tenant_id']]})
                for l3p in l3ps:
                    self._manage_ep_policy_rule_sets(
                        context._plugin_context, es, context.current,
                        added_p_prs, added_c_prs, removed_p_prs, removed_c_prs,
                        l3p)

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
        l2p = self._network_id_to_l2p(context, new['network_id'])
        if l2p:
            if old['gateway_ip'] != new['gateway_ip']:
                # Is GBP owned, reflect on APIC
                self._manage_l2p_subnets(context, l2p['id'], [new], [old])
            self._sync_shadow_subnets(context, l2p, old, new)
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
            self._sync_shadow_subnets(context, l2p, None, subnet)

    def process_subnet_deleted(self, context, subnet):
        l2p = self._network_id_to_l2p(context, subnet['network_id'])
        if l2p:
            self._manage_l2p_subnets(context, l2p['id'], [], [subnet])
            self._sync_shadow_subnets(context, l2p, subnet, None)

    def process_port_changed(self, context):
        self._handle_shadow_port_change(context)
        if (context.original_host != context.host or
                context.original_bottom_bound_segment !=
                context.bottom_bound_segment):
            self._delete_path_static_binding_if_reqd(context, True)
            self._create_path_static_binding_if_reqd(context)

    def process_pre_port_deleted(self, context):
        pt = self._port_id_to_pt(context._plugin_context,
                                 context.current['id'])
        if pt:
            context.policy_target_id = pt['id']

    def process_port_deleted(self, context):
        port = context.current
        # do nothing for floating-ip ports
        if port['device_owner'] == n_constants.DEVICE_OWNER_FLOATINGIP:
            LOG.debug("Ignoring floating-ip port %s", port['id'])
            return
        try:
            self.gbp_plugin.delete_policy_target(
                context._plugin_context, context.policy_target_id)
        except AttributeError:
            pass
        self._delete_path_static_binding_if_reqd(context, False)

    def nat_pool_iterator(self, context, tenant_id, floatingip):
        """Get NAT pool for floating IP associated with external-network."""
        fip = floatingip['floatingip']
        f_net_id = fip['floating_network_id']
        subnets = self._get_subnets(context.elevated(),
            {'network_id': [f_net_id]})
        ext_seg = self.gbp_plugin.get_external_segments(context.elevated(),
            {'subnet_id': [s['id'] for s in subnets]}) if subnets else []
        context._plugin = self.gbp_plugin
        context._plugin_context = context
        for es in ext_seg:
            for nat_pool in self._gen_nat_pool_in_ext_seg(context,
                    tenant_id, es):
                yield nat_pool

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
                    context, rule, prefix=alib.REVERSE_PREFIX)
                rule_owner = self._tenant_by_sharing_policy(rule)
                with self.apic_manager.apic.transaction(transaction) as trs:
                    if classifier['direction'] in in_dir:
                        # PRS and subject are the same thing in this case
                        self.apic_manager.manage_contract_subject_in_filter(
                            contract, contract, policy_rule, owner=tenant,
                            transaction=trs, unset=unset,
                            rule_owner=rule_owner)
                        if classifier['protocol'] and (
                                classifier['protocol'].lower() in
                                alib.REVERSIBLE_PROTOCOLS):
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
                        if classifier['protocol'] and (
                                classifier['protocol'].lower() in
                                alib.REVERSIBLE_PROTOCOLS):
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
        is_shadow = bool(l3policy_obj)
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warning(_LW("External Segment %s is not managed by APIC "
                            "mapping driver.") % es['id'])
            return
        pre_existing = (False if is_shadow else self._is_pre_existing(es))
        pfx = self._get_shadow_prefix(plugin_context, is_shadow, l3policy_obj,
                                      self._is_edge_nat(ext_info))
        plugin_context._plugin = self.gbp_plugin
        plugin_context._plugin_context = plugin_context

        mapped_ep = self.name_mapper.external_policy(plugin_context, ep,
                                                     prefix=pfx)
        if not pre_existing:
            mapped_tenant = self._get_tenant_for_shadow(
                is_shadow, l3policy_obj, es)
            mapped_es = self.name_mapper.external_segment(
                plugin_context, es, prefix=pfx)
        else:
            mapped_es = self.name_mapper.name_mapper.pre_existing(
                plugin_context, es['name'])
            l3out_info = self._query_l3out_info(mapped_es,
                self.name_mapper.tenant(es))
            if not l3out_info:
                LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                return
            mapped_tenant = l3out_info['l3out_tenant']
            if ext_info.get('external_epg') == ep['name']:
                mapped_ep = self.name_mapper.name_mapper.pre_existing(
                    plugin_context, ep['name'])

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
        ptg, _ = self._port_id_to_ptg(context, port_id)
        if not ptg:
            # Not GBP port
            return None, None
        network = self._l2p_id_to_network(context, ptg['l2_policy_id'])
        return ptg, network

    def _port_id_to_pt(self, context, port_id):
        pts = self.gbp_plugin.get_policy_targets(
            context, {'port_id': [port_id]})
        if pts:
            return pts[0]

    def _port_id_to_ptg(self, context, port_id):
        pt = self._port_id_to_pt(context, port_id)
        if pt:
            return self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id']), pt
        return None, None

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

    # return True if key exists in req_dict
    def _trim_tDn_from_dict(self, req_dict, key):
        try:
            if req_dict.get(key) is not None:
                del req_dict['tDn']
                return True
            else:
                return False
        except KeyError:
            return True

    def _trim_keys_from_dict(self, req_dict, keys, encap, l3p_name):
        for key in keys:
            try:
                del req_dict[key]
            except KeyError:
                pass

        # remove the default value parameter and replace encap
        if (req_dict.get('targetDscp') and
                req_dict['targetDscp'] == 'unspecified'):
            del req_dict['targetDscp']
        if req_dict.get('addr') and req_dict['addr'] == '0.0.0.0':
            del req_dict['addr']
        if req_dict.get('encap'):
            if req_dict['encap'] == 'unknown':
                del req_dict['encap']
            elif req_dict['encap'].startswith('vlan-'):
                req_dict['encap'] = encap

        # this is for l3extRsEctx case that it
        # doesn't allow tDn being present
        if self._trim_tDn_from_dict(req_dict, 'tnFvCtxName'):
            req_dict['tnFvCtxName'] = l3p_name
        # this is for l3extRsNdIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnNdIfPolName')
        # this is for l3extRsDampeningPol/l3extRsInterleakPol case
        self._trim_tDn_from_dict(req_dict, 'tnRtctrlProfileName')
        # this is for ospfRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnOspfIfPolName')
        # this is for l3extRs[I|E]ngressQosDppPol case
        self._trim_tDn_from_dict(req_dict, 'tnQosDppPolName')
        # this is for bfdRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnBfdIfPolName')
        # this is for bgpRsPeerPfxPol case
        self._trim_tDn_from_dict(req_dict, 'tnBgpPeerPfxPolName')
        # this is for eigrpRsIfPol case
        self._trim_tDn_from_dict(req_dict, 'tnEigrpIfPolName')

        for value in req_dict.values():
            if isinstance(value, dict):
                self._trim_keys_from_dict(value, keys, encap, l3p_name)
            elif isinstance(value, list):
                for element in value:
                    if isinstance(element, dict):
                        self._trim_keys_from_dict(element, keys,
                                                  encap, l3p_name)
        return req_dict

    def _clone_l3out(self, context, es, es_name, es_tenant, encap):
        pre_es_name = self.name_mapper.name_mapper.pre_existing(
            context, es['name'])
        l3out_info = self._query_l3out_info(pre_es_name,
            self.name_mapper.tenant(es), return_full=True)

        old_tenant = self.apic_manager.apic.fvTenant.rn(
            l3out_info['l3out_tenant'])
        new_tenant = self.apic_manager.apic.fvTenant.rn(es_tenant)
        old_l3_out = self.apic_manager.apic.l3extOut.rn(pre_es_name)
        new_l3_out = self.apic_manager.apic.l3extOut.rn(es_name)

        request = {}
        request['children'] = l3out_info['l3out']
        request['attributes'] = {"rn": new_l3_out}

        # trim the request
        keys = (['l3extInstP', 'l3extRtBDToOut',
                 'l3extExtEncapAllocator',
                 'l3extRsOutToBDPublicSubnetHolder', 'modTs',
                 'uid', 'lcOwn', 'monPolDn', 'forceResolve',
                 'rType', 'state', 'stateQual', 'tCl', 'tType',
                 'type', 'tContextDn', 'tRn', 'tag', 'name',
                 'configIssues'])
        vrf = self.apic_manager.apic.fvCtx.name(
            context.current.get('name'))
        request = self._trim_keys_from_dict(request, keys, encap, vrf)

        final_req = {}
        final_req['l3extOut'] = request
        request_json = jsonutils.dumps(final_req)
        if old_tenant != new_tenant:
            request_json = re.sub(old_tenant, new_tenant,
                request_json)
        request_json = re.sub(old_l3_out, new_l3_out, request_json)
        request_json = re.sub('{},*', '', request_json)
        self.apic_manager.apic.post_body(
            self.apic_manager.apic.l3extOut.mo,
            request_json,
            es_tenant,
            str(es_name))

    def _plug_l3p_to_es(self, context, es, is_shadow=False):
        l3_policy = (self.name_mapper.l3_policy(context, context.current)
                     if (not self._is_nat_enabled_on_es(es) or is_shadow) else
                     self._get_nat_vrf_for_es(context, es))
        external_segments = context.current['external_segments']
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if not ext_info:
            LOG.warning(UNMANAGED_SEGMENT % es['id'])
            return
        exposed = ext_info.get('cidr_exposed')

        # Set the external fixed-ip for L3P for the non-shadow call
        if not is_shadow:
            ip = external_segments[es['id']]
            if ip and ip[0]:
                ip = ip[0]
            else:
                ip = getattr(context, 'assigned_router_ips', {}).get(
                    es['id'], [])
                if ip and ip[0]:
                    ip = ip[0]
                else:
                    ip = ext_info.get('cidr_exposed', '/').split('/')[0]
            if not ip:
                raise NoAddressConfiguredOnExternalSegment(
                    l3p_id=context.current['id'], es_id=es['id'])
            context.set_external_fixed_ips(es['id'], [ip])

        is_edge_nat = self._is_edge_nat(ext_info)
        es_name = self.name_mapper.external_segment(context, es,
            prefix=self._get_shadow_prefix(context,
                is_shadow, context.current, is_edge_nat))
        es_name_pre = self.name_mapper.name_mapper.pre_existing(
            context._plugin_context, es['name'])
        es_tenant = self._get_tenant_for_shadow(is_shadow, context.current, es)
        nat_enabled = self._is_nat_enabled_on_es(es)
        pre_existing = False if is_shadow else self._is_pre_existing(es)
        with self.apic_manager.apic.transaction() as trs:
            # Create External Routed Network connected to the proper
            # L3 Context

            is_l3out_creation_needed = not pre_existing

            # don't need to explicitly create the shadow l3out in this case
            # because we are going to query APIC then use the pre-existing
            # l3out as a template then clone it accordingly
            if (is_shadow and is_edge_nat and self._is_pre_existing(es)):
                is_l3out_creation_needed = False

            if is_l3out_creation_needed:
                self.apic_manager.ensure_external_routed_network_created(
                    es_name, owner=es_tenant, context=l3_policy,
                    transaction=trs)
            # Associate pre-existing, no-NAT L3-out with L3policy
            if pre_existing and not nat_enabled:
                l3out_info = self._query_l3out_info(es_name_pre,
                    self.name_mapper.tenant(es))
                if l3out_info:
                    mapped_tenant = l3out_info['l3out_tenant']
                    self.apic_manager.set_context_for_external_routed_network(
                        mapped_tenant, es_name_pre, l3_policy, transaction=trs)

            is_details_needed = False
            if not is_shadow and not pre_existing:
                encap = ext_info.get('encap')  # No encap if None
                is_details_needed = True

            # if its edge nat then we have to flesh
            # out this shadow L3 out in APIC
            if is_shadow and is_edge_nat:
                vlan_id = self.l3out_vlan_alloc.reserve_vlan(
                    es['name'], context.current['id'])
                encap = 'vlan-' + str(vlan_id)
                is_details_needed = True

            if is_details_needed:
                if self._is_pre_existing(es):
                    self._clone_l3out(context, es, es_name, es_tenant, encap)
                else:
                    switch = ext_info['switch']
                    module, sport = ext_info['port'].split('/')
                    router_id = ext_info['router_id']
                    default_gateway = ext_info['gateway_ip']

                    self.apic_manager.set_domain_for_external_routed_network(
                        es_name, owner=es_tenant, transaction=trs)
                    self.apic_manager.ensure_logical_node_profile_created(
                        es_name, switch, module, sport, encap,
                        exposed, owner=es_tenant,
                        router_id=router_id, transaction=trs)
                    for route in es['external_routes']:
                        self.apic_manager.ensure_static_route_created(
                            es_name, switch,
                            route['nexthop'] or default_gateway,
                            owner=es_tenant,
                            subnet=route['destination'], transaction=trs)

                if is_shadow:
                    l2ps = self._get_l2_policies(context._plugin_context,
                        {'id': context.current['l2_policies']})
                    for l2p in l2ps:
                        self.apic_manager.set_l3out_for_bd(
                            self._tenant_by_sharing_policy(l2p),
                            self.name_mapper.l2_policy(context, l2p),
                            es_name)

            if nat_enabled:
                if not is_shadow:
                    # set L3-out for NAT-BD
                    self.apic_manager.set_l3out_for_bd(es_tenant,
                        self._get_nat_bd_for_es(context, es),
                        (self.name_mapper.name_mapper.pre_existing(
                            context, es['name']) if pre_existing else es_name),
                        transaction=trs)
                elif not is_edge_nat:
                    # create tenant-specific NAT EPG if required
                    self._create_tenant_specific_nat_epg(context, es,
                        context.current, transaction=trs)
        if not is_shadow:
            if nat_enabled:
                # create shadow external-networks
                self._plug_l3p_to_es(context, es, True)
                # create shadow external EPGs indirectly by re-plugging
                # external policies to external segment
                eps = context._plugin.get_external_policies(
                    context._plugin_context,
                    filters={'id': es['external_policies'],
                             'tenant_id': [context.current['tenant_id']]})
                for ep in eps:
                    self._plug_external_policy_to_segment(context, ep,
                        [es['id']], ep['provided_policy_rule_sets'],
                        ep['consumed_policy_rule_sets'])
            else:
                # Associate BDs of the VRF to L3-out
                l2ps = self._get_l2_policies(context._plugin_context,
                    {'id': context.current['l2_policies']})
                for l2p in l2ps:
                    self.apic_manager.set_l3out_for_bd(
                        self._tenant_by_sharing_policy(l2p),
                        self.name_mapper.l2_policy(context, l2p),
                        es_name_pre if pre_existing else es_name)

    def _unplug_l3p_from_es(self, context, es, is_shadow=False):
        is_edge_nat = False
        if is_shadow:
            ext_info = self.apic_manager.ext_net_dict.get(es['name'])
            is_edge_nat = self._is_edge_nat(ext_info)
        es_name = self.name_mapper.external_segment(context, es,
            prefix=self._get_shadow_prefix(context,
                is_shadow, context.current, is_edge_nat))
        es_name_pre = self.name_mapper.name_mapper.pre_existing(
            context._plugin_context, es['name'])
        es_tenant = self._get_tenant_for_shadow(is_shadow, context.current, es)
        nat_enabled = self._is_nat_enabled_on_es(es)
        pre_existing = False if is_shadow else self._is_pre_existing(es)
        if not is_shadow:
            if nat_enabled:
                # remove shadow external-networks
                self._unplug_l3p_from_es(context, es, True)
                if not is_edge_nat:
                    # remove tenant-specific NAT EPG if required
                    self._remove_tenant_specific_nat_epg(context, es,
                                                         context.current)
            else:
                # Dissociate BDs of the VRF from L3-out
                l2ps = self._get_l2_policies(context._plugin_context,
                    {'id': context.current['l2_policies']})
                for l2p in l2ps:
                    self.apic_manager.unset_l3out_for_bd(
                        self._tenant_by_sharing_policy(l2p),
                        self.name_mapper.l2_policy(context, l2p),
                        es_name_pre if pre_existing else es_name)
        set_ctx = self.apic_manager.set_context_for_external_routed_network
        if (is_shadow or
            not [x for x in es['l3_policies'] if x != context.current['id']]):
                with self.apic_manager.apic.transaction() as trs:
                    if is_shadow or not pre_existing:
                        self.apic_manager.delete_external_routed_network(
                            es_name, owner=es_tenant, transaction=trs)

                    # Dissociate L3policy from pre-existing, no-NAT L3-out
                    if pre_existing and not nat_enabled:
                        l3out_info = self._query_l3out_info(es_name_pre,
                            self.name_mapper.tenant(es))
                        if l3out_info:
                            mapped_tenant = l3out_info['l3out_tenant']
                            set_ctx(mapped_tenant, es_name_pre, None,
                                    transaction=trs)

                    if nat_enabled and not is_shadow:
                        self.apic_manager.unset_l3out_for_bd(es_tenant,
                            self._get_nat_bd_for_es(context, es),
                            (self.name_mapper.name_mapper.pre_existing(
                                context, es['name'])
                            if pre_existing else es_name),
                            transaction=trs)
                    # if its edge nat then we have to release
                    # the vlan associated with this shadow L3out
                    if is_shadow and self._is_edge_nat(ext_info):
                        self.l3out_vlan_alloc.release_vlan(
                            es['name'], context.current['id'])

                        l2ps = self._get_l2_policies(context._plugin_context,
                            {'id': context.current['l2_policies']})
                        for l2p in l2ps:
                            self.apic_manager.unset_l3out_for_bd(
                                self._tenant_by_sharing_policy(l2p),
                                self.name_mapper.l2_policy(context, l2p),
                                es_name)

    def _build_routes_dict(self, routes):
        result = {}
        for route in routes:
            if route['destination'] not in result:
                result[route['destination']] = []
            result[route['destination']].append(route['nexthop'])
        return result

    def _plug_external_policy_to_segment(self, context, ep, segments,
                                         provided_prs, consumed_prs,
                                         l3policy_obj=None):
        is_shadow = bool(l3policy_obj)
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warning(UNMANAGED_SEGMENT % es['id'])
                    continue
                pfx = self._get_shadow_prefix(context, is_shadow, l3policy_obj,
                                              self._is_edge_nat(ext_info))
                ep_name = self.name_mapper.external_policy(context, ep,
                    prefix=pfx)
                pre_existing = (False if is_shadow else
                                self._is_pre_existing(es))
                pre_existing_epg = False
                nat_enabled = self._is_nat_enabled_on_es(es)
                if not pre_existing:
                    es_name = self.name_mapper.external_segment(context,
                        es, prefix=pfx)
                    es_tenant = self._get_tenant_for_shadow(is_shadow,
                        l3policy_obj, es)
                    if nat_enabled and not is_shadow:
                        ep_name = self.name_mapper.external_segment(context,
                             es, prefix="default-")
                else:
                    es_name = self.name_mapper.name_mapper.pre_existing(
                        context, es['name'])
                    l3out_info = self._query_l3out_info(es_name,
                        self.name_mapper.tenant(es))
                    if not l3out_info:
                        LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                        continue
                    es_tenant = l3out_info['l3out_tenant']
                    pre_existing_epg = (
                        ext_info.get('external_epg') == ep['name'])
                    if pre_existing_epg:
                        ep_name = self.name_mapper.name_mapper.pre_existing(
                            context, ep['name'])

                with self.apic_manager.apic.transaction() as trs:
                    # Create External EPG - with no route restrictions on the
                    # 'real' one and with proper destination routes
                    # in the shadow
                    if not pre_existing_epg:
                        subnets = set((x['destination'] for
                                      x in es['external_routes'])
                                      if (is_shadow or not nat_enabled)
                                      else ['0.0.0.0/0'])
                        for s in subnets:
                            self.apic_manager.ensure_external_epg_created(
                                es_name, subnet=s, external_epg=ep_name,
                                owner=es_tenant, transaction=trs)
                    if is_shadow or not nat_enabled:
                        # User-specified contracts are associated with
                        # shadow external EPGs (if NAT is enabled) or
                        # real external EPGs (if NAT is disabled)
                        self._manage_ep_policy_rule_sets(
                            context._plugin_context, es, ep,
                            provided_prs, consumed_prs, [], [],
                            l3policy_obj, transaction=trs)
                    if is_shadow:
                        if not self._is_edge_nat(ext_info):
                            nat_epg_tenant, nat_epg_name = (
                                self._determine_nat_epg_for_es(
                                    context, es, l3policy_obj))
                            # set up link to NAT EPG
                            (self.apic_manager.
                             associate_external_epg_to_nat_epg(
                                 es_tenant, es_name, ep_name,
                                 nat_epg_name, target_owner=nat_epg_tenant,
                                 transaction=trs))
                    elif nat_enabled:
                        # 'real' external EPGs provide and consume
                        # allow-all contract when NAT is enabled
                        nat_contract = self._get_nat_contract_for_es(
                            context, es)
                        self.apic_manager.set_contract_for_external_epg(
                            es_name, nat_contract,
                            external_epg=ep_name, owner=es_tenant,
                            provided=True, transaction=trs)
                        self.apic_manager.set_contract_for_external_epg(
                            es_name, nat_contract,
                            external_epg=ep_name, owner=es_tenant,
                            provided=False, transaction=trs)

                # create shadow external epgs in L3policies associated
                # with the segment
                if nat_enabled and not is_shadow:
                    l3ps = context._plugin.get_l3_policies(
                        context._plugin_context,
                        filters={'id': es['l3_policies'],
                                 'tenant_id': [ep['tenant_id']]})
                    for l3p in l3ps:
                        self._plug_external_policy_to_segment(context, ep,
                            [es['id']], provided_prs, consumed_prs,
                            l3policy_obj=l3p)

    def _unplug_external_policy_from_segment(self, context, ep, segments,
                                             l3policy_obj=None):
        is_shadow = bool(l3policy_obj)
        if segments:
            added_ess = context._plugin.get_external_segments(
                context._plugin_context, filters={'id': segments})
            for es in added_ess:
                ext_info = self.apic_manager.ext_net_dict.get(es['name'])
                if not ext_info:
                    LOG.warning(UNMANAGED_SEGMENT % es['id'])
                    continue
                pfx = self._get_shadow_prefix(context, is_shadow, l3policy_obj,
                                              self._is_edge_nat(ext_info))
                ep_name = self.name_mapper.external_policy(context, ep,
                                                           prefix=pfx)
                pre_existing = (False if is_shadow else
                                self._is_pre_existing(es))
                pre_existing_epg = False
                nat_enabled = self._is_nat_enabled_on_es(es)
                if nat_enabled and not is_shadow:
                    # remove the shadow external EPGs from L3policies
                    # associated with the segment
                    l3ps = context._plugin.get_l3_policies(
                        context._plugin_context,
                        filters={'id': es['l3_policies'],
                                 'tenant_id': [ep['tenant_id']]})
                    for l3p in l3ps:
                        self._unplug_external_policy_from_segment(context, ep,
                            [es['id']], l3policy_obj=l3p)

                if not pre_existing:
                    es_name = self.name_mapper.external_segment(context, es,
                        prefix=pfx)
                    es_tenant = self._get_tenant_for_shadow(is_shadow,
                        l3policy_obj, es)
                    if nat_enabled and not is_shadow:
                        ep_name = self.name_mapper.external_segment(context,
                            es, prefix="default-")
                else:
                    es_name = self.name_mapper.name_mapper.pre_existing(
                        context, es['name'])
                    l3out_info = self._query_l3out_info(es_name,
                        self.name_mapper.tenant(es))
                    if not l3out_info:
                        LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                        continue
                    es_tenant = l3out_info['l3out_tenant']
                    pre_existing_epg = (
                        ext_info.get('external_epg') == ep['name'])
                    if pre_existing_epg:
                        ep_name = self.name_mapper.name_mapper.pre_existing(
                            context, ep['name'])
                last_ep = not [x for x in es['external_policies']
                               if x != ep['id']]
                if (not pre_existing_epg and
                    (not nat_enabled or is_shadow or last_ep)):
                        self.apic_manager.ensure_external_epg_deleted(
                            es_name, external_epg=ep_name, owner=es_tenant)
                elif pre_existing_epg and nat_enabled:
                    pre_epgs = context._plugin.get_external_policies(
                        context._plugin_context.elevated(),
                        filters={'id': es['external_policies'],
                                 'name': [ep['name']]})
                    # Unset contracts if there are no other pre-existing EPGs
                    if not [x for x in pre_epgs if x['id'] != ep['id']]:
                        nat_contract = self._get_nat_contract_for_es(
                            context, es)
                        with self.apic_manager.apic.transaction() as trs:
                            self.apic_manager.unset_contract_for_external_epg(
                                es_name, nat_contract,
                                external_epg=ep_name, owner=es_tenant,
                                provided=True, transaction=trs)
                            self.apic_manager.unset_contract_for_external_epg(
                                es_name, nat_contract,
                                external_epg=ep_name, owner=es_tenant,
                                provided=False, transaction=trs)

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

        pre_existing = (False if is_shadow else self._is_pre_existing(es))
        is_edge_nat = self._is_edge_nat(ext_info)
        pfx = self._get_shadow_prefix(context, is_shadow, l3policy_obj,
                                      is_edge_nat)

        is_static_route_adjustment_needed = (
            (not is_shadow and not pre_existing) or
            (is_shadow and is_edge_nat and not self._is_pre_existing(es)))
        if is_static_route_adjustment_needed:
            switch = ext_info['switch']
            default_gateway = ext_info['gateway_ip']
            nexthop = lambda h: h if h else default_gateway

        if not pre_existing:
            es_name = self.name_mapper.external_segment(context, es,
                                                        prefix=pfx)
            es_tenant = self._get_tenant_for_shadow(
                is_shadow, l3policy_obj, es)
        else:
            es_name = self.name_mapper.name_mapper.pre_existing(
                context, es['name'])
            l3out_info = self._query_l3out_info(es_name,
                self.name_mapper.tenant(es))
            if not l3out_info:
                LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                return
            es_tenant = l3out_info['l3out_tenant']

        ep_filter = {'id': es['external_policies']}
        if is_shadow:
            ep_filter['tenant_id'] = [l3policy_obj['tenant_id']]
        eps = self._get_external_policies(
            context._plugin_context.elevated(), filters=ep_filter)
        ep_names = [
            self.name_mapper.external_policy(context, ep, prefix=pfx)
            for ep in eps
            if not pre_existing or ep['name'] != ext_info.get('external_epg')]

        nat_enabled = self._is_nat_enabled_on_es(es)
        with self.apic_manager.apic.transaction() as trs:
            for route in removed:
                if route[0] not in new_routes_dict:
                    # Remove Route completely
                    if is_static_route_adjustment_needed:
                        self.apic_manager.ensure_static_route_deleted(
                            es_name, switch, route[0], owner=es_tenant,
                            transaction=trs)
                    if is_shadow or not nat_enabled:
                        # Also from shadow External EPG (nat-enabled), or
                        # real external EPG (nat-disabled)
                        del_epg = (self.apic_manager.
                                   ensure_external_epg_routes_deleted)
                        for ep in ep_names:
                            del_epg(
                                es_name, external_epg=ep, owner=es_tenant,
                                subnets=[route[0]], transaction=trs)
                else:
                    if is_static_route_adjustment_needed:
                        # Only remove nexthop
                        self.apic_manager.ensure_next_hop_deleted(
                            es_name, switch, route[0], nexthop(route[1]),
                            owner=es_tenant, transaction=trs)
            for route in added:
                # Create Static Route on External Routed Network
                if is_static_route_adjustment_needed:
                    self.apic_manager.ensure_static_route_created(
                        es_name, switch, nexthop(route[1]),
                        owner=es_tenant, subnet=route[0], transaction=trs)
                if is_shadow or not nat_enabled:
                    # And on the shadow External EPGs (nat-enabled), or
                    # real external EPG (nat-disabled)
                    for ep in ep_names:
                        self.apic_manager.ensure_external_epg_created(
                            es_name, subnet=route[0], external_epg=ep,
                            owner=es_tenant, transaction=trs)
        # Update the shadow external-segments
        if nat_enabled and not is_shadow:
            l3ps = context._plugin.get_l3_policies(
                context._plugin_context.elevated(),
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
            # if NAT is disabled, allow only one L3P per ES
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': l3p['external_segments'].keys()})
            for es in ess:
                if self._is_nat_enabled_on_es(es):
                    continue
                if [x for x in es['l3_policies'] if x != l3p['id']]:
                    raise OnlyOneL3PolicyIsAllowedPerExternalSegment()
                if self._is_pre_existing(es):
                    l3out_info = self._query_l3out_info(
                        self.name_mapper.name_mapper.pre_existing(
                            context, es['name']),
                        self.name_mapper.tenant(es))
                    if not l3out_info:
                        raise PreExistingL3OutNotFound(l3out=es['name'])

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
            if object.get('proxied_group_id') or object.get(
                    'enforce_service_chains') is False:
                # Then it's a proxy
                # PTG Even though they may belong to a different tenant,
                # the proxy PTGs will be created on the L2P's tenant to
                # make APIC happy
                l2p = self.gbp_plugin.get_l2_policy(
                    nctx.get_admin_context(), object['l2_policy_id'])
                return self._tenant_by_sharing_policy(l2p)
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

    def _get_ext_net_name_for_es(self, es):
        return "%s%s-%s" % (APIC_OWNED, es['name'], es['id'])

    def _get_nat_contract_for_es(self, context, es):
        return ("NAT-allow-%s" %
            self.name_mapper.external_segment(context, es))

    def _get_shadow_prefix(self, context, is_shadow, l3_obj,
                           is_edge_nat=False):
        prefix = SHADOW_PREFIX
        if is_edge_nat:
            prefix = AUTO_PREFIX
        return (is_shadow and
            ('%s%s-' % (prefix,
                str(self.name_mapper.l3_policy(context, l3_obj))))
            or '')

    def _get_tenant_for_shadow(self, is_shadow, shadow_obj, obj):
        return self._tenant_by_sharing_policy(
            shadow_obj if is_shadow else obj)

    def _notify_port_update(self, plugin_context, port_id):
        pointing_pts = self.gbp_plugin.get_policy_targets(
            plugin_context.elevated(),
            {'description': [PROXY_PORT_PREFIX + port_id]})
        pt = self._port_id_to_pt(plugin_context, port_id)
        if pt:
            # Notify ports in cluster
            cluster_ids = [pt['id']]
            if pt.get('cluster_id') and pt.get('cluster_id') != pt['id']:
                cluster_ids.append(pt.get('cluster_id'))
            pointing_pts.extend(
                self.gbp_plugin.get_policy_targets(
                    plugin_context.elevated(),
                    {'cluster_id': cluster_ids}))
        ports = self._get_ports(
            plugin_context, {'id': [port_id] +
                             [x['port_id'] for x in pointing_pts]})
        for port in ports:
            if self._is_port_bound(port):
                LOG.debug("APIC notify port %s", port['id'])
                self.notifier.port_update(plugin_context, port)

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
            added = []
            # Always add a new subnet to L3 proxies
            is_proxy = bool(context.current.get('proxied_group_id'))
            force_add = force_add or is_proxy
            if not subs or force_add:
                l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                    l2p_id)
                if is_proxy:
                    name = APIC_OWNED_RES + context.current['id']
                else:
                    name = APIC_OWNED + l2p['name']

                added = super(
                    ApicMappingDriver, self)._use_implicit_subnet(
                        context, subnet_specifics={'name': name},
                        is_proxy=is_proxy)
            context.add_subnets(subs - set(context.current['subnets']))
            if added:
                l3p_id = l2p['l3_policy_id']
                l3p = context._plugin.get_l3_policy(context._plugin_context,
                                                    l3p_id)
                for subnet in added:
                    self.process_subnet_added(context._plugin_context, subnet)
                if not is_proxy:
                    for router_id in l3p['routers']:
                        for subnet in added:
                            self._plug_router_to_subnet(
                                nctx.get_admin_context(),
                                subnet['id'], router_id)

    def _stitch_proxy_ptg_to_l3p(self, context, l3p):
        """Stitch proxy PTGs properly."""
        # Proxied PTG is moved to a shadow BD (no routing, learning ON?)
        tenant = self._tenant_by_sharing_policy(context.current)
        ctx_owner = self._tenant_by_sharing_policy(l3p)
        l3_policy_name = self.name_mapper.l3_policy(context, l3p)
        proxied = context._plugin.get_policy_target_group(
            context._plugin_context, context.current['proxied_group_id'])
        bd_name = self.name_mapper.policy_target_group(
                context, proxied, prefix=SHADOW_PREFIX)
        ptg_name = self.name_mapper.policy_target_group(context, proxied)
        with self.apic_manager.apic.transaction(None) as trs:
            # Create shadow BD to host the proxied EPG
            self.apic_manager.ensure_bd_created_on_apic(
                tenant, bd_name, ctx_owner=ctx_owner, ctx_name=l3_policy_name,
                allow_broadcast=True, unicast_route=False, transaction=trs,
                enforce_subnet_check=False)
            # Move current PTG to different BD
            self.apic_manager.ensure_epg_created(
                tenant, ptg_name, bd_owner=tenant, bd_name=bd_name,
                transaction=trs)
        # Notify proxied ports
        self._notify_proxy_gateways(proxied['id'])

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
                        LOG.warning(e)

    def _get_l2p_subnets(self, plugin_context, l2p_id):
        l2p = self.gbp_plugin.get_l2_policy(plugin_context, l2p_id)
        return self._get_l2ps_subnets(plugin_context, [l2p])

    def _get_l2ps_subnets(self, plugin_context, l2ps):
        return self._core_plugin.get_subnets(
            plugin_context, {'network_id': [x['network_id'] for x in l2ps]})

    def _configure_implicit_contract(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            # Create Service contract
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=alib.IMPLICIT_PREFIX)
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)

            # Create ARP filter/subject
            entries = alib.get_arp_filter_entry()
            for k, v in entries.iteritems():
                self._associate_service_filter(tenant, contract, k,
                                               k, transaction=trs, **v)

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
                context, l2p, prefix=alib.SERVICE_PREFIX)
            self.apic_manager.create_contract(
                contract, owner=tenant, transaction=trs)

            # Shadow EPG provides this contract
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=True,
                contract_owner=tenant, transaction=trs)

            entries = alib.get_service_contract_filter_entries()

            # Create DNS filter/subject
            self._associate_service_filter(tenant, contract, 'dns',
                                           'dns', transaction=trs,
                                           **entries['dns'])
            self._associate_service_filter(tenant, contract, 'dns',
                                           'r-dns', transaction=trs,
                                           **entries['r-dns'])

            # Create HTTP filter/subject
            self._associate_service_filter(tenant, contract, 'http',
                                           'http', transaction=trs,
                                           **entries['http'])
            self._associate_service_filter(tenant, contract, 'http',
                                           'r-http', transaction=trs,
                                           **entries['r-http'])

            self._associate_service_filter(tenant, contract, 'icmp',
                                           'icmp', transaction=trs,
                                           **entries['icmp'])

            # Create DHCP filter/subject
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'dhcp', transaction=trs,
                                           **entries['dhcp'])
            self._associate_service_filter(tenant, contract, 'dhcp',
                                           'r-dhcp', transaction=trs,
                                           **entries['r-dhcp'])

            # Create ARP filter/subject
            self._associate_service_filter(tenant, contract, 'arp',
                                           'arp', transaction=trs,
                                           **entries['arp'])

            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=alib.IMPLICIT_PREFIX)
            # Shadow EPG provides and consumes implicit contract
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=False,
                contract_owner=tenant, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                tenant, shadow_epg, contract, provider=True,
                contract_owner=tenant, transaction=trs)
        if self.create_auto_ptg:
            data = {
                "id": self._get_auto_ptg_id(l2p['id']),
                "name": self._get_auto_ptg_name(l2p),
                "description": "System created auto PTG per L2P",
                "l2_policy_id": l2p['id'],
                "proxied_group_id": None,
                "proxy_type": None,
                "proxy_group_id": attributes.ATTR_NOT_SPECIFIED,
                "network_service_policy_id": None,
                "service_management": False,
                "shared": l2p['shared'],
            }
            auto_ptg = self._db_plugin(
                context._plugin).create_policy_target_group(
                    context._plugin_context,
                    {'policy_target_group': data})
            # Since we are reverse mapping the APIC EPG to the default PTG
            # we will map the id of the PTG to the APIC EPG name
            self.apic_manager.db.update_apic_name(
                auto_ptg['id'], 'policy_target_group', str(shadow_epg))
            ptg_context = group_policy_context.PolicyTargetGroupContext(
                context._plugin, context._plugin_context, auto_ptg)
            self._use_implicit_subnet(ptg_context)

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
                context, l2p, prefix=alib.SERVICE_PREFIX)
            self.apic_manager.delete_contract(
                contract, owner=tenant, transaction=trs)

    def _delete_implicit_contract(self, context, l2p, transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            tenant = self._tenant_by_sharing_policy(l2p)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=alib.IMPLICIT_PREFIX)
            self.apic_manager.delete_contract(
                contract, owner=tenant, transaction=trs)

    def _configure_epg_service_contract(self, context, ptg, l2p, epg_name,
                                        transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            contract_owner = self._tenant_by_sharing_policy(l2p)
            tenant = self._tenant_by_sharing_policy(ptg)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=alib.SERVICE_PREFIX)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=False,
                contract_owner=contract_owner, transaction=trs)

    def _configure_epg_implicit_contract(self, context, ptg, l2p, epg_name,
                                         transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            contract_owner = self._tenant_by_sharing_policy(l2p)
            tenant = self._tenant_by_sharing_policy(ptg)
            contract = self.name_mapper.l2_policy(
                context, l2p, prefix=alib.IMPLICIT_PREFIX)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=False,
                contract_owner=contract_owner, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                tenant, epg_name, contract, provider=True,
                contract_owner=contract_owner, transaction=trs)

    def _check_es_subnet(self, context, es):
        if es['subnet_id']:
            subnet = self._get_subnet(context._plugin_context,
                                      es['subnet_id'])
            network = self._get_network(context._plugin_context,
                                        subnet['network_id'])
            if not network['router:external']:
                raise gpexc.InvalidSubnetForES(sub_id=subnet['id'],
                                               net_id=network['id'])

    def _use_implicit_external_subnet(self, context, es):
        # create external-network if required
        ext_net_name = self._get_ext_net_name_for_es(es)
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
                     'provider:network_type': attributes.ATTR_NOT_SPECIFIED,
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
                     'cidr': ('169.254.0.0/16' if es['ip_version'] == 4
                              else 'fe80::/64'),
                     'enable_dhcp': False,
                     'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                     'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                     'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                     'host_routes': attributes.ATTR_NOT_SPECIFIED}
            subnet = self._create_subnet(context._plugin_context, attrs)
        return subnet

    def _delete_implicit_external_subnet(self, context, es):
        if not es['subnet_id']:
            return
        subnet = self._get_subnet(context._plugin_context, es['subnet_id'])

        snat_subnets = self._get_subnets(
            context._plugin_context, filters={'name': [HOST_SNAT_POOL],
                                              'network_id':
                                              [subnet['network_id']]})
        for s in snat_subnets:
            self._delete_subnet(context._plugin_context, s['id'])

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
            l2p_sn_ids.update([
                x['id'] for x in self._get_l2p_subnets(context._plugin_context,
                                                       l2p_id)
                if not x['name'].startswith(APIC_OWNED_RES)])

        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_dict.keys()})
        assigned_ips = {}
        for es in es_list:
            if not es['subnet_id']:
                continue
            router_id = sub_r_dict.get(es['subnet_id'])
            if router_id:  # router connecting to ES's subnet exists
                router = self._get_router(context._plugin_context, router_id)
            else:
                router_id = self._use_implicit_router(
                    context, l3p['name'] + '-' + es['name'])
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
            if subnet_id in rtr_sn:  # already attached
                continue
            self._plug_router_to_subnet(plugin_context, subnet_id, router_id)

    def _plug_router_to_subnet(self, plugin_context, subnet_id, router_id):
        if router_id:
            # Allocate port and use it as router interface
            # This will avoid gateway_ip to be used
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
                LOG.exception(_LE("Adding subnet to router with "
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

    def _create_nat_epg_for_es(self, context, es, ext_info):
        nat_bd_name = self._get_nat_bd_for_es(context, es)
        nat_epg_name = self._get_nat_epg_for_es(context, es)
        nat_vrf_name = self._get_nat_vrf_for_es(context, es)
        es_tenant = self._tenant_by_sharing_policy(es)
        nat_epg_tenant = es_tenant
        nat_vrf_tenant = es_tenant
        pre_existing = self._is_pre_existing(es)

        if pre_existing:
            l3out_info = self._query_l3out_info(
                self.name_mapper.name_mapper.pre_existing(
                    context, es['name']),
                self.name_mapper.tenant(es))
            if not l3out_info:
                LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                return
            if not (l3out_info.get('vrf_name') and
                    l3out_info.get('vrf_tenant')):
                LOG.warning(
                    _LW("External routed network %s doesn't have private "
                        "network set") % es['name'])
                return
            es_tenant = l3out_info['l3out_tenant']
            nat_vrf_name = self.name_mapper.name_mapper.pre_existing(
                context, l3out_info['vrf_name'])
            nat_vrf_tenant = l3out_info['vrf_tenant']

        with self.apic_manager.apic.transaction() as trs:
            # create allow-everything contract
            nat_contract = self._get_nat_contract_for_es(context, es)
            self.apic_manager.create_tenant_filter(
                nat_contract, owner=es_tenant,
                entry="allow-all", transaction=trs)
            self.apic_manager.manage_contract_subject_bi_filter(
                nat_contract, nat_contract, nat_contract,
                owner=es_tenant, transaction=trs)

        with self.apic_manager.apic.transaction() as trs:
            # Create NAT VRF if required
            if not pre_existing:
                self.apic_manager.ensure_context_enforced(
                    owner=nat_vrf_tenant, ctx_id=nat_vrf_name,
                    transaction=trs)
            # create NAT EPG, BD for external segment and connect to NAT VRF
            if not self._is_edge_nat(ext_info):
                self.apic_manager.ensure_bd_created_on_apic(
                    nat_epg_tenant, nat_bd_name, ctx_owner=nat_vrf_tenant,
                    ctx_name=nat_vrf_name, transaction=trs)
                self.apic_manager.ensure_epg_created(
                    nat_epg_tenant, nat_epg_name, bd_name=nat_bd_name,
                    transaction=trs)
            gw, plen = ext_info.get('host_pool_cidr', '/').split('/', 1)
            if gw and plen:
                if not self._is_edge_nat(ext_info):
                    self.apic_manager.ensure_subnet_created_on_apic(
                        nat_epg_tenant, nat_bd_name, gw + '/' + plen,
                        transaction=trs)
                if not es['subnet_id']:
                    LOG.warning(_LW("No associated subnet found for"
                        "external segment %(es_id)s. SNAT "
                        "will not function for this network"),
                        {'es_id': es['id']})
                else:
                    es_net_id = self._get_subnet(context._plugin_context,
                            es['subnet_id'])['network_id']
                    # Create a new Neutron subnet corresponding to the
                    # host_pool_cidr.
                    # Each host that needs to provide SNAT for this
                    # external network will get port allocation and IP
                    # from this subnet.
                    host_cidr = ext_info.get('host_pool_cidr')
                    host_cidir_ver = netaddr.IPNetwork(host_cidr).version
                    attrs = {'name': HOST_SNAT_POOL,
                             'cidr': host_cidr,
                             'network_id': es_net_id,
                             'ip_version': host_cidir_ver,
                             'enable_dhcp': False,
                             'gateway_ip': gw,
                             'allocation_pools':
                             attributes.ATTR_NOT_SPECIFIED,
                             'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                             'host_routes':
                             attributes.ATTR_NOT_SPECIFIED,
                             'tenant_id': es['tenant_id']}
                    subnet = self._create_subnet(context._plugin_context,
                            attrs)
                    if not subnet:
                        LOG.warning(_LW("Subnet %(pool) creation failed for "
                            "external network %(net_id)s. SNAT "
                            "will not function for this network"),
                            {'pool': HOST_SNAT_POOL,
                             'net_id': es_net_id})
            # make EPG use allow-everything contract
            if not self._is_edge_nat(ext_info):
                self.apic_manager.set_contract_for_epg(
                    nat_epg_tenant, nat_epg_name, nat_contract,
                    transaction=trs)
                self.apic_manager.set_contract_for_epg(
                    nat_epg_tenant, nat_epg_name, nat_contract, provider=True,
                    transaction=trs)

    def _delete_nat_epg_for_es(self, context, es):
        nat_bd_name = self._get_nat_bd_for_es(context, es)
        nat_epg_name = self._get_nat_epg_for_es(context, es)
        nat_vrf_name = self._get_nat_vrf_for_es(context, es)
        es_tenant = self._tenant_by_sharing_policy(es)
        nat_epg_tenant = es_tenant
        nat_vrf_tenant = es_tenant
        pre_existing = self._is_pre_existing(es)

        if pre_existing:
            l3out_info = self._query_l3out_info(
                self.name_mapper.name_mapper.pre_existing(
                    context, es['name']),
                self.name_mapper.tenant(es))
            if not l3out_info:
                LOG.warning(PRE_EXISTING_SEGMENT % es['name'])
                return
            if not (l3out_info.get('vrf_name') and
                    l3out_info.get('vrf_tenant')):
                LOG.warning(
                       _LW("External routed network %s doesn't have private "
                           "network set") % es['name'])
                return
            es_tenant = l3out_info['l3out_tenant']
            nat_vrf_name = self.name_mapper.name_mapper.pre_existing(
                context, l3out_info['vrf_name'])
            nat_vrf_tenant = l3out_info['vrf_tenant']

        with self.apic_manager.apic.transaction() as trs:
            # delete NAT EPG, BD
            if not self._is_edge_nat(
                self.apic_manager.ext_net_dict[es['name']]):
                self.apic_manager.delete_bd_on_apic(
                    nat_epg_tenant, nat_bd_name, transaction=trs)
                self.apic_manager.delete_epg_for_network(
                    nat_epg_tenant, nat_epg_name, transaction=trs)
            # delete NAT VRF if required
            if not pre_existing:
                self.apic_manager.ensure_context_deleted(
                    nat_vrf_tenant, nat_vrf_name, transaction=trs)

        with self.apic_manager.apic.transaction() as trs:
            # delete allow-everything contract
            nat_contract = self._get_nat_contract_for_es(context, es)
            self.apic_manager.delete_contract(
                nat_contract, owner=es_tenant, transaction=trs)
            self.apic_manager.delete_tenant_filter(
                nat_contract, owner=es_tenant, transaction=trs)

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
            if (self._is_nat_enabled_on_es(old['ext_seg']) and
                not self._is_edge_nat(
                    self.apic_manager.ext_net_dict[old['ext_seg']['name']])):
                tenant_name = self._tenant_by_sharing_policy(old['ext_seg'])
                nat_bd_name = self._get_nat_bd_for_es(context, old['ext_seg'])
                self.apic_manager.ensure_subnet_deleted_on_apic(tenant_name,
                    nat_bd_name, self._gateway_ip(old['subnet']))

        if new and new.get('ext_seg') and new.get('subnet'):
            if (self._is_nat_enabled_on_es(new['ext_seg']) and
                not self._is_edge_nat(
                    self.apic_manager.ext_net_dict[new['ext_seg']['name']])):
                tenant_name = self._tenant_by_sharing_policy(new['ext_seg'])
                nat_bd_name = self._get_nat_bd_for_es(context, new['ext_seg'])
                self.apic_manager.ensure_subnet_created_on_apic(tenant_name,
                    nat_bd_name, self._gateway_ip(new['subnet']))

    def _reject_apic_name_change(self, context):
        if self.name_mapper._is_apic_reference(context.original):
            if context.original['name'] != context.current['name']:
                raise CannotUpdateApicName()

    def _get_ptg_ports(self, ptg):
        context = nctx.get_admin_context()
        pts = self.gbp_plugin.get_policy_targets(
            context, {'id': ptg['policy_targets']})
        port_ids = [x['port_id'] for x in pts]
        return self._get_ports(context, {'id': port_ids})

    def _notify_head_chain_ports(self, ptg_id):
        context = nctx.get_admin_context()
        ptg = self.gbp_plugin.get_policy_target_group(context, ptg_id)
        explicit_eoc_id = self._extract_ptg_explicit_eoc(context, ptg)
        if explicit_eoc_id:
            # Could be a cluster master
            updates = [explicit_eoc_id]
            eoc_pt = self._port_id_to_pt(context, explicit_eoc_id)
            if eoc_pt:
                updates.extend(
                    x['port_id'] for x in self.gbp_plugin.get_policy_targets(
                        context, {'cluster_id': [eoc_pt['id']]}))
            for update in updates:
                self._notify_port_update(context, update)
        # to avoid useless double notification exit now if no proxy
        if not ptg.get('proxy_group_id'):
            return
        # Notify proxy gateway pts
        while ptg['proxy_group_id']:
            ptg = self.gbp_plugin.get_policy_target_group(
                context, ptg['proxy_group_id'])
        self._notify_proxy_gateways(ptg['id'], plugin_context=context)

    def _notify_proxy_gateways(self, group_id, plugin_context=None):
        plugin_context = plugin_context or nctx.get_admin_context()
        proxy_pts = self.gbp_plugin.get_policy_targets(
            plugin_context, {'policy_target_group_id': [group_id],
                             'proxy_gateway': [True]})
        # Get any possible cluster member
        cluster_pts = self.gbp_plugin.get_policy_targets(
            plugin_context, {'cluster_id': [x['id'] for x in proxy_pts]})
        # Get all the fake PTs pointing to the proxy ones to update their ports
        ports = self._get_ports(
            plugin_context, {'id': [x['port_id'] for x in (proxy_pts +
                                                           cluster_pts)]})
        for port in ports:
            self._notify_port_update(plugin_context, port['id'])

    def _create_any_contract(self, origin_ptg_id, transaction=None):
        tenant = apic_manager.TENANT_COMMON
        contract = ANY_PREFIX + origin_ptg_id
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.create_contract(
                    contract, owner=tenant, transaction=trs)
            attrs = {'etherT': 'unspecified'}
            self._associate_service_filter(
                tenant, contract, contract, contract, transaction=trs, **attrs)
        return contract

    def _delete_any_contract(self, origin_ptg_id, transaction=None):
        tenant = apic_manager.TENANT_COMMON
        contract = ANY_PREFIX + origin_ptg_id
        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.delete_contract(
                    contract, owner=tenant, transaction=trs)

    def _get_origin_ptg(self, ptg):
        context = nctx.get_admin_context()
        while ptg['proxied_group_id']:
            ptg = self.gbp_plugin.get_policy_target_group(
                context, ptg['proxied_group_id'])
        return ptg

    def _set_proxy_any_contract(self, proxy_group):
        if proxy_group.get('proxied_group_id'):
            tenant = apic_manager.TENANT_COMMON
            context = nctx.get_admin_context()
            origin = self.gbp_plugin.get_policy_target_group(
                context, proxy_group['proxied_group_id'])
            if not origin['proxied_group_id']:
                # That's the first proxy, it's a special case for we need to
                # create the ANY contract
                any_contract = self._create_any_contract(origin['id'])
                name = self.name_mapper.policy_target_group(
                    context, origin)
                ptg_tenant = self._tenant_by_sharing_policy(origin)
                self.apic_manager.set_contract_for_epg(
                    ptg_tenant, name, any_contract, provider=True,
                    contract_owner=tenant)
            else:
                origin = self._get_origin_ptg(origin)
                any_contract = ANY_PREFIX + origin['id']
            name = self.name_mapper.policy_target_group(
                context, proxy_group)
            ptg_tenant = self._tenant_by_sharing_policy(proxy_group)
            self.apic_manager.set_contract_for_epg(
                ptg_tenant, name, any_contract, provider=False,
                contract_owner=tenant)

    def _unset_any_contract(self, proxy_group):
        if proxy_group.get('proxied_group_id'):
            context = nctx.get_admin_context()
            origin = self.gbp_plugin.get_policy_target_group(
                context, proxy_group['proxied_group_id'])
            if not origin['proxied_group_id']:
                self._delete_any_contract(origin['id'])

    def _check_external_policy(self, context, ep):
        if ep.get('shared', False):
            raise SharedExternalPolicyUnsupported()
        ess = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': ep['external_segments']})
        for es in ess:
            other_eps = context._plugin.get_external_policies(
                context._plugin_context,
                filters={'id': es['external_policies'],
                         'tenant_id': [ep['tenant_id']]})
            if [x for x in other_eps if x['id'] != ep['id']]:
                raise MultipleExternalPoliciesForL3Policy()

    def _is_nat_enabled_on_es(self, es):
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if ext_info:
            if not self.nat_enabled and not self._is_edge_nat(ext_info):
                return False
            opt = ext_info.get('enable_nat', 'true')
            return opt.lower() in ['true', 'yes', '1']
        return False

    def _is_pt_chain_head(self, plugin_context, pt, ptg=None, owned_ips=None,
                          port_id=None):
        if not pt:
            return False

        master_pt = None
        if port_id or pt.get('cluster_id'):
            descr = []
            if port_id:
                descr.append(EOC_PREFIX + port_id)
            if pt.get('cluster_id'):
                master_pt = self._get_pt_cluster_master(plugin_context, pt)
                descr.append(EOC_PREFIX + master_pt['port_id'])
            if bool(self._get_policy_target_groups(
                    plugin_context, filters={'description': descr})):
                return True

        ptg = ptg or self._get_policy_target_group(
            plugin_context, pt['policy_target_group_id'])
        # Check whether PTG is the end of a chain
        chain_end = bool(ptg.get('proxied_group_id') and
                         not ptg.get('proxy_group'))
        if chain_end:
            cluster_id = pt['cluster_id']
            if cluster_id:
                # The master PT must be a proxy gateway for this to be
                # eligible as the chain head
                master_pt = master_pt or self._get_pt_cluster_master(
                    plugin_context, pt)
                # Verify whether this is the active PT
                return bool(master_pt['proxy_gateway'] and
                            self._is_master_owner(plugin_context, pt,
                                                  master_pt=master_pt,
                                                  owned_ips=owned_ips))
            # regular PT not part of a cluster, return if proxy gateway
            return bool(pt['proxy_gateway'])

    def _is_master_owner(self, plugin_context, pt, master_pt=None,
                         owned_ips=None):
        """Verifies if the port owns the master address.

        Returns the master port address or False
        """
        if pt['cluster_id']:
            master_pt = master_pt or self._get_pt_cluster_master(
                plugin_context, pt)
            # Get the owned IPs by PT, and verify at least one of them belong
            # to the cluster master.
            owned_addresses = owned_ips or self._get_owned_addresses(
                plugin_context, pt['port_id'])
            master_port = self._get_port(plugin_context, master_pt['port_id'])
            master_addresses = set([x['ip_address'] for x in
                                    master_port['fixed_ips']])
            if bool(owned_addresses & master_addresses):
                return master_port
        return None

    def _get_owned_addresses(self, plugin_context, port_id):
        return set(self.ha_ip_handler.get_ha_ipaddresses_for_port(port_id))

    def _get_pt_cluster_master(self, plugin_context, pt):
        return (self._get_policy_target(plugin_context, pt['cluster_id'])
                if pt['cluster_id'] != pt['id'] else pt)

    def _is_pre_existing(self, es):
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if ext_info:
            opt = ext_info.get('preexisting', 'false')
            return opt.lower() in ['true', 'yes', '1']
        return False

    def _is_edge_nat(self, ext_info):
        opt = ext_info.get('edge_nat', 'false')
        return opt.lower() in ['true', 'yes', '1']

    def _check_edge_nat_setting(self, es):
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        if ext_info and self._is_edge_nat(ext_info):
            vlan_range = ext_info.get('vlan_range')
            if not vlan_range:
                raise EdgeNatVlanRangeNotFound(l3out=es['name'])
            elif not self.l3out_vlan_alloc.l3out_vlan_ranges.get(es['name']):
                raise EdgeNatBadVlanRange(l3out=es['name'])

    def _query_l3out_info(self, l3out_name, tenant_id, return_full=False):
        info = {'l3out_tenant': tenant_id}
        l3out_children = self.apic_manager.apic.l3extOut.get_subtree(
            info['l3out_tenant'], l3out_name)
        if not l3out_children:
            info['l3out_tenant'] = apic_manager.TENANT_COMMON
            l3out_children = self.apic_manager.apic.l3extOut.get_subtree(
                info['l3out_tenant'], l3out_name)
            if not l3out_children:
                return None
        rs_ctx = [x['l3extRsEctx']
                  for x in l3out_children if x.get('l3extRsEctx')]
        if rs_ctx:
            ctx_dn = rs_ctx[0].get('attributes', {}).get('tDn')
            ctx_dn = ctx_dn.split('/') if ctx_dn else None
            if ctx_dn and len(ctx_dn) == 3:
                if ctx_dn[1].startswith('tn-'):
                    info['vrf_tenant'] = ctx_dn[1][3:]
                if ctx_dn[2].startswith('ctx-'):
                    info['vrf_name'] = ctx_dn[2][4:]
        if return_full:
            info['l3out'] = l3out_children
        return info

    def _check_pre_existing_es(self, context, es):
        if not self._is_pre_existing(es):
            return
        ext_info = self.apic_manager.ext_net_dict.get(es['name'])
        is_edge_nat = self._is_edge_nat(ext_info)
        l3out_info = self._query_l3out_info(
            self.name_mapper.name_mapper.pre_existing(
                context, es['name']),
            self.name_mapper.tenant(es),
            return_full=is_edge_nat)
        if not l3out_info:
            raise PreExistingL3OutNotFound(l3out=es['name'])
        l3out_info['l3out_tenant'] = str(l3out_info['l3out_tenant'])
        es_tenant = str(self._tenant_by_sharing_policy(es))
        if (es_tenant != l3out_info['l3out_tenant'] and
            l3out_info['l3out_tenant'] != apic_manager.TENANT_COMMON):
                raise PreExistingL3OutInIncorrectTenant(
                    l3out_tenant=l3out_info['l3out_tenant'],
                    l3out=es['name'], es=es['name'], es_tenant=es_tenant)
        if is_edge_nat:
            l3out_str = str(l3out_info['l3out'])
            for match in re.finditer("u'ifInstT': u'([^']+)'",
                                     l3out_str):
                if (match.group(1) != 'sub-interface' and
                        match.group(1) != 'ext-svi'):
                    raise EdgeNatWrongL3OutIFType(l3out=es['name'])
            for match in re.finditer("u'authType': u'([^']+)'",
                                     l3out_str):
                if match.group(1) != 'none':
                    raise EdgeNatWrongL3OutAuthTypeForOSPF(l3out=es['name'])
            for match in re.finditer(
                "u'bfdIfP': {u'attributes': {((?!u'attributes': {).)*u'type':"
                " u'([^']+)'",
                l3out_str):
                if match.group(2) != 'none':
                    raise EdgeNatWrongL3OutAuthTypeForBGP(l3out=es['name'])

    def _create_tenant_filter(self, rule_name, tenant, entries=None,
                              transaction=None):
        with self.apic_manager.apic.transaction(transaction) as trs:
            for k, v in entries.iteritems():
                self.apic_manager.create_tenant_filter(
                    rule_name, owner=tenant, transaction=trs, entry=k, **v)

    def _get_l3p_allocated_subnets(self, context, l3p_id,
                                   clean_session=True):
        l2ps = self._get_l2_policies(context._plugin_context,
                                     {'l3_policy_id': [l3p_id]})
        subnets = [x['cidr'] for x in
                   self._get_l2ps_subnets(context._plugin_context, l2ps)]
        return subnets

    def _is_supported_non_opflex_network_type(self, net_type):
        return net_type in [p_const.TYPE_VLAN]

    def _is_supported_non_opflex_network(self, network):
        return self._is_supported_non_opflex_network_type(
            network[providernet.NETWORK_TYPE])

    def _is_supported_non_opflex_port(self, context, port_id):
        port = self._get_port(context._plugin_context, port_id)
        network = self._get_network(context._plugin_context,
                                    port['network_id'])
        return self._is_supported_non_opflex_network(network)

    def _ptg_needs_shadow_network(self, context, ptg):
        net = self._l2p_id_to_network(context._plugin_context,
                                      ptg['l2_policy_id'])
        return self._is_supported_non_opflex_network(net)

    def _get_ptg_shadow_network_name(self, ptg):
        return '%sptg_%s_%s' % (APIC_OWNED, ptg['name'], ptg['id'])

    def _shadow_network_id_to_ptg(self, context, network_id):
        network = self._get_network(context._plugin_context, network_id)
        if network['name'].startswith(APIC_OWNED + 'ptg_'):
            ptg_id = network['name'].split('_')[-1]
            return self._get_policy_target_group(context._plugin_context,
                                                 ptg_id)

    def _get_ptg_shadow_network(self, context, ptg):
        networks = self._get_networks(context._plugin_context,
            filters={'name': [self._get_ptg_shadow_network_name(ptg)],
                     'tenant_id': [ptg['tenant_id']]})
        return networks[0] if networks else None

    def _create_ptg_shadow_network(self, context, ptg):
        if not self._ptg_needs_shadow_network(context, ptg):
            return
        shadow_net = self._get_ptg_shadow_network(context, ptg)
        if not shadow_net:
            attrs = {'tenant_id': ptg['tenant_id'],
                     'name': self._get_ptg_shadow_network_name(ptg),
                     'admin_state_up': True,
                     'shared': ptg.get('shared', False)}
            shadow_net = self._create_network(context._plugin_context, attrs)
            l2p = self._get_l2_policy(context._plugin_context,
                                      ptg['l2_policy_id'])
            for sub_id in ptg['subnets']:
                sub = self._get_subnet(context._plugin_context, sub_id)
                self._sync_shadow_subnets(context._plugin_context, l2p, None,
                                          sub, ptg=ptg)

    def _sync_shadow_subnets(self, plugin_context, l2p, old, new, ptg=None):
        network = self._get_network(plugin_context, l2p['network_id'])
        if not self._is_supported_non_opflex_network(network):
            return
        ref_subnet = new or old
        admin_ctx = plugin_context.elevated()
        ptgs = [ptg] if ptg else self._get_policy_target_groups(admin_ctx,
            filters={'id': l2p['policy_target_groups']})
        if new:
            attrs = {'enable_dhcp': ref_subnet['enable_dhcp'],
                     'gateway_ip': ref_subnet['gateway_ip'],
                     'allocation_pools': ref_subnet['allocation_pools'],
                     'dns_nameservers': ref_subnet['dns_nameservers'],
                     'host_routes': ref_subnet['host_routes']}
            if not old:
                attrs.update({
                    'ip_version': ref_subnet['ip_version'],
                    'cidr': ref_subnet['cidr']})
        for grp in ptgs:
            admin_ctx._plugin_context = admin_ctx
            shadow_net = self._get_ptg_shadow_network(admin_ctx, grp)
            if not shadow_net:
                continue
            shadow_subnet = self._get_subnets(admin_ctx,
                filters={'cidr': [ref_subnet['cidr']],
                         'network_id': [shadow_net['id']]})
            try:
                if old and not new:
                    if shadow_subnet:
                        self._delete_subnet(plugin_context,
                                            shadow_subnet[0]['id'])
                elif new and not old:
                    attrs.update({
                        'tenant_id': shadow_net['tenant_id'],
                        'name': '%ssub_%s' % (APIC_OWNED, ref_subnet['id']),
                        'network_id': shadow_net['id']})
                    self._create_subnet(plugin_context, copy.deepcopy(attrs))
                else:
                    if shadow_subnet:
                        self._update_subnet(plugin_context,
                                            shadow_subnet[0]['id'],
                                            copy.deepcopy(attrs))
            except Exception:
                LOG.exception(
                    _LE('Shadow subnet operation for group %s failed'),
                    grp['id'])
                raise

    def _handle_shadow_port_change(self, context):
        """Special handling for changes to ports in shadow network.

        1. Disable certain kinds of ports like DHCP to avoid interference
        on the data path.
        2. Copy device_id from shadow port to corresponding port in
           L2P's network.

        """
        port = context.current
        ptg = self._shadow_network_id_to_ptg(context, port['network_id'])
        admin_ctx = context._plugin_context.elevated()
        if ptg:
            # Disable DHCP port
            if (port['device_owner'] == n_constants.DEVICE_OWNER_DHCP and
                    port['admin_state_up'] is True):
                self._update_port(admin_ctx, port['id'],
                                  {'admin_state_up': False})
            # Copy device_id
            l2p = self._get_l2_policy(admin_ctx, ptg['l2_policy_id'])
            l2p_port = self._get_ports(
                admin_ctx,
                filters={'mac_address': [port['mac_address']],
                         'network_id': [l2p['network_id']]})
            if l2p_port:
                l2p_port = l2p_port[0]
                if l2p_port['device_id'] != port['device_id']:
                    self._update_port(admin_ctx, l2p_port['id'],
                                      {'device_id': port['device_id']})

    def _delete_ptg_shadow_network(self, context, ptg):
        shadow_net = self._get_ptg_shadow_network(context, ptg)
        if shadow_net:
            self._delete_network(context._plugin_context, shadow_net['id'])

    def _check_explicit_port(self, context, ptg, shadow_net):
        pt = context.current
        shadow_port = self._get_port(context._plugin_context,
                                     pt['port_id'])
        if shadow_port['network_id'] != shadow_net['id']:
            raise ExplicitPortInWrongNetwork(port=shadow_port['id'],
                pt=pt['id'], net=shadow_port['network_id'],
                exp_net=shadow_net['id'])

        # check overlapping IP/MAC address in L2P network
        l2p = self._get_l2_policy(context._plugin_context, ptg['l2_policy_id'])
        shadow_ips = [i['ip_address'] for i in shadow_port['fixed_ips']
                      if i.get('ip_address')]
        ip_overlap_ports = self._get_ports(context._plugin_context,
            filters={'network_id': [l2p['network_id']],
                     'fixed_ips': {'ip_address': shadow_ips}})
        mac_overlap_ports = self._get_ports(context._plugin_context,
            filters={'network_id': [l2p['network_id']],
                     'mac_address': [shadow_port['mac_address']]})
        if ip_overlap_ports or mac_overlap_ports:
            raise ExplicitPortOverlap(net=l2p['network_id'],
                                      port=shadow_port['id'],
                                      ip=shadow_ips,
                                      mac=shadow_port['mac_address'])

    def _create_implicit_and_shadow_ports(self, context, ptg,
                                          implicit_subnets=None):
        shadow_net = self._get_ptg_shadow_network(context, ptg)
        pt = context.current
        pt_port_id = pt['port_id']
        if not shadow_net:
            if not pt_port_id:
                self._use_implicit_port(context, implicit_subnets)
            return

        # Always create an "implicit" port in the L2P network. If PT had
        # a port originally, then treat that port as the "shadow" port,
        # else create the shadow port in the shadow network. In both cases,
        # associate the shadow port to the PT.
        context.current['port_attributes'] = {'device_owner':
                                              'apic:%s' % pt['id']}

        if pt_port_id:
            shadow_port = self._get_port(context._plugin_context, pt_port_id)
            context.current['port_attributes'].update({
                'device_id': shadow_port['device_id'],
                'fixed_ips': self._strip_subnet(shadow_port['fixed_ips']),
                'mac_address': shadow_port['mac_address']})

        self._use_implicit_port(context, implicit_subnets)

        if pt_port_id:
            # set this again because _use_implicit_port() will update it
            # to the newly created port
            context.set_port_id(pt_port_id)
            port_ctx = self._core_plugin.get_bound_port_context(
                context._plugin_context, pt_port_id)
            if port_ctx:
                self._create_path_static_binding_if_reqd(port_ctx)
        else:
            implicit_port = self._get_port(context._plugin_context,
                                           pt['port_id'])
            shadow_subnets = self._get_subnets(
                context._plugin_context,
                filters={'network_id': [shadow_net['id']]})
            context.current['port_attributes'] = {
                'network_id': shadow_net['id'],
                'fixed_ips': self._strip_subnet(implicit_port['fixed_ips']),
                'mac_address': implicit_port['mac_address']}
            self._use_implicit_port(context, shadow_subnets)

    def _delete_implicit_and_shadow_ports(self, context):
        pt = context.current
        if pt['port_id']:
            owned = self._port_is_owned(context._plugin_context.session,
                                        pt['port_id'])
            if owned:
                self._cleanup_port(context._plugin_context, pt['port_id'])
            else:
                port_ctx = self._core_plugin.get_bound_port_context(
                    context._plugin_context, pt['port_id'])
                if port_ctx:
                    self._delete_path_static_binding_if_reqd(port_ctx, False)
        ptg = self._get_policy_target_group(context._plugin_context,
                                            pt['policy_target_group_id'])
        if self._ptg_needs_shadow_network(context, ptg):
            l2p = self._get_l2_policy(context._plugin_context,
                                      ptg['l2_policy_id'])
            implicit_ports = self._get_ports(context._plugin_context,
                filters={'device_owner': ['apic:%s' % pt['id']],
                         'network_id': [l2p['network_id']]})
            for p in implicit_ports:
                self._cleanup_port(context._plugin_context, p['id'])

    def _get_static_binding_info_for_port(self, context, use_original):
        bound_seg = (context.original_bottom_bound_segment if use_original else
                     context.bottom_bound_segment)
        if not bound_seg or not self._is_supported_non_opflex_network_type(
                bound_seg.get(n_api.NETWORK_TYPE)):
            return
        port = context.original if use_original else context.current
        ptg = self._shadow_network_id_to_ptg(context, port['network_id'])
        if ptg:
            port_in_shadow_network = True
            l2p = self._get_l2_policy(context._plugin_context,
                                      ptg['l2_policy_id'])
        else:
            port_in_shadow_network = False
            l2p = self._network_id_to_l2p(context._plugin_context,
                                          port['network_id'])
        if ptg:
            ptg_tenant = self._tenant_by_sharing_policy(ptg)
            endpoint_group_name = self.name_mapper.policy_target_group(
                context, ptg)
        elif l2p:
            ptg_tenant = self._tenant_by_sharing_policy(l2p)
            endpoint_group_name = self.name_mapper.l2_policy(
                context, l2p, prefix=SHADOW_PREFIX)
        else:
            return
        return {'tenant': ptg_tenant,
                'epg': endpoint_group_name,
                'bd': self.name_mapper.l2_policy(context, l2p),
                'host': use_original and context.original_host or context.host,
                'segment': bound_seg,
                'in_shadow_network': port_in_shadow_network}

    def _create_path_static_binding_if_reqd(self, context):
        bind_info = self._get_static_binding_info_for_port(context, False)
        if bind_info:
            if bind_info['in_shadow_network']:
                pt = self._port_id_to_pt(context._plugin_context,
                                         context.current['id'])
                if not pt:
                    # ignore ports in shadow network that are not associated
                    # with a PT
                    return
            LOG.info(_LI('Creating static path binding for port '
                         '%(port)s, %(info)s'),
                     {'port': context.current['id'], 'info': bind_info})
            self.apic_manager.ensure_path_created_for_port(
                bind_info['tenant'], bind_info['epg'], bind_info['host'],
                bind_info['segment'][n_api.SEGMENTATION_ID],
                bd_name=bind_info['bd'])

    def _delete_path_static_binding_if_reqd(self, context, use_original):
        bind_info = self._get_static_binding_info_for_port(
            context, use_original)
        if bind_info:
            bound_port_count = nctx.get_admin_context().session.query(
                ml2_models.PortBindingLevel).filter_by(
                    host=bind_info['host'],
                    segment_id=bind_info['segment'][n_api.ID]).filter(
                        ml2_models.PortBindingLevel.port_id !=
                        context.current['id']).count()
            if not bound_port_count:
                # last port belonging to ACI EPG on this host was removed
                LOG.info(_LI('Deleting static path binding for port '
                             '%(port)s, %(info)s'),
                         {'port': context.current['id'], 'info': bind_info})
                self.apic_manager.ensure_path_deleted_for_port(
                    bind_info['tenant'], bind_info['epg'], bind_info['host'])

    def _strip_subnet(self, fixed_ips):
        for ip in fixed_ips:
            ip.pop('subnet_id', None)
        return fixed_ips

    def _determine_nat_epg_for_es(self, context, es, tenant_obj):
        nat_epg_name = self._get_nat_epg_for_es(context, es)
        nat_epg_tenant = None
        if (es['shared'] and
            self._tenant_uses_specific_nat_epg(context, es, tenant_obj)):
                nat_epg_tenant = self.name_mapper.tenant(tenant_obj)
        nat_epg_tenant = nat_epg_tenant or self._tenant_by_sharing_policy(es)
        return str(nat_epg_tenant), str(nat_epg_name)

    def _tenant_uses_specific_nat_epg(self, context, es, tenant_obj):
        session = context._plugin_context.session
        cnt = session.query(TenantSpecificNatEpg).filter_by(
            external_segment_id=es['id']).filter_by(
                tenant_id=tenant_obj['tenant_id']).count()
        return bool(cnt)

    def _create_tenant_specific_nat_epg(self, context, es, l3_policy,
                                        transaction=None):
        if not es['shared']:
            return

        l3ps = self._get_l3_policies(context._plugin_context.elevated(),
            filters={'id': [l3p for l3p in es['l3_policies']
                            if l3p != l3_policy['id']],
                     'tenant_id': [l3_policy['tenant_id']]})
        if l3ps:
            # there are other L3Ps from this tenant - don't explicitly create
            # tenant-specific NAT EPG so that we continue using whatever
            # those L3Ps were using
            return

        uses_specific_nat_epg = self._tenant_uses_specific_nat_epg(
            context, es, l3_policy)
        if uses_specific_nat_epg or not self.per_tenant_nat_epg:
            return

        nat_bd_name = self._get_nat_bd_for_es(context, es)
        nat_epg_name = self._get_nat_epg_for_es(context, es)
        nat_contract = self._get_nat_contract_for_es(context, es)
        nat_epg_tenant = self.name_mapper.tenant(l3_policy)
        es_tenant = self._tenant_by_sharing_policy(es)

        with self.apic_manager.apic.transaction(transaction) as trs:
            self.apic_manager.ensure_epg_created(
                nat_epg_tenant, nat_epg_name, bd_name=nat_bd_name,
                bd_owner=es_tenant, transaction=trs)
            self.apic_manager.set_contract_for_epg(
                nat_epg_tenant, nat_epg_name, nat_contract,
                transaction=trs)
            self.apic_manager.set_contract_for_epg(
                nat_epg_tenant, nat_epg_name, nat_contract, provider=True,
                transaction=trs)
        session = context._plugin_context.session
        with session.begin(subtransactions=True):
            db_obj = TenantSpecificNatEpg(
                external_segment_id=es['id'], tenant_id=l3_policy['tenant_id'])
            session.add(db_obj)
        LOG.debug('Created tenant-specific NAT EPG (%(tenant)s, %(epg)s) for '
                  'external segment %(es)s',
                  {'tenant': nat_epg_tenant, 'epg': nat_epg_name,
                   'es': es['id']})

    def _remove_tenant_specific_nat_epg(self, context, es, l3_policy,
                                        transaction=None):
        if not es['shared']:
            return
        uses_specific_nat_epg = self._tenant_uses_specific_nat_epg(
            context, es, l3_policy)
        if not uses_specific_nat_epg:
            return

        # remove NAT EPG if this is last L3P from this tenant
        l3ps = self._get_l3_policies(context._plugin_context.elevated(),
            filters={'id': [l3p for l3p in es['l3_policies']
                            if l3p != l3_policy['id']],
                     'tenant_id': [l3_policy['tenant_id']]})
        if not l3ps:
            session = context._plugin_context.session
            with session.begin(subtransactions=True):
                db_obj = session.query(TenantSpecificNatEpg).filter_by(
                    external_segment_id=es['id']).filter_by(
                        tenant_id=l3_policy['tenant_id']).first()
                if db_obj:
                    session.delete(db_obj)

            nat_epg_name = self._get_nat_epg_for_es(context, es)
            nat_epg_tenant = self.name_mapper.tenant(l3_policy)
            self.apic_manager.delete_epg_for_network(
                nat_epg_tenant, nat_epg_name, transaction=transaction)

            LOG.debug('Removed tenant-specific NAT EPG (%(tenant)s, %(epg)s) '
                      'for external segment %(es)s',
                      {'tenant': nat_epg_tenant, 'epg': nat_epg_name,
                       'es': es['id']})

    def _extract_ptg_explicit_eoc(self, plugin_context, ptg):
        """Extract PTG End of Chain

        Given a PTG, retrieves the explicit End of the Chain from its
        description and returns a Neutron port
        :return: Neutron port or None
        """
        if EOC_PREFIX in ptg.get('description', ''):
            return ptg['description'][len(EOC_PREFIX):]

    def _db_plugin(self, plugin_obj):
            return super(gbp_plugin.GroupPolicyPlugin, plugin_obj)

    def _get_auto_ptg_name(self, l2p):
        return AUTO_PTG_NAME_PREFIX % l2p['id']

    def _get_auto_ptg_id(self, l2p_id):
        return AUTO_PTG_ID_PREFIX % hashlib.md5(l2p_id).hexdigest()
