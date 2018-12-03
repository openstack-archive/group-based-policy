# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
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

from collections import defaultdict
from collections import namedtuple
import copy
import netaddr
import os
import re
import sqlalchemy as sa
from sqlalchemy import orm

from aim.aim_lib.db import model as aim_lib_model
from aim.aim_lib import nat_strategy
from aim import aim_manager
from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim.common import utils
from aim import context as aim_context
from aim import exceptions as aim_exceptions
from aim import utils as aim_utils
from neutron.agent import securitygroups_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics as n_topics
from neutron.db import api as db_api
from neutron.db.models import address_scope as as_db
from neutron.db.models import allowed_address_pair as n_addr_pair_db
from neutron.db.models import l3 as l3_db
from neutron.db.models import securitygroup as sg_models
from neutron.db.models import segment as segments_model
from neutron.db import models_v2
from neutron.db import provisioning_blocks
from neutron.db import rbac_db_models
from neutron.db import segments_db
from neutron.plugins.ml2 import db as n_db
from neutron.plugins.ml2 import driver_context as ml2_context
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as a_const)
from neutron.plugins.ml2 import models
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_constants
from neutron_lib import context as nctx
from neutron_lib import exceptions as n_exceptions
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from opflexagent import constants as ofcst
from opflexagent import host_agent_rpc as arpc
from opflexagent import rpc as ofrpc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
import oslo_messaging
from oslo_utils import importutils

from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_l3 as a_l3
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    constants as aim_cst)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import config  # noqa
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import exceptions
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import extension_db
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import trunk_driver

LOG = log.getLogger(__name__)
DEVICE_OWNER_SNAT_PORT = 'apic:snat-pool'
DEVICE_OWNER_SVI_PORT = 'apic:svi'

ANY_FILTER_NAME = 'AnyFilter'
ANY_FILTER_ENTRY_NAME = 'AnyFilterEntry'
DEFAULT_VRF_NAME = 'DefaultVRF'
UNROUTED_VRF_NAME = 'UnroutedVRF'
COMMON_TENANT_NAME = 'common'
ROUTER_SUBJECT_NAME = 'route'
DEFAULT_SG_NAME = 'DefaultSecurityGroup'
L3OUT_NODE_PROFILE_NAME = 'NodeProfile'
L3OUT_IF_PROFILE_NAME = 'IfProfile'
L3OUT_EXT_EPG = 'ExtEpg'

SUPPORTED_VNIC_TYPES = [portbindings.VNIC_NORMAL,
                        portbindings.VNIC_DIRECT]

AGENT_TYPE_DVS = 'DVS agent'
VIF_TYPE_DVS = 'dvs'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
VIF_TYPE_FABRIC = 'fabric'
FABRIC_HOST_ID = 'fabric'

NO_ADDR_SCOPE = object()

DVS_AGENT_KLASS = 'networking_vsphere.common.dvs_agent_rpc_api.DVSClientAPI'
DEFAULT_HOST_DOMAIN = '*'

LEGACY_SNAT_NET_NAME_PREFIX = 'host-snat-network-for-internal-use-'
LEGACY_SNAT_SUBNET_NAME = 'host-snat-pool-for-internal-use'
LEGACY_SNAT_PORT_NAME = 'host-snat-pool-port-for-internal-use'
LEGACY_SNAT_PORT_DEVICE_OWNER = 'host-snat-pool-port-device-owner-internal-use'

# TODO(kentwu): Move this to AIM utils maybe to avoid adding too much
# APIC logic to the mechanism driver
ACI_CHASSIS_DESCR_STRING = 'topology/pod-%s/node-%s'
ACI_PORT_DESCR_FORMATS = ('topology/pod-(\d+)/paths-(\d+)/pathep-'
                          '\[eth(\d+)/(\d+(\/\d+)*)\]')
ACI_VPCPORT_DESCR_FORMAT = ('topology/pod-(\d+)/protpaths-(\d+)-(\d+)/pathep-'
                            '\[(.*)\]')


InterfaceValidationInfo = namedtuple(
    'InterfaceValidationInfo',
    ['router_id', 'ip_address', 'subnet', 'scope_mapping'])


class KeystoneNotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        event_type='^identity.project.[updated|deleted]')

    def __init__(self, mechanism_driver):
        self._driver = mechanism_driver
        self._dvs_notifier = None

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        LOG.debug("Keystone notification getting called!")

        tenant_id = payload.get('resource_info')
        # malformed notification?
        if not tenant_id:
            return None

        if event_type == 'identity.project.updated':
            new_project_name = (self._driver.project_name_cache.
                                update_project_name(tenant_id))
            if not new_project_name:
                return None

            # we only update tenants which have been created in APIC. For other
            # cases, their nameAlias will be set when the first resource is
            # being created under that tenant
            session = db_api.get_writer_session()
            tenant_aname = self._driver.name_mapper.project(session, tenant_id)
            aim_ctx = aim_context.AimContext(session)
            tenant = aim_resource.Tenant(name=tenant_aname)
            if not self._driver.aim.get(aim_ctx, tenant):
                return None

            self._driver.aim.update(aim_ctx, tenant,
                display_name=aim_utils.sanitize_display_name(new_project_name))
            return oslo_messaging.NotificationResult.HANDLED

        if event_type == 'identity.project.deleted':
            if not self._driver.enable_keystone_notification_purge:
                return None

            self.tenant = tenant_id
            self._driver.project_name_cache.purge_gbp(self)

            # delete the tenant and AP in AIM also
            session = db_api.get_writer_session()
            tenant_aname = self._driver.name_mapper.project(session, tenant_id)
            aim_ctx = aim_context.AimContext(session)
            ap = aim_resource.ApplicationProfile(tenant_name=tenant_aname,
                                                 name=self._driver.ap_name)
            self._driver.aim.delete(aim_ctx, ap)
            tenant = aim_resource.Tenant(name=tenant_aname)
            self._driver.aim.delete(aim_ctx, tenant)

            return oslo_messaging.NotificationResult.HANDLED


class ApicMechanismDriver(api_plus.MechanismDriver,
                          db.DbMixin,
                          extension_db.ExtensionDbMixin):
    NIC_NAME_LEN = 14

    class TopologyRpcEndpoint(object):
        target = oslo_messaging.Target(version=arpc.VERSION)

        def __init__(self, mechanism_driver):
            self.md = mechanism_driver

        @db_api.retry_if_session_inactive()
        def update_link(self, context, *args, **kwargs):
            context._session = db_api.get_writer_session()
            return self.md.update_link(context, *args, **kwargs)

        @db_api.retry_if_session_inactive()
        def delete_link(self, context, *args, **kwargs):
            # Don't take any action on link deletion in order to tolerate
            # situations like fabric upgrade or flapping links. Old links
            # are removed once a specific host is attached somewhere else.
            # To completely decommission the host, aimctl can be used to
            # cleanup the hostlink table
            return

    def __init__(self):
        LOG.info("APIC AIM MD __init__")

    def initialize(self):
        LOG.info("APIC AIM MD initializing")
        self.project_name_cache = cache.ProjectNameCache()
        self.name_mapper = apic_mapper.APICNameMapper()
        self.aim = aim_manager.AimManager()
        self._core_plugin = None
        self._l3_plugin = None
        self._gbp_plugin = None
        self._gbp_driver = None
        # Get APIC configuration and subscribe for changes
        self.enable_metadata_opt = (
            cfg.CONF.ml2_apic_aim.enable_optimized_metadata)
        self.enable_dhcp_opt = (
            cfg.CONF.ml2_apic_aim.enable_optimized_dhcp)
        self.ap_name = 'OpenStack'
        self.apic_system_id = cfg.CONF.apic_system_id
        self.notifier = ofrpc.AgentNotifierApi(n_topics.AGENT)
        self.sg_enabled = securitygroups_rpc.is_firewall_enabled()
        # setup APIC topology RPC handler
        self.topology_conn = n_rpc.create_connection()
        self.topology_conn.create_consumer(arpc.TOPIC_APIC_SERVICE,
                                           [self.TopologyRpcEndpoint(self)],
                                           fanout=False)
        self.topology_conn.consume_in_threads()
        self.keystone_notification_exchange = (cfg.CONF.ml2_apic_aim.
                                               keystone_notification_exchange)
        self.keystone_notification_topic = (cfg.CONF.ml2_apic_aim.
                                            keystone_notification_topic)
        self._setup_keystone_notification_listeners()
        self.apic_optimized_dhcp_lease_time = (cfg.CONF.ml2_apic_aim.
                                               apic_optimized_dhcp_lease_time)
        self.enable_keystone_notification_purge = (cfg.CONF.ml2_apic_aim.
                                            enable_keystone_notification_purge)
        self.enable_iptables_firewall = (cfg.CONF.ml2_apic_aim.
                                         enable_iptables_firewall)
        self.l3_domain_dn = cfg.CONF.ml2_apic_aim.l3_domain_dn
        local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = True
        self._ensure_static_resources()
        trunk_driver.register()
        self.port_desc_re = re.compile(ACI_PORT_DESCR_FORMATS)
        self.vpcport_desc_re = re.compile(ACI_VPCPORT_DESCR_FORMAT)
        self.apic_router_id_pool = cfg.CONF.ml2_apic_aim.apic_router_id_pool
        self.apic_router_id_subnet = netaddr.IPSet([self.apic_router_id_pool])

    def _query_used_apic_router_ids(self, aim_ctx):
        used_ids = netaddr.IPSet()
        # Find the l3out_nodes created by us
        aim_l3out_nodes = self.aim.find(
            aim_ctx, aim_resource.L3OutNode,
            node_profile_name=L3OUT_NODE_PROFILE_NAME,
            monitored=False)
        for aim_l3out_node in aim_l3out_nodes:
            used_ids.add(aim_l3out_node.router_id)
        return used_ids

    def _allocate_apic_router_ids(self, aim_ctx, node_path):
        aim_l3out_nodes = self.aim.find(
            aim_ctx, aim_resource.L3OutNode,
            node_profile_name=L3OUT_NODE_PROFILE_NAME,
            node_path=node_path)
        for aim_l3out_node in aim_l3out_nodes:
            if aim_l3out_node.router_id:
                return aim_l3out_node.router_id
        used_ids = self._query_used_apic_router_ids(aim_ctx)
        available_ids = self.apic_router_id_subnet - used_ids
        for ip_address in available_ids:
            return str(ip_address)
        raise exceptions.ExhaustedApicRouterIdPool(
            pool=self.apic_router_id_pool)

    def _ensure_static_resources(self):
        session = db_api.get_writer_session()
        aim_ctx = aim_context.AimContext(session)
        self._ensure_common_tenant(aim_ctx)
        self._ensure_unrouted_vrf(aim_ctx)
        self._ensure_any_filter(aim_ctx)
        self._setup_default_arp_dhcp_security_group_rules(aim_ctx)

    def _setup_default_arp_dhcp_security_group_rules(self, aim_ctx):
        sg_name = self._default_sg_name
        dname = aim_utils.sanitize_display_name('DefaultSecurityGroup')
        sg = aim_resource.SecurityGroup(
            tenant_name=COMMON_TENANT_NAME, name=sg_name, display_name=dname)
        self.aim.create(aim_ctx, sg, overwrite=True)

        dname = aim_utils.sanitize_display_name('DefaultSecurityGroupSubject')
        sg_subject = aim_resource.SecurityGroupSubject(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name, name='default', display_name=dname)
        self.aim.create(aim_ctx, sg_subject, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupArpEgressRule')
        arp_egress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='arp_egress',
            display_name=dname,
            direction='egress',
            ethertype='arp',
            conn_track='normal')
        self.aim.create(aim_ctx, arp_egress_rule, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupArpIngressRule')
        arp_ingress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='arp_ingress',
            display_name=dname,
            direction='ingress',
            ethertype='arp',
            conn_track='normal')
        self.aim.create(aim_ctx, arp_ingress_rule, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupDhcpEgressRule')
        dhcp_egress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='dhcp_egress',
            display_name=dname,
            direction='egress',
            ethertype='ipv4',
            ip_protocol='udp',
            from_port='67',
            to_port='67',
            conn_track='normal')
        self.aim.create(aim_ctx, dhcp_egress_rule, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupDhcpIngressRule')
        dhcp_ingress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='dhcp_ingress',
            display_name=dname,
            direction='ingress',
            ethertype='ipv4',
            ip_protocol='udp',
            from_port='68',
            to_port='68',
            conn_track='normal')
        self.aim.create(aim_ctx, dhcp_ingress_rule, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupDhcp6EgressRule')
        dhcp6_egress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='dhcp6_egress',
            display_name=dname,
            direction='egress',
            ethertype='ipv6',
            ip_protocol='udp',
            from_port='547',
            to_port='547',
            conn_track='normal')
        self.aim.create(aim_ctx, dhcp6_egress_rule, overwrite=True)

        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupDhcp6IngressRule')
        dhcp6_ingress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='dhcp6_ingress',
            display_name=dname,
            direction='ingress',
            ethertype='ipv6',
            ip_protocol='udp',
            from_port='546',
            to_port='546',
            conn_track='normal')
        self.aim.create(aim_ctx, dhcp6_ingress_rule, overwrite=True)

        # Need this rule for the SLAAC traffic to go through
        dname = aim_utils.sanitize_display_name(
            'DefaultSecurityGroupIcmp6IngressRule')
        icmp6_ingress_rule = aim_resource.SecurityGroupRule(
            tenant_name=COMMON_TENANT_NAME,
            security_group_name=sg_name,
            security_group_subject_name='default',
            name='icmp6_ingress',
            display_name=dname,
            direction='ingress',
            ethertype='ipv6',
            ip_protocol='icmpv6',
            remote_ips=['::/0'])
        self.aim.create(aim_ctx, icmp6_ingress_rule, overwrite=True)

    def _setup_keystone_notification_listeners(self):
        targets = [oslo_messaging.Target(
                    exchange=self.keystone_notification_exchange,
                    topic=self.keystone_notification_topic, fanout=True)]
        endpoints = [KeystoneNotificationEndpoint(self)]
        pool = "cisco_aim_listener-workers"
        server = oslo_messaging.get_notification_listener(
            n_rpc.NOTIFICATION_TRANSPORT, targets, endpoints,
            executor='eventlet', pool=pool)
        server.start()

    def ensure_tenant(self, plugin_context, project_id):
        LOG.debug("APIC AIM MD ensuring AIM Tenant for project_id: %s",
                  project_id)

        if not project_id:
            # The l3_db module creates gateway ports with empty string
            # project IDs in order to hide those ports from
            # users. Since we are not currently mapping ports to
            # anything in AIM, we can ignore these. Any other cases
            # where empty string project IDs are used may require
            # mapping AIM resources under some actual Tenant.
            return

        self.project_name_cache.ensure_project(project_id)

        # TODO(rkukura): Move the following to calls made from
        # precommit methods so AIM Tenants, ApplicationProfiles, and
        # Filters are [re]created whenever needed.
        with db_api.context_manager.writer.using(plugin_context):
            session = plugin_context.session
            tenant_aname = self.name_mapper.project(session, project_id)
            project_name = self.project_name_cache.get_project_name(project_id)
            if project_name is None:
                project_name = ''
            aim_ctx = aim_context.AimContext(session)
            tenant = aim_resource.Tenant(
                name=tenant_aname, descr=self.apic_system_id,
                display_name=aim_utils.sanitize_display_name(project_name))
            # NOTE(ivar): by overwriting the existing tenant, we make sure
            # existing deployments will update their description value. This
            # however negates any change to the Tenant object done by direct
            # use of aimctl.
            self.aim.create(aim_ctx, tenant, overwrite=True)
            # REVISIT: Setting of display_name was added here to match
            # aim_lib behavior when it creates APs, but the
            # display_name aim_lib uses might vary.
            ap = aim_resource.ApplicationProfile(
                tenant_name=tenant_aname, name=self.ap_name,
                display_name=aim_utils.sanitize_display_name(self.ap_name))
            if not self.aim.get(aim_ctx, ap):
                self.aim.create(aim_ctx, ap)

    def _get_unique_domains(self, mappings):
        domains = []
        unique_domains = set()
        for mapping in mappings:
            if mapping.domain_name not in unique_domains:
                unique_domains.add(mapping.domain_name)
                domains.append({'type': mapping.domain_type,
                                'name': mapping.domain_name})
        return domains

    def _get_vmm_domains(self, aim_ctx, ns):
        domains = []
        if not isinstance(ns, nat_strategy.NoNatStrategy):
            aim_hd_mappings = self.aim.find(
                aim_ctx, aim_infra.HostDomainMappingV2,
                domain_type=utils.OPENSTACK_VMM_TYPE)
            if aim_hd_mappings:
                domains = self._get_unique_domains(aim_hd_mappings)
            if not domains:
                domains, _ = self.get_aim_domains(aim_ctx)
        return domains

    def create_network_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating network: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        if self._is_external(current):
            l3out, ext_net, ns = self._get_aim_nat_strategy(current)
            if not ext_net:
                return  # Unmanaged external network
            domains = self._get_vmm_domains(aim_ctx, ns)
            ns.create_l3outside(aim_ctx, l3out, vmm_domains=domains)
            ns.create_external_network(aim_ctx, ext_net)
            # Get external CIDRs for all external networks that share
            # this APIC external network.
            cidrs = sorted(
                self.get_external_cidrs_by_ext_net_dn(
                    session, ext_net.dn, lock_update=True))
            ns.update_external_cidrs(aim_ctx, ext_net, cidrs)

            for resource in ns.get_l3outside_resources(aim_ctx, l3out):
                if isinstance(resource, aim_resource.BridgeDomain):
                    bd = resource
                elif isinstance(resource, aim_resource.EndpointGroup):
                    epg = resource
                elif isinstance(resource, aim_resource.VRF):
                    vrf = resource
        elif self._is_svi(current):
            l3out, ext_net, _ = self._get_aim_external_objects(current)
            if ext_net:
                other_nets = set(
                    self.get_svi_network_ids_by_l3out_dn(
                        session, l3out.dn, lock_update=True))
                other_nets.discard(current['id'])
                if other_nets:
                    raise exceptions.PreExistingSVICannotUseSameL3out()

                aim_l3out_np = aim_resource.L3OutNodeProfile(
                    tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                    name=L3OUT_NODE_PROFILE_NAME)
                self.aim.create(aim_ctx, aim_l3out_np, overwrite=True)
                aim_l3out_ip = aim_resource.L3OutInterfaceProfile(
                    tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                    node_profile_name=L3OUT_NODE_PROFILE_NAME,
                    name=L3OUT_IF_PROFILE_NAME)
                self.aim.create(aim_ctx, aim_l3out_ip, overwrite=True)
            # This means no DN is being provided. Then we should try to create
            # the l3out automatically
            else:
                tenant_aname = self.name_mapper.project(session,
                                                        current['tenant_id'])
                vrf = self._map_default_vrf(session, current)
                vrf = self._ensure_default_vrf(aim_ctx, vrf)
                aname = self.name_mapper.network(session, current['id'])
                dname = aim_utils.sanitize_display_name(current['name'])

                aim_l3out = aim_resource.L3Outside(
                    tenant_name=tenant_aname,
                    name=aname, display_name=dname, vrf_name=vrf.name,
                    l3_domain_dn=self.l3_domain_dn,
                    bgp_enable=self._is_bgp_enabled(current))
                self.aim.create(aim_ctx, aim_l3out)

                aim_l3out_np = aim_resource.L3OutNodeProfile(
                    tenant_name=tenant_aname, l3out_name=aname,
                    name=L3OUT_NODE_PROFILE_NAME)
                self.aim.create(aim_ctx, aim_l3out_np)
                aim_l3out_ip = aim_resource.L3OutInterfaceProfile(
                    tenant_name=tenant_aname, l3out_name=aname,
                    node_profile_name=L3OUT_NODE_PROFILE_NAME,
                    name=L3OUT_IF_PROFILE_NAME)
                self.aim.create(aim_ctx, aim_l3out_ip)

                aim_ext_net = aim_resource.ExternalNetwork(
                    tenant_name=tenant_aname,
                    l3out_name=aname, name=L3OUT_EXT_EPG)
                self.aim.create(aim_ctx, aim_ext_net)
                scope = "import-security"
                aggregate = ""
                if (self._is_bgp_enabled(current) and
                        current.get(cisco_apic.BGP_TYPE) == 'default_export'):
                    scope = "export-rtctrl,import-security"
                    aggregate = "export-rtctrl"
                aim_ext_subnet_ipv4 = aim_resource.ExternalSubnet(
                    tenant_name=tenant_aname,
                    l3out_name=aname,
                    external_network_name=L3OUT_EXT_EPG, cidr='0.0.0.0/0',
                    scope=scope,
                    aggregate=aggregate)
                self.aim.create(aim_ctx, aim_ext_subnet_ipv4)
                aim_ext_subnet_ipv6 = aim_resource.ExternalSubnet(
                    tenant_name=tenant_aname,
                    l3out_name=aname,
                    external_network_name=L3OUT_EXT_EPG, cidr='::/0',
                    scope=scope,
                    aggregate=aggregate)
                self.aim.create(aim_ctx, aim_ext_subnet_ipv6)

                self._add_network_mapping(session, current['id'], None, None,
                                          vrf, aim_ext_net)
            return
        else:
            bd, epg = self._map_network(session, current)

            dname = aim_utils.sanitize_display_name(current['name'])
            vrf = self._map_unrouted_vrf()

            bd.display_name = dname
            bd.vrf_name = vrf.name
            bd.enable_arp_flood = True
            bd.enable_routing = False
            bd.limit_ip_learn_to_subnets = True
            # REVISIT(rkukura): When AIM changes default
            # ep_move_detect_mode value to 'garp', remove it here.
            bd.ep_move_detect_mode = 'garp'
            self.aim.create(aim_ctx, bd)

            epg.display_name = dname
            epg.bd_name = bd.name
            self.aim.create(aim_ctx, epg)

        self._add_network_mapping_and_notify(
            context._plugin_context, current['id'], bd, epg, vrf)

    def update_network_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating network: %s", current)

        # TODO(amitbose) - Handle inter-conversion between external and
        # private networks

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        mapping = self._get_network_mapping(session, current['id'])

        is_ext = self._is_external(current)
        # REVISIT: Remove is_ext from condition and add UT for
        # updating external network name.
        if (not is_ext and
            current['name'] != original['name']):
            dname = aim_utils.sanitize_display_name(current['name'])
            if not self._is_svi(current):
                bd = self._get_network_bd(mapping)
                self.aim.update(aim_ctx, bd, display_name=dname)
                epg = self._get_network_epg(mapping)
                self.aim.update(aim_ctx, epg, display_name=dname)
            else:
                l3out = self._get_network_l3out(mapping)
                if l3out:
                    self.aim.update(aim_ctx, l3out, display_name=dname)

        if is_ext:
            _, ext_net, ns = self._get_aim_nat_strategy(current)
            if ext_net:
                old = sorted(original[cisco_apic.EXTERNAL_CIDRS])
                new = sorted(current[cisco_apic.EXTERNAL_CIDRS])
                if old != new:
                    # Get external CIDRs for all external networks that share
                    # this APIC external network.
                    cidrs = sorted(
                        self.get_external_cidrs_by_ext_net_dn(
                            session, ext_net.dn, lock_update=True))
                    ns.update_external_cidrs(aim_ctx, ext_net, cidrs)
                # TODO(amitbose) Propagate name updates to AIM
        else:
            # BGP config is supported only for svi networks.
            if not self._is_svi(current):
                return
            # Check for pre-existing l3out SVI.
            network_db = self.plugin._get_network(context._plugin_context,
                                                  current['id'])
            if network_db.aim_extension_mapping.external_network_dn:
                ext_net = aim_resource.ExternalNetwork.from_dn(
                    network_db.aim_extension_mapping.external_network_dn)
            # Handle BGP enable state update.
            bgp_enable_trigger = False
            if self._is_bgp_enabled(current) != original.get(cisco_apic.BGP):
                if self._is_bgp_enabled(current):
                    bgp_enable_trigger = True
                if not network_db.aim_extension_mapping.external_network_dn:
                    l3out = self._get_network_l3out(mapping)
                    self.aim.update(aim_ctx, l3out,
                                    bgp_enable=self._is_bgp_enabled(current))
            scope = "import-security"
            aggregate = ""
            # Handle pre-existing SVI where mapping is not present.
            if not network_db.aim_extension_mapping.external_network_dn:
                tenant_name = mapping.l3out_tenant_name
                l3out_name = mapping.l3out_name
                l3out_ext_subnet_v4 = (
                    self._get_network_l3out_default_ext_subnetv4(mapping))
                l3out_ext_subnet_v6 = (
                    self._get_network_l3out_default_ext_subnetv6(mapping))
            else:
                tenant_name = ext_net.tenant_name
                l3out_name = ext_net.l3out_name

            # Handle BGP disable trigger.
            if (not self._is_bgp_enabled(current) and
                    original.get(cisco_apic.BGP)):
                if not network_db.aim_extension_mapping.external_network_dn:
                    self.aim.update(aim_ctx, l3out_ext_subnet_v4, scope=scope,
                                    aggregate=aggregate)
                    self.aim.update(aim_ctx, l3out_ext_subnet_v6, scope=scope,
                                    aggregate=aggregate)
                l3out_bgp_peers = self.aim.find(
                    aim_ctx,
                    aim_resource.L3OutInterfaceBgpPeerP,
                    tenant_name=tenant_name,
                    l3out_name=l3out_name)
                for peer in l3out_bgp_peers:
                    if not peer.monitored:
                        self.aim.delete(aim_ctx, peer)
                return
            # When BGP is disabled, don't act on updates to bgp params.
            if not self._is_bgp_enabled(current):
                return
            # Handle BGP_ASN update.
            asn_changed = (current.get(cisco_apic.BGP_ASN) !=
                           original.get(cisco_apic.BGP_ASN))
            asn = (current.get(cisco_apic.BGP_ASN) if
                   cisco_apic.BGP_ASN in current else
                   original[cisco_apic.BGP_ASN])
            if asn_changed:
                l3out_bgp_peers = self.aim.find(
                    aim_ctx, aim_resource.L3OutInterfaceBgpPeerP,
                    tenant_name=tenant_name,
                    l3out_name=l3out_name)
                for peer in l3out_bgp_peers:
                    self.aim.update(aim_ctx, peer, asn=asn)
            if (current.get(cisco_apic.BGP_TYPE) != original.get(
                cisco_apic.BGP_TYPE)) or bgp_enable_trigger:
                if current.get(cisco_apic.BGP_TYPE) == 'default_export':
                    scope = "export-rtctrl,import-security"
                    aggregate = "export-rtctrl"
                    l3out_ifs = self.aim.find(
                        aim_ctx, aim_resource.L3OutInterface,
                        tenant_name=tenant_name,
                        l3out_name=l3out_name)
                    for l3out_if in l3out_ifs:
                        if not l3out_if.monitored:
                            primary = netaddr.IPNetwork(
                                l3out_if.primary_addr_a)
                            subnet = str(primary.cidr)
                            aim_bgp_peer_prefix = (
                                aim_resource.L3OutInterfaceBgpPeerP(
                                    tenant_name=l3out_if.tenant_name,
                                    l3out_name=l3out_if.l3out_name,
                                    node_profile_name=
                                    l3out_if.node_profile_name,
                                    interface_profile_name=
                                    l3out_if.interface_profile_name,
                                    interface_path=l3out_if.interface_path,
                                    addr=subnet,
                                    asn=asn))
                            self.aim.create(aim_ctx, aim_bgp_peer_prefix,
                                            overwrite=True)
                elif current.get(cisco_apic.BGP_TYPE) == '':
                    l3out_bgp_peers = self.aim.find(
                        aim_ctx,
                        aim_resource.L3OutInterfaceBgpPeerP,
                        tenant_name=tenant_name,
                        l3out_name=l3out_name)
                    for peer in l3out_bgp_peers:
                        if not peer.monitored:
                            self.aim.delete(aim_ctx, peer)
                if not network_db.aim_extension_mapping.external_network_dn:
                    self.aim.update(aim_ctx, l3out_ext_subnet_v4, scope=scope,
                                    aggregate=aggregate)
                    self.aim.update(aim_ctx, l3out_ext_subnet_v6, scope=scope,
                                    aggregate=aggregate)

    def delete_network_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting network: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        if self._is_external(current):
            l3out, ext_net, ns = self._get_aim_nat_strategy(current)
            if not ext_net:
                return  # Unmanaged external network
            # REVISIT: lock_update=True is needed to handle races. Find
            # alternative solutions since Neutron discourages using such
            # queries.
            other_nets = set(
                self.get_network_ids_by_ext_net_dn(
                    session, ext_net.dn, lock_update=True))
            other_nets.discard(current['id'])
            if not other_nets:
                ns.delete_external_network(aim_ctx, ext_net)
            other_nets = set(
                self.get_network_ids_by_l3out_dn(
                    session, l3out.dn, lock_update=True))
            other_nets.discard(current['id'])
            if not other_nets:
                ns.delete_l3outside(aim_ctx, l3out)
        elif self._is_svi(current):
            l3out, ext_net, _ = self._get_aim_external_objects(current)
            aim_l3out = self.aim.get(aim_ctx, l3out)
            if not aim_l3out:
                return
            # this means its pre-existing l3out
            if aim_l3out.monitored:
                # just delete everything under NodeProfile
                aim_l3out_np = aim_resource.L3OutNodeProfile(
                    tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                    name=L3OUT_NODE_PROFILE_NAME)
                self.aim.delete(aim_ctx, aim_l3out_np, cascade=True)
            else:
                self.aim.delete(aim_ctx, l3out, cascade=True)
                # Before we can clean up the default vrf, we have to
                # remove the association in the network_mapping first.
                mapping = self._get_network_mapping(session, current['id'])
                if mapping:
                    self._set_network_vrf(mapping, self._map_unrouted_vrf())
                vrf = self._map_default_vrf(session, current)
                self._cleanup_default_vrf(aim_ctx, vrf)
        else:
            mapping = self._get_network_mapping(session, current['id'])
            if mapping:
                bd = self._get_network_bd(mapping)
                self.aim.delete(aim_ctx, bd)
                epg = self._get_network_epg(mapping)
                self.aim.delete(aim_ctx, epg)
                session.delete(mapping)

    def extend_network_dict_bulk(self, session, results, single=False):
        # Gather db objects
        aim_ctx = aim_context.AimContext(session)
        aim_resources = []
        res_dict_by_aim_res_dn = {}

        for res_dict, net_db in results:
            res_dict[cisco_apic.SYNC_STATE] = cisco_apic.SYNC_NOT_APPLICABLE
            res_dict[cisco_apic.DIST_NAMES] = {}
            mapping = net_db.aim_mapping
            dist_names = res_dict.setdefault(cisco_apic.DIST_NAMES, {})
            if not mapping and single:
                # Needed because of commit
                # d8c1e153f88952b7670399715c2f88f1ecf0a94a in Neutron that
                # put the extension call in Pike+ *before* the precommit
                # calls happen in network creation. I believe this is a but
                # and should be discussed with the Neutron team.
                mapping = self._get_network_mapping(session, net_db.id)
            if mapping:
                if mapping.epg_name:
                    bd = self._get_network_bd(mapping)
                    dist_names[cisco_apic.BD] = bd.dn
                    epg = self._get_network_epg(mapping)
                    dist_names[cisco_apic.EPG] = epg.dn
                    aim_resources.extend([bd, epg])
                    res_dict_by_aim_res_dn[epg.dn] = res_dict
                    res_dict_by_aim_res_dn[bd.dn] = res_dict
                elif mapping.l3out_name:
                    l3out_ext_net = self._get_network_l3out_ext_net(mapping)
                    dist_names[cisco_apic.EXTERNAL_NETWORK] = l3out_ext_net.dn
                    aim_resources.append(l3out_ext_net)
                    res_dict_by_aim_res_dn[l3out_ext_net.dn] = res_dict

                vrf = self._get_network_vrf(mapping)
                dist_names[cisco_apic.VRF] = vrf.dn
                aim_resources.append(vrf)
                res_dict_by_aim_res_dn[vrf.dn] = res_dict
            if not net_db.aim_extension_mapping and single:
                # Needed because of commit
                # d8c1e153f88952b7670399715c2f88f1ecf0a94a in Neutron that
                # put the extension call in Pike+ *before* the precommit
                # calls happen in network creation. I believe this is a but
                # and should be discussed with the Neutron team.
                ext_dict = self.get_network_extn_db(session, net_db.id)
            else:
                ext_dict = self.make_network_extn_db_conf_dict(
                    net_db.aim_extension_mapping,
                    net_db.aim_extension_cidr_mapping,
                    net_db.aim_extension_domain_mapping)
            if cisco_apic.EXTERNAL_NETWORK in ext_dict:
                dn = ext_dict.pop(cisco_apic.EXTERNAL_NETWORK)
                a_ext_net = aim_resource.ExternalNetwork.from_dn(dn)
                res_dict.setdefault(cisco_apic.DIST_NAMES, {})[
                    cisco_apic.EXTERNAL_NETWORK] = dn
                aim_resources.append(a_ext_net)
                res_dict_by_aim_res_dn[a_ext_net.dn] = res_dict

            res_dict.update(ext_dict)

        # Merge statuses
        for status in self.aim.get_statuses(aim_ctx, aim_resources):
            res_dict = res_dict_by_aim_res_dn.get(status.resource_dn, {})
            res_dict[cisco_apic.SYNC_STATE] = self._merge_status(
                aim_ctx,
                res_dict.get(cisco_apic.SYNC_STATE,
                             cisco_apic.SYNC_NOT_APPLICABLE),
                None, status=status)

    def extend_network_dict(self, session, network_db, result):
        if result.get(api_plus.BULK_EXTENDED):
            return
        LOG.debug("APIC AIM MD extending dict for network: %s", result)
        self.extend_network_dict_bulk(session, [(result, network_db)],
                                      single=True)

    def create_subnet_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        if network_db.external is not None and current['gateway_ip']:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            # Check subnet overlap with subnets from other Neutron
            # external networks that map to the same APIC L3Out
            other_nets = set(
                self.get_network_ids_by_l3out_dn(
                    session, l3out.dn, lock_update=True))
            other_nets.discard(network_id)
            cidrs = (session.query(models_v2.Subnet.cidr).filter(
                models_v2.Subnet.network_id.in_(other_nets)).all())
            cidrs = netaddr.IPSet([c[0] for c in cidrs])
            if cidrs & netaddr.IPSet([current['cidr']]):
                raise exceptions.ExternalSubnetOverlapInL3Out(
                    cidr=current['cidr'], l3out=l3out.dn)
            ns.create_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(current))

        # Limit 1 subnet per SVI network as each SVI interface
        # in ACI can only have 1 primary addr
        if self._is_svi_db(network_db):
            subnets_size = (session.query(models_v2.Subnet)
                            .filter(models_v2.Subnet.network_id == network_id)
                            .count())
            if subnets_size > 1:
                raise exceptions.OnlyOneSubnetInSVINetwork()

        # Neutron subnets in non-external networks are mapped to AIM
        # Subnets as they are added to routers as interfaces.

    def update_subnet_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        is_ext = network_db.external is not None
        session = context._plugin_context.session

        # If subnet is no longer a SNAT pool, check if SNAT IP ports
        # are allocated
        if (is_ext and original[cisco_apic.SNAT_HOST_POOL] and
            not current[cisco_apic.SNAT_HOST_POOL] and
            self._has_snat_ip_ports(context._plugin_context, current['id'])):
                raise exceptions.SnatPortsInUse(subnet_id=current['id'])

        if (not is_ext and
            current['name'] != original['name']):
            # Nothing to be done for SVI network.
            if self._is_svi(context.network.current):
                return

            bd = self._get_network_bd(network_db.aim_mapping)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            current['id']):
                router_db = self.l3_plugin._get_router(context._plugin_context,
                                                       router_id)
                dname = aim_utils.sanitize_display_name(
                    router_db.name + "-" +
                    (current['name'] or current['cidr']))

                sn = self._map_subnet(current, gw_ip, bd)
                self.aim.update(aim_ctx, sn, display_name=dname)

        elif (is_ext and current['gateway_ip'] != original['gateway_ip']):

            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            if original['gateway_ip']:
                ns.delete_subnet(aim_ctx, l3out,
                                 self._subnet_to_gw_ip_mask(original))
            if current['gateway_ip']:
                ns.create_subnet(aim_ctx, l3out,
                                 self._subnet_to_gw_ip_mask(current))

    def delete_subnet_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting subnet: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = current['network_id']
        network_db = self.plugin._get_network(context._plugin_context,
                                              network_id)
        if network_db.external is not None and current['gateway_ip']:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if not ext_net:
                return  # Unmanaged external network
            ns.delete_subnet(aim_ctx, l3out,
                             self._subnet_to_gw_ip_mask(current))

        # Non-external neutron subnets are unmapped from AIM Subnets as
        # they are removed from routers.

    def extend_subnet_dict(self, session, subnet_db, result):
        if result.get(api_plus.BULK_EXTENDED):
            return
        LOG.debug("APIC AIM MD extending dict for subnet: %s", result)

        sync_state = cisco_apic.SYNC_NOT_APPLICABLE
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        network_db = (session.query(models_v2.Network).
                      filter_by(id=subnet_db.network_id).
                      one_or_none())
        if not network_db:
            LOG.warning("Network not found in extend_subnet_dict for %s",
                        result)
            return

        if network_db.external is not None:
            l3out, ext_net, ns = self._get_aim_nat_strategy_db(session,
                                                               network_db)
            if ext_net:
                sub = ns.get_subnet(aim_ctx, l3out,
                                    self._subnet_to_gw_ip_mask(subnet_db))
                if sub:
                    dist_names[cisco_apic.SUBNET] = sub.dn
                    sync_state = self._merge_status(aim_ctx, sync_state, sub)
        elif network_db.aim_mapping and network_db.aim_mapping.bd_name:
            bd = self._get_network_bd(network_db.aim_mapping)

            for gw_ip, router_id in self._subnet_router_ips(session,
                                                            subnet_db.id):
                sn = self._map_subnet(subnet_db, gw_ip, bd)
                dist_names[gw_ip] = sn.dn
                sync_state = self._merge_status(aim_ctx, sync_state, sn)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def update_subnetpool_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating subnetpool: %s", current)

        if 'address_scope_id' not in current:
            # address_scope_id may not be returned with update,
            # when "Fields" parameter is specified
            # TODO(annak): verify this
            return
        session = context._plugin_context.session

        current_scope_id = current['address_scope_id']
        original_scope_id = original['address_scope_id']
        if current_scope_id != original_scope_id:
            # Find router interfaces involving subnets from this pool.
            pool_id = current['id']
            rps = (session.query(l3_db.RouterPort).
                   join(models_v2.Port,
                        models_v2.Port.id == l3_db.RouterPort.port_id).
                   join(models_v2.IPAllocation,
                        models_v2.IPAllocation.port_id == models_v2.Port.id).
                   join(models_v2.Subnet,
                        models_v2.Subnet.id ==
                        models_v2.IPAllocation.subnet_id).
                   filter(models_v2.Subnet.subnetpool_id == pool_id,
                          l3_db.RouterPort.port_type ==
                          n_constants.DEVICE_OWNER_ROUTER_INTF).
                   all())
            if rps:
                # TODO(rkukura): Implement moving the effected router
                # interfaces from one scope to another, from scoped to
                # unscoped, and from unscoped to scoped. This might
                # require moving the BDs and EPGs of routed networks
                # associated with the pool to the new scope's
                # project's Tenant. With multi-scope routing, it also
                # might result in individual routers being associated
                # with more or fewer scopes. Updates from scoped to
                # unscoped might still need to be rejected due to
                # overlap within a Tenant's default VRF. For now, we
                # just reject the update.
                raise exceptions.ScopeUpdateNotSupported()

    def create_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD creating address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        id = current['id']

        # See if extension driver already created mapping.
        mapping = self._get_address_scope_mapping(session, id)
        if mapping:
            vrf = self._get_address_scope_vrf(mapping)
            scopes = self._get_address_scopes_owning_vrf(session, vrf)
            self._update_vrf_display_name(aim_ctx, vrf, scopes)
        else:
            dname = aim_utils.sanitize_display_name(current['name'])
            vrf = self._map_address_scope(session, current)
            vrf.display_name = dname
            self.aim.create(aim_ctx, vrf)
            self._add_address_scope_mapping(session, id, vrf)

        # ML2Plus does not extend address scope dict after precommit.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, vrf)
        current[cisco_apic.DIST_NAMES] = {cisco_apic.VRF: vrf.dn}
        current[cisco_apic.SYNC_STATE] = sync_state

    def update_address_scope_precommit(self, context):
        current = context.current
        original = context.original
        LOG.debug("APIC AIM MD updating address_scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        mapping = self._get_address_scope_mapping(session, current['id'])

        if current['name'] != original['name'] and mapping.vrf_owned:
            vrf = self._get_address_scope_vrf(mapping)
            scopes = self._get_address_scopes_owning_vrf(session, vrf)
            self._update_vrf_display_name(aim_ctx, vrf, scopes)

    def delete_address_scope_precommit(self, context):
        current = context.current
        LOG.debug("APIC AIM MD deleting address scope: %s", current)

        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        mapping = self._get_address_scope_mapping(session, current['id'])

        if mapping and mapping.vrf_owned:
            vrf = self._get_address_scope_vrf(mapping)
            session.delete(mapping)
            scopes = self._get_address_scopes_owning_vrf(session, vrf)
            self._update_vrf_display_name(aim_ctx, vrf, scopes)
            if not scopes:
                self.aim.delete(aim_ctx, vrf)

    def extend_address_scope_dict(self, session, scope, result):
        if result.get(api_plus.BULK_EXTENDED):
            return
        LOG.debug("APIC AIM MD extending dict for address scope: %s", result)

        # REVISIT: Consider moving to ApicExtensionDriver.

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        mapping = self._get_address_scope_mapping(session, scope.id)
        if mapping:
            vrf = self._get_address_scope_vrf(mapping)
            dist_names[cisco_apic.VRF] = vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def _update_vrf_display_name(self, aim_ctx, vrf, scopes):
        # Assumes scopes is sorted by ip_version.
        if not scopes:
            return
        elif (len(scopes) == 1 or not scopes[1].name or
              scopes[0].name == scopes[1].name):
            dname = scopes[0].name
        elif not scopes[0].name:
            dname = scopes[1].name
        else:
            dname = scopes[0].name + '-' + scopes[1].name
        dname = aim_utils.sanitize_display_name(dname)
        self.aim.update(aim_ctx, vrf, display_name=dname)

    def create_router(self, context, current):
        LOG.debug("APIC AIM MD creating router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        contract, subject = self._map_router(session, current)

        dname = aim_utils.sanitize_display_name(current['name'])

        contract.display_name = dname
        self.aim.create(aim_ctx, contract)

        subject.display_name = dname
        subject.bi_filters = [self._any_filter_name]
        self.aim.create(aim_ctx, subject)

        # External-gateway information about the router will be handled
        # when the first router-interface port is created

        # REVISIT(rkukura): Consider having L3 plugin extend router
        # dict again after calling this function.
        sync_state = cisco_apic.SYNC_SYNCED
        sync_state = self._merge_status(aim_ctx, sync_state, contract)
        sync_state = self._merge_status(aim_ctx, sync_state, subject)
        current[cisco_apic.DIST_NAMES] = {a_l3.CONTRACT: contract.dn,
                                          a_l3.CONTRACT_SUBJECT:
                                          subject.dn}
        current[cisco_apic.SYNC_STATE] = sync_state

    def update_router(self, context, current, original):
        LOG.debug("APIC AIM MD updating router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        if current['name'] != original['name']:
            contract, subject = self._map_router(session, current)

            name = current['name']
            dname = aim_utils.sanitize_display_name(name)

            self.aim.update(aim_ctx, contract, display_name=dname)
            self.aim.update(aim_ctx, subject, display_name=dname)

            # REVISIT(rkukura): Refactor to share common code below with
            # extend_router_dict.
            for intf in (session.query(models_v2.IPAllocation).
                         join(l3_db.RouterPort,
                              l3_db.RouterPort.port_id ==
                              models_v2.IPAllocation.port_id).
                         filter(l3_db.RouterPort.router_id == current['id'],
                                l3_db.RouterPort.port_type ==
                                n_constants.DEVICE_OWNER_ROUTER_INTF)):

                # TODO(rkukura): Avoid separate queries for these.
                subnet_db = (session.query(models_v2.Subnet).
                             filter_by(id=intf.subnet_id).
                             one())
                network_db = (session.query(models_v2.Network).
                              filter_by(id=subnet_db.network_id).
                              one())

                if network_db.aim_mapping and network_db.aim_mapping.bd_name:
                    dname = aim_utils.sanitize_display_name(
                        name + "-" + (subnet_db.name or subnet_db.cidr))
                    bd = self._get_network_bd(network_db.aim_mapping)
                    sn = self._map_subnet(subnet_db, intf.ip_address, bd)
                    self.aim.update(aim_ctx, sn, display_name=dname)

        def is_diff(old, new, attr):
            return sorted(old[attr]) != sorted(new[attr])

        old_net = (original.get('external_gateway_info') or
                   {}).get('network_id')
        new_net = (current.get('external_gateway_info') or
                   {}).get('network_id')
        if old_net and not new_net:
            self._delete_snat_ip_ports_if_reqd(context, old_net,
                                               current['id'])
        if ((old_net != new_net or
             is_diff(original, current, a_l3.EXTERNAL_PROVIDED_CONTRACTS) or
             is_diff(original, current, a_l3.EXTERNAL_CONSUMED_CONTRACTS)) and
            self._get_router_intf_count(session, current)):

            if old_net == new_net:
                old_net = None
                affected_port_ids = []
            else:
                # SNAT information of ports on the subnet that interface
                # with the router will change because router's gateway
                # changed.
                sub_ids = self._get_router_interface_subnets(session,
                                                             current['id'])
                affected_port_ids = self._get_non_router_ports_in_subnets(
                    session, sub_ids)

            old_net = self.plugin.get_network(context,
                                              old_net) if old_net else None
            new_net = self.plugin.get_network(context,
                                              new_net) if new_net else None
            vrfs = self._get_vrfs_for_router(session, current['id'])
            for vrf in vrfs:
                self._manage_external_connectivity(
                    context, current, old_net, new_net, vrf)

            # Send a port update so that SNAT info may be recalculated for
            # affected ports in the interfaced subnets.
            self._notify_port_update_bulk(context, affected_port_ids)

        # REVISIT(rkukura): Update extension attributes?

    def delete_router(self, context, current):
        LOG.debug("APIC AIM MD deleting router: %s", current)

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        # Handling of external-gateway information is done when the router
        # interface ports are deleted, or the external-gateway is
        # cleared through update_router. At least one of those need
        # to happen before a router can be deleted, so we don't
        # need to do anything special when router is deleted

        contract, subject = self._map_router(session, current)

        self.aim.delete(aim_ctx, subject)
        self.aim.delete(aim_ctx, contract)

    def extend_router_dict(self, session, router_db, result):
        if result.get(api_plus.BULK_EXTENDED):
            return
        LOG.debug("APIC AIM MD extending dict for router: %s", result)

        # REVISIT(rkukura): Consider optimizing this method by
        # persisting the router->VRF relationship.

        sync_state = cisco_apic.SYNC_SYNCED
        dist_names = {}
        aim_ctx = aim_context.AimContext(session)

        contract, subject = self._map_router(session, router_db)

        dist_names[a_l3.CONTRACT] = contract.dn
        sync_state = self._merge_status(aim_ctx, sync_state, contract)

        dist_names[a_l3.CONTRACT_SUBJECT] = subject.dn
        sync_state = self._merge_status(aim_ctx, sync_state, subject)

        # REVISIT: Do we really need to include Subnet DNs in
        # apic:distinguished_names and apic:synchronization_state?
        # Eliminating these would reduce or potentially eliminate (if
        # we persist the router->VRF mapping) the querying needed
        # here.
        unscoped_vrf = None
        scope_ids = set()
        for intf in (session.query(models_v2.IPAllocation.ip_address,
                                   models_v2.Subnet,
                                   models_v2.Network).
                     join(models_v2.Subnet,
                          models_v2.Subnet.id ==
                          models_v2.IPAllocation.subnet_id).
                     join(models_v2.Network,
                          models_v2.Network.id ==
                          models_v2.Subnet.network_id).
                     join(l3_db.RouterPort,
                          l3_db.RouterPort.port_id ==
                          models_v2.IPAllocation.port_id).
                     filter(l3_db.RouterPort.router_id == router_db.id,
                            l3_db.RouterPort.port_type ==
                            n_constants.DEVICE_OWNER_ROUTER_INTF)):
            ip_address, subnet_db, network_db = intf
            if not network_db.aim_mapping:
                LOG.warning(
                    "Mapping missing for network %s in extend_router_dict" %
                    network_db.id)
                continue

            if network_db.aim_mapping.bd_name:
                bd = self._get_network_bd(network_db.aim_mapping)
                sn = self._map_subnet(subnet_db, intf.ip_address, bd)
                dist_names[intf.ip_address] = sn.dn
                sync_state = self._merge_status(aim_ctx, sync_state, sn)

            scope_id = (subnet_db.subnetpool and
                        subnet_db.subnetpool.address_scope_id)
            if scope_id:
                scope_ids.add(scope_id)
            else:
                vrf = self._get_network_vrf(network_db.aim_mapping)
                if unscoped_vrf and unscoped_vrf.identity != vrf.identity:
                    # This should never happen. If it does, it
                    # indicates an inconsistency in the DB state
                    # rather than any sort of user error. We log an
                    # error to aid debugging in case such an
                    # inconsistency somehow does occur.
                    LOG.error("Inconsistent unscoped VRFs %s and %s for "
                              "router %s.", vrf, unscoped_vrf, router_db)
                unscoped_vrf = vrf

        for scope_id in scope_ids:
            scope_db = self._scope_by_id(session, scope_id)
            if not scope_db.aim_mapping:
                LOG.warning(
                    "Mapping missing for address scope %s in "
                    "extend_router_dict" % scope_db.id)
                continue

            vrf = self._get_address_scope_vrf(scope_db.aim_mapping)
            dist_names[a_l3.SCOPED_VRF % scope_id] = vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, vrf)

        if unscoped_vrf:
            dist_names[a_l3.UNSCOPED_VRF] = unscoped_vrf.dn
            sync_state = self._merge_status(aim_ctx, sync_state, unscoped_vrf)

        result[cisco_apic.DIST_NAMES] = dist_names
        result[cisco_apic.SYNC_STATE] = sync_state

    def add_router_interface(self, context, router, port, subnets):
        LOG.debug("APIC AIM MD adding subnets %(subnets)s to router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router, 'port': port})

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = port['network_id']
        network_db = self.plugin._get_network(context, network_id)

        # SVI network with pre-existing l3out is not allowed to be
        # connected to a router at this moment
        if self._is_preexisting_svi_db(network_db):
            raise exceptions.PreExistingSVICannotBeConnectedToRouter()

        # Find the address_scope(s) for the new interface.
        #
        # REVISIT: If dual-stack interfaces allowed, process each
        # stack's scope separately, or at least raise an exception.
        scope_id = self._get_address_scope_id_for_subnets(context, subnets)

        # Find number of existing interface ports on the router for
        # this scope, excluding the one we are adding.
        router_intf_count = self._get_router_intf_count(
            session, router, scope_id)

        # Find up to two existing router interfaces for this
        # network. The interface currently being added is not
        # included, because the RouterPort has not yet been added to
        # the DB session.
        net_intfs = (session.query(l3_db.RouterPort.router_id,
                                   models_v2.Subnet).
                     join(models_v2.IPAllocation,
                          models_v2.IPAllocation.port_id ==
                          l3_db.RouterPort.port_id).
                     join(models_v2.Subnet,
                          models_v2.Subnet.id ==
                          models_v2.IPAllocation.subnet_id).
                     filter(models_v2.Subnet.network_id == network_id,
                            l3_db.RouterPort.port_type ==
                            n_constants.DEVICE_OWNER_ROUTER_INTF).
                     limit(2).
                     all())
        if net_intfs:
            # Since the EPGs that provide/consume routers' contracts
            # are at network rather than subnet granularity,
            # topologies where different subnets on the same network
            # are interfaced to different routers, which are valid in
            # Neutron, would result in unintended routing. We
            # therefore require that all router interfaces for a
            # network share either the same router or the same subnet.
            #
            # REVISIT: Remove override flag when no longer needed for
            # GBP.
            if not context.override_network_routing_topology_validation:
                different_router = False
                different_subnet = False
                router_id = router['id']
                subnet_ids = [subnet['id'] for subnet in subnets]
                for existing_router_id, existing_subnet in net_intfs:
                    if router_id != existing_router_id:
                        different_router = True
                    for subnet_id in subnet_ids:
                        if subnet_id != existing_subnet.id:
                            different_subnet = True
                if different_router and different_subnet:
                    raise exceptions.UnsupportedRoutingTopology()

            # REVISIT: Remove this check for isomorphism once identity
            # NAT can be used to move IPv6 traffic from an IPv4 VRF to
            # the intended IPv6 VRF.
            _, subnet = net_intfs[0]
            existing_scope_id = (NO_ADDR_SCOPE if not subnet.subnetpool or
                                 not subnet.subnetpool.address_scope_id else
                                 subnet.subnetpool.address_scope_id)
            if scope_id != existing_scope_id:
                if (scope_id != NO_ADDR_SCOPE and
                    existing_scope_id != NO_ADDR_SCOPE):
                    scope_db = self._scope_by_id(session, scope_id)
                    vrf = self._get_address_scope_vrf(scope_db.aim_mapping)
                    existing_scope_db = self._scope_by_id(
                        session, existing_scope_id)
                    existing_vrf = self._get_address_scope_vrf(
                        existing_scope_db.aim_mapping)
                    if vrf.identity != existing_vrf.identity:
                        raise (exceptions.
                               NonIsomorphicNetworkRoutingUnsupported())
                else:
                    raise exceptions.NonIsomorphicNetworkRoutingUnsupported()

        nets_to_notify = set()
        ports_to_notify = set()
        router_topo_moved = False

        # Ensure that all the BDs and EPGs in the resulting topology
        # are mapped under the same Tenant so that the BDs can all
        # reference the topology's VRF and the EPGs can all provide
        # and consume the router's Contract. This is handled
        # differently for scoped and unscoped topologies.
        if scope_id != NO_ADDR_SCOPE:
            scope_db = self._scope_by_id(session, scope_id)
            vrf = self._get_address_scope_vrf(scope_db.aim_mapping)
        else:
            intf_topology = self._network_topology(session, network_db)
            router_topology = self._router_topology(session, router['id'])

            intf_shared_net = self._topology_shared(intf_topology)
            router_shared_net = self._topology_shared(router_topology)

            intf_vrf = self._map_default_vrf(
                session, intf_shared_net or network_db)
            router_vrf = (
                self._map_default_vrf(
                    session,
                    router_shared_net or router_topology.itervalues().next())
                if router_topology else None)

            # Choose VRF and move one topology if necessary.
            if router_vrf and intf_vrf.identity != router_vrf.identity:
                if intf_shared_net and router_shared_net:
                    raise exceptions.UnscopedSharedNetworkProjectConflict(
                        net1=intf_shared_net.id,
                        proj1=intf_shared_net.tenant_id,
                        net2=router_shared_net.id,
                        proj2=router_shared_net.tenant_id)
                elif intf_shared_net:
                    # Interface topology has shared network, so move
                    # router topology.
                    vrf = self._ensure_default_vrf(aim_ctx, intf_vrf)
                    self._move_topology(
                        context, aim_ctx, router_topology, router_vrf, vrf,
                        nets_to_notify)
                    router_topo_moved = True
                    self._cleanup_default_vrf(aim_ctx, router_vrf)
                elif router_shared_net:
                    # Router topology has shared network, so move
                    # interface topology, unless first interface for
                    # network.
                    vrf = router_vrf
                    if net_intfs:
                        self._move_topology(
                            context, aim_ctx, intf_topology, intf_vrf, vrf,
                            nets_to_notify)
                        self._cleanup_default_vrf(aim_ctx, intf_vrf)
                else:
                    # This should never happen.
                    LOG.error("Interface topology %(intf_topology)s and "
                              "router topology %(router_topology)s have "
                              "different VRFs, but neither is shared",
                              {'intf_topology': intf_topology,
                               'router_topology': router_topology})
                    raise exceptions.InternalError()
            else:
                vrf = self._ensure_default_vrf(aim_ctx, intf_vrf)

        epg = None
        # Associate or map network, depending on whether it has other
        # interfaces.
        if not net_intfs:
            # First interface for network.
            if network_db.aim_mapping.epg_name:
                bd, epg = self._associate_network_with_vrf(
                    context, aim_ctx, network_db, vrf, nets_to_notify)
            elif network_db.aim_mapping.l3out_name:
                l3out, epg = self._associate_network_with_vrf(
                    context, aim_ctx, network_db, vrf, nets_to_notify)
        else:
            # Network is already routed.
            #
            # REVISIT: For non-isomorphic dual-stack network, may need
            # to move the BD and EPG from already-routed v6 VRF to
            # newly-routed v4 VRF, and setup identity NAT for the v6
            # traffic.
            if network_db.aim_mapping.epg_name:
                bd = self._get_network_bd(network_db.aim_mapping)
                epg = self._get_network_epg(network_db.aim_mapping)
            elif network_db.aim_mapping.l3out_name:
                epg = self._get_network_l3out_ext_net(
                    network_db.aim_mapping)

        if network_db.aim_mapping.epg_name:
            # Create AIM Subnet(s) for each added Neutron subnet.
            for subnet in subnets:
                gw_ip = self._ip_for_subnet(subnet, port['fixed_ips'])

                dname = aim_utils.sanitize_display_name(
                    router['name'] + "-" +
                    (subnet['name'] or subnet['cidr']))

                sn = self._map_subnet(subnet, gw_ip, bd)
                sn.display_name = dname
                sn = self.aim.create(aim_ctx, sn)

        # Ensure network's EPG provides/consumes router's Contract.
        contract = self._map_router(session, router, True)

        # this could be internal or external EPG
        epg = self.aim.get(aim_ctx, epg)
        if epg:
            contracts = epg.consumed_contract_names
            if contract.name not in contracts:
                contracts.append(contract.name)
                epg = self.aim.update(aim_ctx, epg,
                                      consumed_contract_names=contracts)
            contracts = epg.provided_contract_names
            if contract.name not in contracts:
                contracts.append(contract.name)
                epg = self.aim.update(aim_ctx, epg,
                                      provided_contract_names=contracts)

        # If external-gateway is set, handle external-connectivity changes.
        # External network is not supported for SVI network for now.
        if router.gw_port_id and not self._is_svi_db(network_db):
            net = self.plugin.get_network(context,
                                          router.gw_port.network_id)
            # If this is first interface-port, then that will determine
            # the VRF for this router. Setup external-connectivity for VRF.
            if not router_intf_count:
                self._manage_external_connectivity(context, router, None, net,
                                                   vrf)
            elif router_topo_moved:
                # Router moved from router_vrf to vrf, so
                # 1. Update router_vrf's external connectivity to exclude
                #    router
                # 2. Update vrf's external connectivity to include router
                self._manage_external_connectivity(context, router, net, None,
                                                   router_vrf)
                self._manage_external_connectivity(context, router, None, net,
                                                   vrf)

            aim_l3out, _, ns = self._get_aim_nat_strategy(net)
            if aim_l3out and ns:
                ns.set_bd_l3out(aim_ctx, bd, aim_l3out)

            # SNAT information of ports on the subnet will change because
            # of router interface addition. Send a port update so that it may
            # be recalculated.
            port_ids = self._get_non_router_ports_in_subnets(
                session,
                [subnet['id'] for subnet in subnets])
            ports_to_notify.update(port_ids)

        # Enqueue notifications for all affected ports.
        if nets_to_notify:
            port_ids = self._get_non_router_ports_in_networks(
                session, nets_to_notify)
            ports_to_notify.update(port_ids)
        if ports_to_notify:
            self._notify_port_update_bulk(context, ports_to_notify)

    def remove_router_interface(self, context, router_id, port, subnets):
        LOG.debug("APIC AIM MD removing subnets %(subnets)s from router "
                  "%(router)s as interface port %(port)s",
                  {'subnets': subnets, 'router': router_id, 'port': port})

        session = context.session
        aim_ctx = aim_context.AimContext(session)

        network_id = port['network_id']
        network_db = self.plugin._get_network(context, network_id)

        # Find the address_scope(s) for the old interface.
        #
        # REVISIT: If dual-stack interfaces allowed, process each
        # stack's scope separately, or at least raise an exception.
        scope_id = self._get_address_scope_id_for_subnets(context, subnets)

        router_db = (session.query(l3_db.Router).
                     filter_by(id=router_id).
                     one())
        contract = self._map_router(session, router_db, True)

        epg = None
        old_vrf = self._get_network_vrf(network_db.aim_mapping)
        if network_db.aim_mapping.epg_name:
            bd = self._get_network_bd(network_db.aim_mapping)
            epg = self._get_network_epg(network_db.aim_mapping)
            # Remove AIM Subnet(s) for each removed Neutron subnet.
            for subnet in subnets:
                gw_ip = self._ip_for_subnet(subnet, port['fixed_ips'])
                sn = self._map_subnet(subnet, gw_ip, bd)
                self.aim.delete(aim_ctx, sn)
        # SVI network with auto l3out.
        elif network_db.aim_mapping.l3out_name:
            epg = self._get_network_l3out_ext_net(network_db.aim_mapping)

        # Find remaining routers with interfaces to this network.
        router_ids = [r[0] for r in
                      session.query(l3_db.RouterPort.router_id).
                      join(models_v2.Port,
                           models_v2.Port.id == l3_db.RouterPort.port_id).
                      filter(models_v2.Port.network_id == network_id,
                             l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).distinct()]

        # If network is no longer connected to this router, stop
        # network's EPG from providing/consuming this router's
        # Contract.
        if router_id not in router_ids and epg:
            epg = self.aim.get(aim_ctx, epg)

            contracts = [name for name in epg.consumed_contract_names
                         if name != contract.name]
            epg = self.aim.update(aim_ctx, epg,
                                  consumed_contract_names=contracts)

            contracts = [name for name in epg.provided_contract_names
                         if name != contract.name]
            epg = self.aim.update(aim_ctx, epg,
                                  provided_contract_names=contracts)

        nets_to_notify = set()
        ports_to_notify = set()
        router_topo_moved = False

        # If unscoped topologies have split, move VRFs as needed.
        #
        # REVISIT: For non-isomorphic dual-stack network, may need to
        # move the BD and EPG from the previously-routed v4 VRF to the
        # still-routed v6 VRF, and disable identity NAT for the v6
        # traffic.
        if scope_id == NO_ADDR_SCOPE:
            # If the interface's network has not become unrouted, see
            # if its topology must be moved.
            if router_ids:
                intf_topology = self._network_topology(session, network_db)
                intf_shared_net = self._topology_shared(intf_topology)
                intf_vrf = self._map_default_vrf(
                    session, intf_shared_net or network_db)
                if old_vrf.identity != intf_vrf.identity:
                    intf_vrf = self._ensure_default_vrf(aim_ctx, intf_vrf)
                    self._move_topology(
                        context, aim_ctx, intf_topology, old_vrf, intf_vrf,
                        nets_to_notify)

            # See if the router's topology must be moved.
            router_topology = self._router_topology(session, router_db.id)
            if router_topology:
                router_shared_net = self._topology_shared(router_topology)
                router_vrf = self._map_default_vrf(
                    session,
                    router_shared_net or router_topology.itervalues().next())
                if old_vrf.identity != router_vrf.identity:
                    router_vrf = self._ensure_default_vrf(aim_ctx, router_vrf)
                    self._move_topology(
                        context, aim_ctx, router_topology, old_vrf, router_vrf,
                        nets_to_notify)
                    router_topo_moved = True

        # If network is no longer connected to any router, make the
        # network's BD unrouted.
        if not router_ids:
            self._dissassociate_network_from_vrf(
                context, aim_ctx, network_db, old_vrf, nets_to_notify)
            if scope_id == NO_ADDR_SCOPE:
                self._cleanup_default_vrf(aim_ctx, old_vrf)

        # If external-gateway is set, handle external-connectivity changes.
        # External network is not supproted for SVI network for now.
        if router_db.gw_port_id and not self._is_svi_db(network_db):
            net = self.plugin.get_network(context,
                                          router_db.gw_port.network_id)
            # If this was the last interface for this VRF for this
            # router, update external-conectivity to exclude this
            # router.
            if not self._get_router_intf_count(session, router_db, scope_id):
                self._manage_external_connectivity(
                    context, router_db, net, None, old_vrf)

                self._delete_snat_ip_ports_if_reqd(context, net['id'],
                                                   router_id)
            elif router_topo_moved:
                # Router moved from old_vrf to router_vrf, so
                # 1. Update old_vrf's external connectivity to exclude router
                # 2. Update router_vrf's external connectivity to include
                #    router
                self._manage_external_connectivity(context, router_db, net,
                                                   None, old_vrf)
                self._manage_external_connectivity(context, router_db, None,
                                                   net, router_vrf)

            # If network is no longer connected to this router
            if router_id not in router_ids:
                aim_l3out, _, ns = self._get_aim_nat_strategy(net)
                if aim_l3out and ns:
                    ns.unset_bd_l3out(aim_ctx, bd, aim_l3out)

            # SNAT information of ports on the subnet will change because
            # of router interface removal. Send a port update so that it may
            # be recalculated.
            port_ids = self._get_non_router_ports_in_subnets(
                session,
                [subnet['id'] for subnet in subnets])
            ports_to_notify.update(port_ids)

        # Enqueue notifications for all affected ports.
        if nets_to_notify:
            port_ids = self._get_non_router_ports_in_networks(
                session, nets_to_notify)
            ports_to_notify.update(port_ids)
        if ports_to_notify:
            self._notify_port_update_bulk(context, ports_to_notify)

    def bind_port(self, context):
        port = context.current
        LOG.debug("Attempting to bind port %(port)s on network %(net)s",
                  {'port': port['id'],
                   'net': context.network.current['id']})

        # Check the VNIC type.
        vnic_type = port.get(portbindings.VNIC_TYPE,
                             portbindings.VNIC_NORMAL)
        if vnic_type not in SUPPORTED_VNIC_TYPES:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        if port[portbindings.HOST_ID].startswith(FABRIC_HOST_ID):
            for segment in context.segments_to_bind:
                context.set_binding(segment[api.ID],
                                    VIF_TYPE_FABRIC,
                                    {portbindings.CAP_PORT_FILTER: False},
                                    status=n_constants.PORT_STATUS_ACTIVE)
                return

        is_vm_port = port['device_owner'].startswith('compute:')

        if (is_vm_port and self.gbp_driver and not
            self.gbp_driver.check_allow_vm_names(context, port)):
            return

        if vnic_type in [portbindings.VNIC_NORMAL]:
            if is_vm_port:
                # For compute ports, try to bind DVS agent first.
                if self._agent_bind_port(context, AGENT_TYPE_DVS,
                                         self._dvs_bind_port):
                    return

            # Try to bind OpFlex agent.
            if self._agent_bind_port(context, ofcst.AGENT_TYPE_OPFLEX_OVS,
                                     self._opflex_bind_port):
                return

            # Try to bind OpFlex VPP agent.
            if self._agent_bind_port(context, ofcst.AGENT_TYPE_OPFLEX_VPP,
                                     self._opflex_bind_port):
                return

        # If we reached here, it means that either there is no active opflex
        # agent running on the host, or the agent on the host is not
        # configured for this physical network. Treat the host as a physical
        # node (i.e. has no OpFlex agent running) and try binding
        # hierarchically if the network-type is OpFlex.
        self._bind_physical_node(context)

    def _update_sg_rule_with_remote_group_set(self, context, port):
        security_groups = port['security_groups']
        original_port = context.original
        if original_port:
            removed_sgs = (set(original_port['security_groups']) -
                           set(security_groups))
            added_sgs = (set(security_groups) -
                         set(original_port['security_groups']))
            self._really_update_sg_rule_with_remote_group_set(
                                context, port, removed_sgs, is_delete=True)
            self._really_update_sg_rule_with_remote_group_set(
                                context, port, added_sgs, is_delete=False)

    def _really_update_sg_rule_with_remote_group_set(
                    self, context, port, security_groups, is_delete):
        if not security_groups:
            return
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        sg_rules = (session.query(sg_models.SecurityGroupRule).
                    filter(sg_models.SecurityGroupRule.remote_group_id.
                           in_(security_groups)).
                    all())
        fixed_ips = [x['ip_address'] for x in port['fixed_ips']]
        for sg_rule in sg_rules:
            tenant_aname = self.name_mapper.project(session,
                                                    sg_rule['tenant_id'])
            sg_rule_aim = aim_resource.SecurityGroupRule(
                tenant_name=tenant_aname,
                security_group_name=sg_rule['security_group_id'],
                security_group_subject_name='default',
                name=sg_rule['id'])
            aim_sg_rule = self.aim.get(aim_ctx, sg_rule_aim)
            if not aim_sg_rule:
                continue
            ip_version = 0
            if sg_rule['ethertype'] == 'IPv4':
                ip_version = 4
            elif sg_rule['ethertype'] == 'IPv6':
                ip_version = 6
            for fixed_ip in fixed_ips:
                if is_delete:
                    if fixed_ip in aim_sg_rule.remote_ips:
                        aim_sg_rule.remote_ips.remove(fixed_ip)
                elif ip_version == netaddr.IPAddress(fixed_ip).version:
                    if fixed_ip not in aim_sg_rule.remote_ips:
                        aim_sg_rule.remote_ips.append(fixed_ip)
            self.aim.update(aim_ctx, sg_rule_aim,
                            remote_ips=aim_sg_rule.remote_ips)

    def create_port_precommit(self, context):
        port = context.current
        self._really_update_sg_rule_with_remote_group_set(
            context, port, port['security_groups'], is_delete=False)
        self._insert_provisioning_block(context)

    def _insert_provisioning_block(self, context):
        # we insert a status barrier to prevent the port from transitioning
        # to active until the agent reports back that the wiring is done
        port = context.current
        if (not context.host or
                port['status'] == n_constants.PORT_STATUS_ACTIVE):
            # no point in putting in a block if the status is already ACTIVE
            return

        # Check the VNIC type.
        vnic_type = port.get(portbindings.VNIC_TYPE,
                             portbindings.VNIC_NORMAL)
        if vnic_type not in SUPPORTED_VNIC_TYPES:
            LOG.debug("No provisioning_block due to unsupported vnic_type: %s",
                      vnic_type)
            return

        if (context.host_agents(ofcst.AGENT_TYPE_OPFLEX_OVS) or
                context.host_agents(AGENT_TYPE_DVS)):
            provisioning_blocks.add_provisioning_component(
                context._plugin_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    def update_port_precommit(self, context):
        port = context.current
        if context.original_host and context.original_host != context.host:
            self.disassociate_domain(context, use_original=True)
            if self._use_static_path(context.original_bottom_bound_segment):
                # remove static binding for old host
                self._update_static_path(context, host=context.original_host,
                    segment=context.original_bottom_bound_segment, remove=True)
                self._release_dynamic_segment(context, use_original=True)
        if self._is_port_bound(port):
            if self._use_static_path(context.bottom_bound_segment):
                self._associate_domain(context, is_vmm=False)
                self._update_static_path(context)
            elif (context.bottom_bound_segment and
                  self._is_opflex_type(
                        context.bottom_bound_segment[api.NETWORK_TYPE])):
                self._associate_domain(context, is_vmm=True)
        self._update_sg_rule_with_remote_group_set(context, port)
        self._insert_provisioning_block(context)
        registry.notify(aim_cst.GBP_PORT, events.PRECOMMIT_UPDATE,
                        self, driver_context=context)

    def update_port_postcommit(self, context):
        port = context.current
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.update_postcommit_port_call(
                context.current,
                context.original,
                context.bottom_bound_segment,
                context.host
            )

    def delete_port_precommit(self, context):
        port = context.current
        if self._is_port_bound(port):
            if self._use_static_path(context.bottom_bound_segment):
                self._update_static_path(context, remove=True)
                self.disassociate_domain(context)
                self._release_dynamic_segment(context)
            elif (context.bottom_bound_segment and
                  self._is_opflex_type(
                      context.bottom_bound_segment[api.NETWORK_TYPE])):
                self.disassociate_domain(context)
        self._really_update_sg_rule_with_remote_group_set(
            context, port, port['security_groups'], is_delete=True)

    def create_security_group_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        sg = context.current
        tenant_aname = self.name_mapper.project(session, sg['tenant_id'])
        sg_aim = aim_resource.SecurityGroup(
            tenant_name=tenant_aname, name=sg['id'],
            display_name=aim_utils.sanitize_display_name(sg['name']))
        self.aim.create(aim_ctx, sg_aim)
        # Always create this default subject
        sg_subject = aim_resource.SecurityGroupSubject(
            tenant_name=tenant_aname,
            security_group_name=sg['id'], name='default')
        self.aim.create(aim_ctx, sg_subject)

        # Create those implicit rules
        for sg_rule in sg.get('security_group_rules', []):
            sg_rule_aim = aim_resource.SecurityGroupRule(
                tenant_name=tenant_aname,
                security_group_name=sg['id'],
                security_group_subject_name='default',
                name=sg_rule['id'],
                direction=sg_rule['direction'],
                ethertype=sg_rule['ethertype'].lower(),
                ip_protocol=(sg_rule['protocol'] if sg_rule['protocol']
                             else 'unspecified'),
                remote_ips=(sg_rule['remote_ip_prefix']
                            if sg_rule['remote_ip_prefix'] else ''),
                from_port=(sg_rule['port_range_min']
                           if sg_rule['port_range_min'] else 'unspecified'),
                to_port=(sg_rule['port_range_max']
                         if sg_rule['port_range_max'] else 'unspecified'))
            self.aim.create(aim_ctx, sg_rule_aim)

    def update_security_group_precommit(self, context):
        # Only display_name change makes sense here
        sg = context.current
        original_sg = context.original
        if sg.get('name') == original_sg.get('name'):
            return
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        tenant_aname = self.name_mapper.project(session, sg['tenant_id'])
        sg_aim = aim_resource.SecurityGroup(
            tenant_name=tenant_aname, name=sg['id'])
        self.aim.update(aim_ctx, sg_aim,
                        display_name=aim_utils.sanitize_display_name(
                            sg['name']))

    def delete_security_group_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        sg = context.current
        tenant_aname = self.name_mapper.project(session, sg['tenant_id'])
        sg_aim = aim_resource.SecurityGroup(tenant_name=tenant_aname,
                                            name=sg['id'])
        self.aim.delete(aim_ctx, sg_aim, cascade=True)

    def _get_sg_rule_tenant_id(self, session, sg_rule):
        # There is a bug in Neutron that sometimes the tenant_id contained
        # within the sg_rule is pointing to the wrong tenant. So here we have
        # to query DB to get the tenant_id of the SG then use that instead.
        tenant_id = (session.query(sg_models.SecurityGroup.tenant_id).
                     filter(sg_models.SecurityGroup.id ==
                            sg_rule['security_group_id']).first())[0]
        return tenant_id

    def create_security_group_rule_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        sg_rule = context.current
        tenant_id = self._get_sg_rule_tenant_id(session, sg_rule)
        tenant_aname = self.name_mapper.project(session, tenant_id)
        if sg_rule.get('remote_group_id'):
            remote_ips = []
            sg_ports = (session.query(models_v2.Port).
                        join(sg_models.SecurityGroupPortBinding,
                             sg_models.SecurityGroupPortBinding.port_id ==
                             models_v2.Port.id).
                        filter(sg_models.SecurityGroupPortBinding.
                               security_group_id ==
                               sg_rule['remote_group_id']).
                        all())
            for sg_port in sg_ports:
                for fixed_ip in sg_port['fixed_ips']:
                    remote_ips.append(fixed_ip['ip_address'])
        else:
            remote_ips = ([sg_rule['remote_ip_prefix']]
                          if sg_rule['remote_ip_prefix'] else '')

        sg_rule_aim = aim_resource.SecurityGroupRule(
            tenant_name=tenant_aname,
            security_group_name=sg_rule['security_group_id'],
            security_group_subject_name='default',
            name=sg_rule['id'],
            direction=sg_rule['direction'],
            ethertype=sg_rule['ethertype'].lower(),
            ip_protocol=(sg_rule['protocol'] if sg_rule['protocol']
                         else 'unspecified'),
            remote_ips=remote_ips,
            from_port=(sg_rule['port_range_min']
                       if sg_rule['port_range_min'] else 'unspecified'),
            to_port=(sg_rule['port_range_max']
                     if sg_rule['port_range_max'] else 'unspecified'))
        self.aim.create(aim_ctx, sg_rule_aim)

    def delete_security_group_rule_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        sg_rule = context.current
        tenant_id = self._get_sg_rule_tenant_id(session, sg_rule)
        tenant_aname = self.name_mapper.project(session, tenant_id)
        sg_rule_aim = aim_resource.SecurityGroupRule(
            tenant_name=tenant_aname,
            security_group_name=sg_rule['security_group_id'],
            security_group_subject_name='default',
            name=sg_rule['id'])
        self.aim.delete(aim_ctx, sg_rule_aim)

    def delete_port_postcommit(self, context):
        port = context.current
        if (port.get('binding:vif_details') and
                port['binding:vif_details'].get('dvs_port_group_name')) and (
                self.dvs_notifier):
            self.dvs_notifier.delete_port_call(
                context.current,
                context.original,
                context.bottom_bound_segment,
                context.host
            )

    def create_floatingip(self, context, current):
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update_for_fip(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def update_floatingip(self, context, original, current):
        if (original['port_id'] and
            original['port_id'] != current['port_id']):
            self._notify_port_update_for_fip(context, original['port_id'])
        if current['port_id']:
            current['status'] = n_constants.FLOATINGIP_STATUS_ACTIVE
            self._notify_port_update_for_fip(context, current['port_id'])
        else:
            current['status'] = n_constants.FLOATINGIP_STATUS_DOWN

    def delete_floatingip(self, context, current):
        if current['port_id']:
            self._notify_port_update_for_fip(context, current['port_id'])

    # Topology RPC method handler
    def update_link(self, context, host, interface, mac,
                    switch, module, port, pod_id='1', port_description=''):
        LOG.debug('Topology RPC: update_link: %s',
                  ', '.join([str(p) for p in
                             (host, interface, mac, switch, module, port,
                              pod_id, port_description)]))
        with db_api.context_manager.writer.using(context):
            if not switch:
                return

            session = context.session
            aim_ctx = aim_context.AimContext(db_session=session)
            hlink = self.aim.get(aim_ctx,
                                 aim_infra.HostLink(host_name=host,
                                                    interface_name=interface))
            if hlink and hlink.path == port_description:
                # There was neither a change nor a refresh required.
                return
            # Create or Update hostlink in AIM
            attrs = dict(interface_mac=mac,
                         switch_id=switch, module=module, port=port,
                         path=port_description, pod_id=pod_id)
            if hlink:
                self.aim.update(aim_ctx, hlink, **attrs)
            else:
                hlink = aim_infra.HostLink(host_name=host,
                                           interface_name=interface,
                                           **attrs)
                self.aim.create(aim_ctx, hlink, overwrite=True)
            self._update_network_links(context, host)

    # Topology RPC method handler
    def delete_link(self, context, host, interface, mac, switch, module, port):
        LOG.debug('Topology RPC: delete_link: %s',
                  ', '.join([str(p) for p in
                             (host, interface, mac, switch, module, port)]))
        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)

        with db_api.context_manager.writer.using(context):
            hlink = self.aim.get(aim_ctx,
                                 aim_infra.HostLink(host_name=host,
                                                    interface_name=interface))
            if not hlink:
                # Host link didn't exist to begin with, nothing to do here.
                return

            self.aim.delete(aim_ctx, hlink)
            self._update_network_links(context, host)

    def _update_network_links(self, context, host):
        # Update static paths of all EPGs with ports on the host.
        # For correctness, rebuild tha static paths for the entire host
        # instead of the specific interface. We could do it in a
        # per-interface basis once we can correlate existing paths to
        # the (host, interface) hence avoiding leaking entries. Although
        # this is all good in theory, it would require some extra design
        # due to the fact that VPC interfaces have the same path but
        # two different ifaces assigned to them.
        aim_ctx = aim_context.AimContext(db_session=context.session)
        hlinks = self.aim.find(aim_ctx, aim_infra.HostLink, host_name=host)
        nets_segs = self._get_non_opflex_segments_on_host(context, host)
        for net, seg in nets_segs:
            self._rebuild_host_path_for_network(context, net, seg, host,
                                                hlinks)
        registry.notify(aim_cst.GBP_NETWORK_LINK,
                        events.PRECOMMIT_UPDATE, self, context=context,
                        networks_map=nets_segs, host_links=hlinks,
                        host=host)

    def _agent_bind_port(self, context, agent_type, bind_strategy):
        current = context.current
        for agent in context.host_agents(agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if bind_strategy(context, segment, agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return True
            else:
                LOG.warning("Refusing to bind port %(port)s to dead "
                            "agent: %(agent)s",
                            {'port': current['id'], 'agent': agent})

    def _opflex_bind_port(self, context, segment, agent):
        network_type = segment[api.NETWORK_TYPE]
        if self._is_opflex_type(network_type):
            opflex_mappings = agent['configurations'].get('opflex_networks')
            LOG.debug("Checking segment: %(segment)s "
                      "for physical network: %(mappings)s ",
                      {'segment': segment, 'mappings': opflex_mappings})
            if (opflex_mappings is not None and
                segment[api.PHYSICAL_NETWORK] not in opflex_mappings):
                return False
        elif network_type != 'local':
            return False
        context.set_binding(
            segment[api.ID], self._opflex_get_vif_type(agent),
            self._opflex_get_vif_details(context, agent))
        return True

    def _dvs_bind_port(self, context, segment, agent):
        """Populate VIF type and details for DVS VIFs.

           For DVS VIFs, provide the portgroup along
           with the security groups setting. Note that
           DVS port binding always returns true. This
           is because it should only be called when the
           host ID matches the agent's host ID, where
           host ID is not an actual host, but a psuedo-
           host that only exists to match the host ID
           for the related DVS agent (i.e. for port-
           binding).
        """
        # Use default security groups from MD
        aim_ctx = aim_context.AimContext(
            db_session=context._plugin_context.session)
        session = aim_ctx.db_session
        port = context.current
        if self.gbp_driver:
            epg = self.gbp_driver._get_port_epg(context._plugin_context, port)
        else:
            mapping = self._get_network_mapping(session, port['network_id'])
            epg = self._get_network_epg(mapping)
        vif_details = {'dvs_port_group_name': ('%s|%s|%s' %
                                               (epg.tenant_name,
                                                epg.app_profile_name,
                                                epg.name)),
                       portbindings.CAP_PORT_FILTER: self.sg_enabled}
        currentcopy = copy.copy(context.current)
        currentcopy['portgroup_name'] = (
            vif_details['dvs_port_group_name'])
        booked_port_info = None
        if self.dvs_notifier:
            booked_port_info = self.dvs_notifier.bind_port_call(
                currentcopy,
                [context.bottom_bound_segment],
                context.network.current,
                context.host
            )
        if booked_port_info:
            vif_details['dvs_port_key'] = booked_port_info['key']

        context.set_binding(segment[api.ID],
                            VIF_TYPE_DVS, vif_details)
        return True

    def _bind_physical_node(self, context):
        # Bind physical nodes hierarchically by creating a dynamic segment.
        for segment in context.segments_to_bind:
            net_type = segment[api.NETWORK_TYPE]
            # TODO(amitbose) For ports on baremetal (Ironic) hosts, use
            # binding:profile to decide if dynamic segment should be created.
            if self._is_opflex_type(net_type):
                # TODO(amitbose) Consider providing configuration options
                # for picking network-type and physical-network name
                # for the dynamic segment
                seg_args = {api.NETWORK_TYPE: n_constants.TYPE_VLAN,
                            api.PHYSICAL_NETWORK:
                            segment[api.PHYSICAL_NETWORK]}
                dyn_seg = context.allocate_dynamic_segment(seg_args)
                LOG.info('Allocated dynamic-segment %(s)s for port %(p)s',
                         {'s': dyn_seg, 'p': context.current['id']})
                dyn_seg['aim_ml2_created'] = True
                context.continue_binding(segment[api.ID], [dyn_seg])
                return True
            elif segment.get('aim_ml2_created'):
                # Complete binding if another driver did not bind the
                # dynamic segment that we created.
                context.set_binding(segment[api.ID], portbindings.VIF_TYPE_OVS,
                    self._update_binding_sg())
                return True

    def _opflex_get_vif_type(self, agent):
        if agent['agent_type'] == ofcst.AGENT_TYPE_OPFLEX_VPP:
            return portbindings.VIF_TYPE_VHOST_USER
        else:
            if (agent['configurations'].get('datapath_type') ==
            a_const.OVS_DATAPATH_NETDEV):
                return portbindings.VIF_TYPE_VHOST_USER
            else:
                return portbindings.VIF_TYPE_OVS

    @staticmethod
    def _agent_vhu_sockpath(agent, port_id):
        """Return the agent's vhost-user socket path for a given port"""
        sockdir = agent['configurations'].get('vhostuser_socket_dir',
                                              a_const.VHOST_USER_SOCKET_DIR)
        sock_name = (n_constants.VHOST_USER_DEVICE_PREFIX +
                     port_id)[:ApicMechanismDriver.NIC_NAME_LEN]
        return os.path.join(sockdir, sock_name)

    def _get_vhost_mode(self):
        # REVISIT(kshastri):  this function converts the ovs vhost user
        # driver mode into the qemu vhost user mode. If OVS is the server,
        # qemu is the client and vice-versa. For ACI MD, we will need to
        # support agent capabilities field to choose client-mode. As of
        # now only support server mode for nova.
        return portbindings.VHOST_USER_MODE_SERVER

    def _opflex_get_vif_details(self, context, agent):
        vif_type = self._opflex_get_vif_type(agent)
        details = {}
        if vif_type == portbindings.VIF_TYPE_VHOST_USER:
            sock_path = self._agent_vhu_sockpath(agent,
                                                context.current['id'])
            mode = self._get_vhost_mode()
            details = {portbindings.VHOST_USER_MODE: mode,
                       portbindings.VHOST_USER_SOCKET: sock_path}
            if agent['agent_type'] == ofcst.AGENT_TYPE_OPFLEX_VPP:
                details.update({portbindings.CAP_PORT_FILTER: False,
                                portbindings.OVS_HYBRID_PLUG: False,
                                portbindings.VHOST_USER_OVS_PLUG: False,
                                ofcst.VHOST_USER_VPP_PLUG: True})
            else:
                details.update({portbindings.OVS_DATAPATH_TYPE:
                                a_const.OVS_DATAPATH_NETDEV,
                                portbindings.VHOST_USER_OVS_PLUG: True})

        if agent['agent_type'] == ofcst.AGENT_TYPE_OPFLEX_OVS:
            details.update(self._update_binding_sg())
        return details

    def _update_binding_sg(self):
        enable_firewall = False
        if self.enable_iptables_firewall:
            enable_firewall = self.sg_enabled
        return {portbindings.CAP_PORT_FILTER: enable_firewall,
                portbindings.OVS_HYBRID_PLUG: enable_firewall}

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            self._l3_plugin = directory.get_plugin(n_constants.L3)
        return self._l3_plugin

    @property
    def dvs_notifier(self):
        if not self._dvs_notifier:
            self._dvs_notifier = importutils.import_object(
                DVS_AGENT_KLASS,
                nctx.get_admin_context_without_session()
            )
        return self._dvs_notifier

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = directory.get_plugin("GROUP_POLICY")
        return self._gbp_plugin

    @property
    def gbp_driver(self):
        if not self._gbp_driver and self.gbp_plugin:
            self._gbp_driver = (self.gbp_plugin.policy_driver_manager.
                                policy_drivers['aim_mapping'].obj)
        return self._gbp_driver

    def _merge_status(self, aim_ctx, sync_state, resource, status=None):
        status = status or self.aim.get_status(aim_ctx, resource,
                                               create_if_absent=False)
        if not status:
            # REVISIT(rkukura): This should only occur if the AIM
            # resource has not yet been created when
            # extend_<resource>_dict() runs at the begining of a
            # create operation. In this case, the real sync_state
            # value will be generated, either in
            # create_<resource>_precommit() or in a 2nd call to
            # extend_<resource>_dict() after the precommit phase,
            # depending on the resource. It might be safer to force
            # sync_state to a SYNC_MISSING value here that is not
            # overwritten on subsequent calls to _merge_status(), in
            # case the real sync_state value somehow does not get
            # generated. But sync_state handling in general needs to
            # be revisited (and properly tested), so we can deal with
            # this at that time.
            return sync_state
        if status.is_error():
            sync_state = cisco_apic.SYNC_ERROR
        elif status.is_build() and sync_state is not cisco_apic.SYNC_ERROR:
            sync_state = cisco_apic.SYNC_BUILD
        return (cisco_apic.SYNC_SYNCED
                if sync_state is cisco_apic.SYNC_NOT_APPLICABLE
                else sync_state)

    def _get_vrfs_for_router(self, session, router_id):
        # REVISIT: Persist router/VRF relationship?

        # Find the unique VRFs for the scoped interfaces, accounting
        # for isomorphic scopes.
        vrfs = {}
        scope_dbs = (session.query(as_db.AddressScope).
                     join(models_v2.SubnetPool,
                          models_v2.SubnetPool.address_scope_id ==
                          as_db.AddressScope.id).
                     join(models_v2.Subnet,
                          models_v2.Subnet.subnetpool_id ==
                          models_v2.SubnetPool.id).
                     join(models_v2.IPAllocation,
                          models_v2.IPAllocation.subnet_id ==
                          models_v2.Subnet.id).
                     join(l3_db.RouterPort,
                          l3_db.RouterPort.port_id ==
                          models_v2.IPAllocation.port_id).
                     filter(l3_db.RouterPort.router_id == router_id).
                     filter(l3_db.RouterPort.port_type ==
                            n_constants.DEVICE_OWNER_ROUTER_INTF).
                     distinct())
        for scope_db in scope_dbs:
            vrf = self._get_address_scope_vrf(scope_db.aim_mapping)
            vrfs[tuple(vrf.identity)] = vrf

        # Find VRF for first unscoped interface.
        network_db = (session.query(models_v2.Network).
                      join(models_v2.Subnet,
                           models_v2.Subnet.network_id ==
                           models_v2.Network.id).
                      join(models_v2.IPAllocation,
                           models_v2.IPAllocation.subnet_id ==
                           models_v2.Subnet.id).
                      outerjoin(models_v2.SubnetPool,
                                models_v2.SubnetPool.id ==
                                models_v2.Subnet.subnetpool_id).
                      join(l3_db.RouterPort,
                           l3_db.RouterPort.port_id ==
                           models_v2.IPAllocation.port_id).
                      filter(l3_db.RouterPort.router_id == router_id,
                             l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).
                      filter(sa.or_(models_v2.Subnet.subnetpool_id.is_(None),
                                    models_v2.SubnetPool.address_scope_id.is_(
                                        None))).
                      limit(1).
                      first())
        if network_db:
            vrf = self._get_network_vrf(network_db.aim_mapping)
            vrfs[tuple(vrf.identity)] = vrf

        return vrfs.values()

    # Used by policy driver.
    def _get_address_scope_ids_for_vrf(self, session, vrf):
        mappings = self._get_address_scope_mappings_for_vrf(session, vrf)
        return [mapping.scope_id for mapping in mappings]

    def _get_network_ids_for_vrf(self, session, vrf):
        mappings = self._get_network_mappings_for_vrf(session, vrf)
        return [mapping.network_id for mapping in mappings]

    def _get_routers_for_vrf(self, session, vrf):
        # REVISIT: Persist router/VRF relationship?

        scope_ids = self._get_address_scope_ids_for_vrf(session, vrf)
        if scope_ids:
            rtr_dbs = (session.query(l3_db.Router)
                       .join(l3_db.RouterPort,
                             l3_db.RouterPort.router_id == l3_db.Router.id)
                       .join(models_v2.IPAllocation,
                             models_v2.IPAllocation.port_id ==
                             l3_db.RouterPort.port_id)
                       .join(models_v2.Subnet,
                             models_v2.Subnet.id ==
                             models_v2.IPAllocation.subnet_id)
                       .join(models_v2.SubnetPool,
                             models_v2.SubnetPool.id ==
                             models_v2.Subnet.subnetpool_id)
                       .filter(l3_db.RouterPort.port_type ==
                               n_constants.DEVICE_OWNER_ROUTER_INTF)
                       .filter(models_v2.SubnetPool.address_scope_id.in_(
                           scope_ids))
                       .distinct())
        else:
            net_ids = self._get_network_ids_for_vrf(session, vrf)
            rtr_dbs = (session.query(l3_db.Router).
                       join(l3_db.RouterPort,
                            l3_db.RouterPort.router_id == l3_db.Router.id).
                       join(models_v2.Port,
                            models_v2.Port.id == l3_db.RouterPort.port_id).
                       filter(models_v2.Port.network_id.in_(net_ids),
                              l3_db.RouterPort.port_type ==
                              n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct())
        return rtr_dbs

    def _associate_network_with_vrf(self, ctx, aim_ctx, network_db, new_vrf,
                                    nets_to_notify):
        LOG.debug("Associating previously unrouted network %(net_id)s named "
                  "'%(net_name)s' in project %(net_tenant)s with VRF %(vrf)s",
                  {'net_id': network_db.id, 'net_name': network_db.name,
                   'net_tenant': network_db.tenant_id, 'vrf': new_vrf})

        # NOTE: Must only be called for networks that are not yet
        # attached to any router.

        if not self._is_svi_db(network_db):
            bd = self._get_network_bd(network_db.aim_mapping)
            epg = self._get_network_epg(network_db.aim_mapping)
            tenant_name = bd.tenant_name
        else:
            l3out = self._get_network_l3out(network_db.aim_mapping)
            tenant_name = l3out.tenant_name

        if (new_vrf.tenant_name != COMMON_TENANT_NAME and
            tenant_name != new_vrf.tenant_name):
            # Move BD and EPG to new VRF's Tenant, set VRF, and make
            # sure routing is enabled.
            LOG.debug("Moving network from tenant %(old)s to tenant %(new)s",
                      {'old': tenant_name, 'new': new_vrf.tenant_name})
            if not self._is_svi_db(network_db):
                bd = self.aim.get(aim_ctx, bd)
                self.aim.delete(aim_ctx, bd)
                bd.tenant_name = new_vrf.tenant_name
                bd.enable_routing = True
                bd.vrf_name = new_vrf.name
                bd = self.aim.create(aim_ctx, bd)
                self._set_network_bd(network_db.aim_mapping, bd)
                epg = self.aim.get(aim_ctx, epg)
                self.aim.delete(aim_ctx, epg)
                # ensure app profile exists in destination tenant
                ap = aim_resource.ApplicationProfile(
                    tenant_name=new_vrf.tenant_name, name=self.ap_name)
                if not self.aim.get(aim_ctx, ap):
                    self.aim.create(aim_ctx, ap)
                epg.tenant_name = new_vrf.tenant_name
                epg = self.aim.create(aim_ctx, epg)
                self._set_network_epg_and_notify(ctx, network_db.aim_mapping,
                                                 epg)
            else:
                old_l3out = self.aim.get(aim_ctx, l3out)
                l3out = copy.copy(old_l3out)
                l3out.tenant_name = new_vrf.tenant_name
                l3out.vrf_name = new_vrf.name
                l3out = self.aim.create(aim_ctx, l3out)
                self._set_network_l3out(network_db.aim_mapping,
                                        l3out)
                for old_child in self.aim.get_subtree(aim_ctx, old_l3out):
                    new_child = copy.copy(old_child)
                    new_child.tenant_name = new_vrf.tenant_name
                    new_child = self.aim.create(aim_ctx, new_child)
                    self.aim.delete(aim_ctx, old_child)
                self.aim.delete(aim_ctx, old_l3out)
        else:
            # Just set VRF and enable routing.
            if not self._is_svi_db(network_db):
                bd = self.aim.update(aim_ctx, bd, enable_routing=True,
                                     vrf_name=new_vrf.name)
            else:
                l3out = self.aim.update(aim_ctx, l3out,
                                        vrf_name=new_vrf.name)

        self._set_network_vrf_and_notify(ctx, network_db.aim_mapping, new_vrf)

        # All non-router ports on this network need to be notified
        # since their BD's VRF and possibly their BD's and EPG's
        # Tenants have changed.
        nets_to_notify.add(network_db.id)

        if not self._is_svi_db(network_db):
            return bd, epg
        else:
            ext_net = self._get_network_l3out_ext_net(network_db.aim_mapping)
            return l3out, ext_net

    def _dissassociate_network_from_vrf(self, ctx, aim_ctx, network_db,
                                        old_vrf, nets_to_notify):
        LOG.debug("Dissassociating network %(net_id)s named '%(net_name)s' in "
                  "project %(net_tenant)s from VRF %(vrf)s",
                  {'net_id': network_db.id, 'net_name': network_db.name,
                   'net_tenant': network_db.tenant_id, 'vrf': old_vrf})

        session = aim_ctx.db_session

        if not self._is_svi_db(network_db):
            new_vrf = self._map_unrouted_vrf()
        else:
            new_vrf = self._map_default_vrf(session, network_db)
        new_tenant_name = self.name_mapper.project(
            session, network_db.tenant_id)

        # REVISIT(rkukura): Share code with _associate_network_with_vrf?
        if (old_vrf.tenant_name != COMMON_TENANT_NAME and
            old_vrf.tenant_name != new_tenant_name):
            # Move BD and EPG to network's Tenant, set unrouted VRF,
            # and disable routing.
            LOG.debug("Moving network from tenant %(old)s to tenant %(new)s",
                      {'old': old_vrf.tenant_name, 'new': new_tenant_name})

            if not self._is_svi_db(network_db):
                bd = self._get_network_bd(network_db.aim_mapping)
                bd = self.aim.get(aim_ctx, bd)
                self.aim.delete(aim_ctx, bd)
                bd.tenant_name = new_tenant_name
                bd.enable_routing = False
                bd.vrf_name = new_vrf.name
                bd = self.aim.create(aim_ctx, bd)
                self._set_network_bd(network_db.aim_mapping, bd)
                epg = self._get_network_epg(network_db.aim_mapping)
                epg = self.aim.get(aim_ctx, epg)
                self.aim.delete(aim_ctx, epg)
                epg.tenant_name = new_tenant_name
                epg = self.aim.create(aim_ctx, epg)
                self._set_network_epg_and_notify(ctx, network_db.aim_mapping,
                                                 epg)
            else:
                l3out = self._get_network_l3out(network_db.aim_mapping)
                old_l3out = self.aim.get(aim_ctx, l3out)
                l3out = copy.copy(old_l3out)
                l3out.tenant_name = new_tenant_name
                l3out.vrf_name = new_vrf.name
                l3out = self.aim.create(aim_ctx, l3out)
                self._set_network_l3out(network_db.aim_mapping,
                                        l3out)
                for old_child in self.aim.get_subtree(aim_ctx, old_l3out):
                    new_child = copy.copy(old_child)
                    new_child.tenant_name = new_tenant_name
                    new_child = self.aim.create(aim_ctx, new_child)
                    self.aim.delete(aim_ctx, old_child)
                self.aim.delete(aim_ctx, old_l3out)
        else:
            # Just set unrouted VRF and disable routing.
            if not self._is_svi_db(network_db):
                bd = self._get_network_bd(network_db.aim_mapping)
                bd = self.aim.update(aim_ctx, bd, enable_routing=False,
                                     vrf_name=new_vrf.name)
            else:
                l3out = self._get_network_l3out(network_db.aim_mapping)
                l3out = self.aim.update(aim_ctx, l3out,
                                        vrf_name=new_vrf.name)

        self._set_network_vrf_and_notify(ctx, network_db.aim_mapping, new_vrf)

        # All non-router ports on this network need to be notified
        # since their BD's VRF and possibly their BD's and EPG's
        # Tenants have changed.
        nets_to_notify.add(network_db.id)

    def _move_topology(self, ctx, aim_ctx, topology, old_vrf, new_vrf,
                       nets_to_notify):
        LOG.info("Moving routed networks %(topology)s from VRF "
                 "%(old_vrf)s to VRF %(new_vrf)s",
                 {'topology': topology.keys(),
                  'old_vrf': old_vrf,
                  'new_vrf': new_vrf})

        # TODO(rkukura): Validate that nothing in new_vrf overlaps
        # with topology.

        for network_db in topology.itervalues():
            if old_vrf.tenant_name != new_vrf.tenant_name:
                # New VRF is in different Tenant, so move BD, EPG, and
                # all Subnets to new VRF's Tenant and set BD's VRF.
                LOG.debug("Moving network %(net)s from tenant %(old)s to "
                          "tenant %(new)s",
                          {'net': network_db.id,
                           'old': old_vrf.tenant_name,
                           'new': new_vrf.tenant_name})
                if network_db.aim_mapping.epg_name:
                    bd = self._get_network_bd(network_db.aim_mapping)
                    old_bd = self.aim.get(aim_ctx, bd)
                    new_bd = copy.copy(old_bd)
                    new_bd.tenant_name = new_vrf.tenant_name
                    new_bd.vrf_name = new_vrf.name
                    bd = self.aim.create(aim_ctx, new_bd)
                    self._set_network_bd(network_db.aim_mapping, bd)
                    for subnet in self.aim.find(
                            aim_ctx, aim_resource.Subnet,
                            tenant_name=old_bd.tenant_name,
                            bd_name=old_bd.name):
                        self.aim.delete(aim_ctx, subnet)
                        subnet.tenant_name = bd.tenant_name
                        subnet = self.aim.create(aim_ctx, subnet)
                    self.aim.delete(aim_ctx, old_bd)

                    epg = self._get_network_epg(network_db.aim_mapping)
                    epg = self.aim.get(aim_ctx, epg)
                    self.aim.delete(aim_ctx, epg)
                    epg.tenant_name = new_vrf.tenant_name
                    epg = self.aim.create(aim_ctx, epg)
                    self._set_network_epg_and_notify(ctx,
                                                     network_db.aim_mapping,
                                                     epg)
                # SVI network with auto l3out
                elif network_db.aim_mapping.l3out_name:
                    l3out = self._get_network_l3out(network_db.aim_mapping)
                    old_l3out = self.aim.get(aim_ctx, l3out)
                    l3out = copy.copy(old_l3out)
                    l3out.tenant_name = new_vrf.tenant_name
                    l3out.vrf_name = new_vrf.name
                    l3out = self.aim.create(aim_ctx, l3out)
                    self._set_network_l3out(network_db.aim_mapping,
                                            l3out)
                    for old_child in self.aim.get_subtree(aim_ctx, old_l3out):
                        new_child = copy.copy(old_child)
                        new_child.tenant_name = new_vrf.tenant_name
                        new_child = self.aim.create(aim_ctx, new_child)
                        self.aim.delete(aim_ctx, old_child)
                    self.aim.delete(aim_ctx, old_l3out)
            else:
                if network_db.aim_mapping.epg_name:
                    # New VRF is in same Tenant, so just set BD's VRF.
                    bd = self._get_network_bd(network_db.aim_mapping)
                    bd = self.aim.update(aim_ctx, bd, vrf_name=new_vrf.name)
                elif network_db.aim_mapping.l3out_name:
                    # New VRF is in same Tenant, so just set l3out's VRF.
                    l3out = self._get_network_l3out(network_db.aim_mapping)
                    l3out = self.aim.update(aim_ctx, l3out,
                                            vrf_name=new_vrf.name)

            self._set_network_vrf_and_notify(ctx, network_db.aim_mapping,
                                             new_vrf)

        # All non-router ports on all networks in topology need to be
        # notified since their BDs' VRFs and possibly their BDs' and
        # EPGs' Tenants have changed.
        nets_to_notify.update(topology.keys())

    def _router_topology(self, session, router_id):
        LOG.debug("Getting topology for router %s", router_id)
        visited_networks = {}
        visited_router_ids = set()
        self._expand_topology_for_routers(
            session, visited_networks, visited_router_ids, [router_id])
        LOG.debug("Returning router topology %s", visited_networks)
        return visited_networks

    def _network_topology(self, session, network_db):
        LOG.debug("Getting topology for network %s", network_db.id)
        visited_networks = {}
        visited_router_ids = set()
        self._expand_topology_for_networks(
            session, visited_networks, visited_router_ids, [network_db])
        LOG.debug("Returning network topology %s", visited_networks)
        return visited_networks

    def _expand_topology_for_routers(self, session, visited_networks,
                                     visited_router_ids, new_router_ids):
        LOG.debug("Adding routers %s to topology", new_router_ids)
        added_ids = set(new_router_ids) - visited_router_ids
        if added_ids:
            visited_router_ids |= added_ids
            LOG.debug("Querying for networks interfaced to routers %s",
                      added_ids)
            query = (session.query(models_v2.Network, models_v2.Subnet).
                     join(models_v2.Subnet,
                          models_v2.Subnet.network_id == models_v2.Network.id).
                     join(models_v2.IPAllocation,
                          models_v2.IPAllocation.subnet_id ==
                          models_v2.Subnet.id).
                     join(l3_db.RouterPort,
                          l3_db.RouterPort.port_id ==
                          models_v2.IPAllocation.port_id).
                     filter(l3_db.RouterPort.router_id.in_(added_ids)))
            if visited_networks:
                query = query.filter(
                    ~models_v2.Network.id.in_(visited_networks.keys()))
            results = (query.filter(l3_db.RouterPort.port_type ==
                                    n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct().
                       all())
            self._expand_topology_for_networks(
                session, visited_networks, visited_router_ids,
                [network for network, subnet in results if not
                 (subnet.subnetpool and subnet.subnetpool.address_scope_id)])

    def _expand_topology_for_networks(self, session, visited_networks,
                                      visited_router_ids, new_networks):
        LOG.debug("Adding networks %s to topology",
                  [net.id for net in new_networks])
        added_ids = []
        for net in new_networks:
            if net.id not in visited_networks:
                visited_networks[net.id] = net
                added_ids.append(net.id)
        if added_ids:
            LOG.debug("Querying for routers interfaced to networks %s",
                      added_ids)
            query = (session.query(l3_db.RouterPort.router_id).
                     join(models_v2.Port,
                          models_v2.Port.id == l3_db.RouterPort.port_id).
                     filter(models_v2.Port.network_id.in_(added_ids)))
            if visited_router_ids:
                query = query.filter(
                    ~l3_db.RouterPort.router_id.in_(visited_router_ids))
            results = (query.filter(l3_db.RouterPort.port_type ==
                                    n_constants.DEVICE_OWNER_ROUTER_INTF).
                       distinct().
                       all())
            self._expand_topology_for_routers(
                session, visited_networks, visited_router_ids,
                [result[0] for result in results])

    def _topology_shared(self, topology):
        for network_db in topology.values():
            if self._network_shared(network_db):
                return network_db

    def _network_shared(self, network_db):
        for entry in network_db.rbac_entries:
            # Access is enforced by Neutron itself, and we only
            # care whether or not the network is shared, so we
            # ignore the entry's target_tenant.
            if entry.action == rbac_db_models.ACCESS_SHARED:
                return True

    def _ip_for_subnet(self, subnet, fixed_ips):
        subnet_id = subnet['id']
        for fixed_ip in fixed_ips:
            if fixed_ip['subnet_id'] == subnet_id:
                return fixed_ip['ip_address']

    def _subnet_router_ips(self, session, subnet_id):
        return (session.query(models_v2.IPAllocation.ip_address,
                              l3_db.RouterPort.router_id).
                join(l3_db.RouterPort,
                     l3_db.RouterPort.port_id ==
                     models_v2.IPAllocation.port_id).
                filter(
                    models_v2.IPAllocation.subnet_id == subnet_id,
                    l3_db.RouterPort.port_type ==
                    n_constants.DEVICE_OWNER_ROUTER_INTF
                ))

    def _scope_by_id(self, session, scope_id):
        return (session.query(as_db.AddressScope).
                filter_by(id=scope_id).
                one_or_none())

    def _map_network(self, session, network, vrf=None):
        tenant_aname = (vrf.tenant_name if vrf and vrf.tenant_name != 'common'
                        else self.name_mapper.project(
                                session, network['tenant_id']))
        id = network['id']
        aname = self.name_mapper.network(session, id)

        bd = aim_resource.BridgeDomain(tenant_name=tenant_aname,
                                       name=aname)
        epg = aim_resource.EndpointGroup(tenant_name=tenant_aname,
                                         app_profile_name=self.ap_name,
                                         name=aname)
        return bd, epg

    def _map_subnet(self, subnet, gw_ip, bd):
        prefix_len = subnet['cidr'].split('/')[1]
        gw_ip_mask = gw_ip + '/' + prefix_len

        sn = aim_resource.Subnet(tenant_name=bd.tenant_name,
                                 bd_name=bd.name,
                                 gw_ip_mask=gw_ip_mask)
        return sn

    def _map_address_scope(self, session, scope):
        id = scope['id']
        tenant_aname = self.name_mapper.project(session, scope['tenant_id'])
        aname = self.name_mapper.address_scope(session, id)

        vrf = aim_resource.VRF(tenant_name=tenant_aname, name=aname)
        return vrf

    def _map_router(self, session, router, contract_only=False):
        id = router['id']
        aname = self.name_mapper.router(session, id)

        contract = aim_resource.Contract(tenant_name=COMMON_TENANT_NAME,
                                         name=aname)
        if contract_only:
            return contract
        subject = aim_resource.ContractSubject(tenant_name=COMMON_TENANT_NAME,
                                               contract_name=aname,
                                               name=ROUTER_SUBJECT_NAME)
        return contract, subject

    def _map_default_vrf(self, session, network):
        tenant_aname = self.name_mapper.project(session, network['tenant_id'])

        vrf = aim_resource.VRF(tenant_name=tenant_aname,
                               name=DEFAULT_VRF_NAME)
        return vrf

    def _map_unrouted_vrf(self):
        vrf = aim_resource.VRF(
            tenant_name=COMMON_TENANT_NAME,
            name=self.apic_system_id + '_' + UNROUTED_VRF_NAME)
        return vrf

    def _ensure_common_tenant(self, aim_ctx):
        attrs = aim_resource.Tenant(
            name=COMMON_TENANT_NAME, monitored=True, display_name='')
        tenant = self.aim.get(aim_ctx, attrs)
        if not tenant:
            LOG.info("Creating common tenant")
            tenant = self.aim.create(aim_ctx, attrs)
        return tenant

    def _ensure_unrouted_vrf(self, aim_ctx):
        attrs = self._map_unrouted_vrf()
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            attrs.display_name = (
                aim_utils.sanitize_display_name('CommonUnroutedVRF'))
            LOG.info("Creating common unrouted VRF")
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _ensure_any_filter(self, aim_ctx):
        filter_name = self._any_filter_name
        dname = aim_utils.sanitize_display_name("AnyFilter")
        filter = aim_resource.Filter(tenant_name=COMMON_TENANT_NAME,
                                     name=filter_name,
                                     display_name=dname)
        if not self.aim.get(aim_ctx, filter):
            LOG.info("Creating common Any Filter")
            self.aim.create(aim_ctx, filter)

        dname = aim_utils.sanitize_display_name("AnyFilterEntry")
        entry = aim_resource.FilterEntry(tenant_name=COMMON_TENANT_NAME,
                                         filter_name=filter_name,
                                         name=ANY_FILTER_ENTRY_NAME,
                                         display_name=dname)
        if not self.aim.get(aim_ctx, entry):
            LOG.info("Creating common Any FilterEntry")
            self.aim.create(aim_ctx, entry)

        return filter

    @property
    def _any_filter_name(self):
        return self.apic_system_id + '_' + ANY_FILTER_NAME

    @property
    def _default_sg_name(self):
        return self.apic_system_id + '_' + DEFAULT_SG_NAME

    def _ensure_default_vrf(self, aim_ctx, attrs):
        vrf = self.aim.get(aim_ctx, attrs)
        if not vrf:
            attrs.display_name = (
                aim_utils.sanitize_display_name('DefaultRoutedVRF'))
            LOG.info("Creating default VRF for %s", attrs.tenant_name)
            vrf = self.aim.create(aim_ctx, attrs)
        return vrf

    def _cleanup_default_vrf(self, aim_ctx, vrf):
        if not self._is_vrf_used_by_networks(aim_ctx.db_session, vrf):
            LOG.info("Deleting default VRF for %s", vrf.tenant_name)
            self.aim.delete(aim_ctx, vrf)

    # Used by policy driver.
    def get_bd_for_network(self, session, network):
        mapping = self._get_network_mapping(session, network['id'])
        return mapping and self._get_network_bd(mapping)

    # Used by policy driver.
    def get_epg_for_network(self, session, network):
        mapping = self._get_network_mapping(session, network['id'])
        return mapping and self._get_network_epg(mapping)

    # Used by policy driver.
    def get_vrf_for_network(self, session, network):
        mapping = self._get_network_mapping(session, network['id'])
        return mapping and self._get_network_vrf(mapping)

    # Used by policy driver.
    def get_network_ids_for_bd(self, session, bd):
        mapping = self._get_network_mappings_for_bd(session, bd)
        return [m.network_id for m in mapping]

    def get_aim_domains(self, aim_ctx):
        vmms = [{'name': x.name, 'type': x.type}
                for x in self.aim.find(aim_ctx, aim_resource.VMMDomain)
                if x.type == utils.OPENSTACK_VMM_TYPE]
        phys = [{'name': x.name}
                for x in self.aim.find(aim_ctx, aim_resource.PhysicalDomain)]
        return vmms, phys

    def _is_external(self, network):
        return network.get('router:external')

    def _is_svi(self, network):
        return network.get(cisco_apic.SVI)

    def _is_svi_db(self, network_db):
        if (network_db.aim_extension_mapping and
                network_db.aim_extension_mapping.svi):
            return True
        return False

    def _is_preexisting_svi_db(self, network_db):
        if (network_db.aim_extension_mapping and
                network_db.aim_extension_mapping.svi and
                network_db.aim_extension_mapping.external_network_dn):
            return True
        return False

    def _is_bgp_enabled(self, network):
        return network.get(cisco_apic.BGP)

    def _nat_type_to_strategy(self, nat_type):
        ns_cls = nat_strategy.DistributedNatStrategy
        if nat_type == '':
            ns_cls = nat_strategy.NoNatStrategy
        elif nat_type == 'edge':
            ns_cls = nat_strategy.EdgeNatStrategy
        ns = ns_cls(self.aim)
        ns.app_profile_name = self.ap_name
        ns.common_scope = self.apic_system_id
        return ns

    def _get_aim_external_objects(self, network):
        ext_net_dn = (network.get(cisco_apic.DIST_NAMES, {})
                      .get(cisco_apic.EXTERNAL_NETWORK))
        if not ext_net_dn:
            return None, None, None
        nat_type = network.get(cisco_apic.NAT_TYPE)
        aim_ext_net = aim_resource.ExternalNetwork.from_dn(ext_net_dn)
        aim_l3out = aim_resource.L3Outside(
            tenant_name=aim_ext_net.tenant_name, name=aim_ext_net.l3out_name)
        return aim_l3out, aim_ext_net, self._nat_type_to_strategy(nat_type)

    def _get_aim_nat_strategy(self, network):
        if not self._is_external(network):
            return None, None, None
        return self._get_aim_external_objects(network)

    def _get_aim_external_objects_db(self, session, network_db):
        extn_info = self.get_network_extn_db(session, network_db.id)
        if extn_info and cisco_apic.EXTERNAL_NETWORK in extn_info:
            dn = extn_info[cisco_apic.EXTERNAL_NETWORK]
            a_ext_net = aim_resource.ExternalNetwork.from_dn(dn)
            a_l3out = aim_resource.L3Outside(
                tenant_name=a_ext_net.tenant_name,
                name=a_ext_net.l3out_name)
            ns = self._nat_type_to_strategy(
                    extn_info.get(cisco_apic.NAT_TYPE))
            return a_l3out, a_ext_net, ns
        return None, None, None

    def _get_aim_nat_strategy_db(self, session, network_db):
        if network_db.external is not None:
            return self._get_aim_external_objects_db(session, network_db)
        return None, None, None

    def _subnet_to_gw_ip_mask(self, subnet):
        cidr = subnet['cidr'].split('/')
        return aim_resource.Subnet.to_gw_ip_mask(
            subnet['gateway_ip'] or cidr[0], int(cidr[1]))

    def _get_router_intf_count(self, session, router, scope_id=None):
        if not scope_id:
            result = (session.query(l3_db.RouterPort).
                      filter(l3_db.RouterPort.router_id == router['id']).
                      filter(l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).
                      count())
        elif scope_id == NO_ADDR_SCOPE:
            result = (session.query(l3_db.RouterPort).
                      join(models_v2.IPAllocation,
                           models_v2.IPAllocation.port_id ==
                           l3_db.RouterPort.port_id).
                      join(models_v2.Subnet,
                           models_v2.Subnet.id ==
                           models_v2.IPAllocation.subnet_id).
                      outerjoin(models_v2.SubnetPool,
                                models_v2.SubnetPool.id ==
                                models_v2.Subnet.subnetpool_id).
                      filter(l3_db.RouterPort.router_id == router['id']).
                      filter(l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).
                      filter(sa.or_(models_v2.Subnet.subnetpool_id.is_(None),
                                    models_v2.SubnetPool.address_scope_id.is_(
                                        None))).
                      count())
        else:
            # Include interfaces for isomorphic scope.
            mapping = self._get_address_scope_mapping(session, scope_id)
            vrf = self._get_address_scope_vrf(mapping)
            mappings = self._get_address_scope_mappings_for_vrf(session, vrf)
            scope_ids = [mapping.scope_id for mapping in mappings]
            result = (session.query(l3_db.RouterPort).
                      join(models_v2.IPAllocation,
                           models_v2.IPAllocation.port_id ==
                           l3_db.RouterPort.port_id).
                      join(models_v2.Subnet,
                           models_v2.Subnet.id ==
                           models_v2.IPAllocation.subnet_id).
                      join(models_v2.SubnetPool,
                           models_v2.SubnetPool.id ==
                           models_v2.Subnet.subnetpool_id).
                      filter(l3_db.RouterPort.router_id == router['id']).
                      filter(l3_db.RouterPort.port_type ==
                             n_constants.DEVICE_OWNER_ROUTER_INTF).
                      filter(models_v2.SubnetPool.address_scope_id.in_(
                          scope_ids)).
                      count())
        return result

    def _get_address_scope_id_for_subnets(self, context, subnets):
        # Assuming that all the subnets provided are consistent w.r.t.
        # address-scope, use the first available subnet to determine
        # address-scope. If subnets is a mix of v4 and v6 subnets,
        # then v4 subnets are given preference.
        subnets = sorted(subnets, key=lambda x: x['ip_version'])

        scope_id = NO_ADDR_SCOPE
        subnetpool_id = subnets[0]['subnetpool_id'] if subnets else None
        if subnetpool_id:
            subnetpool_db = self.plugin._get_subnetpool(context,
                                                        subnetpool_id)
            scope_id = (subnetpool_db.address_scope_id or NO_ADDR_SCOPE)
        return scope_id

    def _manage_external_connectivity(self, context, router, old_network,
                                      new_network, vrf):
        session = context.session
        aim_ctx = aim_context.AimContext(db_session=session)

        # Keep only the identity attributes of the VRF so that calls to
        # nat-library have consistent resource values. This
        # is mainly required to ease unit-test verification.
        vrf = aim_resource.VRF(tenant_name=vrf.tenant_name, name=vrf.name)
        rtr_dbs = self._get_routers_for_vrf(session, vrf)

        prov = set()
        cons = set()

        def update_contracts(router):
            contract = self._map_router(session, router, True)
            prov.add(contract.name)
            cons.add(contract.name)

            r_info = self.get_router_extn_db(session, router['id'])
            prov.update(r_info[a_l3.EXTERNAL_PROVIDED_CONTRACTS])
            cons.update(r_info[a_l3.EXTERNAL_CONSUMED_CONTRACTS])

        if old_network:
            _, ext_net, ns = self._get_aim_nat_strategy(old_network)
            if ext_net:
                # Find Neutron networks that share the APIC external network.
                eqv_nets = self.get_network_ids_by_ext_net_dn(
                    session, ext_net.dn, lock_update=True)
                rtr_old = [r for r in rtr_dbs
                           if (r.gw_port_id and
                               r.gw_port.network_id in eqv_nets)]
                prov = set()
                cons = set()
                for r in rtr_old:
                    update_contracts(r)

                if rtr_old:
                    ext_net.provided_contract_names = sorted(prov)
                    ext_net.consumed_contract_names = sorted(cons)
                    ns.connect_vrf(aim_ctx, ext_net, vrf)
                else:
                    ns.disconnect_vrf(aim_ctx, ext_net, vrf)
        if new_network:
            _, ext_net, ns = self._get_aim_nat_strategy(new_network)
            if ext_net:
                # Find Neutron networks that share the APIC external network.
                eqv_nets = self.get_network_ids_by_ext_net_dn(
                    session, ext_net.dn, lock_update=True)
                rtr_new = [r for r in rtr_dbs
                           if (r.gw_port_id and
                               r.gw_port.network_id in eqv_nets)]
                prov = set()
                cons = set()
                for r in rtr_new:
                    update_contracts(r)
                update_contracts(router)
                ext_net.provided_contract_names = sorted(prov)
                ext_net.consumed_contract_names = sorted(cons)
                ns.connect_vrf(aim_ctx, ext_net, vrf)

    def _is_port_bound(self, port):
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def _notify_port_update(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context.elevated(), port_id)
        if self._is_port_bound(port):
            LOG.debug("Enqueing notify for port %s", port['id'])
            txn = local_api.get_outer_transaction(
                plugin_context.session.transaction)
            local_api.send_or_queue_notification(plugin_context.session,
                                                 txn, self.notifier,
                                                 'port_update',
                                                 [plugin_context, port])

    def _notify_port_update_for_fip(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context.elevated(), port_id)
        ports_to_notify = [port_id]
        fixed_ips = [x['ip_address'] for x in port['fixed_ips']]
        if fixed_ips:
            addr_pair = (
                plugin_context.session.query(
                    n_addr_pair_db.AllowedAddressPair)
                .join(models_v2.Port,
                      models_v2.Port.id ==
                      n_addr_pair_db.AllowedAddressPair.port_id)
                .filter(models_v2.Port.network_id == port['network_id'])
                .filter(n_addr_pair_db.AllowedAddressPair.ip_address.in_(
                    fixed_ips)).all())
            ports_to_notify.extend([x['port_id'] for x in addr_pair])
        for p in sorted(ports_to_notify):
            self._notify_port_update(plugin_context, p)

    def _notify_port_update_bulk(self, plugin_context, port_ids):
        # REVISIT: Is a single query for all ports possible?
        for p_id in port_ids:
            self._notify_port_update(plugin_context, p_id)

    def get_or_allocate_snat_ip(self, plugin_context, host_or_vrf,
                                ext_network):
        """Fetch or allocate SNAT IP on the external network.

        IP allocation is done by creating a port on the external network,
        and associating an owner with it. The owner could be the ID of
        a host (or VRF) if SNAT IP allocation per host (or per VRF) is
        desired.
        If IP was found or successfully allocated, returns a dict like:
            {'host_snat_ip': <ip_addr>,
             'gateway_ip': <gateway_ip of subnet>,
             'prefixlen': <prefix_length_of_subnet>}
        """
        session = plugin_context.session
        snat_port = (session.query(models_v2.Port)
                     .filter(models_v2.Port.network_id == ext_network['id'],
                             models_v2.Port.device_id == host_or_vrf,
                             models_v2.Port.device_owner ==
                             DEVICE_OWNER_SNAT_PORT)
                     .first())
        snat_ip = None
        if not snat_port or snat_port.fixed_ips is None:
            # allocate SNAT port
            extn_db_sn = extension_db.SubnetExtensionDb
            snat_subnets = (session.query(models_v2.Subnet)
                            .join(extn_db_sn,
                                  extn_db_sn.subnet_id == models_v2.Subnet.id)
                            .filter(models_v2.Subnet.network_id ==
                                    ext_network['id'])
                            .filter(extn_db_sn.snat_host_pool.is_(True))
                            .all())
            if not snat_subnets:
                LOG.info('No subnet in external network %s is marked as '
                         'SNAT-pool',
                         ext_network['id'])
                return
            for snat_subnet in snat_subnets:
                try:
                    attrs = {'device_id': host_or_vrf,
                             'device_owner': DEVICE_OWNER_SNAT_PORT,
                             'tenant_id': ext_network['tenant_id'],
                             'name': 'snat-pool-port:%s' % host_or_vrf,
                             'network_id': ext_network['id'],
                             'mac_address': n_constants.ATTR_NOT_SPECIFIED,
                             'fixed_ips': [{'subnet_id': snat_subnet.id}],
                             'admin_state_up': False}
                    port = self.plugin.create_port(plugin_context,
                                                   {'port': attrs})
                    if port and port['fixed_ips']:
                        snat_ip = port['fixed_ips'][0]['ip_address']
                        break
                except n_exceptions.IpAddressGenerationFailure:
                    LOG.info('No more addresses available in subnet %s '
                             'for SNAT IP allocation',
                             snat_subnet['id'])
        else:
            snat_ip = snat_port.fixed_ips[0].ip_address
            snat_subnet = (session.query(models_v2.Subnet)
                           .filter(models_v2.Subnet.id ==
                                   snat_port.fixed_ips[0].subnet_id)
                           .one())

        if snat_ip:
            return {'host_snat_ip': snat_ip,
                    'gateway_ip': snat_subnet['gateway_ip'],
                    'prefixlen': int(snat_subnet['cidr'].split('/')[1])}

    def _has_snat_ip_ports(self, plugin_context, subnet_id):
        session = plugin_context.session
        return (session.query(models_v2.Port)
                .join(models_v2.IPAllocation,
                      models_v2.IPAllocation.port_id == models_v2.Port.id)
                .filter(models_v2.IPAllocation.subnet_id == subnet_id)
                .filter(models_v2.Port.device_owner == DEVICE_OWNER_SNAT_PORT)
                .first())

    def _delete_snat_ip_ports_if_reqd(self, plugin_context,
                                      ext_network_id, exclude_router_id):
        e_context = plugin_context.elevated()
        session = plugin_context.session
        # if there are no routers uplinked to the external network,
        # then delete any ports allocated for SNAT IP
        gw_qry = (session.query(models_v2.Port)
                  .filter(models_v2.Port.network_id == ext_network_id,
                          models_v2.Port.device_owner ==
                          n_constants.DEVICE_OWNER_ROUTER_GW,
                          models_v2.Port.device_id != exclude_router_id))
        if not gw_qry.first():
            snat_ports = (session.query(models_v2.Port.id)
                          .filter(models_v2.Port.network_id == ext_network_id,
                                  models_v2.Port.device_owner ==
                                  DEVICE_OWNER_SNAT_PORT)
                          .all())
            for p in snat_ports:
                try:
                    self.plugin.delete_port(e_context, p[0])
                except n_exceptions.NeutronException as ne:
                    LOG.warning('Failed to delete SNAT port %(port)s: '
                                '%(ex)s',
                                {'port': p, 'ex': ne})

    def check_floatingip_external_address(self, context, floatingip):
        session = context.session
        if floatingip.get('subnet_id'):
            sn_ext = self.get_subnet_extn_db(session, floatingip['subnet_id'])
            if sn_ext.get(cisco_apic.SNAT_HOST_POOL, False):
                raise exceptions.SnatPoolCannotBeUsedForFloatingIp()
        elif floatingip.get('floating_ip_address'):
            extn_db_sn = extension_db.SubnetExtensionDb
            cidrs = (session.query(models_v2.Subnet.cidr)
                    .join(extn_db_sn,
                          extn_db_sn.subnet_id == models_v2.Subnet.id)
                    .filter(models_v2.Subnet.network_id ==
                            floatingip['floating_network_id'])
                    .filter(extn_db_sn.snat_host_pool.is_(True))
                    .all())
            cidrs = netaddr.IPSet([c[0] for c in cidrs])
            if floatingip['floating_ip_address'] in cidrs:
                raise exceptions.SnatPoolCannotBeUsedForFloatingIp()

    def get_subnets_for_fip(self, context, floatingip):
        session = context.session
        extn_db_sn = extension_db.SubnetExtensionDb
        other_sn = (session.query(models_v2.Subnet.id)
                    .outerjoin(extn_db_sn,
                               extn_db_sn.subnet_id == models_v2.Subnet.id)
                    .filter(models_v2.Subnet.network_id ==
                            floatingip['floating_network_id'])
                    .filter(sa.or_(extn_db_sn.snat_host_pool.is_(False),
                                   extn_db_sn.snat_host_pool.is_(None)))
                    .all())
        return [s[0] for s in other_sn]

    def _is_opflex_type(self, net_type):
        return net_type == ofcst.TYPE_OPFLEX

    def _is_supported_non_opflex_type(self, net_type):
        return net_type in [n_constants.TYPE_VLAN]

    def _use_static_path(self, bound_segment):
        return (bound_segment and
                self._is_supported_non_opflex_type(
                    bound_segment[api.NETWORK_TYPE]))

    def _convert_segment(self, segment):
        seg = None
        if segment:
            if segment.get(api.NETWORK_TYPE) in [n_constants.TYPE_VLAN]:
                seg = 'vlan-%s' % segment[api.SEGMENTATION_ID]
            else:
                LOG.debug('Unsupported segmentation type for static path '
                          'binding: %s',
                          segment.get(api.NETWORK_TYPE))
        return seg

    def _filter_host_links_by_segment(self, session, segment, host_links):
        # All host links must belong to the same host
        filtered_host_links = []
        if host_links:
            aim_ctx = aim_context.AimContext(db_session=session)
            host_link_net_labels = self.aim.find(
                aim_ctx, aim_infra.HostLinkNetworkLabel,
                host_name=host_links[0].host_name,
                network_label=segment[api.PHYSICAL_NETWORK])
            # This segment uses specific host interfaces
            if host_link_net_labels:
                ifaces = set([x.interface_name for x in host_link_net_labels])
                filtered_host_links = [
                    x for x in host_links if x.interface_name in
                    ifaces and x.path]
        # If the filtered host link list is empty, return the original one.
        # TODO(ivar): we might want to raise an exception if there are not
        # host link available instead of falling back to the full list.
        return filtered_host_links or host_links

    def _rebuild_host_path_for_network(self, plugin_context, network, segment,
                                       host, host_links):
        seg = self._convert_segment(segment)
        if not seg:
            return
        # Filter host links if needed
        aim_ctx = aim_context.AimContext(db_session=plugin_context.session)
        host_links = self._filter_host_links_by_segment(plugin_context.session,
                                                        segment, host_links)

        if self._is_svi(network):
            l3out, _, _ = self._get_aim_external_objects(network)
            # Nuke existing interfaces for host
            search_args = {
                'tenant_name': l3out.tenant_name,
                'l3out_name': l3out.name,
                'node_profile_name': L3OUT_NODE_PROFILE_NAME,
                'interface_profile_name': L3OUT_IF_PROFILE_NAME,
                'host': host
            }
            for aim_l3out_if in self.aim.find(
                    aim_ctx, aim_resource.L3OutInterface, **search_args):
                self.aim.delete(aim_ctx, aim_l3out_if, cascade=True)
            for link in host_links:
                self._update_static_path_for_svi(
                    plugin_context.session, plugin_context, network, segment,
                    new_path=link, l3out=l3out)
        else:
            epg = self.get_epg_for_network(plugin_context.session, network)
            if not epg:
                LOG.info('Network %s does not map to any EPG', network['id'])
                return
            epg = self.aim.get(aim_ctx, epg)
            # Remove old host values
            paths = set([(x['path'], x['encap'], x['host'])
                         for x in epg.static_paths if x['host'] != host])
            # Add new ones
            paths |= set([(x.path, seg, x.host_name) for x in host_links])
            self.aim.update(aim_ctx, epg, static_paths=[
                {'path': x[0], 'encap': x[1], 'host': x[2]} for x in paths])

    def _update_static_path_for_svi(self, session, plugin_context, network,
                                    segment, old_path=None, new_path=None,
                                    l3out=None):
        if new_path and not segment:
            return

        seg = self._convert_segment(segment)
        if not seg:
            return
        if new_path:
            path = new_path.path
        else:
            path = old_path.path
        nodes = []
        node_paths = []
        is_vpc = False
        match = self.port_desc_re.match(path)
        if match:
            pod_id, switch, module, port = match.group(1, 2, 3, 4)
            nodes.append(switch)
            node_paths.append(ACI_CHASSIS_DESCR_STRING % (pod_id, switch))
        else:
            match = self.vpcport_desc_re.match(path)
            if match:
                pod_id, switch1, switch2, bundle = match.group(1, 2, 3, 4)
                nodes.append(switch1)
                nodes.append(switch2)
                node_paths.append(ACI_CHASSIS_DESCR_STRING % (pod_id,
                                                              switch1))
                node_paths.append(ACI_CHASSIS_DESCR_STRING % (pod_id,
                                                              switch2))
                is_vpc = True
            else:
                LOG.error('Unsupported static path format: %s', path)
                return

        aim_ctx = aim_context.AimContext(db_session=session)
        if not l3out:
            l3out, _, _ = self._get_aim_external_objects(network)
        if new_path:
            for node_path in node_paths:
                apic_router_id = self._allocate_apic_router_ids(aim_ctx,
                                                                node_path)
                aim_l3out_node = aim_resource.L3OutNode(
                    tenant_name=l3out.tenant_name, l3out_name=l3out.name,
                    node_profile_name=L3OUT_NODE_PROFILE_NAME,
                    node_path=node_path, router_id=apic_router_id,
                    router_id_loopback=False)
                self.aim.create(aim_ctx, aim_l3out_node, overwrite=True)

            if not network['subnets']:
                return
            subnet = (session.query(models_v2.Subnet)
                      .filter(models_v2.Subnet.id ==
                              network['subnets'][0]).one())
            mask = subnet['cidr'].split('/')[1]

            primary_ips = []
            for node in nodes:
                filters = {'network_id': [network['id']],
                           'name': ['apic-svi-port:node-%s' % node]}
                svi_ports = self.plugin.get_ports(plugin_context, filters)
                if svi_ports and svi_ports[0]['fixed_ips']:
                    ip = svi_ports[0]['fixed_ips'][0]['ip_address']
                    primary_ips.append(ip + '/' + mask)
                else:
                    attrs = {'device_id': '',
                             'device_owner': DEVICE_OWNER_SVI_PORT,
                             'tenant_id': network['tenant_id'],
                             'name': 'apic-svi-port:node-%s' % node,
                             'network_id': network['id'],
                             'mac_address': n_constants.ATTR_NOT_SPECIFIED,
                             'fixed_ips': [{'subnet_id':
                                            network['subnets'][0]}],
                             'admin_state_up': False}
                    port = self.plugin.create_port(plugin_context,
                                                   {'port': attrs})
                    if port and port['fixed_ips']:
                        ip = port['fixed_ips'][0]['ip_address']
                        primary_ips.append(ip + '/' + mask)
                    else:
                        LOG.error('cannot allocate a port for the SVI primary'
                                  ' addr')
                        return
            secondary_ip = subnet['gateway_ip'] + '/' + mask
            aim_l3out_if = aim_resource.L3OutInterface(
                tenant_name=l3out.tenant_name,
                l3out_name=l3out.name,
                node_profile_name=L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=L3OUT_IF_PROFILE_NAME,
                interface_path=path, encap=seg, host=new_path.host_name,
                primary_addr_a=primary_ips[0],
                secondary_addr_a_list=[{'addr': secondary_ip}],
                primary_addr_b=primary_ips[1] if is_vpc else '',
                secondary_addr_b_list=[{'addr':
                                        secondary_ip}] if is_vpc else [])
            self.aim.create(aim_ctx, aim_l3out_if, overwrite=True)
            network_db = self.plugin._get_network(plugin_context,
                                                  network['id'])
            if (network_db.aim_extension_mapping.bgp_enable and
                    network_db.aim_extension_mapping.bgp_type
                    == 'default_export'):
                aim_bgp_peer_prefix = aim_resource.L3OutInterfaceBgpPeerP(
                    tenant_name=l3out.tenant_name,
                    l3out_name=l3out.name,
                    node_profile_name=L3OUT_NODE_PROFILE_NAME,
                    interface_profile_name=L3OUT_IF_PROFILE_NAME,
                    interface_path=path,
                    addr=subnet['cidr'],
                    asn=network_db.aim_extension_mapping.bgp_asn)
                self.aim.create(aim_ctx, aim_bgp_peer_prefix, overwrite=True)
        else:
            aim_l3out_if = aim_resource.L3OutInterface(
                tenant_name=l3out.tenant_name,
                l3out_name=l3out.name,
                node_profile_name=L3OUT_NODE_PROFILE_NAME,
                interface_profile_name=L3OUT_IF_PROFILE_NAME,
                interface_path=path)
            self.aim.delete(aim_ctx, aim_l3out_if, cascade=True)

    def _update_static_path_for_network(self, session, network, segment,
                                        old_path=None, new_path=None):
        if new_path and not segment:
            return

        epg = self.get_epg_for_network(session, network)
        if not epg:
            LOG.info('Network %s does not map to any EPG', network['id'])
            return

        seg = self._convert_segment(segment)
        if not seg:
            return

        aim_ctx = aim_context.AimContext(db_session=session)
        epg = self.aim.get(aim_ctx, epg)
        to_remove = [old_path.path] if old_path else []
        to_remove.extend([new_path.path] if new_path else [])
        if to_remove:
            epg.static_paths = [p for p in epg.static_paths
                                if p.get('path') not in to_remove]
        if new_path:
            epg.static_paths.append({'path': new_path.path, 'encap': seg,
                                     'host': new_path.host_name})
        LOG.debug('Setting static paths for EPG %s to %s',
                  epg, epg.static_paths)
        self.aim.update(aim_ctx, epg, static_paths=epg.static_paths)

    def _update_static_path(self, port_context, host=None, segment=None,
                            remove=False):
        host = host or port_context.host
        segment = segment or port_context.bottom_bound_segment
        session = port_context._plugin_context.session

        if not segment:
            LOG.debug('Port %s is not bound to any segment',
                      port_context.current['id'])
            return
        if remove:
            # check if there are any other ports from this network on the host
            exist = (session.query(models.PortBindingLevel)
                     .filter_by(host=host, segment_id=segment['id'])
                     .filter(models.PortBindingLevel.port_id !=
                             port_context.current['id'])
                     .first())
            if exist:
                return

        aim_ctx = aim_context.AimContext(db_session=session)
        host_links = self.aim.find(aim_ctx, aim_infra.HostLink, host_name=host)
        host_links = self._filter_host_links_by_segment(session, segment,
                                                        host_links)
        for hlink in host_links:
            if self._is_svi(port_context.network.current):
                self._update_static_path_for_svi(
                    session, port_context._plugin_context,
                    port_context.network.current, segment,
                    **{'old_path' if remove else 'new_path': hlink})
            else:
                self._update_static_path_for_network(
                    session, port_context.network.current, segment,
                    **{'old_path' if remove else 'new_path': hlink})

    def _release_dynamic_segment(self, port_context, use_original=False):
        top = (port_context.original_top_bound_segment if use_original
               else port_context.top_bound_segment)
        btm = (port_context.original_bottom_bound_segment if use_original
               else port_context.bottom_bound_segment)
        if (top and btm and
            self._is_opflex_type(top[api.NETWORK_TYPE]) and
            self._is_supported_non_opflex_type(btm[api.NETWORK_TYPE])):
            # if there are no other ports bound to segment, release the segment
            ports = (port_context._plugin_context.session
                     .query(models.PortBindingLevel)
                     .filter_by(segment_id=btm[api.ID])
                     .filter(models.PortBindingLevel.port_id !=
                             port_context.current['id'])
                     .first())
            if not ports:
                LOG.info('Releasing dynamic-segment %(s)s for port %(p)s',
                         {'s': btm, 'p': port_context.current['id']})
                port_context.release_dynamic_segment(btm[api.ID])

    # public interface for aim_mapping GBP policy driver
    def associate_domain(self, port_context):
        if self._is_port_bound(port_context.current):
            if self._use_static_path(port_context.bottom_bound_segment):
                self._associate_domain(port_context, is_vmm=False)
            elif (port_context.bottom_bound_segment and
                  self._is_opflex_type(
                        port_context.bottom_bound_segment[api.NETWORK_TYPE])):
                self._associate_domain(port_context, is_vmm=True)

    def _skip_domain_processing(self, port_context):
        ext_net = port_context.network.current
        # skip domain processing if it's not managed by us, or
        # for external networks with NAT (FIPs or SNAT),
        if not ext_net:
            return True
        if ext_net[external_net.EXTERNAL] is True:
            _, _, ns = self._get_aim_nat_strategy(ext_net)
            if not isinstance(ns, nat_strategy.NoNatStrategy):
                return True
        return False

    def _associate_domain(self, port_context, is_vmm=True):
        if self._is_svi(port_context.network.current):
            return
        port = port_context.current
        session = port_context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        if self._skip_domain_processing(port_context):
            return
        ptg = None
        # TODO(kentwu): remove this coupling with policy driver if possible
        if self.gbp_driver:
            ptg, pt = self.gbp_driver._port_id_to_ptg(
                port_context._plugin_context, port['id'])
        if ptg:
            epg = self.gbp_driver._aim_endpoint_group(session, ptg)
        else:
            mapping = self._get_network_mapping(session, port['network_id'])
            epg = self._get_network_epg(mapping)
        aim_epg = self.aim.get(aim_ctx, epg)
        host_id = port[portbindings.HOST_ID]
        aim_hd_mappings = (self.aim.find(aim_ctx,
                                         aim_infra.HostDomainMappingV2,
                                         host_name=host_id) or
                           self.aim.find(aim_ctx,
                                         aim_infra.HostDomainMappingV2,
                                         host_name=DEFAULT_HOST_DOMAIN))
        domains = []
        try:
            if is_vmm:
                # Get all the openstack VMM domains. We either
                # get domains from a lookup of the HostDomainMappingV2
                # table, or we get all the applicable VMM domains
                # found in AIM. We then apply these to the EPG.
                if aim_hd_mappings:
                    domains = [{'type': mapping.domain_type,
                                'name': mapping.domain_name}
                               for mapping in aim_hd_mappings
                               if mapping.domain_type in ['OpenStack']]
                if not domains:
                    vmms, phys = self.get_aim_domains(aim_ctx)
                    self.aim.update(aim_ctx, epg,
                                    vmm_domains=vmms)
                else:
                    vmms = aim_epg.vmm_domains[:]
                    for domain in domains:
                        if domain not in aim_epg.vmm_domains:
                            aim_epg.vmm_domains.append(domain)
                    if vmms != aim_epg.vmm_domains:
                        vmms = aim_epg.vmm_domains
                        self.aim.update(aim_ctx, epg, vmm_domains=vmms)
            else:
                # Get all the Physical domains. We either get domains
                # from a lookup of the HostDomainMappingV2
                # table, or we get all the applicable Physical
                # domains found in AIM. We then apply these to the EPG.
                if aim_hd_mappings:
                    domains = [{'name': mapping.domain_name}
                               for mapping in aim_hd_mappings
                               if mapping.domain_type in ['PhysDom']]
                if not domains:
                    vmms, phys = self.get_aim_domains(aim_ctx)
                    self.aim.update(aim_ctx, epg,
                                    physical_domains=phys)
                else:
                    phys = aim_epg.physical_domains[:]
                    for domain in domains:
                        if domain not in aim_epg.physical_domains:
                            aim_epg.physical_domains.append(domain)
                    if phys != aim_epg.physical_domains:
                        phys = aim_epg.physical_domains
                        self.aim.update(aim_ctx, epg,
                                        physical_domains=phys)
        # this could be caused by concurrent transactions
        except db_exc.DBDuplicateEntry as e:
            LOG.debug(e)

    # public interface for aim_mapping GBP policy driver also
    def disassociate_domain(self, port_context, use_original=False):
        if self._is_svi(port_context.network.current):
            return

        btm = (port_context.original_bottom_bound_segment if use_original
               else port_context.bottom_bound_segment)
        if not btm:
            return
        port = port_context.current
        if (self._is_opflex_type(btm[api.NETWORK_TYPE]) or
                self._is_supported_non_opflex_type(btm[api.NETWORK_TYPE])):
            if self._skip_domain_processing(port_context):
                return
            host_id = (port_context.original_host if use_original
                       else port_context.host)
            session = port_context._plugin_context.session
            aim_ctx = aim_context.AimContext(session)
            aim_hd_mappings = self.aim.find(aim_ctx,
                                            aim_infra.HostDomainMappingV2,
                                            host_name=host_id)
            if not aim_hd_mappings:
                return

            if self._is_opflex_type(btm[api.NETWORK_TYPE]):
                domain_type = 'OpenStack'
            else:
                domain_type = 'PhysDom'

            domains = []
            hd_mappings = []
            for mapping in aim_hd_mappings:
                d_type = mapping.domain_type
                if d_type == domain_type and mapping.domain_name:
                    domains.append(mapping.domain_name)
                    hd_mappings.extend(self.aim.find(aim_ctx,
                        aim_infra.HostDomainMappingV2,
                        domain_name=mapping.domain_name,
                        domain_type=d_type))
            if not domains:
                return
            hosts = [x.host_name
                     for x in hd_mappings
                     if x.host_name != DEFAULT_HOST_DOMAIN]
            ptg = None
            if self.gbp_driver:
                ptg, pt = self.gbp_driver._port_id_to_ptg(
                    port_context._plugin_context, port['id'])

            def _bound_port_query(session, port, hosts=None):
                ports = (session.query(models.PortBindingLevel).
                         join(models_v2.Port, models_v2.Port.id ==
                              models.PortBindingLevel.port_id))
                if hosts:
                    ports = ports.filter(
                        models.PortBindingLevel.host.in_(hosts))
                ports = ports.filter(
                    models.PortBindingLevel.port_id != port['id'])
                return ports

            if ptg:
                # if there are no other ports under this PTG bound to those
                # hosts under this vmm, release the domain
                bound_ports = _bound_port_query(session, port, hosts=hosts)
                bound_ports = [x['port_id'] for x in bound_ports]
                ptg_ports = self.gbp_driver.get_ptg_port_ids(
                    port_context._plugin_context, ptg)
                ports = set(bound_ports).intersection(ptg_ports)
                if ports:
                    return
                epg = self.gbp_driver._aim_endpoint_group(session, ptg)
            else:
                # if there are no other ports under this network bound to those
                # hosts under this vmm, release the domain
                ports = _bound_port_query(session, port, hosts=hosts)
                if ports.first():
                    return
                mapping = self._get_network_mapping(
                    session, port['network_id'])
                epg = self._get_network_epg(mapping)
            aim_epg = self.aim.get(aim_ctx, epg)
            try:
                if self._is_opflex_type(btm[api.NETWORK_TYPE]):
                    vmms = aim_epg.vmm_domains[:]
                    for domain in domains:
                        mapping = {'type': domain_type,
                                   'name': domain}
                        if mapping in aim_epg.vmm_domains:
                            aim_epg.vmm_domains.remove(mapping)
                    if vmms != aim_epg.vmm_domains:
                        vmms = aim_epg.vmm_domains
                        self.aim.update(aim_ctx, epg,
                                        vmm_domains=vmms)
                else:
                    phys = aim_epg.physical_domains[:]
                    for domain in domains:
                        mapping = {'name': domain}
                        if mapping in aim_epg.physical_domains:
                            aim_epg.physical_domains.remove(mapping)
                    if phys != aim_epg.physical_domains:
                        phys = aim_epg.physical_domains
                        self.aim.update(aim_ctx, epg,
                                        physical_domains=phys)
            # this could be caused by concurrent transactions
            except db_exc.DBDuplicateEntry as e:
                LOG.debug(e)
            LOG.info('Releasing domain %(d)s for port %(p)s',
                     {'d': domain, 'p': port['id']})

    def _get_non_opflex_segments_on_host(self, context, host):
        session = context.session
        segments = (session.query(segments_model.NetworkSegment)
                    .join(models.PortBindingLevel,
                          models.PortBindingLevel.segment_id ==
                          segments_model.NetworkSegment.id)
                    .filter(models.PortBindingLevel.host == host)
                    .all())
        net_ids = set([])
        result = []
        for seg in segments:
            if (self._is_supported_non_opflex_type(seg[api.NETWORK_TYPE]) and
                    seg.network_id not in net_ids):
                net = self.plugin.get_network(context, seg.network_id)
                result.append((net, segments_db._make_segment_dict(seg)))
                net_ids.add(seg.network_id)
        return result

    def _get_router_interface_subnets(self, session, router_id):
        subnet_ids = (session.query(models_v2.IPAllocation.subnet_id)
                      .join(l3_db.RouterPort,
                            l3_db.RouterPort.port_id ==
                            models_v2.IPAllocation.port_id)
                      .filter(l3_db.RouterPort.router_id == router_id)
                      .distinct())
        return [s[0] for s in subnet_ids]

    def _get_non_router_ports_in_subnets(self, session, subnet_ids):
        if not subnet_ids:
            return []
        port_ids = (session.query(models_v2.IPAllocation.port_id)
                    .join(models_v2.Port,
                          models_v2.Port.id == models_v2.IPAllocation.port_id)
                    .filter(models_v2.IPAllocation.subnet_id.in_(subnet_ids))
                    .filter(models_v2.Port.device_owner !=
                            n_constants.DEVICE_OWNER_ROUTER_INTF)
                    .all())
        return [p[0] for p in port_ids]

    def _get_non_router_ports_in_networks(self, session, network_ids):
        if not network_ids:
            return []
        port_ids = (session.query(models_v2.Port.id).
                    filter(models_v2.Port.network_id.in_(network_ids)).
                    filter(models_v2.Port.device_owner !=
                           n_constants.DEVICE_OWNER_ROUTER_INTF).
                    all())
        return [p[0] for p in port_ids]

    def _get_port_network_id(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context, port_id)
        return port['network_id']

    def _get_svi_default_external_epg(self, network):
        if not network.get(cisco_apic.SVI):
            return None
        ext_net_dn = network.get(cisco_apic.DIST_NAMES, {}).get(
            cisco_apic.EXTERNAL_NETWORK)
        return aim_resource.ExternalNetwork.from_dn(ext_net_dn)

    def _get_svi_net_l3out(self, network):
        aim_ext_net = self._get_svi_default_external_epg(network)
        if not aim_ext_net:
            return None
        return aim_resource.L3Outside(
            tenant_name=aim_ext_net.tenant_name, name=aim_ext_net.l3out_name)

    def _get_bd_by_network_id(self, session, network_id):
        net_mapping = self._get_network_mapping(session, network_id)
        return self._get_network_bd(net_mapping)

    def _get_epg_by_network_id(self, session, network_id):
        net_mapping = self._get_network_mapping(session, network_id)
        return self._get_network_epg(net_mapping)

    def _get_vrf_by_network(self, session, network):
        vrf_dn = network.get(cisco_apic.DIST_NAMES, {}).get(cisco_apic.VRF)
        if vrf_dn:
            return aim_resource.VRF.from_dn(vrf_dn)
        # Pre-existing EXT NET.
        l3out = self._get_svi_net_l3out(network)
        if l3out:
            aim_ctx = aim_context.AimContext(db_session=session)
            l3out = self.aim.get(aim_ctx, l3out)
            # TODO(ivar): VRF could be in tenant common, there's no way of
            # knowing it until we put the VRF in the mapping.
            return aim_resource.VRF(tenant_name=l3out.tenant_name,
                                    name=l3out.vrf_name)
        net_mapping = self._get_network_mapping(session, network['id'])
        return self._get_network_vrf(net_mapping)

    def _get_port_static_path_info(self, plugin_context, port):
        port_id = port['id']
        path = encap = host = None
        if self._is_port_bound(port):
            session = plugin_context.session
            aim_ctx = aim_context.AimContext(db_session=session)
            __, binding = n_db.get_locked_port_and_binding(plugin_context,
                                                           port_id)
            levels = n_db.get_binding_levels(plugin_context, port_id,
                                             binding.host)
            network = self.plugin.get_network(
                plugin_context, port['network_id'])
            port_context = ml2_context.PortContext(
                self, plugin_context, port, network, binding, levels)
            host = port_context.host
            segment = port_context.bottom_bound_segment
            host_links = self.aim.find(aim_ctx, aim_infra.HostLink,
                                       host_name=host)
            host_links = self._filter_host_links_by_segment(session, segment,
                                                            host_links)
            encap = self._convert_segment(segment)
            if not host_links:
                LOG.warning("No host link information found for host %s ",
                            host)
                return None, None, None
            # REVISIT(ivar): we should return a list for all available host
            # links
            path = host_links[0].path
        return path, encap, host

    def _get_port_unique_domain(self, plugin_context, port):
        """Get port domain

        Returns a unique domain (either virtual or physical) in which the
        specific endpoint is placed. If the domain cannot be uniquely
        identified returns None

        :param plugin_context:
        :param port:
        :return:
        """
        # TODO(ivar): at the moment, it's likely that this method won't
        # return anything unique for the specific port. This is because we
        # don't require users to specify domain mappings, and even if we did,
        # such mappings are barely scoped by host, and each host could have
        # at the very least one VMM and one Physical domain referring to it
        # (HPB). However, every Neutron port can actually belong only to a
        # single domain. We should implement a way to unequivocally retrieve
        # that information.
        session = plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        if self._is_port_bound(port):
            host_id = port[portbindings.HOST_ID]
            dom_mappings = (self.aim.find(aim_ctx,
                                          aim_infra.HostDomainMappingV2,
                                          host_name=host_id) or
                            self.aim.find(aim_ctx,
                                          aim_infra.HostDomainMappingV2,
                                          host_name=DEFAULT_HOST_DOMAIN))
            if not dom_mappings:
                # If there's no direct mapping, get all the existing domains in
                # AIM.
                vmms, phys = self.get_aim_domains(aim_ctx)
                for vmm in vmms:
                    dom_mappings.append(
                        aim_infra.HostDomainMappingV2(
                            domain_type=vmm['type'], domain_name=vmm['name'],
                            host_name=DEFAULT_HOST_DOMAIN))
                for phy in phys:
                    dom_mappings.append(
                        aim_infra.HostDomainMappingV2(
                            domain_type='PhysDom', domain_name=phy['name'],
                            host_name=DEFAULT_HOST_DOMAIN))
            if not dom_mappings or len(dom_mappings) > 1:
                return None, None
            return dom_mappings[0].domain_type, dom_mappings[0].domain_name
        return None, None

    def _add_network_mapping_and_notify(self, context, network_id, bd, epg,
                                        vrf):
        with db_api.context_manager.writer.using(context):
            self._add_network_mapping(context.session, network_id, bd, epg,
                                      vrf)
            registry.notify(aim_cst.GBP_NETWORK_VRF, events.PRECOMMIT_UPDATE,
                            self, context=context, network_id=network_id)

    def _set_network_epg_and_notify(self, context, mapping, epg):
        with db_api.context_manager.writer.using(context):
            self._set_network_epg(mapping, epg)
            registry.notify(aim_cst.GBP_NETWORK_EPG, events.PRECOMMIT_UPDATE,
                            self, context=context,
                            network_id=mapping.network_id)

    def _set_network_vrf_and_notify(self, context, mapping, vrf):
        with db_api.context_manager.writer.using(context):
            self._set_network_vrf(mapping, vrf)
            registry.notify(aim_cst.GBP_NETWORK_VRF, events.PRECOMMIT_UPDATE,
                            self, context=context,
                            network_id=mapping.network_id)

    def validate_aim_mapping(self, mgr):
        # First do any cleanup and/or migration of Neutron resources
        # used internally by the legacy plugins.
        self._validate_legacy_resources(mgr)

        # Register all AIM resource types used by mapping.
        mgr.register_aim_resource_class(aim_infra.HostDomainMappingV2)
        mgr.register_aim_resource_class(aim_resource.ApplicationProfile)
        mgr.register_aim_resource_class(aim_resource.BridgeDomain)
        mgr.register_aim_resource_class(aim_resource.Contract)
        mgr.register_aim_resource_class(aim_resource.ContractSubject)
        mgr.register_aim_resource_class(aim_resource.EndpointGroup)
        mgr.register_aim_resource_class(aim_resource.ExternalNetwork)
        mgr.register_aim_resource_class(aim_resource.ExternalSubnet)
        mgr.register_aim_resource_class(aim_resource.Filter)
        mgr.register_aim_resource_class(aim_resource.FilterEntry)
        mgr.register_aim_resource_class(aim_resource.L3Outside)
        mgr.register_aim_resource_class(aim_resource.PhysicalDomain)
        mgr.register_aim_resource_class(aim_resource.SecurityGroup)
        mgr.register_aim_resource_class(aim_resource.SecurityGroupRule)
        mgr.register_aim_resource_class(aim_resource.SecurityGroupSubject)
        mgr.register_aim_resource_class(aim_resource.Subnet)
        mgr.register_aim_resource_class(aim_resource.Tenant)
        mgr.register_aim_resource_class(aim_resource.VMMDomain)
        mgr.register_aim_resource_class(aim_resource.VRF)

        # Copy common Tenant from actual to expected AIM store.
        for tenant in mgr.aim_mgr.find(
            mgr.actual_aim_ctx, aim_resource.Tenant, name=COMMON_TENANT_NAME):
            mgr.aim_mgr.create(mgr.expected_aim_ctx, tenant)

        # Copy AIM resources that are managed via aimctl from actual
        # to expected AIM stores.
        for resource_class in [aim_infra.HostDomainMappingV2,
                               aim_resource.PhysicalDomain,
                               aim_resource.VMMDomain]:
            for resource in mgr.actual_aim_resources(resource_class):
                mgr.aim_mgr.create(mgr.expected_aim_ctx, resource)

        # Copy pre-existing AIM resources for external networking from
        # actual to expected AIM stores.
        for resource_class in [aim_resource.ExternalNetwork,
                               aim_resource.ExternalSubnet,
                               aim_resource.L3Outside,
                               aim_resource.VRF]:
            for resource in mgr.actual_aim_resources(resource_class):
                if resource.monitored:
                    mgr.aim_mgr.create(mgr.expected_aim_ctx, resource)

        # Register DB tables to be validated.
        mgr.register_db_instance_class(
            aim_lib_model.CloneL3Out, ['tenant_name', 'name'])
        mgr.register_db_instance_class(
            db.AddressScopeMapping, ['scope_id'])
        mgr.register_db_instance_class(
            db.NetworkMapping, ['network_id'])

        # Determine expected AIM resources and DB records for each
        # Neutron resource type. We stash a set identifying the
        # projects that have been processed so far in the validation
        # manager since this will be needed for both Neutron and GBP
        # resources.
        mgr._expected_projects = set()
        self._validate_static_resources(mgr)
        self._validate_address_scopes(mgr)
        router_dbs, ext_net_routers = self._validate_routers(mgr)
        self._validate_networks(mgr, router_dbs, ext_net_routers)
        self._validate_security_groups(mgr)
        self._validate_ports(mgr)
        self._validate_subnetpools(mgr)
        self._validate_floatingips(mgr)
        self._validate_port_bindings(mgr)

    def _validate_legacy_resources(self, mgr):
        # Delete legacy SNAT ports.
        for port_id, in (
                mgr.actual_session.query(models_v2.Port.id).
                filter_by(
                    name=LEGACY_SNAT_PORT_NAME,
                    device_owner=LEGACY_SNAT_PORT_DEVICE_OWNER)):
            if mgr.should_repair(
                    "legacy APIC driver SNAT port %s" % port_id, "Deleting"):
                try:
                    self.plugin.delete_port(mgr.actual_context, port_id)
                except n_exceptions.NeutronException as exc:
                    mgr.validation_failed(
                        "deleting legacy APIC driver SNAT port %s failed "
                        "with %s" % (port_id, exc))

        # Delete legacy SNAT subnets.
        for subnet_id, in (
                mgr.actual_session.query(models_v2.Subnet.id).
                filter_by(name=LEGACY_SNAT_SUBNET_NAME)):
            subnet = self.plugin.get_subnet(mgr.actual_context, subnet_id)
            net = self.plugin.get_network(
                mgr.actual_context, subnet['network_id'])
            net_name = net['name']
            if net_name and net_name.startswith(LEGACY_SNAT_NET_NAME_PREFIX):
                ext_net_id = net_name[len(LEGACY_SNAT_NET_NAME_PREFIX):]
                ext_net = (mgr.actual_session.query(models_v2.Network).
                           filter_by(id=ext_net_id).
                           one_or_none())
                if ext_net and ext_net.external:
                    if mgr.should_repair(
                            "legacy APIC driver SNAT subnet %s" %
                            subnet['cidr'],
                            "Migrating"):
                        try:
                            del subnet['id']
                            del subnet['project_id']
                            subnet['tenant_id'] = ext_net.project_id
                            subnet['network_id'] = ext_net.id
                            subnet['name'] = 'SNAT host pool'
                            subnet[cisco_apic.SNAT_HOST_POOL] = True
                            subnet = self.plugin.create_subnet(
                                mgr.actual_context, {'subnet': subnet})
                        except n_exceptions.NeutronException as exc:
                            mgr.validation_failed(
                                "Migrating legacy APIC driver SNAT subnet %s "
                                "failed with %s" % (subnet['cidr'], exc))
            if mgr.should_repair(
                    "legacy APIC driver SNAT subnet %s" % subnet_id,
                    "Deleting"):
                try:
                    self.plugin.delete_subnet(mgr.actual_context, subnet_id)
                except n_exceptions.NeutronException as exc:
                    mgr.validation_failed(
                        "deleting legacy APIC driver SNAT subnet %s failed "
                        "with %s" % (subnet_id, exc))

        # Delete legacy SNAT networks.
        for net_id, in (
                mgr.actual_session.query(models_v2.Network.id).
                filter(models_v2.Network.name.startswith(
                    LEGACY_SNAT_NET_NAME_PREFIX))):
            if mgr.should_repair(
                    "legacy APIC driver SNAT network %s" % net_id,
                    "Deleting"):
                try:
                    self.plugin.delete_network(mgr.actual_context, net_id)
                except n_exceptions.NeutronException as exc:
                    mgr.validation_failed(
                        "deleting legacy APIC driver SNAT network %s failed "
                        "with %s" % (net_id, exc))

        # REVISIT: Without this expunge_all call, the
        # test_legacy_cleanup UT intermittently fails with the
        # subsequent validation steps attempting to repair missing
        # subnet extension data, changing the apic:snat_host_pool
        # value of the migrated SNAT subnet from True to False. The
        # way the extension_db module creates the SubnetExtensionDb
        # instance during create_subnet is apparently not updating the
        # relationship from a cached Subnet instance. Until this issue
        # is understood and resolved, we expunge all instances from
        # the session before proceeding.
        mgr.actual_session.expunge_all()

    def _validate_static_resources(self, mgr):
        self._ensure_common_tenant(mgr.expected_aim_ctx)
        self._ensure_unrouted_vrf(mgr.expected_aim_ctx)
        self._ensure_any_filter(mgr.expected_aim_ctx)
        self._setup_default_arp_dhcp_security_group_rules(
            mgr.expected_aim_ctx)

    def _validate_address_scopes(self, mgr):
        owned_scopes_by_vrf = defaultdict(list)
        for scope_db in mgr.actual_session.query(as_db.AddressScope):
            self._expect_project(mgr, scope_db.project_id)
            mapping = scope_db.aim_mapping
            if mapping:
                mgr.expect_db_instance(mapping)
            else:
                vrf = self._map_address_scope(mgr.expected_session, scope_db)
                mapping = self._add_address_scope_mapping(
                    mgr.expected_session, scope_db.id, vrf, update_scope=False)
            vrf = self._get_address_scope_vrf(mapping)
            vrf.monitored = not mapping.vrf_owned
            vrf.display_name = (
                aim_utils.sanitize_display_name(scope_db.name)
                if mapping.vrf_owned else "")
            vrf.policy_enforcement_pref = 'enforced'
            mgr.expect_aim_resource(vrf, replace=True)
            if mapping.vrf_owned:
                scopes = owned_scopes_by_vrf[tuple(vrf.identity)]
                scopes.append(scope_db)
                # REVISIT: Fail if multiple scopes for same address family?
                if len(scopes) > 1:
                    scopes = sorted(scopes, key=lambda scope: scope.ip_version)
                    self._update_vrf_display_name(
                        mgr.expected_aim_ctx, vrf, scopes)

    def _validate_routers(self, mgr):
        router_dbs = {}
        ext_net_routers = defaultdict(list)
        for router_db in mgr.actual_session.query(l3_db.Router):
            self._expect_project(mgr, router_db.project_id)
            router_dbs[router_db.id] = router_db
            if router_db.gw_port_id:
                ext_net_routers[router_db.gw_port.network_id].append(
                    router_db.id)

            contract, subject = self._map_router(
                mgr.expected_session, router_db)
            dname = aim_utils.sanitize_display_name(router_db.name)

            contract.scope = "context"
            contract.display_name = dname
            contract.monitored = False
            mgr.expect_aim_resource(contract)

            subject.in_filters = []
            subject.out_filters = []
            subject.bi_filters = [self._any_filter_name]
            subject.service_graph_name = ''
            subject.in_service_graph_name = ''
            subject.out_service_graph_name = ''
            subject.display_name = dname
            subject.monitored = False
            mgr.expect_aim_resource(subject)

        return router_dbs, ext_net_routers

    def _validate_networks(self, mgr, router_dbs, ext_net_routers):
        net_dbs = {net_db.id: net_db for net_db in
                   mgr.actual_session.query(models_v2.Network).options(
                       orm.joinedload('segments'))}

        router_ext_prov, router_ext_cons = self._get_router_ext_contracts(mgr)
        routed_nets = self._get_router_interface_info(mgr)
        network_vrfs, router_vrfs = self._determine_vrfs(
            mgr, net_dbs, routed_nets)

        for net_db in net_dbs.values():
            if not net_db.aim_extension_mapping:
                self._missing_network_extension_mapping(mgr, net_db)
            self._expect_project(mgr, net_db.project_id)

            for subnet_db in net_db.subnets:
                if not subnet_db.aim_extension_mapping:
                    self._missing_subnet_extension_mapping(mgr, subnet_db)
                self._expect_project(mgr, subnet_db.project_id)

            for segment_db in net_db.segments:
                # REVISIT: Consider validating that physical_network
                # and segmentation_id values make sense for the
                # network_type, and possibly validate that there are
                # no conflicting segment allocations.
                if (segment_db.network_type not in
                    self.plugin.type_manager.drivers):
                    # REVISIT: For migration from non-APIC backends,
                    # change type to 'opflex'?
                    mgr.validation_failed(
                        "network %(net_id)s segment %(segment_id)s type "
                        "%(type)s is invalid" % {
                            'net_id': segment_db.network_id,
                            'segment_id': segment_db.id,
                            'type': segment_db.network_type})

            bd = None
            epg = None
            vrf = None
            ext_net = None
            if net_db.external:
                bd, epg, vrf = self._validate_external_network(
                    mgr, net_db, ext_net_routers, router_dbs, router_vrfs,
                    router_ext_prov, router_ext_cons)
            elif self._is_svi_db(net_db):
                mgr.validation_failed(
                    "SVI network validation not yet implemented")
            else:
                bd, epg, vrf = self._validate_normal_network(
                    mgr, net_db, network_vrfs, router_dbs, routed_nets)

            # Copy binding-related attributes from actual EPG to
            # expected EPG.
            #
            # REVISIT: Should compute expected values, but current
            # domain and static_path code needs significant
            # refactoring to enable re-use. The resulting static_paths
            # also may not be deterministic, at least in the SVI BGP
            # case. We therefore may need to validate that the actual
            # values are sensible rather than computing the expected
            # values.
            if epg:
                actual_epg = mgr.actual_aim_resource(epg)
                if actual_epg:
                    expected_epg = mgr.expected_aim_resource(epg)
                    expected_epg.vmm_domains = actual_epg.vmm_domains
                    expected_epg.physical_domains = actual_epg.physical_domains
                    expected_epg.static_paths = actual_epg.static_paths
                    # REVISIT: Move to ValidationManager, just before
                    # comparing actual and expected resources?
                    expected_epg.openstack_vmm_domain_names = [
                        d['name'] for d in expected_epg.vmm_domains
                        if d['type'] == 'OpenStack']
                    expected_epg.physical_domain_names = [
                        d['name'] for d in expected_epg.physical_domains]
                else:
                    # REVISIT: Force rebinding of ports using this
                    # EPG?
                    pass

            # Expect NetworkMapping record if applicable.
            if bd or epg or vrf or ext_net:
                self._add_network_mapping(
                    mgr.expected_session, net_db.id, bd, epg, vrf, ext_net,
                    update_network=False)

    def _get_router_ext_contracts(self, mgr):
        # Get external contracts for routers.
        router_ext_prov = defaultdict(set)
        router_ext_cons = defaultdict(set)
        for contract in mgr.actual_session.query(
                extension_db.RouterExtensionContractDb):
            if contract.provides:
                router_ext_prov[contract.router_id].add(contract.contract_name)
            else:
                router_ext_cons[contract.router_id].add(contract.contract_name)

        return router_ext_prov, router_ext_cons

    def _get_router_interface_info(self, mgr):
        # Find details of all router interfaces for each routed network.
        routed_nets = defaultdict(list)
        for intf in (
                mgr.actual_session.query(l3_db.RouterPort.router_id,
                                         models_v2.IPAllocation.ip_address,
                                         models_v2.Subnet,
                                         db.AddressScopeMapping).
                join(models_v2.IPAllocation,
                     models_v2.IPAllocation.port_id ==
                     l3_db.RouterPort.port_id).
                join(models_v2.Subnet,
                     models_v2.Subnet.id ==
                     models_v2.IPAllocation.subnet_id).
                outerjoin(models_v2.SubnetPool,
                          models_v2.SubnetPool.id ==
                          models_v2.Subnet.subnetpool_id).
                outerjoin(db.AddressScopeMapping,
                          db.AddressScopeMapping.scope_id ==
                          models_v2.SubnetPool.address_scope_id).
                filter(l3_db.RouterPort.port_type ==
                       n_constants.DEVICE_OWNER_ROUTER_INTF)):
            intf = InterfaceValidationInfo._make(intf)
            routed_nets[intf.subnet.network_id].append(intf)

        return routed_nets

    def _determine_vrfs(self, mgr, net_dbs, routed_nets):
        # Determine VRFs for all scoped routed networks, as well as
        # unscoped topology information.
        network_vrfs = {}
        router_vrfs = defaultdict(dict)
        unscoped_net_router_ids = {}
        unscoped_router_net_ids = defaultdict(set)
        unscoped_net_dbs = {}
        shared_unscoped_net_ids = []
        for intfs in routed_nets.values():
            net_id = None
            v4_scope_mapping = None
            v6_scope_mapping = None
            router_ids = set()
            for intf in intfs:
                router_ids.add(intf.router_id)
                if not net_id:
                    net_id = intf.subnet.network_id
                if intf.scope_mapping:
                    if intf.subnet.ip_version == 4:
                        if (v4_scope_mapping and
                            v4_scope_mapping != intf.scope_mapping):
                            mgr.validation_failed(
                                "inconsistent IPv4 scopes for network %s" %
                                intfs)
                        else:
                            v4_scope_mapping = intf.scope_mapping
                    elif intf.subnet.ip_version == 6:
                        if (v6_scope_mapping and
                            v6_scope_mapping != intf.scope_mapping):
                            mgr.validation_failed(
                                "inconsistent IPv6 scopes for network %s" %
                                intfs)
                        else:
                            v6_scope_mapping = intf.scope_mapping
            # REVISIT: If there is a v6 scope and no v4 scope, but
            # there are unscoped v4 subnets, should the unscoped
            # topology's default VRF be used instead? Or should
            # validation fail?
            scope_mapping = v4_scope_mapping or v6_scope_mapping
            if scope_mapping:
                vrf = self._get_address_scope_vrf(scope_mapping)
                network_vrfs[net_id] = vrf
                for router_id in router_ids:
                    router_vrfs[router_id][tuple(vrf.identity)] = vrf
            else:
                unscoped_net_router_ids[net_id] = router_ids
                for router_id in router_ids:
                    unscoped_router_net_ids[router_id].add(net_id)
                net_db = net_dbs[net_id]
                unscoped_net_dbs[net_id] = net_db
                if self._network_shared(net_db):
                    shared_unscoped_net_ids.append(intf.subnet.network_id)

        default_vrfs = set()

        def use_default_vrf(net_db):
            vrf = self._map_default_vrf(mgr.expected_session, net_db)
            key = tuple(vrf.identity)
            if key not in default_vrfs:
                default_vrfs.add(key)
                vrf.display_name = 'DefaultRoutedVRF'
                vrf.policy_enforcement_pref = 'enforced'
                vrf.monitored = False
                mgr.expect_aim_resource(vrf)
            network_vrfs[net_db.id] = vrf
            return vrf

        def expand_shared_topology(net_id, vrf):
            for router_id in unscoped_net_router_ids[net_id]:
                router_vrfs[router_id][tuple(vrf.identity)] = vrf
                for net_id in unscoped_router_net_ids[router_id]:
                    if net_id not in network_vrfs:
                        network_vrfs[net_id] = vrf
                        expand_shared_topology(net_id, vrf)

        # Process shared unscoped topologies.
        for net_id in shared_unscoped_net_ids:
            if net_id not in network_vrfs:
                vrf = use_default_vrf(unscoped_net_dbs[net_id])
                expand_shared_topology(net_id, vrf)

        # Process remaining (unshared) unscoped networks.
        for net_db in unscoped_net_dbs.values():
            if net_db.id not in network_vrfs:
                vrf = use_default_vrf(net_db)
                for router_id in unscoped_net_router_ids[net_db.id]:
                    router_vrfs[router_id][tuple(vrf.identity)] = vrf

        return network_vrfs, router_vrfs

    def _missing_network_extension_mapping(self, mgr, net_db):
        # Note that this is intended primarily to handle migration to
        # apic_aim, where the previous plugin and/or drivers did not
        # populate apic_aim's extension data. Migration of external
        # networks is supported through configuration of ACI
        # ExternalNetwork DNs, but other apic_aim-specific features
        # such as SVI do not apply to these migration use cases. After
        # migration, other attributes can be changed via the REST API
        # if needed.

        if not mgr.should_repair(
                "network %s missing extension data" % net_db.id):
            return

        ext_net_dn = None
        if net_db.external:
            ext_net_dn = cfg.CONF.ml2_apic_aim.migrate_ext_net_dns.get(
                net_db.id)
            if not ext_net_dn:
                mgr.validation_failed(
                    "missing extension data for external network %s and no "
                    "external network DN configured" % net_db.id)
            try:
                ext_net = aim_resource.ExternalNetwork.from_dn(ext_net_dn)
                ext_net = mgr.aim_mgr.get(mgr.expected_aim_ctx, ext_net)
                if not ext_net:
                    mgr.validation_failed(
                        "missing extension data for external network %(net)s "
                        "and configured external network DN '%(dn)s' does not "
                        "exist" % {'net': net_db.id, 'dn': ext_net_dn})
                    ext_net_dn = None
            except aim_exceptions.InvalidDNForAciResource:
                mgr.validation_failed(
                    "missing extension data for external network %(net)s and "
                    "configured external network DN '%(dn)s' is invalid" %
                    {'net': net_db.id, 'dn': ext_net_dn})
                ext_net_dn = None
        res_dict = {
            cisco_apic.EXTERNAL_NETWORK: ext_net_dn,
            cisco_apic.SVI: False,
            cisco_apic.BGP: False,
            cisco_apic.BGP_TYPE: 'default_export',
            cisco_apic.BGP_ASN: 0,
            cisco_apic.NESTED_DOMAIN_NAME: '',
            cisco_apic.NESTED_DOMAIN_TYPE: '',
            cisco_apic.NESTED_DOMAIN_INFRA_VLAN: None,
            cisco_apic.NESTED_DOMAIN_SERVICE_VLAN: None,
            cisco_apic.NESTED_DOMAIN_NODE_NETWORK_VLAN: None,
        }
        if net_db.external:
            # REVISIT: These are typical values, but the ability to
            # specify them per-network via config could be useful in
            # certain migration use cases. The apic:external_cidrs
            # attribute is mutable, so can be fixed manually after
            # migration. The apic:nat_type attribute is immutable, so
            # using other values requires deleting and re-creating the
            # external network.
            res_dict[cisco_apic.NAT_TYPE] = 'distributed'
            res_dict[cisco_apic.EXTERNAL_CIDRS] = ['0.0.0.0/0']
        self.set_network_extn_db(mgr.actual_session, net_db.id, res_dict)

    def _missing_subnet_extension_mapping(self, mgr, subnet_db):
        # Note that this is intended primarily to handle migration to
        # apic_aim, where the previous plugin and/or drivers did not
        # populate apic_aim's extension data. After migration, the
        # SNAT_HOST_POOL attribute can be changed via the REST API if
        # needed.

        if not mgr.should_repair(
                "subnet %s missing extension data" % subnet_db.id):
            return

        res_dict = {
            cisco_apic.SNAT_HOST_POOL: False
        }
        self.set_subnet_extn_db(mgr.actual_session, subnet_db.id, res_dict)

    def _validate_normal_network(self, mgr, net_db, network_vrfs, router_dbs,
                                 routed_nets):
        routed_vrf = network_vrfs.get(net_db.id)
        vrf = routed_vrf or self._map_unrouted_vrf()
        bd, epg = self._map_network(mgr.expected_session, net_db, vrf)

        router_contract_names = set()
        for intf in routed_nets.get(net_db.id, []):
            # REVISIT: Refactor to share code.
            gw_ip = intf.ip_address
            router_db = router_dbs[intf.router_id]
            dname = aim_utils.sanitize_display_name(
                router_db['name'] + '-' +
                (intf.subnet.name or intf.subnet.cidr))
            sn = self._map_subnet(intf.subnet, gw_ip, bd)
            sn.scope = 'public'
            sn.display_name = dname
            sn.monitored = False
            mgr.expect_aim_resource(sn)

            contract = self._map_router(
                mgr.expected_session, router_db, True)
            router_contract_names.add(contract.name)
        router_contract_names = list(router_contract_names)

        # REVISIT: Refactor to share code.
        dname = aim_utils.sanitize_display_name(net_db.name)

        bd.display_name = dname
        bd.vrf_name = vrf.name
        bd.enable_arp_flood = True
        bd.enable_routing = len(router_contract_names) is not 0
        bd.limit_ip_learn_to_subnets = True
        bd.ep_move_detect_mode = 'garp'
        bd.l3out_names = []
        bd.monitored = False
        mgr.expect_aim_resource(bd)

        epg.display_name = dname
        epg.bd_name = bd.name
        epg.policy_enforcement_pref = 'unenforced'
        epg.provided_contract_names = router_contract_names
        epg.consumed_contract_names = router_contract_names
        epg.openstack_vmm_domain_names = []
        epg.physical_domain_names = []
        epg.vmm_domains = []
        epg.physical_domains = []
        epg.static_paths = []
        epg.epg_contract_masters = []
        epg.monitored = False
        mgr.expect_aim_resource(epg)

        return bd, epg, vrf

    def _validate_external_network(self, mgr, net_db, ext_net_routers,
                                   router_dbs, router_vrfs, router_ext_prov,
                                   router_ext_cons):
        l3out, ext_net, ns = self._get_aim_nat_strategy_db(
            mgr.actual_session, net_db)
        if not ext_net:
            return None, None, None

        # REVISIT: Avoid piecemeal queries against the actual DB
        # throughout this code.

        # Copy the external network's pre-existing resources, if they
        # are monitored, from the actual AIM store to the validation
        # AIM store, so that the NatStrategy behaves as expected
        # during validation. Make sure not to overwrite any
        # pre-existing resources that have already been copied.
        actual_l3out = mgr.aim_mgr.get(mgr.actual_aim_ctx, l3out)
        if actual_l3out and actual_l3out.monitored:
            if not mgr.aim_mgr.get(mgr.expected_aim_ctx, actual_l3out):
                mgr.aim_mgr.create(mgr.expected_aim_ctx, actual_l3out)
            ext_vrf = aim_resource.VRF(
                tenant_name=actual_l3out.tenant_name,
                name=actual_l3out.vrf_name)
            actual_ext_vrf = mgr.aim_mgr.get(mgr.actual_aim_ctx, ext_vrf)
            if not actual_ext_vrf:
                ext_vrf.tenant_name = 'common'
                actual_ext_vrf = mgr.aim_mgr.get(mgr.actual_aim_ctx, ext_vrf)
            if actual_ext_vrf and actual_ext_vrf.monitored:
                if not mgr.aim_mgr.get(mgr.expected_aim_ctx, actual_ext_vrf):
                    mgr.aim_mgr.create(mgr.expected_aim_ctx, actual_ext_vrf)
        actual_ext_net = mgr.aim_mgr.get(mgr.actual_aim_ctx, ext_net)
        if actual_ext_net and actual_ext_net.monitored:
            if not mgr.aim_mgr.get(mgr.expected_aim_ctx, actual_ext_net):
                mgr.aim_mgr.create(mgr.expected_aim_ctx, actual_ext_net)
            for actual_ext_sn in mgr.aim_mgr.find(
                    mgr.actual_aim_ctx, aim_resource.ExternalSubnet,
                    tenant_name=actual_ext_net.tenant_name,
                    l3out_name=actual_ext_net.l3out_name,
                    external_network_name=actual_ext_net.name,
                    monitored=True):
                if not mgr.aim_mgr.get(mgr.expected_aim_ctx, actual_ext_sn):
                    mgr.aim_mgr.create(mgr.expected_aim_ctx, actual_ext_sn)

        domains = self._get_vmm_domains(mgr.expected_aim_ctx, ns)
        ns.create_l3outside(
            mgr.expected_aim_ctx, l3out, vmm_domains=domains)
        ns.create_external_network(mgr.expected_aim_ctx, ext_net)

        # Get external CIDRs for all external networks that share this
        # APIC external network.
        cidrs = sorted(self.get_external_cidrs_by_ext_net_dn(
            mgr.actual_session, ext_net.dn, lock_update=False))
        ns.update_external_cidrs(mgr.expected_aim_ctx, ext_net, cidrs)
        for resource in ns.get_l3outside_resources(
                mgr.expected_aim_ctx, l3out):
            if isinstance(resource, aim_resource.BridgeDomain):
                bd = resource
            elif isinstance(resource, aim_resource.EndpointGroup):
                epg = resource
            elif isinstance(resource, aim_resource.VRF):
                vrf = resource

        for subnet_db in net_db.subnets:
            if subnet_db.gateway_ip:
                ns.create_subnet(
                    mgr.expected_aim_ctx, l3out,
                    self._subnet_to_gw_ip_mask(subnet_db))

        # REVISIT: Process each AIM ExternalNetwork rather than each
        # external Neutron network?
        eqv_net_ids = self.get_network_ids_by_ext_net_dn(
            mgr.actual_session, ext_net.dn, lock_update=False)
        router_ids = set()
        for eqv_net_id in eqv_net_ids:
            router_ids.update(ext_net_routers[eqv_net_id])
        vrf_routers = defaultdict(set)
        int_vrfs = {}
        for router_id in router_ids:
            for int_vrf in router_vrfs[router_id].values():
                key = tuple(int_vrf.identity)
                vrf_routers[key].add(router_id)
                int_vrfs[key] = int_vrf

        for key, routers in vrf_routers.items():
            prov = set()
            cons = set()
            for router_id in routers:
                contract = self._map_router(
                    mgr.expected_session, router_dbs[router_id], True)
                prov.add(contract.name)
                cons.add(contract.name)
                prov.update(router_ext_prov[router_id])
                cons.update(router_ext_cons[router_id])
            ext_net.provided_contract_names = sorted(prov)
            ext_net.consumed_contract_names = sorted(cons)
            int_vrf = int_vrfs[key]

            # Keep only the identity attributes of the VRF so that
            # calls to nat-library have consistent resource
            # values. This is mainly required to ease unit-test
            # verification. Note that this also effects validation
            # of the L3Outside's display_name.
            int_vrf = aim_resource.VRF(
                tenant_name=int_vrf.tenant_name, name=int_vrf.name)
            ns.connect_vrf(mgr.expected_aim_ctx, ext_net, int_vrf)

        return bd, epg, vrf

    def _validate_security_groups(self, mgr):
        sg_ips = defaultdict(set)
        for sg_id, ip in (
                mgr.actual_session.query(
                    sg_models.SecurityGroupPortBinding.security_group_id,
                    models_v2.IPAllocation.ip_address).
                join(models_v2.IPAllocation,
                     models_v2.IPAllocation.port_id ==
                     sg_models.SecurityGroupPortBinding.port_id)):
            sg_ips[sg_id].add(ip)

        for sg_db in (mgr.actual_session.query(sg_models.SecurityGroup).
                      options(orm.joinedload('rules'))):
            # Ignore anonymous SGs, which seem to be a Neutron bug.
            if sg_db.tenant_id:
                self._expect_project(mgr, sg_db.project_id)
                tenant_name = self.name_mapper.project(
                    mgr.expected_session, sg_db.tenant_id)
                sg = aim_resource.SecurityGroup(
                    tenant_name=tenant_name, name=sg_db.id,
                    display_name=aim_utils.sanitize_display_name(sg_db.name))
                mgr.expect_aim_resource(sg)
                sg_subject = aim_resource.SecurityGroupSubject(
                    tenant_name=tenant_name, security_group_name=sg_db.id,
                    name='default')
                mgr.expect_aim_resource(sg_subject)
                for rule_db in sg_db.rules:
                    remote_ips = []
                    if rule_db.remote_group_id:
                        ip_version = (4 if rule_db.ethertype == 'IPv4' else
                                      6 if rule_db.ethertype == 'IPv6' else
                                      0)
                        remote_ips = [
                            ip for ip in sg_ips[rule_db.remote_group_id]
                            if netaddr.IPAddress(ip).version == ip_version]
                    elif rule_db.remote_ip_prefix:
                        remote_ips = [rule_db.remote_ip_prefix]
                    sg_rule = aim_resource.SecurityGroupRule(
                        tenant_name=tenant_name,
                        security_group_name=rule_db.security_group_id,
                        security_group_subject_name='default',
                        name=rule_db.id,
                        direction=rule_db.direction,
                        ethertype=rule_db.ethertype.lower(),
                        ip_protocol=(rule_db.protocol if rule_db.protocol
                                     else 'unspecified'),
                        remote_ips=remote_ips,
                        from_port=(rule_db.port_range_min
                                   if rule_db.port_range_min
                                   else 'unspecified'),
                        to_port=(rule_db.port_range_max
                                 if rule_db.port_range_max
                                 else 'unspecified'))
                    mgr.expect_aim_resource(sg_rule)

    def _validate_ports(self, mgr):
        for project_id, in (
                mgr.actual_session.query(models_v2.Port.project_id).
                distinct()):
            self._expect_project(mgr, project_id)

    def _validate_subnetpools(self, mgr):
        for project_id, in (
                mgr.actual_session.query(models_v2.SubnetPool.project_id).
                distinct()):
            self._expect_project(mgr, project_id)

    def _validate_floatingips(self, mgr):
        for project_id, in (
                mgr.actual_session.query(l3_db.FloatingIP.project_id).
                distinct()):
            self._expect_project(mgr, project_id)

    def _validate_port_bindings(self, mgr):
        # REVISIT: Deal with distributed port bindings? Also, consider
        # moving this to the ML2Plus plugin or to a base validation
        # manager, as it is not specific to this mechanism driver.

        for port in (mgr.actual_session.query(models_v2.Port).
                     options(orm.joinedload('binding_levels'))):
            binding = port.port_binding
            levels = port.binding_levels
            unbind = False
            # REVISIT: Validate that vif_type and vif_details are
            # correct when host is empty?
            for level in levels:
                if (level.driver not in
                    self.plugin.mechanism_manager.mech_drivers):
                    if mgr.should_repair(
                            "port %(id)s bound with invalid driver "
                            "%(driver)s" %
                            {'id': port.id, 'driver': level.driver},
                            "Unbinding"):
                        unbind = True
                elif (level.host != binding.host):
                    if mgr.should_repair(
                            "port %(id)s bound with invalid host "
                            "%(host)s" %
                            {'id': port.id, 'host': level.host},
                            "Unbinding"):
                        unbind = True
                elif (not level.segment_id):
                    if mgr.should_repair(
                            "port %s bound without valid segment" % port.id,
                            "Unbinding"):
                        unbind = True
            if unbind:
                binding.vif_type = portbindings.VIF_TYPE_UNBOUND
                binding.vif_details = ''
                for level in port.binding_levels:
                    mgr.actual_session.delete(level)

    def _expect_project(self, mgr, project_id):
        # REVISIT: Currently called for all Neutron and GBP resources
        # for which plugin create methods call _ensure_tenant. Remove
        # once per-project resources are managed more dynamically.
        if project_id and project_id not in mgr._expected_projects:
            mgr._expected_projects.add(project_id)
            tenant_name = self.name_mapper.project(
                mgr.expected_session, project_id)

            tenant = aim_resource.Tenant(name=tenant_name)
            project_name = (
                self.project_name_cache.get_project_name(project_id) or '')
            tenant.display_name = aim_utils.sanitize_display_name(project_name)
            tenant.descr = self.apic_system_id
            tenant.monitored = False
            mgr.expect_aim_resource(tenant)

            ap = aim_resource.ApplicationProfile(
                tenant_name=tenant_name, name=self.ap_name)
            ap.display_name = aim_utils.sanitize_display_name(self.ap_name)
            ap.monitored = False
            mgr.expect_aim_resource(ap)

    def bind_unbound_ports(self, mgr):
        # REVISIT: Deal with distributed port bindings? Also, consider
        # moving this to the ML2Plus plugin or to a base validation
        # manager, as it is not specific to this mechanism driver.
        failure_count = 0
        failure_hosts = set()
        for port_id, in (mgr.actual_session.query(models.PortBinding.port_id).
                        filter(models.PortBinding.host != '',
                               models.PortBinding.vif_type ==
                               portbindings.VIF_TYPE_UNBOUND)):
            mgr.output("Attempting to bind port %s" % port_id)
            # REVISIT: Use the more efficient get_bound_port_contexts,
            # which is not available in stable/newton?
            pc = self.plugin.get_bound_port_context(
                mgr.actual_context, port_id)
            if (pc.vif_type == portbindings.VIF_TYPE_BINDING_FAILED or
                pc.vif_type == portbindings.VIF_TYPE_UNBOUND):
                mgr.bind_ports_failed(
                    "Unable to bind port %(port)s on host %(host)s" %
                    {'port': port_id, 'host': pc.host})
                failure_count += 1
                failure_hosts.add(pc.host)
        if failure_count:
            mgr.output(
                "Failed to bind %s ports on hosts %s. See log for details. "
                "Make sure L2 agents are alive, and re-run validation to try "
                "binding them again." % (failure_count, list(failure_hosts)))
        else:
            mgr.output("All ports are bound")
