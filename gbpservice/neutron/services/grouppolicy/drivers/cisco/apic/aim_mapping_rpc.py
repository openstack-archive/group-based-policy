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

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import api as db_api

from neutron.db import db_base_plugin_common
from neutron.db.models import address_scope as ascp_db
from neutron.db.models import external_net
from neutron.db.models import l3
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import rpc as ml2_rpc
from neutron_lib.api.definitions import portbindings
from opflexagent import rpc as o_rpc
from oslo_log import log

from aim.db import models as aim_models

from gbpservice.neutron.db.grouppolicy import (
    group_policy_mapping_db as gpmdb)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    db as aim_db)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    port_ha_ipaddress_binding as ha_ip_db)

from sqlalchemy import bindparam


LOG = log.getLogger(__name__)


class AIMMappingRPCMixin(ha_ip_db.HAIPOwnerDbMixin):
    """RPC mixin for AIM mapping.

    Collection of all the RPC methods consumed by the AIM mapping.
    By defining the mixin requirements, we can potentially move the RPC
    handling between GBP and Neutron preserving the same code base. Such
    requirements might be easier to implement in some places (eg. won't
    require model extensions) compared to others, based on the visibility
    that each module has over the network abstraction.
    """

    def setup_opflex_rpc_listeners(self):
        self.notifier = o_rpc.AgentNotifierApi(topics.AGENT)
        LOG.debug("Set up Opflex RPC listeners.")
        self.opflex_endpoints = [
            o_rpc.GBPServerRpcCallback(self, self.notifier)]
        self.opflex_topic = o_rpc.TOPIC_OPFLEX
        self.opflex_conn = n_rpc.create_connection()
        self.opflex_conn.create_consumer(
            self.opflex_topic, self.opflex_endpoints, fanout=False)
        return self.opflex_conn.consume_in_threads()

    @db_api.retry_if_session_inactive()
    def _retrieve_vrf_details(self, context, **kwargs):
        with context.session.begin(subtransactions=True):
            details = {'l3_policy_id': kwargs['vrf_id']}
            details['_cache'] = {}
            self._add_vrf_details(context, details['l3_policy_id'], details)
            details.pop('_cache', None)
        return details

    def _get_vrf_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling _get_vrf_details for: %s", kwargs)
        try:
            return self._retrieve_vrf_details(context, **kwargs)
        except Exception as e:
            vrf = kwargs.get('vrf_id')
            LOG.error("An exception has occurred while retrieving vrf "
                      "gbp details for %s", vrf)
            LOG.exception(e)
            return {'l3_policy_id': vrf}

    def get_vrf_details(self, context, **kwargs):
        return self._get_vrf_details(context, **kwargs)

    def request_vrf_details(self, context, **kwargs):
        return self._get_vrf_details(context, **kwargs)

    def get_gbp_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling get_gbp_details for: %s", kwargs)
        try:
            return self._get_gbp_details(context, kwargs, kwargs.get('host'))
        except Exception as e:
            device = kwargs.get('device')
            LOG.error("An exception has occurred while retrieving device "
                      "gbp details for %s", device)
            LOG.exception(e)
            return {'device': device}

    def request_endpoint_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling get_endpoint_details for: %s", kwargs)
        request = kwargs.get('request')
        try:
            return self._request_endpoint_details(context, **kwargs)
        except Exception as e:
            LOG.error("An exception has occurred while requesting device "
                      "gbp details for %s", request.get('device'))
            LOG.exception(e)
            return None

    @db_api.retry_if_session_inactive()
    def _request_endpoint_details(self, context, **kwargs):
        request = kwargs.get('request')
        host = kwargs.get('host')
        gbp_details = self._get_gbp_details(context, request, host)
        if hasattr(context, 'neutron_details'):
            neutron_details = context.neutron_details
        else:
            neutron_details = ml2_rpc.RpcCallbacks(None,
                None).get_device_details(context, **request)
        result = {'device': request['device'],
                  'timestamp': request['timestamp'],
                  'request_id': request['request_id'],
                  'gbp_details': gbp_details,
                  'neutron_details': neutron_details,
                  'trunk_details': self._get_trunk_details(context,
                                                           request, host)}
        return result

    # Child class needs to support:
    # - self._send_port_update_notification(context, port)
    def ip_address_owner_update(self, context, **kwargs):
        if not kwargs.get('ip_owner_info'):
            return
        ports_to_update = self.update_ip_owner(kwargs['ip_owner_info'])
        for p in ports_to_update:
            LOG.debug("APIC ownership update for port %s", p)
            self._send_port_update_notification(context, p)

    def _get_trunk_details(self, context, request, host):
        if self._trunk_plugin:
            device = request.get('device')
            port_id = self._core_plugin._device_to_port_id(context, device)
            # Find Trunk associated to this port (if any)
            trunks = self._trunk_plugin.get_trunks(
                context, filters={'port_id': [port_id]})
            subports = None
            if not trunks:
                subports = self.retrieve_subports(
                    context, filters={'port_id': [port_id]})
                if subports:
                    trunks = self._trunk_plugin.get_trunks(
                        context, filters={'id': [subports[0].trunk_id]})
            if trunks:
                return {'trunk_id': trunks[0]['id'],
                        'master_port_id': trunks[0]['port_id'],
                        'subports': (
                            [s.to_dict() for s in subports] if subports else
                            self._trunk_plugin.get_subports(
                                context, trunks[0]['id'])['sub_ports'])}

    # NOTE(ivar): for some reason, the Trunk plugin doesn't expose a way to
    # retrieve a subport starting from the port ID.
    @db_base_plugin_common.filter_fields
    def retrieve_subports(self, context, filters=None, fields=None,
                          sorts=None, limit=None, marker=None,
                          page_reverse=False):
        filters = filters or {}
        pager = objects_base.Pager(sorts=sorts, limit=limit,
                                   page_reverse=page_reverse,
                                   marker=marker)
        return trunk_objects.SubPort.get_objects(context, _pager=pager,
                                                 **filters)

    # Things you need in order to run this Mixin:
    # - self._core_plugin: attribute that points to the Neutron core plugin;
    # - self._is_port_promiscuous(context, port): define whether or not
    # a port should be put in promiscuous mode;
    # - self._get_port_epg(context, port): returns the AIM EPG for the specific
    # port
    # for both Neutron and GBP.
    # - self._is_dhcp_optimized(context, port);
    # - self._is_metadata_optimized(context, port);
    # - self._set_dhcp_lease_time(details)
    # - self._get_dns_domain(context, port)
    @db_api.retry_if_session_inactive()
    def _get_gbp_details(self, context, request, host):
        return self._get_gbp_details_new(context, request, host)

    def _get_gbp_details_old(self, context, request, host):
        with context.session.begin(subtransactions=True):
            device = request.get('device')

            core_plugin = self._core_plugin
            port_id = core_plugin._device_to_port_id(context, device)
            port_context = core_plugin.get_bound_port_context(context, port_id,
                                                              host)
            if not port_context:
                LOG.warning("Device %(device)s requested by agent "
                            "%(agent_id)s not found in database",
                            {'device': port_id,
                             'agent_id': request.get('agent_id')})
                return {'device': request.get('device')}
            port = port_context.current

            # NOTE(ivar): removed the PROXY_PORT_PREFIX hack.
            # This was needed to support network services without hotplug.

            epg = self._get_port_epg(context, port)

            details = {'device': request.get('device'),
                       'enable_dhcp_optimization': self._is_dhcp_optimized(
                           context, port),
                       'enable_metadata_optimization': (
                           self._is_metadata_optimized(context, port)),
                       'port_id': port_id,
                       'mac_address': port['mac_address'],
                       'app_profile_name': epg.app_profile_name,
                       'tenant_id': port['tenant_id'],
                       'host': port[portbindings.HOST_ID],
                       # TODO(ivar): scope names, possibly through AIM or the
                       # name mapper
                       'ptg_tenant': epg.tenant_name,
                       'endpoint_group_name': epg.name,
                       'promiscuous_mode': self._is_port_promiscuous(context,
                                                                     port),
                       'extra_ips': [],
                       'floating_ip': [],
                       'ip_mapping': [],
                       # Put per mac-address extra info
                       'extra_details': {}}

            # Set VM name if needed.
            if port['device_owner'].startswith(
                    'compute:') and port['device_id']:
                vm = nclient.NovaClient().get_server(port['device_id'])
                details['vm-name'] = vm.name if vm else port['device_id']
            mtu = self._get_port_mtu(context, port)
            if mtu:
                details['interface_mtu'] = mtu
            details['dns_domain'] = self._get_dns_domain(context, port)

            if port.get('security_groups'):
                self._add_security_group_details(context, port, details)

            # NOTE(ivar): having these methods cleanly separated actually makes
            # things less efficient by requiring lots of calls duplication.
            # we could alleviate this by passing down a cache that stores
            # commonly requested objects (like EPGs). 'details' itself could
            # be used for such caching.
            details['_cache'] = {}
            vrf = self._get_port_vrf(context, port)
            details['l3_policy_id'] = '%s %s' % (vrf.tenant_name, vrf.name)
            self._add_subnet_details(context, port, details)
            self._add_allowed_address_pairs_details(context, port, details)
            self._add_vrf_details(context, details['l3_policy_id'], details)
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            self._add_segmentation_label_details(context, port, details)
            self._set_dhcp_lease_time(details)
            details.pop('_cache', None)

        LOG.debug("Details for port %s : %s", port['id'], details)
        return details

    def _get_objects_for_cache(self, context, port_id):
        with context.session.begin(subtransactions=True):
            # Get the port resource, and all its related resources
            port_query = self.bakery(lambda session:
                session.query(models_v2.Port))
            port_query += lambda q: q.outerjoin(
                ha_ip_db.HAIPAddressToPortAssocation)
            port_query += lambda q: q.filter(models_v2.Port.id.
                startswith(bindparam('port_id')))
            port_db = port_query(context.session).params(port_id=port_id).one()
            context.port_db = port_db

            # Get subnets
            # REVISIT: This should be a baked query
            subnet_ids = [ip.subnet_id for ip in port_db.fixed_ips]
            subnets_db = context.session.query(models_v2.Subnet).filter(
                models_v2.Subnet.id.in_(subnet_ids)).all()
            context.subnets_db = subnets_db
            subnet_net_ids = tuple([sub.network_id for sub in subnets_db])

            # Get DHCP ports
            # REVISIT: See if this can be converted to a baked query
            dhcp_db = context.session.query(models_v2.Port).filter(
                models_v2.Port.device_owner.startswith(
                    'network:dhcp')).filter(
                models_v2.Port.network_id.in_(subnet_net_ids)).all()
            context.dhcp_db = dhcp_db

            # Get the network resource, and all it's related reources
            network_id = port_db.network_id
            net_query = self.bakery(lambda session:
                session.query(models_v2.Network))
            net_query += lambda q: q.filter(models_v2.Network.id ==
                bindparam('network_id'))
            network_db = net_query(context.session).params(
                network_id=network_id).one()
            context.network_db = network_db

            # Get the NetworkMapping resource
            mapping_query = self.bakery(lambda session:
                session.query(aim_db.NetworkMapping))
            mapping_query += lambda q: q.filter(
                aim_db.NetworkMapping.network_id == bindparam('network_id'))
            network_mapping_db = mapping_query(context.session).params(
                network_id=network_id).one_or_none()
            context.network_mapping_db = network_mapping_db

            # These queries are for the VRF subnets (i.e. all the subnets
            # that are under one VRF). The neutron port belongs to a network,
            # which maps to a VRF in APIC. We need to get all of the subnets
            # that belong to this VRF for the neutron-opflex-gaent, so that
            # it can support NAT'ing, routing, etc. There are 2 cases we need
            # to handle:
            # 1) Explicit VRF mapping is used with Address scopes. Here we can
            #    get the address scopes that map to this VRF, then get the
            #    subnetpools that reference the VRF, and then get the prefixes
            #    from the pools
            # 2) Default scope is used (i.e. implicit VRF mapping). In this
            #    case, we query for the BDs with the given vrf_name that are
            #    in the given vrf_tenant, and then get the neutron networks
            #    for those BDs, and finally the CIDRs from the subnets on
            #    those neutron networks
            # REVISIT: These should be converted to baked queries
            vrf = self._get_port_vrf(context, port_db)
            vrfs = context.session.query(aim_db.AddressScopeMapping).filter_by(
                vrf_tenant_name=vrf.tenant_name,
                vrf_name=vrf.name).all()
            context.vrf_mappings = vrfs

            subnetpools_db = context.session.query(
                models_v2.SubnetPool).outerjoin(
                models_v2.SubnetPoolPrefix).join(
                ascp_db.AddressScope, ascp_db.AddressScope.id ==
                models_v2.SubnetPool.address_scope_id).join(
                aim_db.AddressScopeMapping,
                aim_db.AddressScopeMapping.scope_id ==
                ascp_db.AddressScope.id).filter_by(
                vrf_tenant_name=vrf.tenant_name, vrf_name=vrf.name).all()
            context.subnetpools_db = subnetpools_db

            # Unfortunately, there is no relationship in the ORM between
            # a VRF and BridgeDomainin -- the BDs reference the VRF by name,
            # which doesn't include the ACI tenant. When the VRF lives in the
            # common tenant, the only way we can deduce the BDs belonging to it
            # is by eliminating all the BDs that are not in the common tenant,
            # and have a VRF with the same name in their tenant.
            if vrf.tenant_name == md.COMMON_TENANT_NAME:
                # REVISIT: should we just let this use existing cade?
                all_vrf_bds = context.session.query(
                    aim_models.BridgeDomain).filter(
                    aim_models.BridgeDomain.vrf_name == vrf.name).all()
                all_vrfs = context.session.query(
                    aim_models.VRF).filter(aim_models.VRF.tenant_name ==
                    vrf.name).all()
                bd_tenants = set([x.tenant_name for x in all_vrf_bds])
                vrf_tenants = set([x.tenant_name for x in all_vrfs
                                   if x.tenant_name != vrf.tenant_name])
                valid_tenants = bd_tenants - vrf_tenants
                vrf_bds_db = [x for x in all_vrf_bds
                              if x.tenant_name in valid_tenants]
            else:
                vrf_bds_db = context.session.query(
                    aim_models.BridgeDomain).filter(
                    aim_models.BridgeDomain.tenant_name ==
                    vrf.tenant_name).filter(aim_models.BridgeDomain.vrf_name ==
                    vrf.name).all()
            context.vrf_bds_db = vrf_bds_db

            # Get all the router interface ports that are on the same
            # subnets as the fixed IPs for the port resource. Then
            # use the router IDs from those ports to look for the
            # external networks connected to those routers
            port_sn = set([x['subnet_id'] for x in port_db['fixed_ips']])
            ports = context.session.query(models_v2.Port).join(
                models_v2.IPAllocation).filter(
                models_v2.IPAllocation.subnet_id.in_(port_sn)).filter(
                models_v2.Port.device_owner ==
                'network:router_interface').all()
            routers = set([p.device_id for p in ports])
            external_nets = context.session.query(
                models_v2.Network).join(external_net.ExternalNetwork).join(
                models_v2.Port,
                models_v2.Network.id == models_v2.Port.network_id).join(
                l3.RouterPort,
                l3.RouterPort.port_id == models_v2.Port.id).filter(
                l3.RouterPort.router_id.in_(routers)).outerjoin(
                    aim_db.NetworkMapping).all()
            context.external_nets = external_nets

            # Get the PTG resource.
            pt_query = self.bakery(lambda session:
                session.query(gpmdb.PolicyTargetMapping,
                gpmdb.PolicyTargetMapping.port_id == models_v2.Port.id))
            pt_query += lambda q: q.outerjoin(gpmdb.PolicyTargetGroupMapping)
            pt_query += lambda q: q.outerjoin(gpmdb.L2PolicyMapping)
            pt_query += lambda q: q.outerjoin(gpmdb.L3PolicyMapping)
            pt_query += lambda q: q.filter(
                gpmdb.PolicyTargetMapping.port_id == bindparam('port_id'))
            pt_db = pt_query(context.session).params(port_id=port_id).first()
            if pt_db:
                pt_db = pt_db[0]
                context.pt_db = pt_db
                ptg_db = pt_db.policy_target_group
                context.ptg_db = ptg_db
                if ptg_db:
                    l2p_db = ptg_db.l2_policy
                    context.l2p_db = l2p_db
                    if l2p_db:
                        l3p_db = l2p_db.l3_policy
                        context.l3p_db = l3p_db

    def _get_gbp_details_new(self, context, request, host):
        # REVISIT: We shouldn't need to do this
        context.session.expunge_all()
        with context.session.begin(subtransactions=True):
            device = request.get('device')

            core_plugin = self._core_plugin
            port_id = core_plugin._device_to_port_id(context, device)
            self._get_objects_for_cache(context, port_id)
            port = context.port_db
            if not port:
                LOG.warning("Device %(device)s requested by agent "
                            "%(agent_id)s not found in database",
                            {'device': port_id,
                             'agent_id': request.get('agent_id')})
                return {'device': request.get('device')}
            binding = port.port_binding
            # See if we need to do port binding. This would not
            # be the normal case, as port binding is triggered on
            # the update call (this case is for re-binding).
            if binding and binding.host and binding.vif_type:
                port_context = driver_context.PortContext(
                    self._core_plugin, context, port, context.network_db,
                    binding, port.binding_levels)
                if (port_context.network.network_segments and
                        self._core_plugin._should_bind_port(port_context)):
                    port_context = core_plugin.get_bound_port_context(context,
                        port_id, host)
                    if not port_context:
                        LOG.warning("Device %(device)s requested by agent "
                                    "%(agent_id)s not found in database",
                                    {'device': port_id,
                                     'agent_id': request.get('agent_id')})
                        return {'device': request.get('device')}

            epg = self._get_port_epg_cached(context, port_id)

            details = {'device': request.get('device'),
                       'enable_dhcp_optimization': self._is_dhcp_optimized(
                           context, port),
                       'enable_metadata_optimization': (
                           self._is_metadata_optimized(context, port)),
                       'port_id': port_id,
                       'mac_address': port['mac_address'],
                       'app_profile_name': epg.app_profile_name,
                       'tenant_id': port['tenant_id'],
                       'host': port.port_binding.host,
                       # TODO(ivar): scope names, possibly through AIM or the
                       # name mapper
                       'ptg_tenant': epg.tenant_name,
                       'endpoint_group_name': epg.name,
                       'promiscuous_mode': self._is_port_promiscuous(context,
                                                                     port),
                       'extra_ips': [],
                       'floating_ip': [],
                       'ip_mapping': [],
                       # Put per mac-address extra info
                       'extra_details': {}}

            # Set VM name if needed.
            if port['device_owner'].startswith(
                    'compute:') and port['device_id']:
                vm = nclient.NovaClient().get_server(port['device_id'])
                details['vm-name'] = vm.name if vm else port['device_id']
            mtu = self._get_port_mtu(context, port)
            if mtu:
                details['interface_mtu'] = mtu
            details['dns_domain'] = self._get_dns_domain(context, port)

            if port.get('security_groups'):
                self._add_security_group_details(context, port, details)

            # NOTE(ivar): having these methods cleanly separated actually makes
            # things less efficient by requiring lots of calls duplication.
            # we could alleviate this by passing down a cache that stores
            # commonly requested objects (like EPGs). 'details' itself could
            # be used for such caching.
            details['_cache'] = {}
            vrf = self._get_port_vrf(context, port)
            details['l3_policy_id'] = '%s %s' % (vrf.tenant_name, vrf.name)
            self._add_subnet_details(context, port, details)
            self._add_allowed_address_pairs_details(context, port, details)
            self._add_vrf_details(context, details['l3_policy_id'], details)
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            self._add_segmentation_label_details(context, port, details)
            self._set_dhcp_lease_time(details)
            details.pop('_cache', None)
            self._add_nested_domain_details(context, port, details)

            bottom_segment = {}
            fixed_ips = [{'ip_address': ip.ip_address,
                          'subnet_id': ip.subnet_id} for ip in port.fixed_ips]
            for segment in context.network_db.segments:
                bottom_segment = segment
                if port.binding_levels and (segment['id']
                        == port.binding_levels[-1].segment_id):
                    break

            neutron_details = {'admin_state_up': port['admin_state_up'],
                               'device_owner': port['device_owner'],
                               'fixed_ips': fixed_ips,
                               'network_id': port['network_id'],
                               'port_id': port['id'],
                               'network_type':
                                   bottom_segment.get('network_type'),
                               'physical_network':
                                   bottom_segment.get('physical_network')}
            context.neutron_details = neutron_details

        LOG.debug("Details for port %s : %s", port['id'], details)
        return details

    def _get_owned_addresses(self, plugin_context, port_id):
        return set(self.ha_ip_handler.get_ha_ipaddresses_for_port(port_id))

    def _add_security_group_details(self, context, port, details):
        vif_details = port.get('binding:vif_details')
        # For legacy VMs, they are running in this mode which means
        # they will use iptables to support SG. Then we don't bother
        # to configure any SG for them here.
        if (vif_details and vif_details.get('port_filter') and
                vif_details.get('ovs_hybrid_plug')):
            return
        details['security_group'] = []

        if hasattr(context, 'port_db'):
            # REVISIT: This should use baked queries
            sgs_db = context.port_db.security_groups
            sg_ids = [sg.security_group_id for sg in sgs_db]
            port_sgs = (context.session.query(sg_models.SecurityGroup.id,
                            sg_models.SecurityGroup.tenant_id).
                        filter(sg_models.SecurityGroup.id.
                               in_(sg_ids)).
                    all())
        else:
            port_sgs = (context.session.query(sg_models.SecurityGroup.id,
                            sg_models.SecurityGroup.tenant_id).
                        filter(sg_models.SecurityGroup.id.
                               in_(port['security_groups'])).
                    all())
        for sg_id, tenant_id in port_sgs:
            tenant_aname = self.aim_mech_driver.name_mapper.project(
                context.session, tenant_id)
            details['security_group'].append(
                {'policy-space': tenant_aname,
                 'name': sg_id})
        # Always include this SG which has the default arp & dhcp rules
        details['security_group'].append(
            {'policy-space': 'common',
             'name': self.aim_mech_driver._default_sg_name})

    # Child class needs to support:
    # - self._get_subnet_details(context, port, details)
    def _add_subnet_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - subnets;
        details['subnets'] = self._get_subnet_details(context, port, details)

    def _add_nat_details(self, context, port, host, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - floating_ip;
        # - ip_mapping;
        # - host_snat_ips.
        (details['floating_ip'], details['ip_mapping'],
            details['host_snat_ips']) = self._get_nat_details(
                context, port, host, details)

    # Child class needs to support:
    # - self._get_aap_details(context, port, details)
    def _add_allowed_address_pairs_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - allowed_address_pairs
        # This should take care of realizing whether a given address is
        # active in the specific port
        details['allowed_address_pairs'] = self._get_aap_details(context, port,
                                                                 details)

    # Child class needs to support:
    # - self._get_vrf_subnets(context, vrf_tenant_name, vrf_name, details):
    # Subnets managed by the specific VRF.
    def _add_vrf_details(self, context, vrf_id, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - l3_policy_id;
        # - vrf_tenant;
        # - vrf_name;
        # - vrf_subnets.
        tenant_name, name = vrf_id.split(' ')
        details['vrf_tenant'] = tenant_name
        details['vrf_name'] = name
        details['vrf_subnets'] = self._get_vrf_subnets(context, tenant_name,
                                                       name, details)

    # Child class needs to support:
    # - self._get_nested_domain(context, port)
    def _add_nested_domain_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - nested_domain_name;
        # - nested_domain_type;
        # - nested_domain_infra_vlan;
        # - nested_domain_service_vlan;
        # - nested_domain_node_network_vlan;
        # - nested_domain_allowed_vlans;
        (details['nested_domain_name'], details['nested_domain_type'],
            details['nested_domain_infra_vlan'],
            details['nested_domain_service_vlan'],
            details['nested_domain_node_network_vlan'],
            details['nested_domain_allowed_vlans'],
            details['nested_host_vlan']) = (
                    self._get_nested_domain(context, port))

    # Child class needs to support:
    # - self._get_segmentation_labels(context, port, details)
    def _add_segmentation_label_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - segmentation_labels
        # apic_segmentation_label is a GBP driver extension configured
        # for the aim_mapping driver
        details['segmentation_labels'] = self._get_segmentation_labels(
            context, port, details)

    def _add_extra_details(self, context, port, details):
        # TODO(ivar): Extra details depend on HA and SC implementation
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill per-mac address extra information.

        # What is an "End of the Chain" port for Neutron?
        pass
