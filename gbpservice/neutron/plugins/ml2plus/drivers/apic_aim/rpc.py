# Copyright (c) 2019 Cisco Systems Inc.
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
import netaddr
import sqlalchemy as sa
from sqlalchemy.ext import baked

from neutron.common import rpc as n_rpc
from neutron.db import api as db_api
from neutron.db.extra_dhcp_opt import models as dhcp_models
from neutron.db.models import allowed_address_pair as aap_models
from neutron.db.models import dns as dns_models
from neutron.db.models import l3 as l3_models
from neutron.db.models import securitygroup as sg_models
from neutron.db.models import segment as segment_models
from neutron.db import models_v2
from neutron.db.port_security import models as psec_models
from neutron.extensions import providernet as provider
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import models as trunk_models
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_constants
from neutron_lib import context as n_context
from opflexagent import host_agent_rpc as oa_rpc
from opflexagent import rpc as o_rpc
from oslo_log import log
import oslo_messaging
from oslo_serialization import jsonutils

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import constants
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import extension_db

LOG = log.getLogger(__name__)

BAKERY = baked.bakery()

EndpointPortInfo = namedtuple(
    'EndpointPortInfo',
    ['project_id',
     'port_id',
     'port_name',
     'network_id',
     'mac_address',
     'admin_state_up',
     'device_id',
     'device_owner',
     'host',
     'vif_type',
     'vif_details',
     'psec_enabled',
     'trunk_id',
     'subport_trunk_id',
     # Not in ocata: 'net_mtu',
     'net_dns_domain',
     'nested_domain_name',
     'nested_domain_type',
     'nested_domain_infra_vlan',
     'nested_domain_service_vlan',
     'nested_domain_node_network_vlan',
     'epg_name',
     'epg_app_profile_name',
     'epg_tenant_name',
     'vrf_name',
     'vrf_tenant_name',
     'vm_name'])

EndpointFixedIpInfo = namedtuple(
    'EndpointFixedIpInfo',
    ['ip_address',
     'subnet_id',
     'ip_version',
     'cidr',
     'gateway_ip',
     'enable_dhcp',
     'dns_nameserver',
     'route_destination',
     'route_nexthop'])

EndpointBindingInfo = namedtuple(
    'EndpointBindingInfo',
    ['host',
     'level',
     'network_type',
     'physical_network'])

EndpointSecurityGroupInfo = namedtuple(
    'EndpointSecurityGroupInfo',
    ['sg_id',
     'project_id'])

EndpointDhcpIpInfo = namedtuple(
    'EndpointDhcpIpInfo',
    ['mac_address',
     'ip_address',
     'subnet_id'])

EndpointSegmentInfo = namedtuple(
    'EndpointSegmentInfo',
    ['network_type',
     'physical_network',
     'segmentation_id'])

EndpointAapInfo = namedtuple(
    'EndpointAapInfo',
    ['mac_address',
     'ip_address'])

EndpointOwnedIpInfo = namedtuple(
    'EndpointOwnedIpInfo',
    ['ip_address',
     'actual_port_id'])

EndpointExternalNetworkInfo = namedtuple(
    'EndpointExternalNetworkInfo',
    ['network_id',
     'project_id',
     'epg_name',
     'epg_app_profile_name',
     'epg_tenant_name',
     'external_network_dn',
     'nat_type'])

EndpointFipInfo = namedtuple(
    'EndpointFipInfo',
    ['floating_ip_id',
     'floating_ip_address',
     'floating_network_id',
     'fixed_ip_address'])

EndpointSnatInfo = namedtuple(
    'EndpointSnatInfo',
    ['network_id',
     'ip_address',
     'cidr',
     'gateway_ip'])

EndpointTrunkInfo = namedtuple(
    'EndpointTrunkInfo',
    ['master_port_id',
     'subport_port_id',
     'segmentation_type',
     'segmentation_id'])


class TopologyRpcEndpoint(object):

    target = oslo_messaging.Target(version=oa_rpc.VERSION)

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
        # cleanup the hostlink table.
        return


class ApicRpcHandlerMixin(object):

    def _start_rpc_listeners(self):
        conn = n_rpc.create_connection()

        # Opflex RPC handler.
        conn.create_consumer(
            o_rpc.TOPIC_OPFLEX,
            [o_rpc.GBPServerRpcCallback(self, self.notifier)],
            fanout=False)

        # Topology RPC hander.
        conn.create_consumer(
            oa_rpc.TOPIC_APIC_SERVICE,
            [TopologyRpcEndpoint(self)],
            fanout=False)

        # Start listeners and return list of servers.
        return conn.consume_in_threads()

    # The following five methods handle RPCs from the Opflex agent.

    def get_gbp_details(self, context, **kwargs):
        LOG.debug("APIC AIM MD handling get_gbp_details for: %s", kwargs)

        # REVISIT: This RPC is no longer invoked by the Opflex agent,
        # and should be eliminated or should simply log an error, but
        # it is used extensively in unit tests.

        request = {'device': kwargs.get('device')}
        host = kwargs.get('host')
        response = self.request_endpoint_details(
            context, request=request, host=host)
        gbp_details = response.get('gbp_details')
        return gbp_details or response

    def get_vrf_details(self, context, **kwargs):
        LOG.debug("APIC AIM MD handling get_vrf_details for: %s", kwargs)

        vrf_id = kwargs.get('vrf_id')
        if not vrf_id:
            LOG.error("Missing vrf_id in get_vrf_details RPC: %s",
                      kwargs)
            return

        try:
            return self._get_vrf_details(context, vrf_id)
        except Exception as e:
            LOG.error("An exception occurred while processing "
                      "get_vrf_details RPC: %s", kwargs)
            LOG.exception(e)
            return {'l3_policy_id': vrf_id}

    def request_endpoint_details(self, context, **kwargs):
        LOG.debug("APIC AIM MD handling request_endpoint_details for: %s",
                  kwargs)

        request = kwargs.get('request')
        if not request:
            LOG.error("Missing request in request_endpoint_details RPC: %s",
                      kwargs)
            return

        device = request.get('device')
        if not device:
            LOG.error("Missing device in request_endpoint_details RPC: %s",
                      kwargs)
            return

        host = kwargs.get('host')
        if not host:
            LOG.error("Missing host in request_endpoint_details RPC: %s",
                      kwargs)
            return

        try:
            return self._request_endpoint_details(context, request, host)
        except Exception as e:
            LOG.error("An exception occurred while processing "
                      "request_endpoint_details RPC: %s", kwargs)
            LOG.exception(e)
            return {'device': device}

    def request_vrf_details(self, context, kwargs):
        LOG.debug("APIC AIM MD handling request_vrf_details for: %s", kwargs)

        # REVISIT: This RPC is not currently invoked by the Opflex
        # agent, but that may be planned. Once it is, move the handler
        # implementation from get_vrf_details() to this method.
        return self.get_vrf_details(context, kwargs)

    def ip_address_owner_update(self, context, **kwargs):
        LOG.debug("APIC AIM MD handling ip_address_owner_update for: %s",
                  kwargs)
        if not kwargs.get('ip_owner_info'):
            return
        ports_to_update = self.update_ip_owner(kwargs['ip_owner_info'])
        for p in ports_to_update:
            LOG.debug("APIC ownership update for port %s", p)
            self._notify_port_update(context, p)

    @db_api.retry_if_session_inactive()
    def _get_vrf_details(self, context, vrf_id):
        vrf_tenant_name, vrf_name = vrf_id.split(' ')
        with db_api.context_manager.reader.using(context) as session:
            vrf_subnets = self._query_vrf_subnets(
                session, vrf_tenant_name, vrf_name)
            return {
                'l3_policy_id': vrf_id,
                'vrf_tenant': vrf_tenant_name,
                'vrf_name': vrf_name,
                'vrf_subnets': vrf_subnets
            }

    @db_api.retry_if_session_inactive()
    def _request_endpoint_details(self, context, request, host):
        device = request['device']
        info = {'device': device}
        response = {
            'device': device,
            'request_id': request.get('request_id'),
            'timestamp': request.get('timestamp')
        }

        # Loop so we can bind the port, if necessary, outside the
        # transaction in which we query the endpoint's state, and then
        # retry.
        while True:
            # Start a read-only transaction. Separate read-write
            # transactions will be used if needed to bind the port or
            # assign SNAT IPs.
            with db_api.context_manager.reader.using(context) as session:
                # Extract possibly truncated port ID from device.
                #
                # REVISIT: If device identifies the port by its MAC
                # address instead of its UUID, _device_to_port_id()
                # will query for the entire port DB object. So
                # consider not calling _device_to_port_id() and
                # instead removing any device prefix here and
                # conditionally filtering in
                # _query_endpoint_port_info() below on either the
                # port's UUID or its mac_address.
                port_id = self.plugin._device_to_port_id(context, device)

                # Query for all the needed scalar (non-list) state
                # associated with the port.
                port_infos = self._query_endpoint_port_info(session, port_id)
                if not port_infos:
                    LOG.info("Nonexistent port %s in requent_endpoint_details "
                             "RPC from host %s", port_id, host)
                    return response
                if len(port_infos) > 1:
                    LOG.info("Multiple ports start with %s in "
                             "requent_endpoint_details RPC from host %s",
                             port_id, host)
                    return response
                port_info = port_infos[0]
                info['port_info'] = port_info

                # If port is bound, check host and do remaining
                # queries.
                if port_info.vif_type not in [
                        portbindings.VIF_TYPE_UNBOUND,
                        portbindings.VIF_TYPE_BINDING_FAILED]:

                    # Check that port is bound to host making the RPC
                    # request.
                    if port_info.host != host:
                        LOG.warning("Port %s bound to host %s, but "
                                    "request_endpoint_details RPC made from "
                                    "host %s",
                                    port_info.port_id, port_info.host, host)
                        return response

                    # Query for all needed state associated with each
                    # of the port's static IPs.
                    info['ip_info'] = self._query_endpoint_fixed_ip_info(
                        session, port_info.port_id)

                    # Query for list of state associated with each of
                    # the port's binding levels, sorted by level.
                    info['binding_info'] = self._query_endpoint_binding_info(
                        session, port_info.port_id)

                    # Query for list of the port's security groups.
                    info['sg_info'] = self._query_endpoint_sg_info(
                        session, port_info.port_id)

                    # Query for list of state associated with each
                    # DHCP IP on the port's network.
                    info['dhcp_ip_info'] = self._query_endpoint_dhcp_ip_info(
                        session, port_info.network_id)

                    # Query for the list of static segments of the
                    # port's network.
                    info['segment_info'] = self._query_endpoint_segment_info(
                        session, port_info.network_id)

                    # Query for the port's allowed address pairs.
                    info['aap_info'] = self._query_endpoint_aap_info(
                        session, port_info.port_id)

                    # Query for list of state associated with each of
                    # the port's HAIP owned IP addresses.
                    info['owned_ip_info'] = (
                        self._query_endpoint_haip_owned_ip_info(
                            session, port_info.port_id, port_info.network_id))

                    # Query for dict of state associated with the
                    # external networks to which the port's subnets
                    # are routed.
                    subnet_ids = set([ip.subnet_id for ip in info['ip_info']])
                    info['ext_net_info'] = self._query_endpoint_ext_net_info(
                        session, subnet_ids)

                    # Query for list of floating IPs for both this
                    # port and all the other ports on which this
                    # port's HAIP owned addresses are actually
                    # defined.
                    fip_port_ids = (
                        [port_info.port_id] +
                        [x.actual_port_id for x in info['owned_ip_info']])
                    info['fip_info'] = self._query_endpoint_fip_info(
                        session, fip_port_ids)

                    # Query for dict of state associated with the SNAT
                    # ports on this host of the endpoint port's
                    # external networks.
                    info['snat_info'] = self._query_endpoint_snat_info(
                        session, host, info['ext_net_info'].keys())

                    # Query for list of trunk subports for a trunk
                    # that the endpoint's port is associated with,
                    # either as the master port or as a subport.
                    trunk_id = port_info.trunk_id or port_info.subport_trunk_id
                    if trunk_id:
                        info['trunk_info'] = self._query_endpoint_trunk_info(
                            session, trunk_id)

                    # Query for the port's extra DHCP options.
                    info['extra_dhcp_opts'] = (
                        self._query_endpoint_extra_dhcp_opts(
                            session, port_info.port_id))

                    # Query for nested domain allowed VLANs for the
                    # port's network.
                    info['nested_domain_allowed_vlans'] = (
                        self._query_endpoint_nested_domain_allowed_vlans(
                            session, port_info.network_id))

                    # Query for VRF subnets.
                    info['vrf_subnets'] = self._query_vrf_subnets(
                        session, port_info.vrf_tenant_name, port_info.vrf_name)

                    # Let the GBP policy driver do its queries and add
                    # its info.
                    if self.gbp_driver:
                        self.gbp_driver.query_endpoint_rpc_info(session, info)

                    # Done with queries, so exit transaction and retry loop.
                    break

            # Attempt to bind port outside transaction.
            pc = self.plugin.get_bound_port_context(context, port_id, host)
            if (pc.vif_type == portbindings.VIF_TYPE_BINDING_FAILED or
                pc.vif_type == portbindings.VIF_TYPE_UNBOUND):
                LOG.warning("The request_endpoint_details RPC handler is "
                            "unable to bind port %s on host %s",
                            port_id, pc.host)
                return response

            # Successfully bound port, so loop to retry queries.

        # Completed queries, so build up the response.
        response['neutron_details'] = self._build_endpoint_neutron_details(
            info)
        response['gbp_details'] = self._build_endpoint_gbp_details(info)
        response['trunk_details'] = self._build_endpoint_trunk_details(info)

        #  Let the GBP policy driver add/update its details in the response.
        if self.gbp_driver:
            self.gbp_driver.update_endpoint_rpc_details(info, response)

        # Return the response.
        return response

    def _query_endpoint_port_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            models_v2.Port.project_id,
            models_v2.Port.id,
            models_v2.Port.name,
            models_v2.Port.network_id,
            models_v2.Port.mac_address,
            models_v2.Port.admin_state_up,
            models_v2.Port.device_id,
            models_v2.Port.device_owner,
            ml2_models.PortBinding.host,
            ml2_models.PortBinding.vif_type,
            ml2_models.PortBinding.vif_details,
            psec_models.PortSecurityBinding.port_security_enabled,
            trunk_models.Trunk.id,
            trunk_models.SubPort.trunk_id,
            # Not in ocata: models_v2.Network.mtu,
            dns_models.NetworkDNSDomain.dns_domain,
            extension_db.NetworkExtensionDb.nested_domain_name,
            extension_db.NetworkExtensionDb.nested_domain_type,
            extension_db.NetworkExtensionDb.nested_domain_infra_vlan,
            extension_db.NetworkExtensionDb.nested_domain_service_vlan,
            extension_db.NetworkExtensionDb.
            nested_domain_node_network_vlan,
            db.NetworkMapping.epg_name,
            db.NetworkMapping.epg_app_profile_name,
            db.NetworkMapping.epg_tenant_name,
            db.NetworkMapping.vrf_name,
            db.NetworkMapping.vrf_tenant_name,
            db.VMName.vm_name,
        ))
        query += lambda q: q.outerjoin(
            ml2_models.PortBinding,
            ml2_models.PortBinding.port_id == models_v2.Port.id)
        query += lambda q: q.outerjoin(
            psec_models.PortSecurityBinding,
            psec_models.PortSecurityBinding.port_id == models_v2.Port.id)
        query += lambda q: q.outerjoin(
            trunk_models.Trunk,
            trunk_models.Trunk.port_id == models_v2.Port.id)
        query += lambda q: q.outerjoin(
            trunk_models.SubPort,
            trunk_models.SubPort.port_id == models_v2.Port.id)
        # models_v2.Network.mtu not in ocata
        # query += lambda q: q.outerjoin(
        #     models_v2.Network,
        #     models_v2.Network.id == models_v2.Port.network_id)
        query += lambda q: q.outerjoin(
            dns_models.NetworkDNSDomain,
            dns_models.NetworkDNSDomain.network_id ==
            models_v2.Port.network_id)
        query += lambda q: q.outerjoin(
            extension_db.NetworkExtensionDb,
            extension_db.NetworkExtensionDb.network_id ==
            models_v2.Port.network_id)
        query += lambda q: q.outerjoin(
            db.NetworkMapping,
            db.NetworkMapping.network_id == models_v2.Port.network_id)
        query += lambda q: q.outerjoin(
            db.VMName,
            db.VMName.device_id == models_v2.Port.device_id)
        query += lambda q: q.filter(
            models_v2.Port.id.startswith(sa.bindparam('port_id')))
        return [EndpointPortInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_endpoint_fixed_ip_info(self, session, port_id):
        # In this query, IPAllocations are outerjoined with
        # DNSNameServers and SubnetRoutes. This avoids needing to make
        # separate queries for DNSNameServers and for SubnetRoutes,
        # but results in rows being returned for the cross product of
        # the DNSNameServer rows and SubnetRoute rows associated with
        # each fixed IP. Unless there are use cases where large
        # numbers of rows in both these tables exist for the same
        # fixed IP, this approach is expected to provide better
        # latency and scalability than using separate
        # queries. Redundant information must be ignored when
        # processing the rows returned from this query.
        query = BAKERY(lambda s: s.query(
            models_v2.IPAllocation.ip_address,
            models_v2.IPAllocation.subnet_id,
            models_v2.Subnet.ip_version,
            models_v2.Subnet.cidr,
            models_v2.Subnet.gateway_ip,
            models_v2.Subnet.enable_dhcp,
            models_v2.DNSNameServer.address,
            models_v2.SubnetRoute.destination,
            models_v2.SubnetRoute.nexthop,
        ))
        query += lambda q: q.join(
            models_v2.Subnet,
            models_v2.Subnet.id == models_v2.IPAllocation.subnet_id)
        query += lambda q: q.outerjoin(
            models_v2.DNSNameServer,
            models_v2.DNSNameServer.subnet_id ==
            models_v2.IPAllocation.subnet_id)
        query += lambda q: q.outerjoin(
            models_v2.SubnetRoute,
            models_v2.SubnetRoute.subnet_id ==
            models_v2.IPAllocation.subnet_id)
        query += lambda q: q.filter(
            models_v2.IPAllocation.port_id == sa.bindparam('port_id'))
        query += lambda q: q.order_by(
            models_v2.DNSNameServer.order)
        return [EndpointFixedIpInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_endpoint_binding_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            ml2_models.PortBindingLevel.host,
            ml2_models.PortBindingLevel.level,
            segment_models.NetworkSegment.network_type,
            segment_models.NetworkSegment.physical_network,
        ))
        query += lambda q: q.join(
            segment_models.NetworkSegment,
            segment_models.NetworkSegment.id ==
            ml2_models.PortBindingLevel.segment_id)
        query += lambda q: q.filter(
            ml2_models.PortBindingLevel.port_id == sa.bindparam('port_id'))
        query += lambda q: q.order_by(
            ml2_models.PortBindingLevel.level)
        return [EndpointBindingInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_endpoint_sg_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            sg_models.SecurityGroup.id,
            sg_models.SecurityGroup.project_id,
        ))
        query += lambda q: q.join(
            sg_models.SecurityGroupPortBinding,
            sg_models.SecurityGroupPortBinding.security_group_id ==
            sg_models.SecurityGroup.id)
        query += lambda q: q.filter(
            sg_models.SecurityGroupPortBinding.port_id ==
            sa.bindparam('port_id'))
        return [EndpointSecurityGroupInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_endpoint_dhcp_ip_info(self, session, network_id):
        query = BAKERY(lambda s: s.query(
            models_v2.Port.mac_address,
            models_v2.IPAllocation.ip_address,
            models_v2.IPAllocation.subnet_id,
        ))
        query += lambda q: q.join(
            models_v2.IPAllocation,
            models_v2.IPAllocation.port_id == models_v2.Port.id)
        query += lambda q: q.filter(
            models_v2.Port.network_id == sa.bindparam('network_id'),
            models_v2.Port.device_owner == n_constants.DEVICE_OWNER_DHCP)
        return [EndpointDhcpIpInfo._make(row) for row in
                query(session).params(
                    network_id=network_id)]

    def _query_endpoint_segment_info(self, session, network_id):
        query = BAKERY(lambda s: s.query(
            segment_models.NetworkSegment.network_type,
            segment_models.NetworkSegment.physical_network,
            segment_models.NetworkSegment.segmentation_id,
        ))
        query += lambda q: q.filter(
            segment_models.NetworkSegment.network_id ==
            sa.bindparam('network_id'),
            segment_models.NetworkSegment.is_dynamic.is_(False))
        return [EndpointSegmentInfo._make(row) for row in
                query(session).params(
                    network_id=network_id)]

    def _query_endpoint_aap_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            aap_models.AllowedAddressPair.mac_address,
            aap_models.AllowedAddressPair.ip_address,
        ))
        query += lambda q: q.filter(
            aap_models.AllowedAddressPair.port_id ==
            sa.bindparam('port_id'))
        return [EndpointAapInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_endpoint_haip_owned_ip_info(self, session, port_id, network_id):
        query = BAKERY(lambda s: s.query(
            db.HAIPAddressToPortAssociation.ha_ip_address,
            models_v2.IPAllocation.port_id,
        ))
        query += lambda q: q.outerjoin(
            models_v2.IPAllocation,
            models_v2.IPAllocation.ip_address ==
            db.HAIPAddressToPortAssociation.ha_ip_address and
            models_v2.IPAllocation.network_id ==
            sa.bindparam('network_id'))
        query += lambda q: q.filter(
            db.HAIPAddressToPortAssociation.port_id ==
            sa.bindparam('port_id'))
        return [EndpointOwnedIpInfo._make(row) for row in
                query(session).params(
                    port_id=port_id,
                    network_id=network_id)]

    def _query_endpoint_ext_net_info(self, session, subnet_ids):
        # REVISIT: Consider replacing this query with additional joins
        # in _query_endpoint_fixed_ip_info to eliminate a round-trip
        # to the DB server. This would require using aliases to
        # disambiguate between the endpoint's port's IPAllocation and
        # the router port's IPAllocation, and its not obvious if
        # aliases can be used with baked queries.
        if not subnet_ids:
            return {}
        # Baked queries using in_ require sqlalchemy >=1.2.
        query = session.query(
            models_v2.Network.id,
            models_v2.Network.project_id,
            db.NetworkMapping.epg_name,
            db.NetworkMapping.epg_app_profile_name,
            db.NetworkMapping.epg_tenant_name,
            extension_db.NetworkExtensionDb.external_network_dn,
            extension_db.NetworkExtensionDb.nat_type,
        )
        query = query.join(
            models_v2.Port,  # router's gw_port
            models_v2.Port.network_id == models_v2.Network.id)
        query = query.join(
            l3_models.Router,
            l3_models.Router.gw_port_id == models_v2.Port.id)
        query = query.join(
            l3_models.RouterPort,
            l3_models.RouterPort.router_id == l3_models.Router.id and
            l3_models.RouterPort.port_type ==
            n_constants.DEVICE_OWNER_ROUTER_INTF)
        query = query.join(
            models_v2.IPAllocation,  # router interface IP
            models_v2.IPAllocation.port_id == l3_models.RouterPort.port_id)
        query = query.join(
            db.NetworkMapping,  # mapping of gw_port's network
            db.NetworkMapping.network_id == models_v2.Port.network_id)
        query = query.outerjoin(
            extension_db.NetworkExtensionDb,
            extension_db.NetworkExtensionDb.network_id ==
            models_v2.Port.network_id)
        query = query.filter(
            models_v2.IPAllocation.subnet_id.in_(subnet_ids))
        query = query.distinct()
        return {row[0]: EndpointExternalNetworkInfo._make(row) for row in
                query}

    def _query_endpoint_fip_info(self, session, port_ids):
        if not port_ids:
            return []
        # Baked queries using in_ require sqlalchemy >=1.2.
        query = session.query(
            l3_models.FloatingIP.id,
            l3_models.FloatingIP.floating_ip_address,
            l3_models.FloatingIP.floating_network_id,
            l3_models.FloatingIP.fixed_ip_address,
        )
        query = query.filter(
            l3_models.FloatingIP.fixed_port_id.in_(port_ids))
        return [EndpointFipInfo._make(row) for row in
                query]

    def _query_endpoint_snat_info(self, session, host, ext_net_ids):
        # REVISIT: Consider replacing this query with additional joins
        # in _query_endpoint_ext_net_info to eliminate a round-trip to
        # the DB server. This would require using aliases to
        # disambiguate tables appearing multiple times in the query,
        # and its not obvious if aliases can be used with baked
        # queries.
        if not ext_net_ids:
            return {}
        # Baked queries using in_ require sqlalchemy >=1.2.
        query = session.query(
            models_v2.Port.network_id,
            models_v2.IPAllocation.ip_address,
            models_v2.Subnet.cidr,
            models_v2.Subnet.gateway_ip,
        )
        query = query.join(
            models_v2.IPAllocation,
            models_v2.IPAllocation.port_id == models_v2.Port.id)
        query = query.join(
            models_v2.Subnet,
            models_v2.Subnet.id == models_v2.IPAllocation.subnet_id)
        query = query.filter(
            models_v2.Port.network_id.in_(ext_net_ids),
            models_v2.Port.device_id == host,
            models_v2.Port.device_owner == constants.DEVICE_OWNER_SNAT_PORT)
        return {row[0]: EndpointSnatInfo._make(row) for row in
                query}

    def _query_endpoint_trunk_info(self, session, trunk_id):
        query = BAKERY(lambda s: s.query(
            trunk_models.Trunk.port_id,
            trunk_models.SubPort.port_id,
            trunk_models.SubPort.segmentation_type,
            trunk_models.SubPort.segmentation_id,
        ))
        query += lambda q: q.join(
            trunk_models.SubPort,
            trunk_models.SubPort.trunk_id == trunk_models.Trunk.id)
        query += lambda q: q.filter(
            trunk_models.Trunk.id == sa.bindparam('trunk_id'))
        return [EndpointTrunkInfo._make(row) for row in
                query(session).params(
                    trunk_id=trunk_id)]

    def _query_endpoint_extra_dhcp_opts(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            dhcp_models.ExtraDhcpOpt.opt_name,
            dhcp_models.ExtraDhcpOpt.opt_value,
        ))
        query += lambda q: q.filter(
            dhcp_models.ExtraDhcpOpt.port_id == sa.bindparam('port_id'))
        return {k: v for k, v in query(session).params(
            port_id=port_id)}

    def _query_endpoint_nested_domain_allowed_vlans(self, session, network_id):
        query = BAKERY(lambda s: s.query(
            extension_db.NetworkExtNestedDomainAllowedVlansDb.vlan,
        ))
        query += lambda q: q.filter(
            extension_db.NetworkExtNestedDomainAllowedVlansDb.network_id ==
            sa.bindparam('network_id'))
        return [x for x, in query(session).params(
            network_id=network_id)]

    def _query_vrf_subnets(self, session, vrf_tenant_name, vrf_name):
        # A VRF mapped from one or two (IPv4 and/or IPv6)
        # address_scopes cannot be associated with unscoped
        # subnets. So first see if the VRF is mapped from
        # address_scopes, and if so, return the subnetpool CIDRs
        # associated with those address_scopes.
        query = BAKERY(lambda s: s.query(
            models_v2.SubnetPoolPrefix.cidr))
        query += lambda q: q.join(
            models_v2.SubnetPool,
            models_v2.SubnetPool.id ==
            models_v2.SubnetPoolPrefix.subnetpool_id)
        query += lambda q: q.join(
            db.AddressScopeMapping,
            db.AddressScopeMapping.scope_id ==
            models_v2.SubnetPool.address_scope_id)
        query += lambda q: q.filter(
            db.AddressScopeMapping.vrf_name ==
            sa.bindparam('vrf_name'),
            db.AddressScopeMapping.vrf_tenant_name ==
            sa.bindparam('vrf_tenant_name'))
        result = [x for x, in query(session).params(
            vrf_name=vrf_name,
            vrf_tenant_name=vrf_tenant_name)]
        if result:
            return result

        # If the VRF is not mapped from address_scopes, return the
        # CIDRs of all the subnets on all the networks associated with
        # the VRF.
        #
        # REVISIT: Consider combining these two queries into a single
        # query, using outerjoins to SubnetPool and
        # AddressScopeMapping. But that would result in all the
        # subnets' CIDRs being returned, even for the scoped case
        # where they are not needed, so it may not be a win.
        query = BAKERY(lambda s: s.query(
            models_v2.Subnet.cidr))
        query += lambda q: q.join(
            db.NetworkMapping,
            db.NetworkMapping.network_id ==
            models_v2.Subnet.network_id)
        query += lambda q: q.filter(
            db.NetworkMapping.vrf_name ==
            sa.bindparam('vrf_name'),
            db.NetworkMapping.vrf_tenant_name ==
            sa.bindparam('vrf_tenant_name'))
        return [x for x, in query(session).params(
            vrf_name=vrf_name,
            vrf_tenant_name=vrf_tenant_name)]

    def _build_endpoint_neutron_details(self, info):
        port_info = info['port_info']
        binding_info = info['binding_info']

        details = {}
        details['admin_state_up'] = port_info.admin_state_up
        details['device_owner'] = port_info.device_owner
        details['fixed_ips'] = self._build_fixed_ips(info)
        details['network_id'] = port_info.network_id
        details['network_type'] = binding_info[-1].network_type
        details['physical_network'] = binding_info[-1].physical_network
        details['port_id'] = port_info.port_id

        return details

    def _build_fixed_ips(self, info):
        ip_info = info['ip_info']

        # Build dict of unique fixed IPs, ignoring duplicates due to
        # joins between Port and DNSNameServers and Routes.
        fixed_ips = {}
        for ip in ip_info:
            if ip.ip_address not in fixed_ips:
                fixed_ips[ip.ip_address] = {'subnet_id': ip.subnet_id,
                                            'ip_address': ip.ip_address}

        return fixed_ips.values()

    def _build_endpoint_gbp_details(self, info):
        port_info = info['port_info']

        # Note that the GBP policy driver will replace these
        # app_profile_name, endpoint_group_name, ptg_tenant,
        # ... values if the port belongs to a GBP PolicyTarget.

        details = {}
        details['allowed_address_pairs'] = self._build_aaps(info)
        details['app_profile_name'] = port_info.epg_app_profile_name
        details['device'] = info['device']  # Redundant.
        if self.apic_optimized_dhcp_lease_time > 0:
            details['dhcp_lease_time'] = self.apic_optimized_dhcp_lease_time
        details['dns_domain'] = port_info.net_dns_domain or ''
        details['enable_dhcp_optimization'] = self.enable_dhcp_opt
        details['enable_metadata_optimization'] = self.enable_metadata_opt
        details['endpoint_group_name'] = port_info.epg_name
        details['floating_ip'] = self._build_fips(info)
        details['host'] = port_info.host
        details['host_snat_ips'] = self._build_host_snat_ips(info)
        mtu = self._get_interface_mtu(info)
        if mtu:
            details['interface_mtu'] = mtu
        details['ip_mapping'] = self._build_ipms(info)
        details['l3_policy_id'] = ("%s %s" %
                                   (port_info.vrf_tenant_name,
                                    port_info.vrf_name))
        details['mac_address'] = port_info.mac_address
        details['nested_domain_allowed_vlans'] = (
            info['nested_domain_allowed_vlans'])
        details['nested_domain_infra_vlan'] = (
            port_info.nested_domain_infra_vlan)
        details['nested_domain_name'] = port_info.nested_domain_name
        details['nested_domain_node_network_vlan'] = (
            port_info.nested_domain_node_network_vlan)
        details['nested_domain_service_vlan'] = (
            port_info.nested_domain_service_vlan)
        details['nested_domain_type'] = port_info.nested_domain_type
        details['nested_host_vlan'] = (
            self.nested_host_vlan if port_info.nested_domain_infra_vlan
            else None)
        details['port_id'] = port_info.port_id  # Redundant.
        details['promiscuous_mode'] = self._get_promiscuous_mode(info)
        details['ptg_tenant'] = port_info.epg_tenant_name
        if info['sg_info']:
            # Only add security group details if the port has SGs and
            # it doesn't belong to a legacy VM using iptables.
            vif_details = (port_info.vif_details and
                           jsonutils.loads(port_info.vif_details))
            if not (vif_details and vif_details.get('port_filter') and
                    vif_details.get('ovs_hybrid_plug')):
                details['security_group'] = self._build_sg_details(info)
        details['subnets'] = self._build_subnet_details(info)
        details['vm-name'] = (port_info.vm_name if
                              port_info.device_owner.startswith('compute:') and
                              port_info.vm_name else port_info.device_id)
        details['vrf_name'] = port_info.vrf_name
        details['vrf_subnets'] = info['vrf_subnets']
        details['vrf_tenant'] = port_info.vrf_tenant_name

        return details

    def _build_aaps(self, info):
        owned_ips = set(ip.ip_address for ip in info['owned_ip_info'])
        aaps = {}
        for allowed in info['aap_info']:
            aaps[allowed.ip_address] = {'ip_address': allowed.ip_address,
                                        'mac_address': allowed.mac_address}
            cidr = netaddr.IPNetwork(allowed.ip_address)
            if ((cidr.version == 4 and cidr.prefixlen != 32) or
                (cidr.version == 6 and cidr.prefixlen != 128)):
                # Never mark CIDRs as "active", but
                # look for owned addresses in this CIDR, and
                # if present, add them to the allowed-address-pairs
                # list, and mark those as "active".
                for ip in owned_ips:
                    if ip in cidr and ip not in aaps:
                        aaps[ip] = {'ip_address': ip,
                                    'mac_address': allowed.mac_address,
                                    'active': True}
            elif allowed.ip_address in owned_ips:
                aaps[allowed.ip_address]['active'] = True
        return aaps.values()

    def _build_fips(self, info):
        ext_net_info = info['ext_net_info']
        fips = []
        for fip in info['fip_info']:
            details = {'id': fip.floating_ip_id,
                       'fixed_ip_address': fip.fixed_ip_address,
                       'floating_ip_address': fip.floating_ip_address}
            ext_net = ext_net_info.get(fip.floating_network_id)
            if (ext_net and ext_net.external_network_dn and
                ext_net.nat_type == 'distributed'):
                details['nat_epg_app_profile'] = ext_net.epg_app_profile_name
                details['nat_epg_name'] = ext_net.epg_name
                details['nat_epg_tenant'] = ext_net.epg_tenant_name
            fips.append(details)
        return fips

    def _build_host_snat_ips(self, info):
        snat_info = info['snat_info']
        host = info['port_info'].host
        ext_nets_with_fips = {fip.floating_network_id
                              for fip in info['fip_info']}
        host_snat_ips = []
        for ext_net in info['ext_net_info'].values():
            if ext_net in ext_nets_with_fips:
                # No need for SNAT IP.
                continue
            snat = snat_info.get(ext_net.network_id)
            if snat:
                snat_ip = {'host_snat_ip': snat.ip_address,
                           'gateway_ip': snat.gateway_ip,
                           'prefixlen': int(snat.cidr.split('/')[1])}
            else:
                # No existing SNAT IP for this external network on
                # this host, so allocate one.
                #
                # REVISIT: Should this have a retry loop/decorator so
                # that we don't have to retry the entire RPC handler
                # if we get a retriable exception?
                ctx = n_context.get_admin_context()
                with db_api.context_manager.writer.using(ctx):
                    snat_ip = self.get_or_allocate_snat_ip(
                        ctx, host, {'id': ext_net.network_id,
                                    'tenant_id': ext_net.project_id})
            if snat_ip:
                snat_ip['external_segment_name'] = (
                    ext_net.external_network_dn.replace('/', ':'))
                host_snat_ips.append(snat_ip)
        return host_snat_ips

    def _get_interface_mtu(self, info):
        if self.advertise_mtu:
            opts = info['extra_dhcp_opts']
            opt_value = opts.get('interface-mtu') or opts.get('26')
            if opt_value:
                try:
                    return int(opt_value)
                except ValueError:
                    pass
            # In stable/pike and newer, mtu is a column in the
            # models_v2.Networks table. Without that column, the MTU
            # is determined using the ML2 type drivers of the
            # network's segments.
            network = {'id': info['port_info'].network_id,
                       'segments':
                       [{provider.NETWORK_TYPE: s.network_type,
                         provider.PHYSICAL_NETWORK: s.physical_network,
                         provider.SEGMENTATION_ID: s.segmentation_id}
                        for s in info['segment_info']]}
            return self.plugin._get_network_mtu(network)

    def _build_ipms(self, info):
        ext_nets_with_fips = {fip.floating_network_id
                              for fip in info['fip_info']}
        return [{'external_segment_name':
                 ext_net.external_network_dn.replace('/', ':'),
                 'nat_epg_app_profile': ext_net.epg_app_profile_name,
                 'nat_epg_name': ext_net.epg_name,
                 'nat_epg_tenant': ext_net.epg_tenant_name}
                for ext_net in info['ext_net_info'].values()
                if ext_net.external_network_dn and
                ext_net.nat_type == 'distributed' and
                ext_net.network_id not in ext_nets_with_fips]

    def _get_promiscuous_mode(self, info):
        port_info = info['port_info']
        # REVISIT: Replace PROMISCUOUS_SUFFIX with a proper API
        # attribute if really needed, but why not just have
        # applications use port_security_enabled=False?
        return (port_info.device_owner in constants.PROMISCUOUS_TYPES or
                port_info.port_name.endswith(constants.PROMISCUOUS_SUFFIX) or
                not port_info.psec_enabled)

    def _build_sg_details(self, info):
        return (
            [{'policy-space': self.name_mapper.project(None, sg.project_id),
              'name': sg.sg_id} for sg in info['sg_info']] +
            [{'policy-space': 'common', 'name': self._default_sg_name}])

    def _build_subnet_details(self, info):
        ip_info = info['ip_info']
        dhcp_ip_info = info['dhcp_ip_info']

        # Build dict of subnets with basic subnet details, and collect
        # joined DNSNameServer and Route info. Order must be preserved
        # among DNSNameServer entries for a subnet.
        subnets = {}
        subnet_dns_nameservers = defaultdict(list)
        subnet_routes = defaultdict(set)
        for ip in ip_info:
            if ip.subnet_id not in subnets:
                subnet = {}
                subnet['cidr'] = ip.cidr
                subnet['enable_dhcp'] = ip.enable_dhcp
                subnet['gateway_ip'] = ip.gateway_ip
                subnet['id'] = ip.subnet_id
                subnet['ip_version'] = ip.ip_version
                subnets[ip.subnet_id] = subnet
            if ip.dns_nameserver:
                dns_nameservers = subnet_dns_nameservers[ip.subnet_id]
                if ip.dns_nameserver not in dns_nameservers:
                    dns_nameservers.append(ip.dns_nameserver)
            if ip.route_destination:
                subnet_routes[ip.subnet_id].add(
                    (ip.route_destination, ip.route_nexthop))

        # Add remaining details to each subnet.
        for subnet_id, subnet in subnets.items():
            dhcp_ips = set()
            dhcp_ports = defaultdict(list)
            for ip in dhcp_ip_info:
                if ip.subnet_id == subnet_id:
                    dhcp_ips.add(ip.ip_address)
                    dhcp_ports[ip.mac_address].append(ip.ip_address)
            dhcp_ips = list(dhcp_ips)

            routes = subnet_routes[subnet_id]
            if subnet['ip_version'] == 4:
                # Find default and metadata routes.
                default_routes = set()
                metadata_routes = set()
                for route in routes:
                    destination = route[0]
                    if destination == constants.IPV4_ANY_CIDR:
                        default_routes.add(route)
                    elif destination == constants.IPV4_METADATA_CIDR:
                        metadata_routes.add(route)
                # Add gateway_ip and missing routes. Note that these
                # might get removed by the GBP PD if the L2P's
                # inject_default_route attribute is False.
                gateway_ip = subnet['gateway_ip']
                if not default_routes and gateway_ip:
                    routes.add((constants.IPV4_ANY_CIDR, gateway_ip))
                # REVISIT: We need to decide if we should provide
                # host-routes for all of the DHCP agents. For now
                # use the first DHCP agent in our list for the
                # metadata host-route next-hop IPs.
                if (not metadata_routes and dhcp_ports and
                    (not self.enable_metadata_opt or
                     (self.enable_metadata_opt and not default_routes))):
                    for ip in dhcp_ports[dhcp_ports.keys()[0]]:
                        routes.add((constants.IPV4_METADATA_CIDR, ip))

            subnet['dhcp_server_ips'] = dhcp_ips
            subnet['dhcp_server_ports'] = dhcp_ports
            subnet['dns_nameservers'] = (subnet_dns_nameservers[subnet_id] or
                                         dhcp_ips)
            subnet['host_routes'] = [
                {'destination': destination, 'nexthop': nexthop}
                for destination, nexthop in routes]

        return subnets.values()

    def _build_endpoint_trunk_details(self, info):
        trunk_info = info.get('trunk_info')
        if not trunk_info:
            return
        port_info = info.get('port_info')
        return {'trunk_id': port_info.trunk_id or port_info.subport_trunk_id,
                'master_port_id': trunk_info[0].master_port_id,
                'subports': [{'port_id': sp.subport_port_id,
                              'segmentation_type': sp.segmentation_type,
                              'segmentation_id': sp.segmentation_id}
                             for sp in trunk_info]}
