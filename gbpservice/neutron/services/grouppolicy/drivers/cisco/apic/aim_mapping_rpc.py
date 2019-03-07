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

from collections import namedtuple
import sqlalchemy as sa
from sqlalchemy.ext import baked

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import api as db_api
from neutron.db import db_base_plugin_common
from neutron.db.models import securitygroup as sg_models
from neutron.extensions import portbindings
from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects
from neutron.plugins.ml2 import rpc as ml2_rpc
from opflexagent import rpc as o_rpc
from oslo_log import log

from gbpservice._i18n import _LE
from gbpservice._i18n import _LW
from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_auto_ptg_db as auto_ptg_db)
from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_segmentation_label_db as seg_label_db)
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    constants as md_const)

LOG = log.getLogger(__name__)

BAKERY = baked.bakery()

EndpointPtInfo = namedtuple(
    'EndpointPtInfo',
    ['pt_id',
     'ptg_id',
     'apg_id',
     'inject_default_route',
     'l3p_project_id',
     'is_auto_ptg'])


class AIMMappingRPCMixin(ha_ip_db.HAIPOwnerDbMixin):
    """RPC mixin for AIM mapping.

    Collection of all the RPC methods consumed by the AIM mapping.
    By defining the mixin requirements, we can potentially move the RPC
    handling between GBP and Neutron preserving the same code base. Such
    requirements might be easier to implement in some places (eg. won't
    require model extensions) compared to others, based on the visibility
    that each module has over the network abstraction.
    """

    # REVISIT: Remove original RPC implementation - everything in this
    # class before the query_endpoint_rpc_info method.

    def setup_opflex_rpc_listeners(self):
        self.notifier = o_rpc.AgentNotifierApi(topics.AGENT)
        LOG.debug("Set up Opflex RPC listeners.")
        self.opflex_endpoints = [
            o_rpc.GBPServerRpcCallback(self, self.notifier)]
        self.opflex_topic = o_rpc.TOPIC_OPFLEX
        self.opflex_conn = n_rpc.create_connection()
        self.opflex_conn.create_consumer(
            self.opflex_topic, self.opflex_endpoints, fanout=False)
        self.opflex_conn.consume_in_threads()

    @db_api.retry_if_session_inactive()
    def _retrieve_vrf_details(self, context, **kwargs):
        with context.session.begin(subtransactions=True):
            details = {'l3_policy_id': kwargs['vrf_id']}
            self._add_vrf_details(context, details['l3_policy_id'], details)
        return details

    def _get_vrf_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling _get_vrf_details for: %s", kwargs)
        try:
            return self._retrieve_vrf_details(context, **kwargs)
        except Exception as e:
            vrf = kwargs.get('vrf_id')
            LOG.error(_LE("An exception has occurred while retrieving vrf "
                          "gbp details for %s"), vrf)
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
            LOG.error(_LE("An exception has occurred while retrieving device "
                          "gbp details for %s"), device)
            LOG.exception(e)
            return {'device': device}

    def request_endpoint_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling get_endpoint_details for: %s", kwargs)
        request = kwargs.get('request')
        try:
            return self._request_endpoint_details(context, **kwargs)
        except Exception as e:
            LOG.error(_LE("An exception has occurred while requesting device "
                          "gbp details for %s"), request.get('device'))
            LOG.exception(e)
            return None

    @db_api.retry_if_session_inactive()
    def _request_endpoint_details(self, context, **kwargs):
        request = kwargs.get('request')
        host = kwargs.get('host')
        result = {'device': request['device'],
                  'timestamp': request['timestamp'],
                  'request_id': request['request_id'],
                  'gbp_details': self._get_gbp_details(context, request,
                                                       host),
                  'neutron_details': ml2_rpc.RpcCallbacks(
                      None, None).get_device_details(context, **request),
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
        with context.session.begin(subtransactions=True):
            device = request.get('device')

            core_plugin = self._core_plugin
            port_id = core_plugin._device_to_port_id(context, device)
            port_context = core_plugin.get_bound_port_context(context, port_id,
                                                              host)
            if not port_context:
                LOG.warning(_LW("Device %(device)s requested by agent "
                                "%(agent_id)s not found in database"),
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

            self._set_nova_vm_name(context, port, details)

            mtu = self._get_port_mtu(context, port)
            if mtu:
                details['interface_mtu'] = mtu
            details['dns_domain'] = self._get_dns_domain(context, port)

            # NOTE(ivar): having these methods cleanly separated actually makes
            # things less efficient by requiring lots of calls duplication.
            # we could alleviate this by passing down a cache that stores
            # commonly requested objects (like EPGs). 'details' itself could
            # be used for such caching.
            if port.get('security_groups'):
                self._add_security_group_details(context, port, details)
            vrf = self._get_port_vrf(context, port)
            details['l3_policy_id'] = '%s %s' % (vrf.tenant_name, vrf.name)
            self._add_subnet_details(context, port, details)
            self._add_allowed_address_pairs_details(context, port, details)
            self._add_vrf_details(context, details['l3_policy_id'], details)
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            self._add_segmentation_label_details(context, port, details)
            self._set_dhcp_lease_time(details)

        LOG.debug("Details for port %s : %s", port['id'], details)
        return details

    def _set_nova_vm_name(self, context, port, details):
        # Set VM name if needed.
        if port['device_owner'].startswith(
                'compute:') and port['device_id']:
            vm = self._get_nova_vm_name(context, port)
            if vm:
                vm_name, = vm
            else:
                vm_name = port['device_id']
            details['vm-name'] = vm_name

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

        # Baked queries using in_ require sqlalchemy >=1.2.
        port_sgs = (context.session.query(
            sg_models.SecurityGroup.id,
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
    # - self._get_subnet_details(context, port)
    def _add_subnet_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - subnets;
        details['subnets'] = self._get_subnet_details(context, port)

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
    # - self._get_aap_details(context, port)
    def _add_allowed_address_pairs_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - allowed_address_pairs
        # This should take care of realizing whether a given address is
        # active in the specific port
        details['allowed_address_pairs'] = self._get_aap_details(context, port)

    # Child class needs to support:
    # - self._get_vrf_subnets(context, vrf_tenant_name, vrf_name):
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
                                                       name)

    # Child class needs to support:
    # - self._get_segmentation_labels(context, port)
    def _add_segmentation_label_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - segmentation_labels
        # apic_segmentation_label is a GBP driver extension configured
        # for the aim_mapping driver
        details['segmentation_labels'] = self._get_segmentation_labels(
            context, port)

    def _add_extra_details(self, context, port, details):
        # TODO(ivar): Extra details depend on HA and SC implementation
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill per-mac address extra information.

        # What is an "End of the Chain" port for Neutron?
        pass

    # The query_endpoint_rpc_info and update_endpoint_rpc_details
    # methods below are called by the apic_aim mechanism driver while
    # handling the request_endpoint_details (aka get_gbp_details) RPC
    # from the agent.

    def query_endpoint_rpc_info(self, session, info):
        # This method is called within a transaction from the apic_aim
        # MD's request_endpoint_details RPC handler to retrieve GBP
        # state needed to build the RPC response, after the info param
        # has already been populated with the data available within
        # Neutron itself.

        # Query for all needed scalar (non-list) state for the
        # policies associated with the port, and make sure the port is
        # owned by a policy target before continuing.
        pt_infos = self._query_pt_info(
            session, info['port_info'].port_id)
        if not pt_infos:
            return

        # A list was returned by the PT info query, like all the other
        # endpoint RPC queries, here and in the mechanism
        # driver. Currently, there will be at most a single item in
        # this list, but a join may later be added to this query in
        # order to eliminate another query's round-trip to the DB
        # server, resulting in multiple rows being returned. For now,
        # we just need that single row.
        pt_info = pt_infos[0]
        info['gbp_pt_info'] = pt_info

        # Query for policy target's segmentation labels.
        info['gbp_segmentation_labels'] = self._query_segmentation_labels(
            session, pt_info.pt_id)

    def _query_pt_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            gpmdb.PolicyTargetMapping.id,
            gpmdb.PolicyTargetMapping.policy_target_group_id,
            gpmdb.PolicyTargetGroupMapping.application_policy_group_id,
            gpmdb.L2PolicyMapping.inject_default_route,
            gpmdb.L3PolicyMapping.project_id,
            auto_ptg_db.ApicAutoPtgDB.is_auto_ptg,
        ))
        query += lambda q: q.join(
            gpmdb.PolicyTargetGroupMapping,
            gpmdb.PolicyTargetGroupMapping.id ==
            gpmdb.PolicyTargetMapping.policy_target_group_id)
        query += lambda q: q.join(
            gpmdb.L2PolicyMapping,
            gpmdb.L2PolicyMapping.id ==
            gpmdb.PolicyTargetGroupMapping.l2_policy_id)
        query += lambda q: q.join(
            gpmdb.L3PolicyMapping,
            gpmdb.L3PolicyMapping.id ==
            gpmdb.L2PolicyMapping.l3_policy_id)
        query += lambda q: q.outerjoin(
            auto_ptg_db.ApicAutoPtgDB,
            auto_ptg_db.ApicAutoPtgDB.policy_target_group_id ==
            gpmdb.PolicyTargetMapping.policy_target_group_id)
        query += lambda q: q.filter(
            gpmdb.PolicyTargetMapping.port_id == sa.bindparam('port_id'))
        return [EndpointPtInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_segmentation_labels(self, session, pt_id):
        query = BAKERY(lambda s: s.query(
            seg_label_db.ApicSegmentationLabelDB.segmentation_label))
        query += lambda q: q.filter(
            seg_label_db.ApicSegmentationLabelDB.policy_target_id ==
            sa.bindparam('pt_id'))
        return [x for x, in query(session).params(
            pt_id=pt_id)]

    def update_endpoint_rpc_details(self, info, details):
        # This method is called outside a transaction from the
        # apic_aim MD's request_endpoint_details RPC handler to add or
        # update details within the RPC response, using data stored in
        # info by query_endpoint_rpc_info.

        # First, make sure the port is owned by a PolicyTarget before
        # continuing.
        pt_info = info.get('gbp_pt_info')
        if not pt_info:
            return
        gbp_details = details['gbp_details']

        # Replace EPG identity if not auto_ptg.
        if not pt_info.is_auto_ptg:
            gbp_details['app_profile_name'] = (
                self.name_mapper.application_policy_group(
                    None, pt_info.apg_id) if pt_info.apg_id
                else self.aim_mech_driver.ap_name)
            gbp_details['endpoint_group_name'] = pt_info.ptg_id
            gbp_details['ptg_tenant'] = (
                self.name_mapper.project(None, pt_info.l3p_project_id))

        # Update subnet gateway_ip and default_routes if needed.
        if not pt_info.inject_default_route:
            for subnet in gbp_details['subnets']:
                del subnet['gateway_ip']
                subnet['host_routes'] = [
                    r for r in subnet['host_routes']
                    if r['destination'] not in
                    [md_const.IPV4_ANY_CIDR, md_const.IPV4_METADATA_CIDR]]

        # Add segmentation labels.
        gbp_details['segmentation_labels'] = (
            info.get('gbp_segmentation_labels'))

        # REVISIT: If/when support for the proxy_group extension is
        # added to the aim_mapping PD, update promiscuous_mode to True
        # if this PT has a cluster_id that identifies a different PT
        # whose group_default_gateway set.
