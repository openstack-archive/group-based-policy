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
from neutron.db.models import securitygroup as sg_models
from neutron.extensions import portbindings
from neutron.objects import base as objects_base
from neutron.objects import trunk as trunk_objects
from neutron.plugins.ml2 import rpc as ml2_rpc
from opflexagent import rpc as o_rpc
from oslo_config import cfg
from oslo_log import log

from gbpservice._i18n import _LE
from gbpservice._i18n import _LW
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    port_ha_ipaddress_binding as ha_ip_db)


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
        if self.aim_mech_driver.enable_prepared_statements_for_ep_file:
            return self._get_gbp_details_new(context, request, host)
        else:
            return self._get_gbp_details_old(context, request, host)

    def _get_gbp_details_old(self, context, request, host):
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

            # Set VM name if needed.
            if port['device_owner'].startswith(
                    'compute:') and port['device_id']:
                vm = nclient.NovaClient().get_server(port['device_id'])
                details['vm-name'] = vm.name if vm else port['device_id']

            details['_cache'] = {}
            mtu = self._get_port_mtu(context, port, details)
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
            vrf = self._get_port_vrf(context, port, details)
            details['l3_policy_id'] = '%s %s' % (vrf.tenant_name, vrf.name)
            self._add_subnet_details(context, port, details)
            self._add_allowed_address_pairs_details(context, port, details)
            self._add_vrf_details(context, details['l3_policy_id'], details)
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            self._add_segmentation_label_details(context, port, details)
            self._set_dhcp_lease_time(details)
            self._add_nested_domain_details(context, port, details)
            details.pop('_cache', None)

        LOG.debug("Details for port %s : %s", port['id'], details)
        return details

    def _compose_in_filter_str(self, obj_list):
        in_str = str(tuple(obj_list))
        # Remove the ',' at the end otherwise MySQL will complain
        if in_str[-1] == ')' and in_str[-2] == ',':
            in_str = in_str[0:-2] + in_str[-1]
        return in_str

    def _build_up_details_cache(self, session, details, port, network):
        ha_addr_query = ("SELECT ha_ip_address FROM "
                         "apic_ml2_ha_ipaddress_to_port_owner WHERE "
                         "apic_ml2_ha_ipaddress_to_port_owner.port_id = '"
                         + port['id'] + "'")
        ha_addr_result = session.execute(ha_addr_query)
        owned_addresses = sorted([x[0] for x in ha_addr_result])
        details['_cache']['owned_addresses'] = owned_addresses

        if port.get('security_groups'):
            # Remove the encoding presentation of the string
            # otherwise MySQL will complain
            sg_list = [str(r) for r in port['security_groups']]
            in_str = self._compose_in_filter_str(sg_list)
            sg_query = ("SELECT id, project_id FROM securitygroups WHERE "
                        "id in " + in_str)
            sg_result = session.execute(sg_query)
            details['_cache']['security_groups'] = sg_result

        # Get the subnet info
        subnets = []
        subnet_ids = [str(ip['subnet_id']) for ip in port['fixed_ips']]
        if subnet_ids:
            subnet_in_str = self._compose_in_filter_str(subnet_ids)
            subnet_query = ("SELECT * FROM subnets WHERE "
                            "id in " + subnet_in_str)
            subnet_result = session.execute(subnet_query)
            # Build up the ORM relationship manually
            for subnet in subnet_result:
                subnet_dict = dict(subnet)
                dns_query = ("SELECT address FROM dnsnameservers WHERE "
                             "subnet_id = '" + subnet['id'] + "'")
                dns_result = session.execute(dns_query)
                subnet_dict['dns_nameservers'] = []
                for dns in dns_result:
                    subnet_dict['dns_nameservers'].append(dns['address'])
                route_query = ("SELECT destination, nexthop FROM "
                               "subnetroutes WHERE "
                               "subnet_id = '" + subnet['id'] + "'")
                route_result = session.execute(route_query)
                subnet_dict['host_routes'] = []
                for route in route_result:
                    subnet_dict['host_routes'].append(
                        {'destination': route['destination'],
                         'nexthop': route['nexthop']})
                subnets.append(subnet_dict)
        details['_cache']['subnets'] = subnets

        # Get DHCP ports
        dhcp_query = ("SELECT id, mac_address FROM ports WHERE "
                      "ports.network_id = '" + network['id'] + "'" + " AND "
                      "ports.device_owner = 'network:dhcp'")
        dhcp_result = session.execute(dhcp_query)
        # Build up the ORM relationship manually
        dhcp_ports = []
        for dhcp_port in dhcp_result:
            dhcp_port_dict = dict(dhcp_port)
            ip_query = ("SELECT ip_address, subnet_id FROM "
                        "ipallocations WHERE "
                        "port_id = '" + dhcp_port['id'] + "'")
            ip_result = session.execute(ip_query)
            dhcp_port_dict['fixed_ips'] = []
            for ip in ip_result:
                dhcp_port_dict['fixed_ips'].append(
                    {'ip_address': ip['ip_address'],
                     'subnet_id': ip['subnet_id']})
            dhcp_ports.append(dhcp_port_dict)
        details['_cache']['dhcp_ports'] = dhcp_ports

        # Get address_scope, subnetpools and vrf_subnets
        address_scope_query = (
            "SELECT scope_id FROM apic_aim_address_scope_mappings WHERE "
            "vrf_name = '" + network['vrf_name'] + "'" + " AND "
            "vrf_tenant_name = '" + network['vrf_tenant_name'] + "'")
        as_result = session.execute(address_scope_query)
        subnetpools = []
        if as_result.rowcount > 0 or as_result.rowcount == -1:
            subnetpools_query = (
                "SELECT subnetpools.id as id FROM subnetpools JOIN "
                "address_scopes AS address_scopes_1 ON "
                "address_scopes_1.id = subnetpools.address_scope_id JOIN "
                "apic_aim_address_scope_mappings AS aim_as_mappings_1 ON "
                "aim_as_mappings_1.scope_id = address_scopes_1.id WHERE "
                "vrf_name = '" + network['vrf_name'] + "'" + " AND "
                "vrf_tenant_name = '" + network['vrf_tenant_name'] +
                "'")
            subnetpools_res = session.execute(subnetpools_query)
            # Build up the ORM relationship manually
            for subnetpool in subnetpools_res:
                subnetpool_dict = dict(subnetpool)
                prefix_query = (
                    "SELECT cidr FROM subnetpoolprefixes WHERE "
                    "subnetpool_id = '" + subnetpool['id'] + "'")
                prefix_result = session.execute(prefix_query)
                subnetpool_dict['prefixes'] = []
                for prefix in prefix_result:
                    subnetpool_dict['prefixes'].append(prefix['cidr'])
                subnetpools.append(subnetpool_dict)
        # Unfortunately, there is no relationship in the ORM between
        # a VRF and BridgeDomainin -- the BDs reference the VRF by name,
        # which doesn't include the ACI tenant. When the VRF lives in the
        # common tenant, the only way we can deduce the BDs belonging to
        # it is by eliminating all the BDs that are not in the common
        # tenant, and have a VRF with the same name in their tenant.
        vrf_subnets = []
        if as_result.rowcount == 0 or as_result.rowcount == -1:
            if network['vrf_tenant_name'] == md.COMMON_TENANT_NAME:
                all_vrfs_bds_query = (
                    "SELECT name, tenant_name FROM aim_bridge_domains "
                    "WHERE vrf_name = '" + network['vrf_name'] + "'")
                all_vrfs_bds_result = session.execute(all_vrfs_bds_query)
                all_vrfs_query = (
                    "SELECT tenant_name FROM aim_vrfs WHERE "
                    "name = '" + network['vrf_name'] + "'")
                all_vrfs_result = session.execute(all_vrfs_query)
                bd_tenants = set(
                            [x.tenant_name for x in all_vrfs_bds_result])
                vrf_tenants = set(
                            [x.tenant_name for x in all_vrfs_result
                             if x.tenant_name != md.COMMON_TENANT_NAME])
                valid_tenants = bd_tenants - vrf_tenants
                aim_bd_result = [x for x in all_vrfs_bds_result
                                 if x.tenant_name in valid_tenants]
            else:
                aim_bd_query = (
                    "SELECT name, tenant_name FROM aim_bridge_domains "
                    "WHERE vrf_name = '" + network['vrf_name'] + "'" +
                    " AND tenant_name = '" +
                    network['vrf_tenant_name'] + "'")
                aim_bd_result = session.execute(aim_bd_query)
            net_ids = self._get_net_ids_from_bds(session,
                                                 aim_bd_result)
            if net_ids:
                net_id_list = [str(r) for r in net_ids]
                in_str = self._compose_in_filter_str(net_id_list)
                vrf_subnet_query = ("SELECT cidr FROM subnets WHERE "
                                    "network_id in " + in_str)
                vrf_subnet_result = session.execute(vrf_subnet_query)
                vrf_subnets = [x['cidr'] for x in vrf_subnet_result]
        details['_cache']['address_scope'] = as_result
        details['_cache']['subnetpools'] = subnetpools
        details['_cache']['vrf_subnets'] = vrf_subnets

        # Get all the router interface ports that are on the same
        # subnets as the fixed IPs for the port resource. Then
        # use the router IDs from those ports to look for the
        # external networks connected to those routers
        router_ports_query = (
            "SELECT device_id FROM ports JOIN "
            "ipallocations AS ipallocations_1 ON "
            "ipallocations_1.port_id = ports.id WHERE "
            "device_owner = 'network:router_interface' AND "
            "ipallocations_1.subnet_id in " + subnet_in_str)
        router_ports_result = session.execute(router_ports_query)
        routers = [str(p.device_id) for p in router_ports_result]
        in_str = self._compose_in_filter_str(routers)
        ext_nets = []
        if routers:
            ext_net_query = (
                "SELECT externalnetworks.network_id as id, "
                "networks_1.project_id as tenant_id,"
                "net_map_1.epg_name, net_map_1.epg_tenant_name, "
                "net_map_1.epg_app_profile_name, net_ext_1.nat_type, "
                "net_ext_1.external_network_dn FROM "
                "externalnetworks JOIN networks AS networks_1 ON "
                "networks_1.id = externalnetworks.network_id JOIN "
                "apic_aim_network_mappings AS net_map_1 ON "
                "net_map_1.network_id = externalnetworks.network_id JOIN "
                "apic_aim_network_extensions AS net_ext_1 ON "
                "net_ext_1.network_id = externalnetworks.network_id JOIN "
                "ports AS ports_1 ON "
                "ports_1.network_id = externalnetworks.network_id JOIN "
                "routerports AS routerports_1 ON "
                "routerports_1.port_id = ports_1.id WHERE "
                "routerports_1.router_id in " + in_str)
            ext_nets = session.execute(ext_net_query)
            ext_nets = list(ext_nets)
        details['_cache']['ext_nets'] = ext_nets

        # For nested domain
        nested_allowed_vlans_query = (
            "SELECT vlan FROM "
            "apic_aim_network_nested_domain_allowed_vlans WHERE "
            "network_id = '" + network['id'] + "'")
        nested_allowed_vlans_result = session.execute(
                                            nested_allowed_vlans_query)
        network['apic:nested_domain_allowed_vlans'] = []
        for allowed_vlan in nested_allowed_vlans_result:
            network['apic:nested_domain_allowed_vlans'].append(
                                                    allowed_vlan.vlan)
        details['_cache']['network'] = network

    def _get_gbp_details_new(self, context, request, host):
        with context.session.begin(subtransactions=True):
            device = request.get('device')

            core_plugin = self._core_plugin
            port_id = core_plugin._device_to_port_id(context, device)
            port_query = ("SELECT project_id, id, name, network_id, "
                          "mac_address, admin_state_up, device_id, "
                          "device_owner, port_security_enabled, host, "
                          "vif_type, vif_details FROM "
                          "ports JOIN portsecuritybindings AS "
                          "portsecuritybindings_1 ON "
                          "ports.id = portsecuritybindings_1.port_id JOIN "
                          "ml2_port_bindings AS ml2_port_bindings_1 ON "
                          "ports.id = ml2_port_bindings_1.port_id "
                          "WHERE ports.id = '" + port_id + "'")
            port_result = context.session.execute(port_query)
            # in UT env., sqlite doesn't implement rowcount so the value
            # is always -1
            if port_result.rowcount != 1 and port_result.rowcount != -1:
                LOG.warning("Can't find the matching port DB record for "
                            "this port ID: %(port_id)s",
                            {'port_id': port_id})
                return {'device': request.get('device')}
            port = port_result.first()

            # Build up the ORM relationship manually
            port = dict(port)
            binding_level_query = ("SELECT segment_id FROM "
                                   "ml2_port_binding_levels WHERE "
                                   "port_id = '" + port_id + "' AND "
                                   "host = '" + port['host'] + "'")
            binding_levels = context.session.execute(binding_level_query)
            port['binding_levels'] = []
            for binding_level in binding_levels:
                port['binding_levels'].append(
                    {'segment_id': binding_level['segment_id']})

            ip_query = ("SELECT ip_address, subnet_id FROM "
                        "ipallocations WHERE "
                        "port_id = '" + port_id + "'")
            ip_result = context.session.execute(ip_query)
            port['fixed_ips'] = []
            for ip in ip_result:
                port['fixed_ips'].append(
                    {'ip_address': ip['ip_address'],
                     'subnet_id': ip['subnet_id']})

            sg_query = ("SELECT security_group_id FROM "
                        "securitygroupportbindings WHERE "
                        "port_id = '" + port_id + "'")
            sg_result = context.session.execute(sg_query)
            port['security_groups'] = []
            for sg in sg_result:
                port['security_groups'].append(sg.security_group_id)

            aap_query = ("SELECT mac_address, ip_address FROM "
                         "allowedaddresspairs WHERE "
                         "port_id = '" + port_id + "'")
            aap_result = context.session.execute(aap_query)
            port['allowed_address_pairs'] = []
            for aap in aap_result:
                port['allowed_address_pairs'].append(
                            {'ip_address': aap['ip_address'],
                             'mac_address': aap['mac_address']})

            dhcp_opt_query = ("SELECT opt_name, opt_value FROM "
                              "extradhcpopts WHERE "
                              "port_id = '" + port_id + "'")
            dhcp_opt_result = context.session.execute(dhcp_opt_query)
            port['extra_dhcp_opts'] = []
            for opt in dhcp_opt_result:
                port['extra_dhcp_opts'].append(
                            {'opt_name': opt['opt_name'],
                             'opt_value': opt['opt_value']})

            net_id = port['network_id']
            net_query = ("SELECT id, epg_name, epg_app_profile_name, "
                         "epg_tenant_name, vrf_name, vrf_tenant_name, "
                         "nested_domain_name as 'apic:nested_domain_name', "
                         "nested_domain_type as 'apic:nested_domain_type', "
                         "nested_domain_infra_vlan as "
                         "'apic:nested_domain_infra_vlan', "
                         "nested_domain_service_vlan as "
                         "'apic:nested_domain_service_vlan', "
                         "nested_domain_node_network_vlan as "
                         "'apic:nested_domain_node_network_vlan', "
                         "dns_domain, port_security_enabled FROM "
                         "apic_aim_network_mappings JOIN "
                         "networks AS net_1 ON net_1.id = "
                         "apic_aim_network_mappings.network_id JOIN "
                         "apic_aim_network_extensions AS net_ext_1 ON "
                         "net_ext_1.network_id = "
                         "apic_aim_network_mappings.network_id "
                         "LEFT OUTER JOIN networksecuritybindings AS "
                         "networksecuritybindings_1 ON net_ext_1.network_id "
                         "= networksecuritybindings_1.network_id "
                         "LEFT OUTER JOIN networkdnsdomains AS "
                         "networkdnsdomains_1 ON net_ext_1.network_id = "
                         "networkdnsdomains_1.network_id WHERE "
                         "apic_aim_network_mappings.network_id = '"
                         + net_id + "'")
            net_result = context.session.execute(net_query)
            if net_result.rowcount != 1 and net_result.rowcount != -1:
                LOG.warning("Can't find the matching network DB record for "
                            "this network ID: %(net_id)s",
                            {'net_id': net_id})
                return {'device': request.get('device')}
            net_record = net_result.first()
            network = dict(net_record)
            network['mtu'] = cfg.CONF.global_physnet_mtu

            # NOTE(ivar): removed the PROXY_PORT_PREFIX hack.
            # This was needed to support network services without hotplug.
            details = {'device': request.get('device'),
                       'enable_dhcp_optimization': self._is_dhcp_optimized(
                           context, port),
                       'enable_metadata_optimization': (
                           self._is_metadata_optimized(context, port)),
                       'port_id': port_id,
                       'mac_address': port['mac_address'],
                       'app_profile_name': network['epg_app_profile_name'],
                       'tenant_id': port['project_id'],
                       'host': port['host'],
                       # TODO(ivar): scope names, possibly through AIM or the
                       # name mapper
                       'ptg_tenant': network['epg_tenant_name'],
                       'endpoint_group_name': network['epg_name'],
                       # TODO(kentwu): make it to support GBP workflow also
                       'promiscuous_mode': self._is_port_promiscuous(
                                                context, port, is_gbp=False),
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

            details['_cache'] = {}
            self._build_up_details_cache(
                            context.session, details, port, network)
            mtu = self._get_port_mtu(context, port, details)
            if mtu:
                details['interface_mtu'] = mtu
            details['dns_domain'] = network['dns_domain']
            if port.get('security_groups'):
                self._add_security_group_details(context, port, details)
            # TODO(kentwu): make it to support GBP workflow if needed
            self._add_subnet_details(context, port, details, is_gbp=False)
            self._add_allowed_address_pairs_details(context, port, details)
            details['l3_policy_id'] = '%s %s' % (
                        network['vrf_tenant_name'], network['vrf_name'])
            self._add_vrf_details(context, details['l3_policy_id'], details)
            # Handle FIPs of owned addresses - find other ports in the
            # network whose address is owned by this port.
            # If those ports have FIPs, then steal them.
            fips_filter = [str(port_id)]
            active_addrs = [str(a['ip_address'])
                            for a in details['allowed_address_pairs']
                            if a.get('active')]
            if active_addrs:
                in_str = self._compose_in_filter_str(active_addrs)
                ports_query = (
                    "SELECT DISTINCT id FROM ports JOIN "
                    "ipallocations AS ipallocations_1 ON "
                    "ipallocations_1.port_id = ports.id WHERE "
                    "ports.network_id = '" + net_id + "' AND "
                    "ipallocations_1.ip_address in " + in_str)
                ports_result = context.session.execute(ports_query)
                fips_filter.extend([str(p['id']) for p in ports_result])
            in_str = self._compose_in_filter_str(fips_filter)
            fips_query = (
                "SELECT id, project_id, fixed_ip_address, "
                "floating_ip_address, floating_network_id, "
                "fixed_port_id as port_id FROM floatingips WHERE "
                "floatingips.fixed_port_id in " + in_str)
            fips_result = context.session.execute(fips_query)
            fips = []
            for fip in fips_result:
                fip_dict = dict(fip)
                fips.append(fip_dict)
            details['_cache']['fips'] = fips
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            # TODO(kentwu): make it to support GBP workflow also
            self._add_segmentation_label_details(context, port, details,
                                                 is_gbp=False)
            self._set_dhcp_lease_time(details)
            self._add_nested_domain_details(context, port, details)
            details.pop('_cache', None)

            # Get the neutron_details
            segments_query = (
                "SELECT id, network_type, physical_network FROM "
                "networksegments WHERE "
                "network_id = '" + net_id + "'")
            segments = context.session.execute(segments_query)
            bottom_segment = {}
            if port['binding_levels']:
                for segment in segments:
                    bottom_segment = dict(segment)
                    if (segment['id'] ==
                            port['binding_levels'][-1]['segment_id']):
                        break
            neutron_details = {'admin_state_up': port['admin_state_up'],
                               'device_owner': port['device_owner'],
                               'fixed_ips': port['fixed_ips'],
                               'network_id': net_id,
                               'port_id': port_id,
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

        if 'security_groups' in details['_cache']:
            port_sgs = details['_cache']['security_groups']
        else:
            port_sgs = (context.session.query(sg_models.SecurityGroup.id,
                                        sg_models.SecurityGroup.tenant_id).
                        filter(sg_models.SecurityGroup.id.
                               in_(port['security_groups'])).
                        all())
        previous_sg_id = None
        previous_tenant_id = None
        for sg_id, tenant_id in port_sgs:
            # This is to work around an UT sqlite bug that duplicate SG
            # entries will be returned somehow if we query it with a SELECT
            # statement directly
            if sg_id == previous_sg_id and tenant_id == previous_tenant_id:
                continue
            tenant_aname = self.aim_mech_driver.name_mapper.project(
                context.session, tenant_id)
            details['security_group'].append(
                {'policy-space': tenant_aname,
                 'name': sg_id})
            previous_sg_id = sg_id
            previous_tenant_id = tenant_id
        # Always include this SG which has the default arp & dhcp rules
        details['security_group'].append(
            {'policy-space': 'common',
             'name': self.aim_mech_driver._default_sg_name})

    # Child class needs to support:
    # - self._get_subnet_details(context, port, details)
    def _add_subnet_details(self, context, port, details, is_gbp=True):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - subnets;
        details['subnets'] = self._get_subnet_details(context, port, details,
                                                      is_gbp)

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
                    self._get_nested_domain(context, port, details))

    # Child class needs to support:
    # - self._get_segmentation_labels(context, port, details)
    def _add_segmentation_label_details(self, context, port, details,
                                        is_gbp=True):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - segmentation_labels
        # apic_segmentation_label is a GBP driver extension configured
        # for the aim_mapping driver
        if is_gbp:
            details['segmentation_labels'] = self._get_segmentation_labels(
                context, port, details)

    def _add_extra_details(self, context, port, details):
        # TODO(ivar): Extra details depend on HA and SC implementation
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill per-mac address extra information.

        # What is an "End of the Chain" port for Neutron?
        pass
