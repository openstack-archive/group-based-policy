from neutron.api.v2 import attributes as attr

from neutron import context as neutron_context
from neutron.common import constants as l3_constants
from neutron import manager
#from neutron.common import common as n_topics
from neutron.common import exceptions as n_exc
from neutron.db import models_v2
from neutron.db import l3_db
from neutron.db.l3_db import (
        RouterPort, EXTERNAL_GW_INFO, DEVICE_OWNER_ROUTER_INTF)
from neutron.plugins.common import constants as n_const
import netaddr
from oslo_config import cfg
from oslo_utils import uuidutils
from sqlalchemy import orm

from gbpservice.nfp.config_orchestrator.common import topics
import neutron_fwaas.extensions
from neutron_fwaas.services.firewall import fwaas_plugin as ref_fw_plugin

from neutron_fwaas.db.firewall import (
        firewall_router_insertion_db as ref_fw_router_ins_db)
from neutron_fwaas.db.firewall import firewall_db as n_firewall


class NFPFirewallPlugin(ref_fw_plugin.FirewallPlugin):
    def __init__(self):
        # Monkey patch L3 agent topic
        # L3 agent was where reference firewall agent runs
        # patch that topic to the NFP firewall agent's topic name
        ref_fw_plugin.f_const.L3_AGENT = topics.FW_NFP_CONFIGAGENT_TOPIC
        #n_topics.L3_AGENT = topics.FW_NFP_CONFIGAGENT_TOPIC

        # Ensure neutron fwaas extensions are loaded
        ext_path = neutron_fwaas.extensions.__path__[0]
        if ext_path not in cfg.CONF.api_extensions_path.split(':'):
            cfg.CONF.set_override(
                'api_extensions_path',
                cfg.CONF.api_extensions_path + ':' + ext_path)

        super(NFPFirewallPlugin, self).__init__()

    # Modifying following plugin function, to relax same router validation
    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):

        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            return tenant_id

    def set_routers_for_firewall(self, context, fw):
        """Sets the routers associated with the fw."""
        pass

    def get_firewall_routers(self, context, fwid):
        """Gets all routers associated with a firewall."""
        fw_rtrs = ['1234567890']
        return fw_rtrs

    def validate_firewall_routers_not_in_use(
            self, context, router_ids, fwid=None):
        """Validate if router-ids not associated with any firewall.

        If any of the router-ids in the list is already associated with
        a firewall, raise an exception else just return.
        """
        pass

    def update_firewall_routers(self, context, fw):
        """Update the firewall with new routers.

        This involves removing existing router associations and replacing
        it with the new router associations provided in the update method.
        """
        return fw


# Monkey patching l3_db's _get_router_for_floatingip method to associate
# floatingip if corresponding routes is present.

def _is_net_reachable_from_net(self, context, tenant_id, from_net_id,
                               to_net_id):
    """Check whether a network is reachable.

    Follow the paths of networks connected by devices, to determine
    whether a network is reachable from another.
    @param context: neutron api request context
    @param tenant_id: the owning tenant
    @param from_net_id: the source network for the search
    @param to_net_id: the destination network for the search
    @return: True or False whether a path exists
    """
    def nexthop_nets_query(nets, visited):
        """query networks connected to devices on nets but not visited."""
        Port = models_v2.Port
        devices_on_nets = context.session.query(Port.device_id).filter(
            Port.tenant_id == tenant_id,
            Port.device_owner.notin_([l3_constants.DEVICE_OWNER_DHCP]),
            Port.network_id.in_(nets)).subquery()
        return context.session.query(Port.network_id).filter(
            Port.tenant_id == tenant_id,
            Port.network_id.notin_(visited),
            Port.device_id.in_(devices_on_nets))
    visited = set([])
    nets = set([from_net_id])
    while nets:
        if to_net_id in nets:
            return True
        visited |= nets
        nets = set((tup[0] for tup in nexthop_nets_query(nets, visited)))
    return False

def _find_net_for_nexthop(self, context, tenant_id, router_id, nexthop):
    """Find the network to which the nexthop belongs.

    Iterate over the router interfaces to find the network of nexthop.
    @param context: neutron api request context
    @param tenant_id: the owning tenant
    @param router_id: a router id
    @param nexthop: an IP address
    @return: the network id of the nexthop or None if not found
    """
    interfaces = context.session.query(models_v2.Port).filter_by(
        # tenant_id=tenant_id,
        device_id=router_id,
        device_owner=DEVICE_OWNER_ROUTER_INTF)
    for interface in interfaces:
        cidrs = [self._core_plugin._get_subnet(context,
                                               ip['subnet_id'])['cidr']
                 for ip in interface['fixed_ips']]
        if netaddr.all_matching_cidrs(nexthop, cidrs):
            return interface['network_id']

def _find_routers_via_routes_for_floatingip(self, context, internal_port,
                                            internal_subnet_id,
                                            external_network_id):
    """Find routers with route to the internal IP address.

    Iterate over the routers that belong to the same tenant as
    'internal_port'. For each router check that the router is connected
    to the external network and whether there is a route to the internal
    IP address. Consider only routers for which there is a path from the
    nexthop of the route to the internal port.

    Sort the list of routers to have the router with the most specific
    route first (largest CIDR prefix mask length).

    @param context: neutron api request context
    @param internal_port: the port dict for the association
    @param internal_subnet_id: the subnet for the association
    @param external_network_id: the network of the floatingip
    @return: a sorted list of matching routers
    """
    internal_ip_address = [
        ip['ip_address'] for ip in internal_port['fixed_ips']
        if ip['subnet_id'] == internal_subnet_id
    ][0]

    # find the tenant routers
    tenant_id = internal_port['tenant_id']
    routers = self.get_routers(context, filters={'tenant_id': [tenant_id]})

    prefix_routers = []
    for router in routers:
        # verify that the router is on "external_network"
        gw_info = router.get(EXTERNAL_GW_INFO)
        if not gw_info or gw_info['network_id'] != external_network_id:
            continue
        # find a matching route 
        if 'routes' not in router:
            continue
        cidr_nexthops = {}
        for route in router['routes']:
            cidr = netaddr.IPNetwork(route['destination'])
            if cidr not in cidr_nexthops:
                cidr_nexthops[cidr] = []
            cidr_nexthops[cidr].append(route['nexthop'])
        smallest_cidr = netaddr.smallest_matching_cidr(
            internal_ip_address,
            cidr_nexthops.keys())
        if not smallest_cidr:
            continue
        # validate that there exists a path to "internal_port"
        for nexthop in cidr_nexthops[smallest_cidr]:
            net_id = self._find_net_for_nexthop(context, tenant_id,
                                                router['id'], nexthop)
            if net_id and self._is_net_reachable_from_net(
                    context,
                    tenant_id,
                    net_id,
                    internal_port['network_id']):
                prefix_routers.append(
                    (smallest_cidr.prefixlen, router['id']))
                break


    return [p_r[1] for p_r in sorted(prefix_routers, reverse=True)]


def _get_router_for_floatingip(self, context, internal_port,
                               internal_subnet_id,
                               external_network_id):
    subnet = self._core_plugin.get_subnet(context, internal_subnet_id)
    if not subnet['gateway_ip']:
        msg = (_('Cannot add floating IP to port on subnet %s '
                 'which has no gateway_ip') % internal_subnet_id)
        raise n_exc.BadRequest(resource='floatingip', msg=msg)

    # Find routers(with router_id and interface address) that
    # connect given internal subnet and the external network.
    # Among them, if the router's interface address matches
    # with subnet's gateway-ip, return that router.
    # Otherwise return the first router.
    gw_port = orm.aliased(models_v2.Port, name="gw_port")
    routerport_qry = context.session.query(
        RouterPort.router_id, models_v2.IPAllocation.ip_address).join(
        models_v2.Port, models_v2.IPAllocation).filter(
        models_v2.Port.network_id == internal_port['network_id'],
        RouterPort.port_type.in_(l3_constants.ROUTER_INTERFACE_OWNERS),
        models_v2.IPAllocation.subnet_id == internal_subnet_id
    ).join(gw_port, gw_port.device_id == RouterPort.router_id).filter(
        gw_port.network_id == external_network_id).distinct()

    first_router_id = None
    for router_id, interface_ip in routerport_qry:
        if interface_ip == subnet['gateway_ip']:
            return router_id
        if not first_router_id:
            first_router_id = router_id
    if first_router_id:
        return first_router_id

    router_ids = self._find_routers_via_routes_for_floatingip(
        context,
        internal_port,
        internal_subnet_id,
        external_network_id)
    if router_ids:
        return router_ids[0]

    raise l3.ExternalGatewayForFloatingIPNotFound(
        subnet_id=internal_subnet_id,
        external_network_id=external_network_id,
        port_id=internal_port['id'])


l3_db.L3_NAT_dbonly_mixin._get_router_for_floatingip = (
        _get_router_for_floatingip)
l3_db.L3_NAT_dbonly_mixin._find_routers_via_routes_for_floatingip = (
        _find_routers_via_routes_for_floatingip)
l3_db.L3_NAT_dbonly_mixin._find_net_for_nexthop = _find_net_for_nexthop
l3_db.L3_NAT_dbonly_mixin._is_net_reachable_from_net = (
        _is_net_reachable_from_net)
