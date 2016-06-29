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

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as keyclient

from neutron.api.v2 import attributes as attr
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import topics as n_topics
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.plugins.common import constants as n_const

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import uuidutils

from gbpservice.common import utils
from gbpservice.contrib.nfp.config_orchestrator.common import topics
from gbpservice.nfp.core import log as nfp_logging
import neutron_fwaas.extensions
from neutron_fwaas.services.firewall import fwaas_plugin as ref_fw_plugin

from neutron_fwaas.db.firewall import firewall_db as n_firewall

LOG = nfp_logging.getLogger(__name__)


class NFPFirewallPlugin(ref_fw_plugin.FirewallPlugin):
    def __init__(self):
        # Monkey patch L3 agent topic
        # L3 agent was where reference firewall agent runs
        # patch that topic to the NFP firewall agent's topic name
        #ref_fw_plugin.f_const.L3_AGENT = topics.FW_NFP_CONFIGAGENT_TOPIC
        n_topics.L3_AGENT = topics.FW_NFP_CONFIGAGENT_TOPIC

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


# Monkey patching the create_firewall db method
def create_firewall(self, context, firewall, status=None):
    fw = firewall['firewall']
    tenant_id = fw['tenant_id']
    # distributed routers may required a more complex state machine;
    # the introduction of a new 'CREATED' state allows this, whilst
    # keeping a backward compatible behavior of the logical resource.
    if not status:
        status = n_const.PENDING_CREATE
    with context.session.begin(subtransactions=True):
        self._validate_fw_parameters(context, fw, tenant_id)
        firewall_db = n_firewall.Firewall(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=fw['name'],
                description=fw['description'],
                firewall_policy_id=fw['firewall_policy_id'],
                admin_state_up=fw['admin_state_up'],
                status=status)
        context.session.add(firewall_db)
    return self._make_firewall_dict(firewall_db)

n_firewall.Firewall_db_mixin.create_firewall = create_firewall

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
    original_context = context
    context = elevate_context(context)
    tenant_id = context.tenant_id

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
            context = original_context
            return True
        visited |= nets
        nets = set((tup[0] for tup in nexthop_nets_query(nets, visited)))
    context = original_context
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
        tenant_id=tenant_id,
        device_id=router_id,
        device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF)
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
    original_context = context
    context = elevate_context(context)
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
        gw_info = router.get(l3_db.EXTERNAL_GW_INFO)
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
            net_id = self._find_net_for_nexthop(context, context.tenant_id,
                                                router['id'], nexthop)
            if net_id and self._is_net_reachable_from_net(
                    context,
                    context.tenant_id,
                    net_id,
                    internal_port['network_id']):
                prefix_routers.append(
                    (smallest_cidr.prefixlen, router['id']))
                break
    context = original_context
    return [p_r[1] for p_r in sorted(prefix_routers, reverse=True)]


def elevate_context(context):
    context = context.elevated()
    context.tenant_id = _resource_owner_tenant_id()
    return context


def _resource_owner_tenant_id():
    user, pwd, tenant, auth_url = utils.get_keystone_creds()
    keystoneclient = keyclient.Client(username=user, password=pwd,
                                      auth_url=auth_url)
    try:
        tenant = keystoneclient.tenants.find(name=tenant)
        return tenant.id
    except k_exceptions.NotFound:
        with excutils.save_and_reraise_exception(reraise=True):
            LOG.error(_('No tenant with name %s exists.'), tenant)
    except k_exceptions.NoUniqueMatch:
        with excutils.save_and_reraise_exception(reraise=True):
            LOG.error(_('Multiple tenants matches found for %s'),
                      tenant)


def _get_router_for_floatingip(self, context, internal_port,
                               internal_subnet_id,
                               external_network_id):
    subnet = self._core_plugin.get_subnet(context, internal_subnet_id)

    if not subnet['gateway_ip']:
        msg = (_('Cannot add floating IP to port on subnet %s '
                 'which has no gateway_ip') % internal_subnet_id)
        raise n_exc.BadRequest(resource='floatingip', msg=msg)

    router_intf_ports = self._get_interface_ports_for_network(
        context, internal_port['network_id'])

    # This joins on port_id so is not a cross-join
    routerport_qry = router_intf_ports.join(models_v2.IPAllocation)
    routerport_qry = routerport_qry.filter(
        models_v2.IPAllocation.subnet_id == internal_subnet_id
    )

    for router_port in routerport_qry:
        router_id = router_port.router.id
        router_gw_qry = context.session.query(models_v2.Port)
        has_gw_port = router_gw_qry.filter_by(
            network_id=external_network_id,
            device_id=router_id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_GW).count()
        if has_gw_port:
            return router_id

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
