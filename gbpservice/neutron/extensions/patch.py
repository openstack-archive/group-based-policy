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

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


# Monkey patch create floatingip to allow subnet_id to be specified.
# this will only be valid for internal calls, and can't be exploited from the
# API.
def create_floatingip(
        self, context, floatingip,
        initial_status=l3_db.l3_constants.FLOATINGIP_STATUS_ACTIVE):
    fip = floatingip['floatingip']
    tenant_id = self._get_tenant_id_for_create(context, fip)
    fip_id = l3_db.uuidutils.generate_uuid()

    f_net_id = fip['floating_network_id']
    if not self._core_plugin._network_is_external(context, f_net_id):
        msg = _("Network %s is not a valid external network") % f_net_id
        raise l3_db.n_exc.BadRequest(resource='floatingip', msg=msg)

    with context.session.begin(subtransactions=True):
        # This external port is never exposed to the tenant.
        # it is used purely for internal system and admin use when
        # managing floating IPs.

        port = {'tenant_id': '',  # tenant intentionally not set
                'network_id': f_net_id,
                'mac_address': l3_db.attributes.ATTR_NOT_SPECIFIED,
                'fixed_ips': l3_db.attributes.ATTR_NOT_SPECIFIED,
                'admin_state_up': True,
                'device_id': fip_id,
                'device_owner': l3_db.DEVICE_OWNER_FLOATINGIP,
                'name': ''}

        if fip.get('floating_ip_address'):
            port['fixed_ips'] = [{'ip_address': fip['floating_ip_address']}]
        if fip.get('subnet_id'):
            port['fixed_ips'] = [{'subnet_id': fip['subnet_id']}]

        external_port = self._core_plugin.create_port(context.elevated(),
                                                      {'port': port})

        # Ensure IP addresses are allocated on external port
        if not external_port['fixed_ips']:
            raise l3_db.n_exc.ExternalIpAddressExhausted(net_id=f_net_id)

        floating_fixed_ip = external_port['fixed_ips'][0]
        floating_ip_address = floating_fixed_ip['ip_address']
        floatingip_db = l3_db.FloatingIP(
            id=fip_id,
            tenant_id=tenant_id,
            status=initial_status,
            floating_network_id=fip['floating_network_id'],
            floating_ip_address=floating_ip_address,
            floating_port_id=external_port['id'])
        fip['tenant_id'] = tenant_id
        # Update association with internal port
        # and define external IP address
        self._update_fip_assoc(context, fip,
                               floatingip_db, external_port)
        context.session.add(floatingip_db)

    return self._make_floatingip_dict(floatingip_db)

l3_db.L3_NAT_dbonly_mixin.create_floatingip = create_floatingip


# Monkey patch updating router-gateway to use specified external fixed IP.
def _create_router_gw_port(self, context, router, network_id, ext_ips):
    if ext_ips and len(ext_ips) > 1:
        msg = _("Routers support only 1 external IP")
        raise n_exc.BadRequest(resource='router', msg=msg)
    # Port has no 'tenant-id', as it is hidden from user
    gw_port = self._core_plugin.create_port(context.elevated(), {
        'port': {'tenant_id': '',  # intentionally not set
                 'network_id': network_id,
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': ext_ips or attributes.ATTR_NOT_SPECIFIED,
                 'device_id': router['id'],
                 'device_owner': l3_db.DEVICE_OWNER_ROUTER_GW,
                 'admin_state_up': True,
                 'name': ''}})

    if not gw_port['fixed_ips']:
        self._core_plugin.delete_port(context.elevated(), gw_port['id'],
                                      l3_port_check=False)
        msg = (_('No IPs available for external network %s') %
               network_id)
        raise n_exc.BadRequest(resource='router', msg=msg)

    with context.session.begin(subtransactions=True):
        router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                     gw_port['id'])
        router_port = l3_db.RouterPort(
            router_id=router.id,
            port_id=gw_port['id'],
            port_type=l3_db.DEVICE_OWNER_ROUTER_GW
        )
        context.session.add(router)
        context.session.add(router_port)


def _validate_gw_info(self, context, gw_port, info, ext_ips):
    network_id = info['network_id'] if info else None
    if network_id:
        network_db = self._core_plugin._get_network(context, network_id)
        if not network_db.external:
            msg = _("Network %s is not an external network") % network_id
            raise n_exc.BadRequest(resource='router', msg=msg)
        if ext_ips:
            subnets = self._core_plugin._get_subnets_by_network(context,
                                                                network_id)
            for s in subnets:
                if not s['gateway_ip']:
                    continue
                for ext_ip in ext_ips:
                    if ext_ip.get('ip_address') == s['gateway_ip']:
                        msg = _("External IP %s is the same as the "
                                "gateway IP") % ext_ip.get('ip_address')
                        raise n_exc.BadRequest(resource='router', msg=msg)
    return network_id


def _create_gw_port_l3(self, context, router_id, router, new_network,
                       ext_ips, ext_ip_change):
    new_valid_gw_port_attachment = (
        new_network and (not router.gw_port or ext_ip_change or
                         router.gw_port['network_id'] != new_network))
    if new_valid_gw_port_attachment:
        subnets = self._core_plugin._get_subnets_by_network(context,
                                                            new_network)
        for subnet in subnets:
            self._check_for_dup_router_subnet(context, router,
                                              new_network, subnet['id'],
                                              subnet['cidr'])
        self._create_router_gw_port(context, router, new_network, ext_ips)


def _create_gw_port_l3_dvr(self, context, router_id, router, new_network,
                           ext_ips, ext_ip_change):
    super(l3_dvr_db.L3_NAT_with_dvr_db_mixin,
          self)._create_gw_port(context, router_id,
                                router, new_network, ext_ips, ext_ip_change)
    if router.extra_attributes.distributed and router.gw_port:
        snat_p_list = self.create_snat_intf_ports_if_not_exists(
            context.elevated(), router)
        if not snat_p_list:
            LOG.debug("SNAT interface ports not created: %s", snat_p_list)


def _update_router_gw_info(self, context, router_id, info, router=None):
    router = router or self._get_router(context, router_id)
    gw_port = router.gw_port
    ext_ips = info.get('external_fixed_ips') if info else []
    ext_ip_change = self._check_for_external_ip_change(
        context, gw_port, ext_ips)
    network_id = self._validate_gw_info(context, gw_port, info, ext_ips)
    if (gw_port and (gw_port['network_id'] != network_id or ext_ip_change)):
        self._delete_current_gw_port(context, router_id, router, network_id)
    self._create_gw_port(context, router_id, router, network_id,
                         ext_ips, ext_ip_change)


def _check_for_external_ip_change(self, context, gw_port, ext_ips):
    # determine if new external IPs differ from the existing fixed_ips
    if not ext_ips:
        # no external_fixed_ips were included
        return False
    if not gw_port:
        return True

    subnet_ids = set(ip['subnet_id'] for ip in gw_port['fixed_ips'])
    new_subnet_ids = set(f['subnet_id'] for f in ext_ips
                         if f.get('subnet_id'))
    subnet_change = not new_subnet_ids == subnet_ids
    if subnet_change:
        return True
    ip_addresses = set(ip['ip_address'] for ip in gw_port['fixed_ips'])
    new_ip_addresses = set(f['ip_address'] for f in ext_ips
                           if f.get('ip_address'))
    ip_address_change = not ip_addresses == new_ip_addresses
    return ip_address_change


l3_db.L3_NAT_dbonly_mixin._create_gw_port = _create_gw_port_l3
l3_dvr_db.L3_NAT_with_dvr_db_mixin._create_gw_port = _create_gw_port_l3_dvr
l3_db.L3_NAT_dbonly_mixin._create_router_gw_port = _create_router_gw_port
l3_db.L3_NAT_dbonly_mixin._validate_gw_info = _validate_gw_info
l3_db.L3_NAT_dbonly_mixin._update_router_gw_info = _update_router_gw_info
l3_db.L3_NAT_dbonly_mixin._check_for_external_ip_change = (
    _check_for_external_ip_change)


# REVISIT(ivar): Monkey patch to allow explicit router_id to be set in Neutron
# for Floating Ip creation (for internal calls only). Once we split the server,
# this could be part of a GBP Neutron L3 driver.
def get_assoc_data(self, context, fip, floating_network_id):
    (internal_port, internal_subnet_id,
     internal_ip_address) = self._internal_fip_assoc_data(context, fip)
    if fip.get('router_id'):
        router_id = fip['router_id']
        del fip['router_id']
    else:
        router_id = self._get_router_for_floatingip(context,
                                                    internal_port,
                                                    internal_subnet_id,
                                                    floating_network_id)

    return fip['port_id'], internal_ip_address, router_id


l3_db.L3_NAT_dbonly_mixin.get_assoc_data = get_assoc_data


# REVISIT(ivar): Neutron adds a tenant filter on SG lookup for a given port,
# this breaks our service chain plumbing model so for now we should monkey
# patch the specific method. A follow up with the Neutron team is needed to
# figure out the reason for this and how to proceed for future releases.
def _get_security_groups_on_port(self, context, port):
    """Check that all security groups on port belong to tenant.

    :returns: all security groups IDs on port belonging to tenant.
    """
    p = port['port']
    if not attributes.is_attr_set(p.get(ext_sg.SECURITYGROUPS)):
        return
    if p.get('device_owner') and p['device_owner'].startswith('network:'):
        return

    port_sg = p.get(ext_sg.SECURITYGROUPS, [])
    filters = {'id': port_sg}
    valid_groups = set(g['id'] for g in
                       self.get_security_groups(context, fields=['id'],
                                                filters=filters))

    requested_groups = set(port_sg)
    port_sg_missing = requested_groups - valid_groups
    if port_sg_missing:
        raise ext_sg.SecurityGroupNotFound(id=str(port_sg_missing[0]))

    return requested_groups

securitygroups_db.SecurityGroupDbMixin._get_security_groups_on_port = (
    _get_security_groups_on_port)


def _delete_floatingip(self, context, id):
    floatingip = self._get_floatingip(context, id)
    router_id = floatingip['router_id']
    context.session.delete(floatingip)
    self._core_plugin.delete_port(context.elevated(),
                                  floatingip['floating_port_id'],
                                  l3_port_check=False)
    return router_id


l3_db.L3_NAT_dbonly_mixin._delete_floatingip = _delete_floatingip
