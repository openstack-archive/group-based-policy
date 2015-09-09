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

from neutron.db import l3_db


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
                'status': l3_db.l3_constants.PORT_STATUS_NOTAPPLICABLE,
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
