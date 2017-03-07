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
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.plugins.ml2 import db as ml2_db
from neutron.tests import tools
from neutron_lib import constants
from oslo_log import log
from sqlalchemy import event
import warnings


LOG = log.getLogger(__name__)


# Remove the following once confirmed that the UTs pass without monkey-patch,
# and also remove the commented imports
# Monkey patch create floatingip to allow subnet_id to be specified.
# this will only be valid for internal calls, and can't be exploited from the
# API.
"""
def create_floatingip(
        self, context, floatingip,
        initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
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
                'status': constants.PORT_STATUS_NOTAPPLICABLE,
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
"""


# REVISIT(ivar): Monkey patch to allow explicit router_id to be set in Neutron
# for Floating Ip creation (for internal calls only). Once we split the server,
# this could be part of a GBP Neutron L3 driver.
def _get_assoc_data(self, context, fip, floatingip_db):
    (internal_port, internal_subnet_id,
     internal_ip_address) = self._internal_fip_assoc_data(
         context, fip, floatingip_db['tenant_id'])
    if fip.get('router_id'):
        router_id = fip['router_id']
        del fip['router_id']
    else:
        router_id = self._get_router_for_floatingip(
            context, internal_port, internal_subnet_id,
            floatingip_db['floating_network_id'])

    return fip['port_id'], internal_ip_address, router_id


l3_db.L3_NAT_dbonly_mixin._get_assoc_data = _get_assoc_data


def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
    previous_router_id = floatingip_db.router_id
    port_id, internal_ip_address, router_id = (
        self._check_and_get_fip_assoc(context, fip, floatingip_db))
    floatingip_db.update({'fixed_ip_address': internal_ip_address,
                          'fixed_port_id': port_id,
                          'router_id': router_id,
                          'last_known_router_id': previous_router_id})
    next_hop = None
    if router_id:
        router = self._get_router(context.elevated(), router_id)
        gw_port = router.gw_port
        if gw_port:
            for fixed_ip in gw_port.fixed_ips:
                addr = netaddr.IPAddress(fixed_ip.ip_address)
                if addr.version == constants.IP_VERSION_4:
                    next_hop = fixed_ip.ip_address
                    break
    args = {'fixed_ip_address': internal_ip_address,
            'fixed_port_id': port_id,
            'router_id': router_id,
            'last_known_router_id': previous_router_id,
            'floating_ip_address': floatingip_db.floating_ip_address,
            'floating_network_id': floatingip_db.floating_network_id,
            'next_hop': next_hop,
            'context': context}
    registry.notify(resources.FLOATING_IP,
                    events.AFTER_UPDATE,
                    self._update_fip_assoc,
                    **args)

l3_db.L3_NAT_dbonly_mixin._update_fip_assoc = _update_fip_assoc


# REVISIT(ivar): Neutron adds a tenant filter on SG lookup for a given port,
# this breaks our service chain plumbing model so for now we should monkey
# patch the specific method. A follow up with the Neutron team is needed to
# figure out the reason for this and how to proceed for future releases.
def _get_security_groups_on_port(self, context, port):
    """Check that all security groups on port belong to tenant.

    :returns: all security groups IDs on port belonging to tenant.
    """
    p = port['port']
    if not securitygroups_db.attributes.is_attr_set(
            p.get(securitygroups_db.ext_sg.SECURITYGROUPS)):
        return
    if p.get('device_owner') and p['device_owner'].startswith('network:'):
        return

    port_sg = p.get(securitygroups_db.ext_sg.SECURITYGROUPS, [])
    filters = {'id': port_sg}
    valid_groups = set(g['id'] for g in
                       self.get_security_groups(context, fields=['id'],
                                                filters=filters))

    requested_groups = set(port_sg)
    port_sg_missing = requested_groups - valid_groups
    if port_sg_missing:
        raise securitygroups_db.ext_sg.SecurityGroupNotFound(
            id=', '.join(port_sg_missing))

    return requested_groups

securitygroups_db.SecurityGroupDbMixin._get_security_groups_on_port = (
    _get_security_groups_on_port)


def get_port_from_device_mac(context, device_mac):
    LOG.debug("get_port_from_device_mac() called for mac %s", device_mac)
    qry = context.session.query(models_v2.Port).filter_by(
        mac_address=device_mac).order_by(models_v2.Port.device_owner.desc())
    return qry.first()

ml2_db.get_port_from_device_mac = get_port_from_device_mac

PUSH_NOTIFICATIONS_METHOD = None
DISCARD_NOTIFICATIONS_METHOD = None


def get_session(autocommit=True, expire_on_commit=False, use_slave=False):
    # The folowing are declared as global so that they can
    # used in the inner functions that follow.
    global PUSH_NOTIFICATIONS_METHOD
    global DISCARD_NOTIFICATIONS_METHOD
    from gbpservice.network.neutronv2 import local_api
    PUSH_NOTIFICATIONS_METHOD = (
        local_api.post_notifications_from_queue)
    DISCARD_NOTIFICATIONS_METHOD = (
        local_api.discard_notifications_after_rollback)

    # The following two lines are copied from the original
    # implementation of db_api.get_session() and should be updated
    # if the original implementation changes.
    new_session = db_api.context_manager.get_legacy_facade().get_session(
        autocommit=autocommit, expire_on_commit=expire_on_commit,
        use_slave=use_slave)

    new_session.notification_queue = {}

    def gbp_after_transaction(session, transaction):
        if transaction and not transaction._parent and (
            not transaction.is_active and not transaction.nested):
            if transaction in session.notification_queue:
                # push the queued notifications only when the
                # outermost transaction completes
                PUSH_NOTIFICATIONS_METHOD(session, transaction)

    def gbp_after_rollback(session):
        # We discard all queued notifiactions if the transaction fails.
        DISCARD_NOTIFICATIONS_METHOD(session)

    if local_api.BATCH_NOTIFICATIONS:
        event.listen(new_session, "after_transaction_end",
                     gbp_after_transaction)
        event.listen(new_session, "after_rollback",
                     gbp_after_rollback)

    return new_session


db_api.get_session = get_session


def _get_tenant_id_for_create(self, context, resource):
    if context.is_admin and 'tenant_id' in resource:
        tenant_id = resource['tenant_id']
    elif ('tenant_id' in resource and
          resource['tenant_id'] != context.project_id):
        reason = _('Cannot create resource for another tenant')
        raise n_exc.AdminRequired(reason=reason)
    else:
        tenant_id = context.project_id

    return tenant_id


common_db_mixin.CommonDbMixin._get_tenant_id_for_create = (
    _get_tenant_id_for_create)


# If the following commit is backported to Neutron stable/netwon
# https://github.com/openstack/neutron/commit/
# afab7c67011fad40fec87749679137d31aa20540
# then this patch can be removed.
def _setUpWarningsFixtureWarnOnce(self):
    self.addCleanup(warnings.resetwarnings)
    for wtype in self.warning_types:
        warnings.filterwarnings("once", category=wtype,
                                module='^neutron\\.')


tools.WarningsFixture. _setUp = _setUpWarningsFixtureWarnOnce
