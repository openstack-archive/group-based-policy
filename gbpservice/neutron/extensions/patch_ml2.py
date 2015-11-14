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

import contextlib

from neutron.common import exceptions as exc
from neutron.common import ipv6_utils
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.openstack.common import excutils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import plugin
from oslo.db import exception as os_db_exception
from sqlalchemy import exc as sql_exc

LOG = log.getLogger(__name__)


class InfiniteLoopError(exc.NeutronException):
    """Potentially infinite loop detected."""
    message = _("Too many retries occured.")


# REVISIT(rkukura): Partially address bug 1510327 (GBP: Deleting
# groups leads to subnet-delete in infinite loop) by limiting the
# retry loop and doing additional info-level logging. This is based on
# the stable/juno version of neutron.plugins.ml2.plugin.Ml2Plugin.
def delete_network(self, context, id):
    # REVISIT(rkukura) The super(Ml2Plugin, self).delete_network()
    # function is not used because it auto-deletes ports and
    # subnets from the DB without invoking the derived class's
    # delete_port() or delete_subnet(), preventing mechanism
    # drivers from being called. This approach should be revisited
    # when the API layer is reworked during icehouse.

    LOG.debug(_("Deleting network %s"), id)
    session = context.session
    attempt = 0
    while True:
        attempt += 1
        LOG.info(_("Attempt %(attempt)s to delete network %(net)s"),
                 {'attempt': attempt, 'net': id})
        if attempt > 100:
            raise InfiniteLoopError()
        try:
            # REVISIT: Serialize this operation with a semaphore
            # to prevent deadlock waiting to acquire a DB lock
            # held by another thread in the same process, leading
            # to 'lock wait timeout' errors.
            #
            # Process L3 first, since, depending on the L3 plugin, it may
            # involve locking the db-access semaphore, sending RPC
            # notifications, and/or calling delete_port on this plugin.
            # Additionally, a rollback may not be enough to undo the
            # deletion of a floating IP with certain L3 backends.
            self._process_l3_delete(context, id)
            # Using query().with_lockmode isn't necessary. Foreign-key
            # constraints prevent deletion if concurrent creation happens.
            with contextlib.nested(lockutils.lock('db-access'),
                                   session.begin(subtransactions=True)):
                # Get ports to auto-delete.
                ports = (session.query(models_v2.Port).
                         enable_eagerloads(False).
                         filter_by(network_id=id).all())
                LOG.debug(_("Ports to auto-delete: %s"), ports)
                only_auto_del = all(p.device_owner
                                    in db_base_plugin_v2.
                                    AUTO_DELETE_PORT_OWNERS
                                    for p in ports)
                if not only_auto_del:
                    LOG.debug(_("Tenant-owned ports exist"))
                    raise exc.NetworkInUse(net_id=id)

                # Get subnets to auto-delete.
                subnets = (session.query(models_v2.Subnet).
                           enable_eagerloads(False).
                           filter_by(network_id=id).all())
                LOG.debug(_("Subnets to auto-delete: %s"), subnets)

                if not (ports or subnets):
                    network = self.get_network(context, id)
                    mech_context = driver_context.NetworkContext(self,
                                                                 context,
                                                                 network)
                    self.mechanism_manager.delete_network_precommit(
                        mech_context)

                    self.type_manager.release_network_segments(session, id)
                    record = self._get_network(context, id)
                    LOG.debug(_("Deleting network record %s"), record)
                    session.delete(record)

                    # The segment records are deleted via cascade from the
                    # network record, so explicit removal is not necessary.
                    LOG.debug(_("Committing transaction"))
                    break
        except os_db_exception.DBError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    ctxt.reraise = False
                    msg = _("A concurrent port creation has occurred")
                    LOG.warning(msg)
                    continue
        LOG.info(_("Auto-deleting ports %(ports)s for network %(net)s"),
                 {'ports': ports, 'net': id})
        self._delete_ports(context, ports)
        LOG.info(_("Auto-deleting subnets %(subnets)s for network %(net)s"),
                 {'subnets': subnets, 'net': id})
        self._delete_subnets(context, subnets)

    try:
        self.mechanism_manager.delete_network_postcommit(mech_context)
    except ml2_exc.MechanismDriverError:
        # TODO(apech) - One or more mechanism driver failed to
        # delete the network.  Ideally we'd notify the caller of
        # the fact that an error occurred.
        LOG.error(_("mechanism_manager.delete_network_postcommit failed"))
    self.notifier.network_delete(context, id)

plugin.Ml2Plugin.delete_network = delete_network


# REVISIT(rkukura): Related to bug 1510327, also limit the retry loop
# here. This is based on the stable/juno version of
# neutron.plugins.ml2.plugin.Ml2Plugin.
def delete_subnet(self, context, id):
    # REVISIT(rkukura) The super(Ml2Plugin, self).delete_subnet()
    # function is not used because it deallocates the subnet's addresses
    # from ports in the DB without invoking the derived class's
    # update_port(), preventing mechanism drivers from being called.
    # This approach should be revisited when the API layer is reworked
    # during icehouse.

    LOG.debug(_("Deleting subnet %s"), id)
    session = context.session
    attempt = 0
    while True:
        attempt += 1
        LOG.info(_("Attempt %(attempt)s to delete subnet %(subnet)s"),
                 {'attempt': attempt, 'subnet': id})
        if attempt > 100:
            raise InfiniteLoopError()
        # REVISIT: Serialize this operation with a semaphore to
        # prevent deadlock waiting to acquire a DB lock held by
        # another thread in the same process, leading to 'lock
        # wait timeout' errors.
        with contextlib.nested(lockutils.lock('db-access'),
                               session.begin(subtransactions=True)):
            record = self._get_subnet(context, id)
            subnet = self._make_subnet_dict(record, None)
            qry_allocated = (session.query(models_v2.IPAllocation).
                             filter_by(subnet_id=id).
                             join(models_v2.Port))
            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            # Remove network owned ports, and delete IP allocations
            # for IPv6 addresses which were automatically generated
            # via SLAAC
            if not is_auto_addr_subnet:
                qry_allocated = (
                    qry_allocated.filter(models_v2.Port.device_owner.
                    in_(db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS)))
            allocated = qry_allocated.all()
            # Delete all the IPAllocation that can be auto-deleted
            if allocated:
                map(session.delete, allocated)
            LOG.debug(_("Ports to auto-deallocate: %s"), allocated)
            # Check if there are tenant owned ports
            tenant_port = (session.query(models_v2.IPAllocation).
                           filter_by(subnet_id=id).
                           join(models_v2.Port).
                           first())
            if tenant_port:
                LOG.debug(_("Tenant-owned ports exist"))
                raise exc.SubnetInUse(subnet_id=id)

            # If allocated is None, then all the IPAllocation were
            # correctly deleted during the previous pass.
            if not allocated:
                mech_context = driver_context.SubnetContext(self, context,
                                                            subnet)
                self.mechanism_manager.delete_subnet_precommit(
                    mech_context)

                LOG.debug(_("Deleting subnet record"))
                session.delete(record)

                LOG.debug(_("Committing transaction"))
                break

        for a in allocated:
            if a.port_id:
                # calling update_port() for each allocation to remove the
                # IP from the port and call the MechanismDrivers
                data = {'port':
                        {'fixed_ips': [{'subnet_id': ip.subnet_id,
                                        'ip_address': ip.ip_address}
                                       for ip in a.ports.fixed_ips
                                       if ip.subnet_id != id]}}
                try:
                    self.update_port(context, a.port_id, data)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Exception deleting fixed_ip from "
                                        "port %s"), a.port_id)

    try:
        self.mechanism_manager.delete_subnet_postcommit(mech_context)
    except ml2_exc.MechanismDriverError:
        # TODO(apech) - One or more mechanism driver failed to
        # delete the subnet.  Ideally we'd notify the caller of
        # the fact that an error occurred.
        LOG.error(_("mechanism_manager.delete_subnet_postcommit failed"))

plugin.Ml2Plugin.delete_subnet = delete_subnet
