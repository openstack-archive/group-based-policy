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

from neutron._i18n import _
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.api.v2 import attributes
from neutron.common import exceptions as exc
from neutron.common import ipv6_utils
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import plugin
from oslo_db import exception as os_db_exception
from oslo_log import log
from oslo_utils import excutils
from sqlalchemy import exc as sql_exc

LOG = log.getLogger(__name__)


class InfiniteLoopError(exc.NeutronException):
    """Potentially infinite loop detected."""
    message = _("Too many retries occured.")


# REVISIT(rkukura): Partially address bug 1510327 (GBP: Deleting
# groups leads to subnet-delete in infinite loop) by limiting the
# retry loop and doing additional info-level logging. This is based on
# the stable/mitaka version of neutron.plugins.ml2.plugin.Ml2Plugin.
def delete_network(self, context, id):
    # REVISIT(rkukura) The super(Ml2Plugin, self).delete_network()
    # function is not used because it auto-deletes ports and
    # subnets from the DB without invoking the derived class's
    # delete_port() or delete_subnet(), preventing mechanism
    # drivers from being called. This approach should be revisited
    # when the API layer is reworked during icehouse.

    LOG.debug("Deleting network %s", id)
    session = context.session
    attempt = 0
    while True:
        attempt += 1
        LOG.info(_LI("Attempt %(attempt)s to delete network %(net)s"),
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
            # involve sending RPC notifications, and/or calling delete_port
            # on this plugin.
            # Additionally, a rollback may not be enough to undo the
            # deletion of a floating IP with certain L3 backends.
            self._process_l3_delete(context, id)
            # Using query().with_lockmode isn't necessary. Foreign-key
            # constraints prevent deletion if concurrent creation happens.
            with session.begin(subtransactions=True):
                # Get ports to auto-delete.
                ports = (session.query(models_v2.Port).
                         enable_eagerloads(False).
                         filter_by(network_id=id).all())
                LOG.debug("Ports to auto-delete: %s", ports)
                only_auto_del = all(p.device_owner
                                    in db_base_plugin_v2.
                                    AUTO_DELETE_PORT_OWNERS
                                    for p in ports)
                if not only_auto_del:
                    LOG.debug("Tenant-owned ports exist")
                    raise exc.NetworkInUse(net_id=id)

                # Get subnets to auto-delete.
                subnets = (session.query(models_v2.Subnet).
                           enable_eagerloads(False).
                           filter_by(network_id=id).all())
                LOG.debug("Subnets to auto-delete: %s", subnets)

                if not (ports or subnets):
                    network = self.get_network(context, id)
                    mech_context = driver_context.NetworkContext(self,
                                                                 context,
                                                                 network)
                    self.mechanism_manager.delete_network_precommit(
                        mech_context)

                    self.type_manager.release_network_segments(session, id)
                    record = self._get_network(context, id)
                    LOG.debug("Deleting network record %s", record)
                    session.delete(record)

                    # The segment records are deleted via cascade from the
                    # network record, so explicit removal is not necessary.
                    LOG.debug("Committing transaction")
                    break

                port_ids = [port.id for port in ports]
                subnet_ids = [subnet.id for subnet in subnets]
        except os_db_exception.DBError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    ctxt.reraise = False
                    LOG.warning(_LW("A concurrent port creation has "
                                    "occurred"))
                    continue
        LOG.info(_LI("Auto-deleting ports %(ports)s for network %(net)s"),
                 {'ports': ports, 'net': id})
        self._delete_ports(context, port_ids)
        LOG.info(_LI("Auto-deleting subnets %(subnets)s for network %(net)s"),
                 {'subnets': subnets, 'net': id})
        self._delete_subnets(context, subnet_ids)

    try:
        self.mechanism_manager.delete_network_postcommit(mech_context)
    except ml2_exc.MechanismDriverError:
        # TODO(apech) - One or more mechanism driver failed to
        # delete the network.  Ideally we'd notify the caller of
        # the fact that an error occurred.
        LOG.error(_LE("mechanism_manager.delete_network_postcommit"
                      " failed"))
    self.notifier.network_delete(context, id)

plugin.Ml2Plugin.delete_network = delete_network


# REVISIT(rkukura): Related to bug 1510327, also limit the retry loop
# here. This is based on the stable/mitaka version of
# neutron.plugins.ml2.plugin.Ml2Plugin.
def delete_subnet(self, context, id):
    # REVISIT(rkukura) The super(Ml2Plugin, self).delete_subnet()
    # function is not used because it deallocates the subnet's addresses
    # from ports in the DB without invoking the derived class's
    # update_port(), preventing mechanism drivers from being called.
    # This approach should be revisited when the API layer is reworked
    # during icehouse.

    LOG.debug("Deleting subnet %s", id)
    session = context.session
    deallocated = set()
    attempt = 0
    while True:
        attempt += 1
        LOG.info(_LI("Attempt %(attempt)s to delete subnet %(subnet)s"),
                 {'attempt': attempt, 'subnet': id})
        if attempt > 100:
            raise InfiniteLoopError()
        with session.begin(subtransactions=True):
            record = self._get_subnet(context, id)
            subnet = self._make_subnet_dict(record, None, context=context)
            qry_allocated = (session.query(models_v2.IPAllocation).
                             filter_by(subnet_id=id).
                             join(models_v2.Port))
            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            # Remove network owned ports, and delete IP allocations
            # for IPv6 addresses which were automatically generated
            # via SLAAC
            if is_auto_addr_subnet:
                self._subnet_check_ip_allocations_internal_router_ports(
                        context, id)
            else:
                qry_allocated = (
                    qry_allocated.filter(models_v2.Port.device_owner.
                    in_(db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS)))
            allocated = set(qry_allocated.all())
            LOG.debug("Ports to auto-deallocate: %s", allocated)
            if not is_auto_addr_subnet:
                user_alloc = self._subnet_get_user_allocation(
                    context, id)
                if user_alloc:
                    LOG.info(_LI("Found port (%(port_id)s, %(ip)s) "
                                 "having IP allocation on subnet "
                                 "%(subnet)s, cannot delete"),
                             {'ip': user_alloc.ip_address,
                              'port_id': user_alloc.port_id,
                              'subnet': id})
                    raise exc.SubnetInUse(subnet_id=id)

            db_base_plugin_v2._check_subnet_not_used(context, id)

            # SLAAC allocations currently can not be removed using
            # update_port workflow, and will persist in 'allocated'.
            # So for now just make sure update_port is called once for
            # them so MechanismDrivers is aware of the change.
            # This way SLAAC allocation is deleted by FK on subnet deletion
            # TODO(pbondar): rework update_port workflow to allow deletion
            # of SLAAC allocation via update_port.
            to_deallocate = allocated - deallocated

            # If to_deallocate is blank, then all known IPAllocations
            # (except SLAAC allocations) were correctly deleted
            # during the previous pass.
            # Check if there are more IP allocations, unless
            # is_auto_address_subnet is True. If transaction isolation
            # level is set to READ COMMITTED allocations made
            # concurrently will be returned by this query and transaction
            # will be restarted. It works for REPEATABLE READ isolation
            # level too because this query is executed only once during
            # transaction, and if concurrent allocations are detected
            # transaction gets restarted. Executing this query second time
            # in transaction would result in not seeing allocations
            # committed by concurrent transactions.
            if not to_deallocate:
                if (not is_auto_addr_subnet and
                        self._subnet_check_ip_allocations(context, id)):
                    # allocation found and it was DHCP port
                    # that appeared after autodelete ports were
                    # removed - need to restart whole operation
                    raise os_db_exception.RetryRequest(
                        exc.SubnetInUse(subnet_id=id))
                network = self.get_network(context, subnet['network_id'])
                mech_context = driver_context.SubnetContext(self, context,
                                                            subnet,
                                                            network)
                self.mechanism_manager.delete_subnet_precommit(
                    mech_context)

                LOG.debug("Deleting subnet record")
                session.delete(record)

                # The super(Ml2Plugin, self).delete_subnet() is not called,
                # so need to manually call delete_subnet for pluggable ipam
                self.ipam.delete_subnet(context, id)

                LOG.debug("Committing transaction")
                break

        for a in to_deallocate:
            deallocated.add(a)
            if a.port:
                # calling update_port() for each allocation to remove the
                # IP from the port and call the MechanismDrivers
                fixed_ips = [{'subnet_id': ip.subnet_id,
                              'ip_address': ip.ip_address}
                             for ip in a.port.fixed_ips
                             if ip.subnet_id != id]
                # By default auto-addressed ips are not removed from port
                # on port update, so mark subnet with 'delete_subnet' flag
                # to force ip deallocation on port update.
                if is_auto_addr_subnet:
                    fixed_ips.append({'subnet_id': id,
                                      'delete_subnet': True})
                data = {attributes.PORT: {'fixed_ips': fixed_ips}}
                try:
                    # NOTE Don't inline port_id; needed for PortNotFound.
                    port_id = a.port_id
                    self.update_port(context, port_id, data)
                except exc.PortNotFound:
                    # NOTE Attempting to access a.port_id here is an error.
                    LOG.debug("Port %s deleted concurrently", port_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE("Exception deleting fixed_ip "
                                          "from port %s"), port_id)

    try:
        self.mechanism_manager.delete_subnet_postcommit(mech_context)
    except ml2_exc.MechanismDriverError:
        # TODO(apech) - One or more mechanism driver failed to
        # delete the subnet.  Ideally we'd notify the caller of
        # the fact that an error occurred.
        LOG.error(_LE("mechanism_manager.delete_subnet_postcommit failed"))

plugin.Ml2Plugin.delete_subnet = delete_subnet
