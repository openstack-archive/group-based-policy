# Copyright (c) 2016 Cisco Systems Inc.
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

from neutron.api import extensions
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.quota import resource_registry
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import inspect

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice.neutron import extensions as extensions_pkg
from gbpservice.neutron.extensions import cisco_apic_l3 as l3_ext
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as extn_db)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)

LOG = logging.getLogger(__name__)


class ApicL3Plugin(common_db_mixin.CommonDbMixin,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   extn_db.ExtensionDbMixin,
                   dns_db.DNSDbMixin):

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute",
                                   "cisco-apic-l3", "dns-integration"]

    @staticmethod
    def get_plugin_type():
        return constants.L3

    @staticmethod
    def get_plugin_description():
        return _("L3 Router Service Plugin using the APIC via AIM")

    @resource_registry.tracked_resources(router=l3_db.Router,
                                         floatingip=l3_db.FloatingIP)
    def __init__(self):
        LOG.info(_LI("APIC AIM L3 Plugin __init__"))
        extensions.append_api_extensions_path(extensions_pkg.__path__)
        self._mechanism_driver = None
        super(ApicL3Plugin, self).__init__()

    @property
    def _md(self):
        if not self._mechanism_driver:
            # REVISIT(rkukura): It might be safer to search the MDs by
            # class rather than index by name, or to use a class
            # variable to find the instance.
            mech_mgr = self._core_plugin.mechanism_manager
            self._mechanism_driver = mech_mgr.mech_drivers['apic_aim'].obj
        return self._mechanism_driver

    def _extend_router_dict_apic(self, router_res, router_db):
        LOG.debug("APIC AIM L3 Plugin extending router dict: %s", router_res)
        session = inspect(router_db).session
        try:
            self._md.extend_router_dict(session, router_db, router_res)
            self._include_router_extn_attr(session, router_res)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_router_dict failed"))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_apic'])

    def create_router(self, context, router):
        LOG.debug("APIC AIM L3 Plugin creating router: %s", router)
        self._md.ensure_tenant(context, router['router']['tenant_id'])
        with context.session.begin(subtransactions=True):
            # REVISIT(rkukura): The base operation may create a port,
            # which should generally not be done inside a
            # transaction. But we need to ensure atomicity, and are
            # generally not concerned with mechanism driver postcommit
            # processing. Consider overriding create_router_db()
            # instead, and/or reimplementing the base funtionality to
            # be completely transaction safe.
            result = super(ApicL3Plugin, self).create_router(context, router)
            self._process_router_op(context, result, router)
            self._md.create_router(context, result)
            return result

    def update_router(self, context, id, router):
        LOG.debug("APIC AIM L3 Plugin updating router %(id)s with: %(router)s",
                  {'id': id, 'router': router})
        with context.session.begin(subtransactions=True):
            # REVISIT(rkukura): The base operation sends notification
            # RPCs, which should generally not be done inside a
            # transaction. But we need to ensure atomicity, and are
            # not using an L3 agent. Consider overriding
            # create_router_db() instead, and/or reimplementing the
            # base funtionality to be completely transaction safe.
            original = self.get_router(context, id)
            result = super(ApicL3Plugin, self).update_router(context, id,
                                                             router)
            self._process_router_op(context, result, router)
            self._md.update_router(context, result, original)
            return result

    def delete_router(self, context, id):
        LOG.debug("APIC AIM L3 Plugin deleting router: %s", id)
        with context.session.begin(subtransactions=True):
            # REVISIT(rkukura): The base operation may delete ports
            # and sends notification RPCs, which should generally not
            # be done inside a transaction. But we need to ensure
            # atomicity, are not using an L3 agent, and are generally
            # not concerned with mechanism driver postcommit
            # processing. Consider reimplementing the base
            # funtionality to be completely transaction safe.
            router = self.get_router(context, id)
            super(ApicL3Plugin, self).delete_router(context, id)
            self._md.delete_router(context, router)

    def _process_router_op(self, context, result, router_req):
        self.set_router_extn_db(context.session, result['id'],
                                router_req['router'])
        self._include_router_extn_attr(context.session, result)

    def _include_router_extn_attr(self, session, router):
        attr = self.get_router_extn_db(session, router['id'])
        router.update(attr)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug("APIC AIM L3 Plugin adding interface %(interface)s "
                  "to router %(router)s",
                  {'interface': interface_info, 'router': router_id})
        with context.session.begin(subtransactions=True):
            # REVISIT(rkukura): The base operation may create or
            # update a port and sends notification RPCs, which should
            # generally not be done inside a transaction. But we need
            # to ensure atomicity, are not using an L3 agent, and are
            # generally not concerned with mechanism driver postcommit
            # processing. Consider reimplementing the base
            # funtionality to be completely transaction safe.
            #
            # REVISIT: Remove override flag when no longer needed for
            # GBP.
            context.override_network_routing_topology_validation = (
                interface_info.get(
                    l3_ext.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION))
            info = super(ApicL3Plugin, self).add_router_interface(
                context, router_id, interface_info)
            del context.override_network_routing_topology_validation
            # REVISIT(tbachman): This update port triggers port
            # binding, which means that port-binding happens inside
            # of a transaction, which shouldn't happen. This isn't
            # an issue with the AIM MD, but should be fixed at some
            # point (e.g. move port-binding outside, possibly queued
            # to be handled outside of the transaction, with some
            # sort of cleanup if it fails).
            self._core_plugin.update_port(context, info['port_id'],
                                          {'port': {portbindings.HOST_ID:
                                                    md.FABRIC_HOST_ID}})
            return info

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        LOG.debug("APIC AIM L3 Plugin adding interface by subnet %(subnet)s "
                  "to router %(router)s",
                  {'subnet': subnet_id, 'router': router['id']})
        port, subnets, new_port = (
            super(ApicL3Plugin, self)._add_interface_by_subnet(
                context, router, subnet_id, owner))
        self._md.add_router_interface(context, router, port, subnets)
        return port, subnets, new_port

    def _add_interface_by_port(self, context, router, port_id, owner):
        LOG.debug("APIC AIM L3 Plugin adding interface by port %(port)s "
                  "to router %(router)s",
                  {'port': port_id, 'router': router['id']})
        port, subnets = (
            super(ApicL3Plugin, self)._add_interface_by_port(
                context, router, port_id, owner))
        self._md.add_router_interface(context, router, port, subnets)
        return port, subnets

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug("APIC AIM L3 Plugin removing interface %(interface)s "
                  "from router %(router)s",
                  {'interface': interface_info, 'router': router_id})
        with context.session.begin(subtransactions=True):
            # REVISIT(rkukura): The base operation may delete or
            # update a port and sends notification RPCs, which should
            # generally not be done inside a transaction. But we need
            # to ensure atomicity, are not using an L3 agent, and are
            # generally not concerned with mechanism driver postcommit
            # processing. Consider reimplementing the base
            # funtionality to be completely transaction safe.
            info = super(ApicL3Plugin, self).remove_router_interface(
                context, router_id, interface_info)
            return info

    def _remove_interface_by_subnet(self, context, router_id, subnet_id,
                                    owner):
        LOG.debug("APIC AIM L3 Plugin removing interface by subnet %(subnet)s "
                  "from router %(router)s",
                  {'subnet': subnet_id, 'router': router_id})
        port_db, subnets = (
            super(ApicL3Plugin, self)._remove_interface_by_subnet(
                context, router_id, subnet_id, owner))
        self._md.remove_router_interface(context, router_id, port_db, subnets)
        return port_db, subnets

    def _remove_interface_by_port(self, context, router_id, port_id, subnet_id,
                                  owner):
        LOG.debug("APIC AIM L3 Plugin removing interface by port %(port)s "
                  "from router %(router)s",
                  {'port': port_id, 'router': router_id})
        port_db, subnets = (
            super(ApicL3Plugin, self)._remove_interface_by_port(
                context, router_id, port_id, subnet_id, owner))
        self._md.remove_router_interface(context, router_id, port_db, subnets)
        return port_db, subnets

    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        self._md.ensure_tenant(context, fip['tenant_id'])
        # Verify that subnet is not a SNAT host-pool
        self._md.check_floatingip_external_address(context, fip)
        with context.session.begin(subtransactions=True):
            if fip.get('subnet_id') or fip.get('floating_ip_address'):
                result = super(ApicL3Plugin, self).create_floatingip(
                    context, floatingip)
            else:
                # Iterate over non SNAT host-pool subnets and try to allocate
                # an address
                other_subs = self._md.get_subnets_for_fip(context, fip)
                result = None
                for ext_sn in other_subs:
                    fip['subnet_id'] = ext_sn
                    try:
                        with context.session.begin(nested=True):
                            result = (super(ApicL3Plugin, self)
                                      .create_floatingip(context, floatingip))
                        break
                    except exceptions.IpAddressGenerationFailure:
                        LOG.info(_LI('No more floating IP addresses available '
                                     'in subnet %s'),
                                 ext_sn)

                if not result:
                    raise exceptions.IpAddressGenerationFailure(
                        net_id=fip['floating_network_id'])
            self._md.create_floatingip(context, result)
            self.update_floatingip_status(context, result['id'],
                                          result['status'])
        return result

    def update_floatingip(self, context, id, floatingip):
        with context.session.begin(subtransactions=True):
            old_fip = self.get_floatingip(context, id)
            result = super(ApicL3Plugin, self).update_floatingip(
                context, id, floatingip)
            self._md.update_floatingip(context, old_fip, result)
            if old_fip['status'] != result['status']:
                self.update_floatingip_status(context, result['id'],
                                              result['status'])
        return result

    def delete_floatingip(self, context, id):
        with context.session.begin(subtransactions=True):
            old_fip = self.get_floatingip(context, id)
            super(ApicL3Plugin, self).delete_floatingip(context, id)
            self._md.delete_floatingip(context, old_fip)
