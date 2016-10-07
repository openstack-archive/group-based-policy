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

from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.api import extensions
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.plugins.common import constants
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import inspect

from gbpservice.neutron import extensions as extensions_pkg

LOG = logging.getLogger(__name__)


class ApicL3Plugin(common_db_mixin.CommonDbMixin,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute",
                                   "cisco-apic-l3"]

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        return _("L3 Router Service Plugin using the APIC via AIM")

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
            info = super(ApicL3Plugin, self).add_router_interface(
                context, router_id, interface_info)
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
