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
from neutron import manager as n_manager
from neutron_lib import exceptions as n_exc
from oslo_log import log
from oslo_utils import excutils

from aim.api import resource as aim_res
from aim import exceptions as aim_exc

from gbpservice.neutron import extensions as extensions_pkg
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as extn_db)

LOG = log.getLogger(__name__)


class ApicExtensionDriver(api_plus.ExtensionDriver,
                          extn_db.ExtensionDbMixin):

    def __init__(self):
        LOG.info(_LI("APIC AIM ED __init__"))
        self._mechanism_driver = None

    def initialize(self):
        LOG.info(_LI("APIC AIM ED initializing"))
        extensions.append_api_extensions_path(extensions_pkg.__path__)

    @property
    def _md(self):
        if not self._mechanism_driver:
            # REVISIT(rkukura): It might be safer to search the MDs by
            # class rather than index by name, or to use a class
            # variable to find the instance.
            plugin = n_manager.NeutronManager.get_plugin()
            mech_mgr = plugin.mechanism_manager
            self._mechanism_driver = mech_mgr.mech_drivers['apic_aim'].obj
        return self._mechanism_driver

    @property
    def extension_alias(self):
        return "cisco-apic"

    def extend_network_dict(self, session, base_model, result):
        try:
            self._md.extend_network_dict(session, base_model, result)
            if result:
                res_dict = self.get_network_extn_db(session, result['id'])
                if cisco_apic.EXTERNAL_NETWORK in res_dict:
                    result.setdefault(cisco_apic.DIST_NAMES, {})[
                        cisco_apic.EXTERNAL_NETWORK] = res_dict.pop(
                            cisco_apic.EXTERNAL_NETWORK)
                result.update(res_dict)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_network_dict failed"))

    def process_create_network(self, plugin_context, data, result):
        if (data.get(cisco_apic.DIST_NAMES) and
            data[cisco_apic.DIST_NAMES].get(cisco_apic.EXTERNAL_NETWORK)):
            dn = data[cisco_apic.DIST_NAMES][cisco_apic.EXTERNAL_NETWORK]
            try:
                aim_res.ExternalNetwork.from_dn(dn)
            except aim_exc.InvalidDNForAciResource:
                raise n_exc.InvalidInput(
                    error_message=('%s is not valid ExternalNetwork DN' % dn))
            res_dict = {cisco_apic.EXTERNAL_NETWORK: dn,
                        cisco_apic.NAT_TYPE:
                        data.get(cisco_apic.NAT_TYPE, 'distributed'),
                        cisco_apic.EXTERNAL_CIDRS:
                        data.get(cisco_apic.EXTERNAL_CIDRS, ['0.0.0.0/0'])}
            self.set_network_extn_db(plugin_context.session, result['id'],
                                     res_dict)
            result.setdefault(cisco_apic.DIST_NAMES, {})[
                    cisco_apic.EXTERNAL_NETWORK] = res_dict.pop(
                        cisco_apic.EXTERNAL_NETWORK)
            result.update(res_dict)

    def process_update_network(self, plugin_context, data, result):
        # only CIDRs can be updated
        if not data.get(cisco_apic.EXTERNAL_CIDRS):
            return
        res_dict = {cisco_apic.EXTERNAL_CIDRS: data[cisco_apic.EXTERNAL_CIDRS]}
        if self.set_network_extn_db(plugin_context.session, result['id'],
                                    res_dict):
            result.update(res_dict)

    def extend_subnet_dict(self, session, base_model, result):
        try:
            self._md.extend_subnet_dict(session, base_model, result)
            if result:
                res_dict = self.get_subnet_extn_db(session, result['id'])
                result[cisco_apic.SNAT_HOST_POOL] = (
                    res_dict.get(cisco_apic.SNAT_HOST_POOL, False))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_subnet_dict failed"))

    def process_create_subnet(self, plugin_context, data, result):
        res_dict = {cisco_apic.SNAT_HOST_POOL:
                    data.get(cisco_apic.SNAT_HOST_POOL, False)}
        self.set_subnet_extn_db(plugin_context.session, result['id'],
                                res_dict)

    def process_update_subnet(self, plugin_context, data, result):
        if not data.get(cisco_apic.SNAT_HOST_POOL):
            return
        res_dict = {cisco_apic.SNAT_HOST_POOL: data[cisco_apic.SNAT_HOST_POOL]}
        self.set_subnet_extn_db(plugin_context.session, result['id'],
                                res_dict)

    def extend_address_scope_dict(self, session, base_model, result):
        try:
            self._md.extend_address_scope_dict(session, base_model, result)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_address_scope_dict failed"))
