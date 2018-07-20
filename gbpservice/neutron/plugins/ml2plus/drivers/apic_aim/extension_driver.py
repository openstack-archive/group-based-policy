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

from aim.api import resource as aim_res
from aim import exceptions as aim_exc
from neutron.api import extensions
from neutron.db import api as db_api
from neutron import manager as n_manager
from neutron_lib import exceptions as n_exc
from oslo_log import log
from oslo_utils import excutils

from gbpservice._i18n import _LI
from gbpservice.neutron import extensions as extensions_pkg
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as extn_db)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db

LOG = log.getLogger(__name__)


class ApicExtensionDriver(api_plus.ExtensionDriver,
                          db.DbMixin,
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
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if db_api.is_retriable(e):
                    LOG.debug("APIC AIM extend_network_dict got retriable "
                              "exception: %s", type(e))
                else:
                    LOG.exception("APIC AIM extend_network_dict failed")

    def extend_network_dict_bulk(self, session, results):
        try:
            self._md.extend_network_dict_bulk(session, results)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if db_api.is_retriable(e):
                    LOG.debug("APIC AIM extend_network_dict got retriable "
                              "exception: %s", type(e))
                else:
                    LOG.exception("APIC AIM extend_network_dict failed")

    def validate_bgp_params(self, data, result=None):
        if result:
            is_svi = result.get(cisco_apic.SVI)
        else:
            is_svi = data.get(cisco_apic.SVI, False)
        is_bgp_enabled = data.get(cisco_apic.BGP, False)
        bgp_type = data.get(cisco_apic.BGP_TYPE, "default_export")
        asn = data.get(cisco_apic.BGP_ASN, "0")
        if not is_svi and (is_bgp_enabled or (bgp_type != "default_export")
                           or (asn != "0")):
            raise n_exc.InvalidInput(error_message="Network has to be created"
                                     " as svi type(--apic:svi True) to enable"
                                     " BGP or to set BGP parameters")

    def process_create_network(self, plugin_context, data, result):
        is_svi = data.get(cisco_apic.SVI, False)
        is_bgp_enabled = data.get(cisco_apic.BGP, False)
        bgp_type = data.get(cisco_apic.BGP_TYPE, "default_export")
        asn = data.get(cisco_apic.BGP_ASN, "0")
        self.validate_bgp_params(data)
        res_dict = {cisco_apic.SVI: is_svi,
                    cisco_apic.BGP: is_bgp_enabled,
                    cisco_apic.BGP_TYPE: bgp_type,
                    cisco_apic.BGP_ASN: asn}
        self.set_network_extn_db(plugin_context.session, result['id'],
                                 res_dict)
        result.update(res_dict)

        if (data.get(cisco_apic.DIST_NAMES) and
            data[cisco_apic.DIST_NAMES].get(cisco_apic.EXTERNAL_NETWORK)):
            dn = data[cisco_apic.DIST_NAMES][cisco_apic.EXTERNAL_NETWORK]
            try:
                aim_res.ExternalNetwork.from_dn(dn)
            except aim_exc.InvalidDNForAciResource:
                raise n_exc.InvalidInput(
                    error_message=('%s is not valid ExternalNetwork DN' % dn))
            if is_svi:
                res_dict = {cisco_apic.EXTERNAL_NETWORK: dn}
            else:
                res_dict = {cisco_apic.EXTERNAL_NETWORK: dn,
                            cisco_apic.NAT_TYPE:
                            data.get(cisco_apic.NAT_TYPE, 'distributed'),
                            cisco_apic.EXTERNAL_CIDRS:
                            data.get(
                                cisco_apic.EXTERNAL_CIDRS, ['0.0.0.0/0'])}
            self.set_network_extn_db(plugin_context.session, result['id'],
                                     res_dict)
            result.setdefault(cisco_apic.DIST_NAMES, {})[
                    cisco_apic.EXTERNAL_NETWORK] = res_dict.pop(
                        cisco_apic.EXTERNAL_NETWORK)
            result.update(res_dict)

    def process_update_network(self, plugin_context, data, result):
        # External_cidr, bgp_enable, bgp_type and bgp_asn can be updated.
        if (cisco_apic.EXTERNAL_CIDRS not in data and
                cisco_apic.BGP not in data and
                cisco_apic.BGP_TYPE not in data and
                cisco_apic.BGP_ASN not in data):
            return
        res_dict = {}
        if result.get(cisco_apic.DIST_NAMES, {}).get(
            cisco_apic.EXTERNAL_NETWORK):
            if cisco_apic.EXTERNAL_CIDRS in data:
                res_dict = {cisco_apic.EXTERNAL_CIDRS:
                            data[cisco_apic.EXTERNAL_CIDRS]}
        self.validate_bgp_params(data, result)
        if cisco_apic.BGP in data:
            res_dict.update({cisco_apic.BGP: data[cisco_apic.BGP]})
        if cisco_apic.BGP_TYPE in data:
            res_dict.update({cisco_apic.BGP_TYPE: data[cisco_apic.BGP_TYPE]})
        if cisco_apic.BGP_ASN in data:
            res_dict.update({cisco_apic.BGP_ASN: data[cisco_apic.BGP_ASN]})
        if res_dict:
            self.set_network_extn_db(plugin_context.session, result['id'],
                                     res_dict)
            result.update(res_dict)

    def extend_subnet_dict(self, session, base_model, result):
        try:
            self._md.extend_subnet_dict(session, base_model, result)
            res_dict = self.get_subnet_extn_db(session, result['id'])
            result[cisco_apic.SNAT_HOST_POOL] = (
                res_dict.get(cisco_apic.SNAT_HOST_POOL, False))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if db_api.is_retriable(e):
                    LOG.debug("APIC AIM extend_subnet_dict got retriable "
                              "exception: %s", type(e))
                else:
                    LOG.exception("APIC AIM extend_subnet_dict failed")

    def process_create_subnet(self, plugin_context, data, result):
        res_dict = {cisco_apic.SNAT_HOST_POOL:
                    data.get(cisco_apic.SNAT_HOST_POOL, False)}
        self.set_subnet_extn_db(plugin_context.session, result['id'],
                                res_dict)
        result.update(res_dict)

    def process_update_subnet(self, plugin_context, data, result):
        if not cisco_apic.SNAT_HOST_POOL in data:
            return
        res_dict = {cisco_apic.SNAT_HOST_POOL: data[cisco_apic.SNAT_HOST_POOL]}
        self.set_subnet_extn_db(plugin_context.session, result['id'],
                                res_dict)
        result.update(res_dict)

    def extend_address_scope_dict(self, session, base_model, result):
        try:
            self._md.extend_address_scope_dict(session, base_model, result)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if db_api.is_retriable(e):
                    LOG.debug("APIC AIM extend_address_scope_dict got "
                              "retriable exception: %s", type(e))
                else:
                    LOG.exception("APIC AIM extend_address_scope_dict failed")

    def process_create_address_scope(self, plugin_context, data, result):
        if (data.get(cisco_apic.DIST_NAMES) and
            data[cisco_apic.DIST_NAMES].get(cisco_apic.VRF)):
            dn = data[cisco_apic.DIST_NAMES][cisco_apic.VRF]
            try:
                vrf = aim_res.VRF.from_dn(dn)
            except aim_exc.InvalidDNForAciResource:
                raise n_exc.InvalidInput(
                    error_message=('%s is not valid VRF DN' % dn))

            # Check if another address scope already maps to this VRF.
            session = plugin_context.session
            mappings = self._get_address_scope_mappings_for_vrf(session, vrf)
            vrf_owned = False
            for mapping in mappings:
                if mapping.address_scope.ip_version == data['ip_version']:
                    raise n_exc.InvalidInput(
                        error_message=(
                            'VRF %s is already in use by address-scope %s' %
                            (dn, mapping.scope_id)))
                vrf_owned = mapping.vrf_owned

            self._add_address_scope_mapping(
                session, result['id'], vrf, vrf_owned)
