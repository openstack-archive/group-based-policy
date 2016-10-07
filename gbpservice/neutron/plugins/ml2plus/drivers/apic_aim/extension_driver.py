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
from oslo_log import log
from oslo_utils import excutils

from gbpservice.neutron import extensions as extensions_pkg
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus

LOG = log.getLogger(__name__)


class ApicExtensionDriver(api_plus.ExtensionDriver):

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
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_network_dict failed"))

    def extend_subnet_dict(self, session, base_model, result):
        try:
            self._md.extend_subnet_dict(session, base_model, result)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_subnet_dict failed"))

    def extend_address_scope_dict(self, session, base_model, result):
        try:
            self._md.extend_address_scope_dict(session, base_model, result)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("APIC AIM extend_address_scope_dict failed"))
