# Copyright 2015 Cisco Systems, Inc.
# All rights reserved.
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

from neutron.api import extensions as api_extensions
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

from gbpservice.neutron import extensions as extensions_pkg
from gbpservice.neutron.db import port_ep_db
from gbpservice.neutron.extensions import apic_port_ep as port_ep


LOG = log.getLogger(__name__)


class PortEndpointExtensionDriver(api.ExtensionDriver):

    _supported_extension_alias = "apic-port-ep"

    def initialize(self):
        LOG.info(_("Initializing APIC port Endpoint Extension"))
        api_extensions.append_api_extensions_path(extensions_pkg.__path__)

    @property
    def extension_alias(self):
        """
        Supported extension alias.
        :returns: alias identifying the core API extension supported
                  by this driver
        """
        return self._supported_extension_alias

    def process_create_port(self, session, data, result):
        pass

    def process_update_port(self, session, data, result):
        up_to_date = data.get(port_ep.ENDPOINT_UP_TO_DATE)
        if up_to_date is False:
            # up_to_date can only be set to False from the REST API.
            port_ep_db.PortEndpointManager().update(session, result['id'],
                                                    up_to_date=up_to_date)
            result[port_ep.ENDPOINT_UP_TO_DATE] = False
        else:
            self.extend_port_dict(session, result)

    def extend_port_dict(self, session, result):
        state = port_ep_db.PortEndpointManager().update(session, result['id'])
        result[port_ep.ENDPOINT_UP_TO_DATE] = state.up_to_date
