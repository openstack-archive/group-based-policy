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

from neutron._i18n import _LI
from oslo_log import log

from gbpservice.neutron.plugins.ml2plus import driver_api

LOG = log.getLogger(__name__)


class ApicMechanismDriver(driver_api.MechanismDriver):

    def initialize(self):
        LOG.info(_LI("APIC AIM MD initializing"))

    def ensure_tenant(self, plugin_context, tenant_id):
        LOG.info(_LI("APIC AIM MD ensuring tenant_id: %s"), tenant_id)

    def create_network_precommit(self, context):
        LOG.info(_LI("APIC AIM MD creating network: %s"), context.current)
