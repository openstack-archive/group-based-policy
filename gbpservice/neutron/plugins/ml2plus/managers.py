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

from gbpservice.neutron.plugins.ml2plus import driver_api

from neutron._i18n import _LE
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers
from oslo_log import log

LOG = log.getLogger(__name__)


class MechanismManager(managers.MechanismManager):

    def __init__(self):
        super(MechanismManager, self).__init__()

    def ensure_tenant(self, plugin_context, tenant_id):
        for driver in self.ordered_mech_drivers:
            if isinstance(driver.obj, driver_api.MechanismDriver):
                try:
                    driver.obj.ensure_tenant(plugin_context, tenant_id)
                except Exception:
                    LOG.exception(_LE("Mechanism driver '%s' failed in "
                                      "ensure_tenant"), driver.name)
                    raise ml2_exc.MechanismDriverError(method="ensure_tenant")
