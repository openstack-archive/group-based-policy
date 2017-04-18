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

from gbpservice.nfp.core import log as nfp_logging


from gbpservice.contrib.nfp.configurator.drivers.base import base_driver
from gbpservice.contrib.nfp.configurator.lib import (
    nfp_service_constants as const)

LOG = nfp_logging.getLogger(__name__)


class HeatDriver(base_driver.BaseDriver):
    """ Heat as a driver for handling config script
        heat configuration requests.

    We initialize service type in this class because agent loads
    class object only for those driver classes that have service type
    initialized. Also, only this driver class is exposed to the agent.

    """

    service_type = const.SERVICE_TYPE
    resource_type = const.HEAT_RESOURCE

    def __init__(self, conf):
        pass

    def run_heat(self, context, kwargs):
        msg = ("Heat template execution request received but unhandled")
        LOG.info(msg)
        return const.UNHANDLED_RESULT
