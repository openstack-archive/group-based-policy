# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_log import log as logging

from neutron.extensions import portbindings
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base

from opflexagent import constants as ofcst


LOG = logging.getLogger(__name__)

NAME = 'apic_aim'

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)

DRIVER = None


class OpflexDriver(base.DriverBase):

    @property
    def is_loaded(self):
        try:
            return NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        return OpflexDriver(NAME,
                            SUPPORTED_INTERFACES,
                            SUPPORTED_SEGMENTATION_TYPES,
                            ofcst.AGENT_TYPE_OPFLEX_OVS)


def register():
    """Register the driver."""
    global DRIVER
    DRIVER = OpflexDriver.create()
    LOG.debug('Opflex trunk driver registered')
