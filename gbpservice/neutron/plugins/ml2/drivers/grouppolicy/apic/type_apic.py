# Copyright (c) 2013 OpenStack Foundation
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

from neutron.common import exceptions as exc
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

from gbpservice.common import constants

LOG = log.getLogger(__name__)


class ApicTypeDriver(api.TypeDriver):

    def __init__(self):
        LOG.info(_("ML2 ApicTypeDriver initialization complete"))

    def get_type(self):
        return constants.TYPE_APIC

    def initialize(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        for key, value in segment.iteritems():
            if value and key != api.NETWORK_TYPE:
                msg = _("%s prohibited for apic provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        # No resources to reserve
        return segment

    def allocate_tenant_segment(self, session):
        # No resources to allocate
        return {api.NETWORK_TYPE: constants.TYPE_APIC}

    def release_segment(self, session, segment):
        # No resources to release
        pass