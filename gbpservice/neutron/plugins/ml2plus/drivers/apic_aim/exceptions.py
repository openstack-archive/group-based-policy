# Copyright (c) 2017 Cisco Systems Inc.
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

from neutron.common import exceptions


class InternalError(exceptions.NeutronException):
    message = _("Internal mechanism driver error - see error log for details.")


class UnsupportedRoutingTopology(exceptions.BadRequest):
    message = _("All router interfaces for a network must share either the "
                "same router or the same subnet.")


class UnscopedSharedNetworkProjectConflict(exceptions.BadRequest):
    message = _("Shared network %(net1)s from project %(proj1)s and shared "
                "network %(net2)s from project %(proj2)s cannot be combined "
                "in the same topology.")


class NonIsomorphicNetworkRoutingUnsupported(exceptions.BadRequest):
    message = _("All router interfaces for a network must utilize the same "
                "VRF.")


class ScopeUpdateNotSupported(exceptions.BadRequest):
    message = _("Updating the address_scope of a subnetpool that is "
                "associated with routers is not currently supported.")


class SnatPortsInUse(exceptions.SubnetInUse):
    def __init__(self, **kwargs):
        kwargs['reason'] = _('Subnet has SNAT IP addresses allocated')
        super(SnatPortsInUse, self).__init__(**kwargs)


class SnatPoolCannotBeUsedForFloatingIp(exceptions.InvalidInput):
    message = _("Floating IP cannot be allocated in SNAT host pool subnet.")
