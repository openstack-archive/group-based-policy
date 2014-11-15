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

"""Exceptions used by Group Policy plugin and drivers."""

from neutron.common import exceptions


class GroupPolicyDriverError(exceptions.NeutronException):
    """Policy driver call failed."""
    message = _("%(method)s failed.")


class GroupPolicyException(exceptions.NeutronException):
    """Base for policy driver exceptions returned to user."""
    pass


class GroupPolicyDeploymentError(GroupPolicyException):
    message = _("Deployment not configured properly. See logs for details.")


class GroupPolicyInternalError(GroupPolicyException):
    message = _("Unexpected internal failure. See logs for details.")


class GroupPolicyBadRequest(exceptions.BadRequest, GroupPolicyException):
    """Base for policy driver exceptions returned to user."""
    pass


class EndpointRequiresEndpointGroup(GroupPolicyBadRequest):
    message = _("An endpoint group was not specified when creating endpoint.")


class EndpointEndpointGroupUpdateNotSupported(GroupPolicyBadRequest):
    message = _("Updating endpoint's endpoint group is not supported.")


class EndpointGroupSubnetRemovalNotSupported(GroupPolicyBadRequest):
    message = _("Removing a subnet from an endpoint group is not supported.")


class L3PolicyMultipleRoutersNotSupported(GroupPolicyBadRequest):
    message = _("L3 policy does not support multiple routers.")


class L3PolicyRoutersUpdateNotSupported(GroupPolicyBadRequest):
    message = _("Updating L3 policy's routers is not supported.")


class NoSubnetAvailable(exceptions.ResourceExhausted, GroupPolicyException):
    message = _("No subnet is available from l3 policy's pool.")


class EndpointGroupInUse(GroupPolicyBadRequest):
    message = _("Endpoint Group %(endpoint_group)s is in use")


class SharedResourceReferenceError(GroupPolicyBadRequest):
    message = _("Shared resource of type %(res_type)s with id %(res_id)s "
                "can't reference the non shared resource of type "
                "%(ref_type)s with id %(ref_id)s")


class InvalidSharedResource(GroupPolicyBadRequest):
    message = _("Resource of type %(type)s cannot be shared by driver "
                "%(driver)s")


class NonSharedL2PolicyOnSharedL3PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Non shared L2 Policy can't reference a shared L3 Policy "
                "of a different tenant")


class NonSharedEndpointGroupOnSharedL2PolicyNotSupported(
        GroupPolicyBadRequest):
    message = _("Non shared Endpoint Group can't reference a shared L2 Policy "
                "of a different tenant")


class NonSharedNetworkOnSharedL2PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Non Shared Network can't be set for a shared L2 Policy")


class InvalidSharedAttributeUpdate(GroupPolicyBadRequest):
    message = _("Invalid shared attribute update. Shared resource %(id)s is"
                "referenced by %(rid)s, which is either shared or owned by a "
                "different tenant.")