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


class PolicyTargetRequiresPolicyTargetGroup(GroupPolicyBadRequest):
    message = _("An policy target group was not specified when "
                "creating policy_target.")


class PolicyTargetGroupUpdateOfPolicyTargetNotSupported(GroupPolicyBadRequest):
    message = _("Updating policy target group of policy target "
                "is not supported.")


class PolicyTargetGroupSubnetRemovalNotSupported(GroupPolicyBadRequest):
    message = _("Removing a subnet from an policy target group is not "
                "supported.")


class L3PolicyMultipleRoutersNotSupported(GroupPolicyBadRequest):
    message = _("L3 policy does not support multiple routers.")


class L3PolicyRoutersUpdateNotSupported(GroupPolicyBadRequest):
    message = _("Updating L3 policy's routers is not supported.")


class NoSubnetAvailable(exceptions.ResourceExhausted, GroupPolicyException):
    message = _("No subnet is available from l3 policy's pool.")


class PolicyTargetGroupInUse(GroupPolicyBadRequest):
    message = _("Policy Target Group %(policy_target_group)s is in use")


class SharedResourceReferenceError(GroupPolicyBadRequest):
    message = _("Shared resource of type %(res_type)s with id %(res_id)s "
                "can't reference the non shared resource of type "
                "%(ref_type)s with id %(ref_id)s")


class InvalidSharedResource(GroupPolicyBadRequest):
    message = _("Resource of type %(type)s cannot be shared by driver "
                "%(driver)s")


class CrossTenantL2PolicyL3PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Cross tenancy not supported between L2Ps and L3Ps")


class CrossTenantPolicyTargetGroupL2PolicyNotSupported(
        GroupPolicyBadRequest):
    message = _("Cross tenancy not supported between PTGs and L2Ps")


class NonSharedNetworkOnSharedL2PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Non Shared Network can't be set for a shared L2 Policy")


class InvalidSharedAttributeUpdate(GroupPolicyBadRequest):
    message = _("Invalid shared attribute update. Shared resource %(id)s is"
                "referenced by %(rid)s, which is either shared or owned by a "
                "different tenant.")