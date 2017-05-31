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

from neutron_lib import exceptions


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


class GroupPolicyNotSupportedError(GroupPolicyBadRequest):
    message = _("Operation %(method_name)s for resource "
                "%(resource_name)s is not supported by this "
                "deployment.")


class PolicyTargetRequiresPolicyTargetGroup(GroupPolicyBadRequest):
    message = _("An policy target group was not specified when "
                "creating policy_target.")


class PolicyTargetGroupUpdateOfPolicyTargetNotSupported(GroupPolicyBadRequest):
    message = _("Updating policy target group of policy target "
                "is not supported.")


class PolicyTargetGroupSubnetRemovalNotSupported(GroupPolicyBadRequest):
    message = _("Removing a subnet from an policy target group is not "
                "supported.")


class L2PolicyUpdateOfPolicyTargetGroupNotSupported(GroupPolicyBadRequest):
    message = _("Updating L2 policy of policy target group is not supported.")


class L3PolicyUpdateOfL2PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Updating L3 policy of L2 policy is not supported.")


class UnsettingInjectDefaultRouteOfL2PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Unsetting inject_default_route attribute of L2 policy is not "
                "supported.")


class L3PolicyMultipleRoutersNotSupported(GroupPolicyBadRequest):
    message = _("L3 policy does not support multiple routers.")


class L3PolicyRoutersUpdateNotSupported(GroupPolicyBadRequest):
    message = _("Updating L3 policy's routers is not supported.")


class NoSubnetAvailable(exceptions.ResourceExhausted, GroupPolicyException):
    message = _("No subnet is available from l3 policy's pool.")


class PolicyTargetGroupInUse(GroupPolicyBadRequest):
    message = _("Policy Target Group %(policy_target_group)s is in use")


class InvalidPortForPTG(GroupPolicyBadRequest):
    message = _("Subnet %(port_subnet_id)s of port %(port_id)s does not "
                "match subnet %(ptg_subnet_id)s of Policy Target Group "
                "%(policy_target_group_id)s.")


class InvalidPortExtraAttributes(GroupPolicyBadRequest):
    message = _("Port extra attribute %(attribute)s is invalid for the "
                "following reason: %(reason)s")


class InvalidSubnetForPTG(GroupPolicyBadRequest):
    message = _("Subnet %(subnet_id)s does not belong to network "
                "%(network_id)s associated with L2P %(l2p_id)s for PTG "
                "%(ptg_id)s.")


class OverlappingIPPoolsInSameTenantNotAllowed(GroupPolicyBadRequest):
    message = _("IP Pool %(ip_pool)s overlaps with one of the existing L3P "
                "for the same tenant %(overlapping_pools)s.")


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
    message = _("Invalid shared attribute update. Shared resource %(id)s is "
                "referenced by %(rid)s, which is either shared or owned by a "
                "different tenant.")


class ExternalRouteOverlapsWithL3PIpPool(GroupPolicyBadRequest):
    message = _("Destination %(destination)s for ES %(es_id)s overlaps with "
                "L3P %(l3p_id)s.")


class ExternalSegmentSubnetOverlapsWithL3PIpPool(GroupPolicyBadRequest):
    message = _("Subnet %(subnet)s for ES %(es_id)s overlaps with "
                "L3P %(l3p_id)s.")


class ExternalRouteNextHopNotInExternalSegment(GroupPolicyBadRequest):
    message = _("One or more external routes' nexthop are not part of "
                "subnet %(cidr)s.")


class InvalidL3PExternalIPAddress(GroupPolicyBadRequest):
    message = _("Address %(ip)s allocated for l3p %(l3p_id)s on segment "
                "%(es_id)s doesn't belong to the segment subnet %(es_cidr)s")


class InvalidAttributeUpdateForES(GroupPolicyBadRequest):
    message = _("Attribute %(attribute)s cannot be updated for External "
                "Segment.")


class MultipleESPerEPNotSupported(GroupPolicyBadRequest):
    message = _("Multiple External Segments per External Policy is not "
                "supported.")


class ESIdRequiredWhenCreatingEP(GroupPolicyBadRequest):
    message = _("External Segment ID is required when creating ExternalPolicy")


class ESUpdateNotSupportedForEP(GroupPolicyBadRequest):
    message = _("external_segments update for External Policy is not "
                "supported.")


class MultipleESPerL3PolicyNotSupported(GroupPolicyBadRequest):
    message = _("Only one External Segment per L3 Policy supported.")


class InvalidSubnetForES(GroupPolicyBadRequest):
    message = _("External Segment subnet %(sub_id)s is not part of an "
                "external network %(net_id)s.")


class OnlyOneEPPerTenantAllowed(GroupPolicyBadRequest):
    message = _("Only one External Policy per Tenant is allowed.")


class ImplicitSubnetNotSupported(GroupPolicyBadRequest):
    message = _("This policy driver doesn't support implicit external "
                "subnet creation.")


class DefaultL3PolicyAlreadyExists(GroupPolicyBadRequest):
    message = _("Default L3 Policy with name %(l3p_name)s already "
                "exists and is visible for this tenant.")


class DefaultExternalSegmentAlreadyExists(GroupPolicyBadRequest):
    message = _("Default External Segment with name %(es_name)s already "
                "exists and is visible for this tenant.")


class InvalidCrossTenantReference(GroupPolicyBadRequest):
    message = _("Not supported cross tenant reference: object "
                "%(res_type)s:%(res_id)s can't link %(ref_type)s:%(ref_id)s "
                "unless it's shared.")


class InvalidNetworkAccess(GroupPolicyBadRequest):
    message = _("%(msg)s : Network id %(network_id)s doesn't belong to "
                " the tenant id %(tenant_id)s.")


class InvalidRouterAccess(GroupPolicyBadRequest):
    message = _("%(msg)s : Router id %(router_id)s does not belong to the "
                " tenant id %(tenant_id)s.")


class MultipleRedirectActionsNotSupportedForRule(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver does not support multiple redirect "
                "actions in a Policy Rule.")


class MultipleRedirectActionsNotSupportedForPRS(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver does not support multiple redirect "
                "actions in a Policy Rule Set.")


class InvalidNetworkServiceParameters(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver currently supports Network Service "
                "Parameters with the following types and values: "
                "type: 'ip_single' value: 'self_subnet'; "
                "type: 'ip_pool' value: 'nat_pool'; "
                "type: 'ip_single' value: 'nat_pool'; "
                "type: 'qos_maxrate' value: numerical of intended Kbps; "
                "type: 'qos_burstrate' value: numerical of intended Kbps.")


class ESSubnetRequiredForNatPool(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver requires an External Segment which "
                "has an external subnet specified to create a Nat Pool")


class InvalidESSubnetCidrForNatPool(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver requires an External Segment which "
                "maps to ip pool value specified in the nat pool")


class NSPRequiresES(GroupPolicyBadRequest):
    message = _("Driver requires an External Segment in "
                "l3policy to associate a NSP with value nat_pool to a PTG")


class NSPRequiresNatPool(GroupPolicyBadRequest):
    message = _("Resource Mapping Driver requires an External Segment in "
                "l3policy which has nat_pool associated for associating a NSP "
                "with value nat_pool to a PTG")


class L3PEsinUseByNSP(exceptions.InUse, GroupPolicyException):
    message = _("The External Segment in L3Policy cannot be updated because "
                "it is in use by Network Service Policy")


class NatPoolinUseByNSP(exceptions.InUse, GroupPolicyException):
    message = _("The Nat Pool is in use by Network Service Policy")


class OverlappingNATPoolInES(GroupPolicyBadRequest):
    message = _("One or more NAT Pools associated with ES %(es_id)s overlaps "
                "with NAT Pool %(np_id)s.")


class OverlappingSubnetForNATPoolInES(GroupPolicyBadRequest):
    message = _("One or more subnets associated with network %(net_id)s "
                "partially overlaps with NAT Pool %(np_id)s.")


class InvalidProxiedGroupL3P(GroupPolicyBadRequest):
    message = _("Cannot proxy PTG %(ptg_id)s: it's on a different L3 policy "
                "%(l3p_id)s")


class InvalidProxiedGroupL2P(GroupPolicyBadRequest):
    message = _("Cannot proxy PTG %(ptg_id)s: it's on the same L2 Policy as "
                "the proxy group of type L2.")


class OnlyOneProxyGatewayAllowed(GroupPolicyBadRequest):
    message = _("Another proxy gateway PT already exists for group "
                "%(group_id)s")


class OnlyOneGroupDefaultGatewayAllowed(GroupPolicyBadRequest):
    message = _("Another group default gateway PT already exists for group "
                "%(group_id)s")


class PTGAlreadyProvidingRedirectPRS(GroupPolicyBadRequest):
    message = _("PTG %(ptg_id)s is already providing a redirect PRS.")


class InvalidClusterId(GroupPolicyBadRequest):
    message = _("In RMD and derived drivers, a PT cluster_id should point to "
                "an existing PT.")


class PolicyTargetInUse(GroupPolicyBadRequest):
    message = _("Cannot delete a PT in use by a cluster.")


class InvalidClusterPtg(GroupPolicyBadRequest):
    message = _("Inter PTG clustering disallowed.")


class NatPoolInUseByPort(exceptions.InUse, GroupPolicyException):
    message = _("Ports or floating IP addresses are using the subnet "
                "corresponding to Nat Pool.")


class IdenticalExternalRoute(GroupPolicyBadRequest):
    message = _("External segments %(es1)s and %(es2)s cannot have "
                "identical external route CIDR %(cidr)s if associated "
                "with a common L3 policy.")


class NoValidAddressScope(GroupPolicyBadRequest):
    message = _("No address scope was either provided, could be "
                "determined, or could be created for a l3_policy.")


class NoAddressScopeForSubnetpool(GroupPolicyBadRequest):
    message = _("Subnetpool does not have an associated address scope.")


class InconsistentAddressScopeSubnetpool(GroupPolicyBadRequest):
    message = _("Subnetpool is not associated with the address "
                "scope for a l3_policy.")


class IncorrectSubnetpoolUpdate(GroupPolicyBadRequest):
    message = _("Subnetpool %(subnetpool_id)s cannot be disassociated "
                "from L3 Policy %(l3p_id)s since it has allocated subnet(s) "
                "associated with that L3 Policy")
