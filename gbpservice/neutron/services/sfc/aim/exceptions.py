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

from neutron_lib import exceptions


class UnsupportedConfiguration(exceptions.BadRequest):
    message = _("Configuration %(conf)s for object of type %(type)s is not "
                "supported.")


class PortPairsDifferentNetworkInGroup(exceptions.BadRequest):
    message = _("For a Port Pair Group, ingress and egress networks should "
                "be the same across Port Pairs. Example of valid "
                "port pairs networks: [(N1, N2), (N1, N2), (N1, N2)]. "
                "Invalid Example: [(N1, N2), (N1, N3), (N3, N2)]. "
                "Port Pair Group ID: %(id)s")


class PortPairsUnsupportedDomain(exceptions.BadRequest):
    message = _("Port Pair's ingress and egress port domains are unsupported "
                "Please check the AIMCTL HostDomainMappingV2 "
                "port pair ID: %(id)s supported domains: %(doms)s")


class PortPairsDifferentDomain(exceptions.BadRequest):
    message = _("Port Pair's ingress and egress port can't be in different "
                "domains. Please check the AIMCTL HostDomainMappingV2 "
                "port pair ID: %(id)s")


class PortPairsNoUniqueDomain(exceptions.BadRequest):
    message = _("Port Pair's ingress and egress port domains can't be "
                "unequivocally identified. Please check the AIMCTL "
                "HostDomainMappingV2 port pair ID: %(id)s")


class PortPairsSameNetwork(exceptions.BadRequest):
    message = _("Port Pair's ingress and egress port can't be in the same "
                "network. port pair ID: %(id)s")


class PortPairsInPortPairGroupDifferentDomain(exceptions.BadRequest):
    message = _("Port Pairs in the same PPG must be in the same domain, "
                "Please check the AIMCTL HostDomainMappingV2 "
                "port pair ID: %(id)s")


class BadFlowClassifier(exceptions.BadRequest):
    message = _("The following L7 parameters must be configured on Flow "
                "Classifiers when using AIM driver: %(params)s")


class FlowClassifierSameSrcDstNetworks(exceptions.BadRequest):
    message = _("Source and Destination networks must be different in Flow "
                "Classifier if not SVI.")


class RouterIDInUseByFlowClassifier(exceptions.BadRequest):
    message = _("Router %(router_id)s is in use by Flow Classifier "
                "%(flowc_id)s.")


class NoL3OutAssociatedToFlowcExternalNetwork(exceptions.BadRequest):
    message = _("Cannot map flow classifier %(id)s, either its source or "
                "destination network is external but has no L3Outside "
                "associated to it.")


class NoPhysicalDomainSpecifiedInServiceEPG(exceptions.BadRequest):
    message = _("No Physical Domain is specified in service EPG %(epg_id)s. ")


class MultipleVRFsDetectedInPortChain(exceptions.BadRequest):
    message = _("Port Chain %(id)s spans across multiple VRFs. All providers, "
                "consumers, and service BDs have to be in the same VRF.")


class FlowClassifierSrcDstNetworksDifferentTenants(exceptions.BadRequest):
    message = _("Source and Destination networks for flow classifier %(id)s "
                "are in different tenants. This is currently unsupported.")


class NetworkInUseByFlowClassifiers(exceptions.BadRequest):
    message = _("Cannot delete network in use by classifiers %(ids)s")


class ServiceNetworkBadType(exceptions.BadRequest):
    message = _("Service networks can't be SVI or External. "
                "Port Pair ID: %(id)s")


class ConflictingNetworksDetectedInPortChain(exceptions.BadRequest):
    message = _("Port Pair Groups in Port Chain cannot share any network. "
                "%(id)s")


class DefaultExternalNetworkNotFound(exceptions.NotFound):
    message = _("Default External Network not found for SVI network "
                "%(id)s.")


class TooManyPPGsPerChainError(exceptions.BadRequest):
    message = _("The max number of PPGs per chain supported is %(maxn)s.")


class FlowClassifierSameSrcDstSVISameSubnet(exceptions.BadRequest):
    message = _("Source and Destination networks must have different subnets "
                "in Flow Classifier if SVI.")


class FlowClassifierSameSubnet(exceptions.BadRequest):
    message = _("Source and Destination cidrs must be different.")
