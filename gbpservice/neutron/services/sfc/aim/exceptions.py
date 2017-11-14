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
    message = _("Configuration %s(conf) for object of type %(type) is not "
                "supported.")


class PortPairsDifferentNetworkInGroup(exceptions.BadRequest):
    message = _("For a Port Pair Group, ingress and egress networks should "
                "be the same across Port Pairs. Example of valid "
                "port pairs networks: [(N1, N2), (N1, N2), (N1, N2)]. "
                "Invalid Example: [(N1, N2), (N1, N3), (N3, N2)]. "
                "Port Pair Group ID: %(id)")


class PortPairsSameNetwork(exceptions.BadRequest):
    message = _("Port Pair's ingress and egress port can't be in the same "
                "network. port pair ID: %(id)")


class BadFlowClassifier(exceptions.BadRequest):
    message = _("The following parameters must be configured on Flow "
                "Classifiers: %(params)s")


class RouterIDInUseByFlowClassifier(exceptions.BadRequest):
    message = _("Router %(router_id)s is in use by Flow Classifier "
                "%(flowc_id).")


class OnlyOneChainPerFlowClassifierAllowed(exceptions.BadRequest):
    message = _("Only one Port Chain per Flow Classifier is allowed. "
                "Conflicting chains: %(current)s %(conflicting)s.")

class FlowClassifierInUseByAChain(exceptions.BadRequest):
    message = _("Cannot update fields in flow classifier while in use by a "
                "port chain. fields: %(fields)s port chain: %(pc_id)s")
