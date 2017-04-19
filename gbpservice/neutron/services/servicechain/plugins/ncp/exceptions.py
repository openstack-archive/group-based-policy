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

"""Exceptions used by NodeCompositionPlugin and drivers."""

from neutron_lib import exceptions


class NodeDriverError(exceptions.NeutronException):
    """Node driver call failed."""
    message = _("%(method)s failed.")


class NodeCompositionPluginException(exceptions.NeutronException):
    """Base for node driver exceptions returned to user."""
    pass


class PlumbingException(exceptions.NeutronException):
    """Base for node driver exceptions returned to user."""
    pass


class NodeCompositionPluginBadRequest(exceptions.BadRequest,
                                      NodeCompositionPluginException):
    """Base for node driver bad request exceptions returned to user."""
    pass


class OneSpecPerInstanceAllowed(NodeCompositionPluginBadRequest):
    message = _("The Node Composition Plugin only supports one Servicechain"
                "Spec per Servicechain Instance.")


class NoDriverAvailableForAction(NodeCompositionPluginBadRequest):
    message = _("The Node Composition Plugin can't find any Node Driver "
                "available for executing %(action)s on node %(node_id)s. "
                "This may be caused by a Servicechain Node misconfiguration "
                "or an unsupported Service Profile.")


class ServiceProfileInUseByAnInstance(NodeCompositionPluginBadRequest):
    message = _("Cannot update Service Profile %(profile_id)s because it's "
                "used by servicechain instance %(instance_id)s.")


class NotAvailablePTGForTargetRequest(PlumbingException):
    message = _("PTG of type %(ptg_type)s doesn't exist for service chain "
                "instance %(instance)s. However, it is required by the "
                "scheduled Node Driver in order to deploy Node %(node)s")


class InuseSpecNodeUpdateNotAllowed(NodeCompositionPluginBadRequest):
    message = _("The Node Composition Plugin does not support updating the "
                "nodes in an instantiated servicechain spec.")
