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

"""Exceptions used by ServiceChain plugin and drivers."""

from neutron_lib import exceptions


class ServiceChainDriverError(exceptions.NeutronException):
    """ServiceChain driver call failed."""
    message = _("%(method)s failed.")


class ServiceChainException(exceptions.NeutronException):
    """Base for servicechain driver exceptions returned to user."""
    pass


class ServiceChainBadRequest(exceptions.BadRequest, ServiceChainException):
    """Base for servicechain driver bad request exceptions returned to user."""
    pass


class ServiceChainDeploymentError(ServiceChainException):
    message = _("Deployment not configured properly. See logs for details.")


class InvalidServiceTypeForReferenceDriver(ServiceChainBadRequest):
    message = _("The reference service chain driver only supports the services"
                " Loadbalancer and Firewall services in a Service Chain Spec")


class NodeUpdateNotSupported(ServiceChainBadRequest):
    message = _("The configured service chain driver does not support Service "
                "Chain Node config update")
