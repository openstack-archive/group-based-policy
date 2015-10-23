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

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as keyclient
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice.common import utils
from gbpservice.neutron.services.servicechain.plugins.ncp.node_plumbers import(
    traffic_stitching_plumber as tscp)

LOG = logging.getLogger(__name__)

TSCP_OPTS = [
    cfg.StrOpt('plumbing_resource_owner_user',
           help=_("Username of the Openstack keystone user who owns the "
                  "resources created by the traffic stitching plumber")),
    cfg.StrOpt('plumbing_resource_owner_password',
               help=_("Openstack keystone password for the user who "
                      "owns the resources created by the traffic stitching "
                      "plumber"),
               secret=True),
    cfg.StrOpt('plumbing_resource_owner_tenant_name',
               help=_("Name of the Tenant that will own the plumber created "
                      " resources"),)
]

cfg.CONF.register_opts(TSCP_OPTS, "admin_owned_resources_apic_tscp")


class AdminOwnedResourcesApicTSCP(tscp.TrafficStitchingPlumber):
    """Traffic Stitching Plumber for APIC with Admin owned resources.

    This plumber for APIC mapping provides the ability to choose the user and
    who owns the resources created by the plumber.
    """

    def initialize(self):
        self._resource_owner_tenant_id = None
        super(AdminOwnedResourcesApicTSCP, self).initialize()

    @property
    def resource_owner_tenant_id(self):
        if not self._resource_owner_tenant_id:
            self._resource_owner_tenant_id = (
                self._get_resource_owner_tenant_id())
        return self._resource_owner_tenant_id

    def plug_services(self, context, deployment):
        context = self._get_resource_owner_context(context)
        super(AdminOwnedResourcesApicTSCP, self).plug_services(
            context, deployment)

    def unplug_services(self, context, deployment):
        context = self._get_resource_owner_context(context)
        super(AdminOwnedResourcesApicTSCP, self).unplug_services(
            context, deployment)

    def _get_resource_owner_tenant_id(self):
        user, pwd, tenant, auth_url = utils.get_keystone_creds()
        keystoneclient = keyclient.Client(username=user, password=pwd,
                                          auth_url=auth_url)
        try:
            tenant = keystoneclient.tenants.find(name=tenant)
            return tenant.id
        except k_exceptions.NotFound:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_('No tenant with name %s exists.'), tenant)
        except k_exceptions.NoUniqueMatch:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_('Multiple tenants matches found for %s'), tenant)

    def _get_resource_owner_context(self, context):
        resource_owner_context = context.elevated()
        resource_owner_context.tenant_id = self.resource_owner_tenant_id
        user, pwd, _, auth_url = utils.get_keystone_creds()
        keystoneclient = keyclient.Client(username=user, password=pwd,
                                          auth_url=auth_url)
        resource_owner_context.auth_token = keystoneclient.get_token(
            self.resource_owner_tenant_id)
        return resource_owner_context
