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

from neutron.openstack.common import log as logging
from novaclient import exceptions as nova_exceptions
import novaclient.v1_1.client as nclient
from oslo.config import cfg

LOG = logging.getLogger(__name__)


class NovaClient:

    def __init__(self):

        bypass_url = "%s/%s" % (cfg.CONF.nova_url,
                                cfg.CONF.nova_admin_tenant_id)

        self.client = nclient.Client(
            username=cfg.CONF.nova_admin_username,
            api_key=cfg.CONF.nova_admin_password,
            project_id=None,
            tenant_id=cfg.CONF.nova_admin_tenant_id,
            auth_url=cfg.CONF.nova_admin_auth_url,
            cacert=cfg.CONF.nova_ca_certificates_file,
            insecure=cfg.CONF.nova_api_insecure,
            bypass_url=bypass_url,
            region_name=cfg.CONF.nova_region_name)

    def get_server(self, server_id):
        try:
            return self.client.servers.get(server_id)
        except nova_exceptions.NotFound:
            LOG.warning(_("Nova returned NotFound for server: %s"),
                        server_id)
        except Exception as e:
            LOG.exception(e)
