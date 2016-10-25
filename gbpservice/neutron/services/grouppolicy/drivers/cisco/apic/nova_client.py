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

from keystoneauth1 import loading as ks_loading
from neutron._i18n import _LW
from neutron.notifiers import nova as n_nova
from novaclient import client as nclient
from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


client = None


def _get_client():
    global client
    if client is None:
        auth = ks_loading.load_auth_from_conf_options(cfg.CONF, 'nova')
        session = ks_loading.load_session_from_conf_options(
            cfg.CONF, 'nova', auth=auth)

        client = nclient.Client(
            n_nova.NOVA_API_VERSION, session=session,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type=cfg.CONF.nova.endpoint_type)
    return client


class NovaClient(object):

    def __init__(self):
        self.client = _get_client()

    def get_server(self, server_id):
        try:
            return self.client.servers.get(server_id)
        except nova_exceptions.NotFound:
            LOG.warning(_LW("Nova returned NotFound for server: %s"),
                        server_id)
        except Exception as e:
            LOG.exception(e)
