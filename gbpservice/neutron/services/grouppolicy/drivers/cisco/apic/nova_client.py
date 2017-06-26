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

from neutron.notifiers import nova as n_nova
from novaclient import exceptions as nova_exceptions
from oslo_log import log as logging

from gbpservice._i18n import _LW


LOG = logging.getLogger(__name__)


client = None


def _get_client():
    global client
    if client is None:
        client = n_nova.Notifier().nclient
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
