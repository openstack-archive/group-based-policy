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

import requests

from oslo.config import cfg
from oslo.serialization import jsonutils
from requests.auth import HTTPBasicAuth

LOG = None

class OdlManager(object):
    """Class to manage ODL translations and workflow.

    This class manages translation from Neutron objects to APIC
    managed objects and contains workflows to implement these
    translations.
    """
    def __init__(self):
        self._username = cfg.CONF.odl_username
        self._password = cfg.CONF.odl_password
        self._host = cfg.CONF.odl_host
        self._port = cfg.CONF.odl_port
        self._base_url = 'http://' + self._host + ':' + self._port + '/restconf'
        self._reg_ep_url = self._base_url + '/operations/endpoint:register-endpoint'
        self._reg_tenants_url = self._base_url + '/config/policy:tenants'
        self._reg_nodes_url = self._base_url + '/config/opendaylight-inventory:nodes'
        self._headers = {'Content-type': 'application/yang.data+json',
                         'Accept': 'application/yang.data+json'}

    def sendjson(self, method, url, headers, obj):
        """Send json to the ODL controller."""

        data = jsonutils.dumps(obj, indent=2, sort_keys=True) if obj else None
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(obj)s)",
                  {'method': method, 'url': url, 'obj': obj})
        r = requests.request(method, url=url,
                             headers=headers, data=data,
                             auth=HTTPBasicAuth(self._username, self._password))
        r.raise_for_status()

    def register_tenants(self, tenants):
        data = {"policy:tenants": {"tenant": tenants.values()}}
        self.sendjson('put', self._reg_tenants_url, self._headers, data)

    def register_eps(self, endpoints):
        for ep in endpoints:
            data = {"input": ep}
            self.sendjson('post', self._reg_ep_url, self._headers, data)

    def register_nodes(self, nodes):
        data = {"opendaylight-inventory:nodes": {"node": nodes}}
        self.sendjson('put', self._reg_nodes_url, self._headers, data)
