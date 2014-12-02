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
import uuid

from neutron.openstack.common import log as logging
from oslo.config import cfg
from oslo.serialization import jsonutils
from requests.auth import HTTPBasicAuth

LOG = logging.getLogger(__name__)
cfg.CONF.import_opt('odl_username',
                    'gbp.neutron.services.grouppolicy.drivers.odl.config',
                    group='odl_driver')
cfg.CONF.import_opt('odl_password',
                    'gbp.neutron.services.grouppolicy.drivers.odl.config',
                    group='odl_driver')
cfg.CONF.import_opt('odl_host',
                    'gbp.neutron.services.grouppolicy.drivers.odl.config',
                    group='odl_driver')
cfg.CONF.import_opt('odl_port',
                    'gbp.neutron.services.grouppolicy.drivers.odl.config',
                    group='odl_driver')

class OdlManager(object):
    """Class to manage ODL translations and workflow.

    This class manages translation from Neutron objects to APIC
    managed objects and contains workflows to implement these
    translations.
    """
    def __init__(self):

        LOG.info(_("Configured ODL username: %s"),
                 cfg.CONF.odl_driver.odl_username)
        LOG.info(_("Configured ODL password: %s"),
                 cfg.CONF.odl_driver.odl_password)
        LOG.info(_("Configured ODL host: %s"),
                 cfg.CONF.odl_driver.odl_host)
        LOG.info(_("Configured ODL port: %s"),
                 cfg.CONF.odl_driver.odl_port)

        self._username = cfg.CONF.odl_driver.odl_username
        self._password = cfg.CONF.odl_driver.odl_password
        self._host = cfg.CONF.odl_driver.odl_host
        self._port = cfg.CONF.odl_driver.odl_port
        self._base_url = 'http://' + self._host + ':' + self._port + '/restconf'
        self._reg_ep_url = self._base_url + '/operations/openstack-endpoint:register-endpoint'
        self._unreg_ep_url = self._base_url + '/operations/endpoint:unregister-endpoint'
        self._tenants_url = self._base_url + '/config/policy:tenants'
        self._policy_url = self._tenants_url + '/policy:tenant'
        self._nodes_url = self._base_url + '/config/opendaylight-inventory:nodes'
        self._headers = {'Content-type': 'application/yang.data+json',
                         'Accept': 'application/yang.data+json'}

    def _sendjson(self, method, url, headers, obj):
        """Send json to the ODL controller."""

        data = jsonutils.dumps(obj, indent=2, sort_keys=True) if obj else None
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(obj)s)",
                  {'method': method, 'url': url, 'obj': obj})
        r = requests.request(method, url=url,
                             headers=headers, data=data,
                             auth=HTTPBasicAuth(self._username, self._password))
        r.raise_for_status()

    def register_endpoints(self, endpoints):
        for ep in endpoints:
            data = {"input": ep}
            self._sendjson('post', self._reg_ep_url, self._headers, data)

    def unregister_endpoints(self, endpoints):
        for ep in endpoints:
            data = {"input": ep}
            self._sendjson('post', self._unreg_ep_url, self._headers, data)

    def register_nodes(self, nodes):
        data = {"opendaylight-inventory:nodes": {"node": nodes}}
        self._sendjson('put', self._nodes_url, self._headers, data)

    def register_tenants(self, tenants):
        data = {"policy:tenants": {"tenant": tenants.values()}}
        self._sendjson('put', self._tenants_url, self._headers, data)

    def create_l3_context(self, tenant_id,l3ctx):
        url = self._policy_url + '/' + tenant_id + '/l3-context/' + l3ctx['id']
        data = {"l3-context": l3ctx}
        self._sendjson('put', url, self._headers, data)

    def delete_l3_context(self, tenant_id, l3ctx):
        url = self._policy_url + '/' + tenant_id + '/l3-context/' + l3ctx['id']
        self._sendjson('delete', url, self._headers, None)

    def create_update_tenant(self, tenant):
        url = self._policy_url + '/' + tenant['id']
        data = {"tenant": tenant}
        self._sendjson('put', url, self._headers, data)
