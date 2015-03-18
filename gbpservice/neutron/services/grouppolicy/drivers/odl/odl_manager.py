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
from requests import auth

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)

cfg.CONF.import_opt(
    'odl_username',
    'gbpservice.neutron.services.grouppolicy.drivers.odl.config',
    group='odl_driver'
)
cfg.CONF.import_opt(
    'odl_password',
    'gbpservice.neutron.services.grouppolicy.drivers.odl.config',
    group='odl_driver'
)
cfg.CONF.import_opt(
    'odl_host',
    'gbpservice.neutron.services.grouppolicy.drivers.odl.config',
    group='odl_driver'
)
cfg.CONF.import_opt(
    'odl_port',
    'gbpservice.neutron.services.grouppolicy.drivers.odl.config',
    group='odl_driver'
)


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
        self._headers = {
            'Content-type': 'application/yang.data+json',
            'Accept': 'application/yang.data+json',
        }

        self._base_url = (
            "http://%(host)s:%(port)s/restconf" %
            {'host': self._host, 'port': self._port}
        )
        self._reg_ep_url = (
            self._base_url +
            '/operations/endpoint:register-endpoint'
        )
        self._unreg_ep_url = (
            self._base_url +
            '/operations/endpoint:unregister-endpoint'
        )
        self._policy_url = (
            self._base_url +
            '/config/policy:tenants/policy:tenant/%(tenant_id)s'
        )
        self._action_url = (
            self._policy_url +
            '/subject-feature-instances/action-instance/%(action)s'
        )
        self._classifier_url = (
            self._policy_url +
            '/subject-feature-instances/classifier-instance/%(classifier)s'
        )
        self._l3ctx_url = (
            self._policy_url +
            '/l3-context/%(l3ctx)s'
        )
        self._l2bd_url = (
            self._policy_url +
            '/l2-bridge-domain/%(l2bd)s'
        )
        self._l2fd_url = (
            self._policy_url +
            '/l2-flood-domain/%(l2fd)s'
        )
        self._epg_url = (
            self._policy_url +
            '/policy:endpoint-group/%(epg)s'
        )
        self._subnet_url = (
            self._policy_url +
            '/subnet/%(subnet)s'
        )
        self._contract_url = (
            self._policy_url +
            '/policy:contract/%(contract)s'
        )

    def _convert2ascii(self, obj):
        if isinstance(obj, dict):
            return {self._convert2ascii(key): self._convert2ascii(value) for
                    key, value in obj.iteritems()}
        elif isinstance(obj, list):
            return [self._convert2ascii(element) for element in obj]
        elif isinstance(obj, unicode):
            return obj.encode('ascii', 'ignore')
        else:
            return obj

    def _sendjson(self, method, url, headers, obj=None):
        """Send json to the ODL controller."""

        medium = self._convert2ascii(obj) if obj else None
        url = self._convert2ascii(url)
        data = (
            jsonutils.dumps(medium, indent=4, sort_keys=True) if medium
            else None
        )
        LOG.debug("=========================================================")
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s)",
                  {'method': method, 'url': url})
        LOG.debug("(%(data)s)", {'data': data})
        LOG.debug("=========================================================")
        r = requests.request(
            method,
            url=url,
            headers=headers,
            data=data,
            auth=auth.HTTPBasicAuth(self._username,
                                    self._password)
        )
        r.raise_for_status()

    def _is_tenant_created(self, tenant_id):
        url = self._convert2ascii(self._policy_url % {'tenant_id': tenant_id})
        r = requests.request(
            'get',
            url=url,
            headers=self._headers,
            auth=auth.HTTPBasicAuth(self._username,
                                    self._password)
        )
        if r.status_code == 200:
            return True
        elif r.status_code == 404:
            return False
        else:
            r.raise_for_status()

    def register_endpoints(self, endpoints):
        for ep in endpoints:
            data = {"input": ep}
            self._sendjson('post', self._reg_ep_url, self._headers, data)

    def unregister_endpoints(self, endpoints):
        for ep in endpoints:
            data = {"input": ep}
            self._sendjson('post', self._unreg_ep_url, self._headers, data)

    def create_update_tenant(self, tenant_id, tenant):
        url = (self._policy_url % {'tenant_id': tenant_id})
        data = {"tenant": tenant}
        self._sendjson('put', url, self._headers, data)

    def create_action(self, tenant_id, action):
        """Create policy action"""
        self._touch_tenant(tenant_id)
        url = (self._action_url %
               {'tenant_id': tenant_id, 'action': action['name']})
        data = {"action-instance": action}
        self._sendjson('put', url, self._headers, data)

    def delete_action(self, tenant_id, action):
        """Delete policy action"""
        url = (self._action_url %
               {'tenant_id': tenant_id, 'action': action['name']})
        self._sendjson('delete', url, self._headers)

    def create_classifier(self, tenant_id, classifier):
        """Create policy classifier"""
        self._touch_tenant(tenant_id)
        url = (self._classifier_url %
               {'tenant_id': tenant_id, 'classifier': classifier['name']})
        data = {"classifier-instance": classifier}
        self._sendjson('put', url, self._headers, data)

    def delete_classifier(self, tenant_id, classifier):
        """Delete policy classifier"""
        url = (self._classifier_url %
               {'tenant_id': tenant_id, 'classifier': classifier['name']})
        self._sendjson('delete', url, self._headers)

    def create_update_l3_context(self, tenant_id, l3ctx):
        self._touch_tenant(tenant_id)
        url = (self._l3ctx_url %
               {'tenant_id': tenant_id, 'l3ctx': l3ctx['id']})
        data = {"l3-context": l3ctx}
        self._sendjson('put', url, self._headers, data)

    def delete_l3_context(self, tenant_id, l3ctx):
        url = (self._l3ctx_url %
               {'tenant_id': tenant_id, 'l3ctx': l3ctx['id']})
        self._sendjson('delete', url, self._headers)

    def create_update_l2_bridge_domain(self, tenant_id, l2bd):
        self._touch_tenant(tenant_id)
        url = (self._l2bd_url %
               {'tenant_id': tenant_id, 'l2bd': l2bd['id']})
        data = {"l2-bridge-domain": l2bd}
        self._sendjson('put', url, self._headers, data)

    def delete_l2_bridge_domain(self, tenant_id, l2bd):
        url = (self._l2bd_url %
               {'tenant_id': tenant_id, 'l2bd': l2bd['id']})
        self._sendjson('delete', url, self._headers)

    def create_update_l2_flood_domain(self, tenant_id, l2fd):
        self._touch_tenant(tenant_id)
        url = (self._l2fd_url %
               {'tenant_id': tenant_id, 'l2fd': l2fd['id']})
        data = {"l2-flood-domain": l2fd}
        self._sendjson('put', url, self._headers, data)

    def delete_l2_flood_domain(self, tenant_id, l2fd):
        url = (self._l2fd_url %
               {'tenant_id': tenant_id, 'l2fd': l2fd['id']})
        self._sendjson('delete', url, self._headers)

    def create_update_endpoint_group(self, tenant_id, epg):
        self._touch_tenant(tenant_id)
        url = (self._epg_url %
               {'tenant_id': tenant_id, 'epg': epg['id']})
        data = {"endpoint-group": epg}
        self._sendjson('put', url, self._headers, data)

    def delete_endpoint_group(self, tenant_id, epg):
        url = (self._epg_url %
               {'tenant_id': tenant_id, 'epg': epg['id']})
        self._sendjson('delete', url, self._headers)

    def create_update_subnet(self, tenant_id, subnet):
        self._touch_tenant(tenant_id)
        url = (self._subnet_url %
               {'tenant_id': tenant_id, 'subnet': subnet['id']})
        data = {"subnet": subnet}
        self._sendjson('put', url, self._headers, data)

    def delete_subnet(self, tenant_id, subnet):
        url = (self._subnet_url %
               {'tenant_id': tenant_id, 'subnet': subnet['id']})
        self._sendjson('delete', url, self._headers)

    def create_update_contract(self, tenant_id, contract):
        url = (self._contract_url %
               {'tenant_id': tenant_id, 'contract': contract['id']})
        data = {"contract": contract}
        self._sendjson('put', url, self._headers, data)

    def _touch_tenant(self, tenant_id):
        tenant = {
            "id": tenant_id
        }
        if not self._is_tenant_created(tenant_id):
            self.create_update_tenant(tenant_id, tenant)
