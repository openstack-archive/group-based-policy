# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import webob.exc

from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_api_mixin as nm)
from gbpservice.neutron.services.grouppolicy.drivers import resource_mapping
from gbpservice.neutron.tests.unit import common as cm


# Based on the resource types, Neutron REST API calls need to be patched to
# different neutron-plugins.
PLUGIN_MAP = {
    'network': '_core_plugin',
    'subnet': '_core_plugin',
    'port': '_core_plugin',
    'security_group': '_core_plugin',
    'security_group_rule': '_core_plugin',
    'router': '_l3_plugin',
}

# Based on the resource types, WSGI calls need to be patched to
# different APIs.
API_MAP = {
    'network': 'api',
    'subnet': 'api',
    'port': 'api',
    'security_group': 'ext_api',
    'security_group_rule': 'ext_api',
    'router': 'ext_api',

}


# security-groups and security-group-rules appear in WSGI resource,
# but security_groups and security_group_rules appear in request body.
def _replace_sg_underscore(resources):
    return resources.replace('_', '-') if (
        'security_group' in resources) else resources


class Neutronv2MockMixin(object):
    """ A mixin class to mock Neutron REST APIs with WSGI calls.

    The _*_resource APIs defined in neutron_api_mixin.NeutronAPIMixin are
    patched here.
    """

    def _setUp_mock(self):
        mock_create = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                        '_create_neutron_resource',
                                        autospec=True).start()
        mock_create.side_effect = self._patched_create_resource
        mock_show = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                      '_get_neutron_resource',
                                      autospec=True).start()
        mock_show.side_effect = self._patched_get_resource
        mock_list = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                      '_get_neutron_resources',
                                      autospec=True).start()
        mock_list.side_effect = self._patched_get_resources
        mock_update = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                        '_update_neutron_resource',
                                        autospec=True).start()
        mock_update.side_effect = self._patched_update_resource
        mock_delete = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                        '_delete_neutron_resource',
                                        autospec=True).start()
        mock_delete.side_effect = self._patched_delete_resource
        mock_add = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                     '_add_router_interface',
                                     autospec=True).start()
        mock_add.side_effect = self._patched_add_router_interface
        mock_remove = mock.patch.object(resource_mapping.ResourceMappingDriver,
                                        '_remove_router_interface',
                                        autospec=True).start()
        mock_remove.side_effect = self._patched_remove_router_interface

    def _wsgi_req(self, req, api, context, detail, return_flag=True):
        req.environ['neutron.context'] = context
        ret = req.get_response(api)
        if ret.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(detail=detail,
                                            code=ret.status_int)
        if return_flag:
            return self.deserialize(self.fmt, ret)

    def _patched_create_resource(self, obj, context, resource, attrs):
        resources = _replace_sg_underscore(cm.get_resource_plural(resource))
        attrs = nm.remove_not_allowed_attrs(resource, attrs, 'post')
        data = {resource: nm.remove_not_specified_attrs(attrs)}
        api = getattr(self, API_MAP[resource])
        req = self.new_create_request(resources, data, self.fmt)
        return self._wsgi_req(req, api, context, resource)[resource]

    def _patched_get_resource(self, obj, context, resource, resource_id):
        resources = _replace_sg_underscore(cm.get_resource_plural(resource))
        api = getattr(self, API_MAP[resource])
        req = self.new_show_request(resources, resource_id)
        return self._wsgi_req(req, api, context, resource)[resource]

    def _patched_get_resources(self, obj, context, resource, filters={}):
        resources = cm.get_resource_plural(resource)
        formatted_resources = _replace_sg_underscore(resources)
        api = getattr(self, API_MAP[resource])
        filter_list = nm.get_filter_combinations(filters)

        res = []
        for filter in filter_list:
            params = None
            if filter:
                param_list = []
                for key, value in filter.iteritems():
                    # REVISIT(yi): need to replace equal sign = with %3D if
                    # present in value
                    param_list.append("%s=%s" % (key, value))
                params = '&'.join(param_list)

            req = self.new_list_request(formatted_resources, self.fmt, params)
            obj = self._wsgi_req(req, api, context, resource)[resources]
            res.extend(x for x in obj if x not in res)
        return res

    def _patched_update_resource(self, obj, context,
                                 resource, resource_id, attrs):
        resources = _replace_sg_underscore(cm.get_resource_plural(resource))
        attrs = nm.remove_not_allowed_attrs(resource, attrs, 'put')
        data = {resource: nm.remove_not_specified_attrs(attrs)}
        api = getattr(self, API_MAP[resource])
        req = self.new_update_request(resources, data, resource_id, self.fmt)
        return self._wsgi_req(req, api, context, resource)[resource]

    def _patched_delete_resource(self, obj, context, resource, resource_id):
        resources = _replace_sg_underscore(cm.get_resource_plural(resource))
        api = getattr(self, API_MAP[resource])
        req = self.new_delete_request(resources, resource_id)
        self._wsgi_req(req, api, context, resource, False)

    def _patched_add_router_interface(
            self, obj, context, router_id, interface):
        req = self.new_action_request(
            'routers', interface, router_id, 'add_router_interface')
        return self._wsgi_req(
            req, self.ext_api, context, 'add_router_interface')

    def _patched_remove_router_interface(
           self, obj, context, router_id, interface):
        req = self.new_action_request(
            'routers', interface, router_id, 'remove_router_interface')
        return self._wsgi_req(
            req, self.ext_api, context, 'remove_router_interface')