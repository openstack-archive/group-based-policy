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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as nexc
from neutron.common import log
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services import service_base

import gbpservice.neutron.extensions

# The code below is a monkey patch of key Neutron's modules. This is needed for
# the GBP service to be loaded correctly. GBP extensions' path is added
# to Neutron's so that it's found at extension scanning time.

extensions.append_api_extensions_path(gbpservice.neutron.extensions.__path__)
constants.SERVICECHAIN = "SERVICECHAIN"
constants.COMMON_PREFIXES["SERVICECHAIN"] = "/servicechain"

LOG = logging.getLogger(__name__)


# Service Chain Exceptions
class ServiceChainNodeNotFound(nexc.NotFound):
    message = _("ServiceChainNode %(sc_node_id)s could not be found")


class ServiceChainSpecNotFound(nexc.NotFound):
    message = _("ServiceChainSpec %(sc_spec_id)s could not be found")


class ServiceChainInstanceNotFound(nexc.NotFound):
    message = _("ServiceChainInstance %(sc_instance_id)s could not be found")


class ServiceChainNodeInUse(nexc.InUse):
    message = _("Unable to complete operation, ServiceChainNode "
                "%(node_id)s is in use")


class ServiceChainSpecInUse(nexc.InUse):
    message = _("Unable to complete operation, ServiceChainSpec "
                "%(spec_id)s is in use")


class ServiceTypeNotFound(nexc.NotFound):
    message = _("ServiceType %(service_type_id) could not be found")


class ServiceTypeNotSupported(nexc.NotFound):
    message = _("ServiceType %(service_type_id) not supported")


class PortNotFound(nexc.NotFound):
    message = _("Port %(port_id)s could not be found")


def _validate_str_list(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        LOG.debug(msg)
        return msg

    for item in data:
        msg = attr._validate_string(item)
        if msg:
            LOG.debug(msg)
            return msg

    if len(set(data)) != len(data):
        msg = _("Duplicate items in the list: '%s'") % ', '.join(data)
        LOG.debug(msg)
        return msg


attr.validators['type:string_list'] = _validate_str_list

SERVICECHAIN_NODES = 'servicechain_nodes'
SERVICECHAIN_SPECS = 'servicechain_specs'
SERVICECHAIN_INSTANCES = 'servicechain_instances'

RESOURCE_ATTRIBUTE_MAP = {
    SERVICECHAIN_NODES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'service_type': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:string': None},
                         'required': True, 'is_visible': True},
        'config': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:string': None},
                   'required': True, 'is_visible': True},
    },
    SERVICECHAIN_SPECS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'nodes': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:uuid_list': None},
                  'convert_to': attr.convert_none_to_empty_list,
                  'default': None, 'is_visible': True,
                  'required': True},
        'config_param_names': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:string_list': None},
                               'default': [], 'is_visible': True},
    },
    SERVICECHAIN_INSTANCES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'servicechain_specs': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_list': None},
                              'convert_to': attr.convert_none_to_empty_list,
                              'default': None, 'is_visible': True,
                              'required': True},
        'provider_ptg_id': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:uuid_or_none': None},
                         'is_visible': True, 'default': None,
                         'required': True},
        'consumer_ptg_id': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:uuid_or_none': None},
                         'is_visible': True, 'default': None,
                         'required': True},
        'classifier_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid_or_none': None},
                          'is_visible': True, 'default': None,
                          'required': True},
        'config_param_values': {'allow_post': True, 'allow_put': False,
                                'validate': {'type:string': None},
                                'default': "", 'is_visible': True},
    },
}


class Servicechain(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Service Chain Abstraction"

    @classmethod
    def get_alias(cls):
        return "servicechain"

    @classmethod
    def get_description(cls):
        return "Extension for Service Chain Abstraction"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/sc/v2.0/"

    @classmethod
    def get_updated(cls):
        return "2014-08-03T12:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.SERVICECHAIN)

    @classmethod
    def get_plugin_interface(cls):
        return ServiceChainPluginBase

    def update_attributes_map(self, attributes):
        super(Servicechain, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class ServiceChainPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.SERVICECHAIN

    def get_plugin_type(self):
        return constants.SERVICECHAIN

    def get_plugin_description(self):
        return 'Service Chain plugin'

    @abc.abstractmethod
    @log.log
    def get_servicechain_nodes(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def get_servicechain_node(self, context, servicechain_node_id,
                              fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def create_servicechain_node(self, context, servicechain_node):
        pass

    @abc.abstractmethod
    @log.log
    def update_servicechain_node(self, context, servicechain_node_id,
                                 servicechain_node):
        pass

    @abc.abstractmethod
    @log.log
    def delete_servicechain_node(self, context, servicechain_node_id):
        pass

    @abc.abstractmethod
    @log.log
    def get_servicechain_specs(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def get_servicechain_spec(self, context, servicechain_spec_id,
                              fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def create_servicechain_spec(self, context, servicechain_spec):
        pass

    @abc.abstractmethod
    @log.log
    def update_servicechain_spec(self, context, servicechain_spec_id,
                                 servicechain_spec):
        pass

    @abc.abstractmethod
    @log.log
    def delete_servicechain_spec(self, context, servicechain_spec_id):
        pass

    @abc.abstractmethod
    @log.log
    def get_servicechain_instances(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def get_servicechain_instance(self, context, servicechain_instance_id,
                                  fields=None):
        pass

    @abc.abstractmethod
    @log.log
    def create_servicechain_instance(self, context, servicechain_instance_id):
        pass

    @abc.abstractmethod
    @log.log
    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        pass

    @abc.abstractmethod
    @log.log
    def delete_servicechain_instance(self, context, servicechain_instance_id):
        pass
