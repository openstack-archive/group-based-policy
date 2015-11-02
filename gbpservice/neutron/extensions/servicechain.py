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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as nexc
from neutron.plugins.common import constants
from neutron.quota import resource_registry
from neutron.services import service_base
from oslo_config import cfg
from oslo_log import log as logging
import six

import gbpservice.neutron.extensions
import gbpservice.neutron.extensions.group_policy  # noqa
from gbpservice.neutron.services.servicechain.common import constants as scc


# The code below is a monkey patch of key Neutron's modules. This is needed for
# the GBP service to be loaded correctly. GBP extensions' path is added
# to Neutron's so that it's found at extension scanning time.
extensions.append_api_extensions_path(gbpservice.neutron.extensions.__path__)
LOG = logging.getLogger(__name__)


# Service Chain Exceptions
class ServiceProfileNotFound(nexc.NotFound):
    message = _("ServiceProfile %(profile_id)s could not be found")


class ServiceProfileInUse(nexc.NotFound):
    message = _("Unable to complete operation, ServiceProfile "
                "%(profile_id)s is in use")


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
SERVICE_PROFILES = 'service_profiles'

RESOURCE_ATTRIBUTE_MAP = {
    SERVICECHAIN_NODES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'service_type': {'allow_post': True, 'allow_put': False,
                         'validate': {'type:string_or_none': None},
                         'is_visible': True, 'default': None},
        'service_profile_id': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True, 'default': None},
        'config': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'required': True, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    SERVICECHAIN_SPECS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    SERVICECHAIN_INSTANCES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
                            'validate': {'type:string_or_none': None},
                            'is_visible': True, 'default': None,
                            'required': True},
        'management_ptg_id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid_or_none': None},
                              'is_visible': True, 'default': None,
                              'required': True},
        'classifier_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:uuid_or_none': None},
                          'is_visible': True, 'default': None,
                          'required': True},
        'config_param_values': {'allow_post': True, 'allow_put': False,
                                'validate': {'type:string': None},
                                'default': "", 'is_visible': True},
    },
    SERVICE_PROFILES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        'vendor': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'is_visible': True, 'default': ''},
        'insertion_mode': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:values':
                                        scc.VALID_INSERTION_MODES},
                           'is_visible': True, 'default': None},
        'service_type': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'is_visible': True, 'required': True},
        'service_flavor': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:string_or_none': None},
                           'is_visible': True, 'default': None},
    },
}


service_chain_quota_opts = [
    cfg.IntOpt('quota_servicechain_node',
               default=-1,
               help=_('Number of Service Chain Nodes allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_servicechain_spec',
               default=-1,
               help=_('Number of Service Chain Specs allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_servicechain_instance',
               default=-1,
               help=_('Number of Service Chain Instances allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_service_profile',
               default=-1,
               help=_('Number of Service Profiles allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(service_chain_quota_opts, 'QUOTAS')


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
        for resource_name in ['servicechain_node', 'servicechain_spec',
                              'servicechain_instance', 'service_profile']:
            resource_registry.register_resource_by_name(resource_name)
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

    def update_chains_pt_added(self, context, policy_target, instance_id):
        """ Auto scaling function.

        Override this method to react to policy target creation.
        """
        pass

    def update_chains_pt_removed(self, context, policy_target, instance_id):
        """ Auto scaling function.

        Override this method to react to policy target deletion.
        """
        pass

    def update_chains_consumer_added(self, context, policy_target_group,
                                     instance_id):
        """ Auto scaling function.

        Override this method to react to policy target group addition as
        a consumer of a chain.
        """
        pass

    def update_chains_consumer_removed(self, context, policy_target_group,
                                       instance_id):
        """ Auto scaling function.

        Override this method to react to policy target group removed as a
        consumer of a chain
        """
        pass

    @abc.abstractmethod
    def get_servicechain_nodes(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_servicechain_node(self, context, servicechain_node_id,
                              fields=None):
        pass

    @abc.abstractmethod
    def create_servicechain_node(self, context, servicechain_node):
        pass

    @abc.abstractmethod
    def update_servicechain_node(self, context, servicechain_node_id,
                                 servicechain_node):
        pass

    @abc.abstractmethod
    def delete_servicechain_node(self, context, servicechain_node_id):
        pass

    @abc.abstractmethod
    def get_servicechain_specs(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_servicechain_spec(self, context, servicechain_spec_id,
                              fields=None):
        pass

    @abc.abstractmethod
    def create_servicechain_spec(self, context, servicechain_spec):
        pass

    @abc.abstractmethod
    def update_servicechain_spec(self, context, servicechain_spec_id,
                                 servicechain_spec):
        pass

    @abc.abstractmethod
    def delete_servicechain_spec(self, context, servicechain_spec_id):
        pass

    @abc.abstractmethod
    def get_servicechain_instances(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_servicechain_instance(self, context, servicechain_instance_id,
                                  fields=None):
        pass

    @abc.abstractmethod
    def create_servicechain_instance(self, context, servicechain_instance):
        pass

    @abc.abstractmethod
    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        pass

    @abc.abstractmethod
    def delete_servicechain_instance(self, context, servicechain_instance_id):
        pass

    @abc.abstractmethod
    def create_service_profile(self, context, service_profile):
        pass

    @abc.abstractmethod
    def update_service_profile(self, context, service_profile_id,
                               service_profile):
        pass

    @abc.abstractmethod
    def delete_service_profile(self, context, service_profile_id):
        pass

    @abc.abstractmethod
    def get_service_profile(self, context, service_profile_id, fields=None):
        pass

    @abc.abstractmethod
    def get_service_profiles(self, context, filters=None, fields=None):
        pass
