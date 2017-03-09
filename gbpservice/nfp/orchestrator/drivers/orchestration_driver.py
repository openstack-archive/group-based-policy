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

import ast
from collections import defaultdict
from neutron._i18n import _LE
from neutron._i18n import _LW

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import data_formatter as df
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.core import executor as nfp_executor
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import nfp_context_manager as nfp_ctx_mgr
from gbpservice.nfp.orchestrator.coal.networking import (
    nfp_gbp_network_driver
)
from gbpservice.nfp.orchestrator.coal.networking import (
    nfp_neutron_network_driver
)
from gbpservice.nfp.orchestrator.openstack import openstack_driver

LOG = nfp_logging.getLogger(__name__)


def _set_network_handler(f):
    def wrapped(self, *args, **kwargs):
        if type(args[0]) == dict:
            device_data = args[0]
        else:
            device_data = args[1]
        if device_data.get('service_details'):
            network_mode = device_data['service_details'].get('network_mode')
            if network_mode:
                kwargs['network_handler'] = self.network_handlers[network_mode]
        return f(self, *args, **kwargs)
    return wrapped


class OrchestrationDriver(object):
    """Generic Driver class for orchestration of virtual appliances

    Launches the VM with all the management and data ports and a new VM
    is launched for each Network Service Instance
    """

    def __init__(self, config, supports_device_sharing=False,
                 supports_hotplug=False, max_interfaces=8):
        self.service_vendor = 'general'
        self.supports_device_sharing = supports_device_sharing
        self.supports_hotplug = supports_hotplug
        self.maximum_interfaces = max_interfaces
        self.identity_handler = openstack_driver.KeystoneClient(config)
        self.compute_handler_nova = openstack_driver.NovaClient(config)
        self.network_handlers = {
            nfp_constants.GBP_MODE:
                nfp_gbp_network_driver.NFPGBPNetworkDriver(config),
            nfp_constants.NEUTRON_MODE:
                nfp_neutron_network_driver.NFPNeutronNetworkDriver(config)
        }
        self.config = config

    def _get_admin_tenant_id(self, token=None):
        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            if not token:
                token = kcm.retry(
                    self.identity_handler.get_admin_token, tries=3)
            admin_tenant_name = (
                self.config.nfp_keystone_authtoken.admin_tenant_name)
            admin_tenant_id = kcm.retry(self.identity_handler.get_tenant_id,
                                        token,
                                        admin_tenant_name, tries=3)
            return admin_tenant_id

    def _get_token(self, device_data_token):

        with nfp_ctx_mgr.KeystoneContextManager as kcm:
            token = (device_data_token
                     if device_data_token
                     else kcm.retry(
                         self.identity_handler.get_admin_token, tries=3))
            return token

    def _is_device_sharing_supported(self):
        return False

    def _create_management_interface(self, token, admin_tenant_id,
                                     device_data, network_handler):

        name = nfp_constants.MANAGEMENT_INTERFACE_NAME
        mgmt_interface = network_handler.create_port(
            token,
            admin_tenant_id,
            device_data['management_network_info']['id'],
            name=name)

        return {'id': mgmt_interface['id'],
                'port_id': mgmt_interface['port_id'],
                'port_model': (nfp_constants.GBP_PORT
                               if device_data['service_details'][
                                   'network_mode'] ==
                               nfp_constants.GBP_MODE
                               else nfp_constants.NEUTRON_PORT),
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': None}

    def _delete_interface(self, device_data, interface,
                          network_handler=None):
        token = self._get_token(device_data.get('token'))
        if not token:
            return None

        network_handler.delete_port(token, interface['id'])

    def _get_interfaces_for_device_create(self, token, admin_tenant_id,
                                          network_handler, device_data):
        try:
            mgmt_interface = self._create_management_interface(
                token,
                admin_tenant_id,
                device_data,
                network_handler)
            device_data['interfaces'] = [mgmt_interface]
        except Exception as e:
            LOG.exception(_LE('Failed to get interfaces for device creation.'
                              'Error: %(error)s'), {'error': e})

    def _delete_interfaces(self, device_data, interfaces,
                           network_handler=None):
        for interface in interfaces:
            self._delete_interface(
                device_data, interface,
                network_handler=network_handler)

    def _verify_provider_metadata(self, image_name, metadata):
        provider_metadata = {}
        try:
            for attr in metadata:
                if attr in nfp_constants.METADATA_SUPPORTED_ATTRIBUTES:
                    provider_metadata[attr] = ast.literal_eval(metadata[attr])
        except Exception as e:
            LOG.error(_LE('Wrong metadata: %(metadata)s provided for '
                          'image name: %(image_name)s. Error: %(error)s'),
                      {'image_name': image_name, 'metadata': metadata,
                       'error': e})
            return None
        return provider_metadata

    def _get_provider_metadata(self, device_data, image_name):
        token = self._get_token(device_data.get('token'))
        if not token:
            return None
        with nfp_ctx_mgr.NovaContextManager as ncm:
            metadata = ncm.retry(self.compute_handler_nova.get_image_metadata,
                                 token,
                                 self._get_admin_tenant_id(token=token),
                                 image_name)
        provider_metadata = self._verify_provider_metadata(
            image_name, metadata)
        if not provider_metadata:
            return {}
        return provider_metadata

    def _get_provider_metadata_fast(self, token,
                                    admin_tenant_id, image_name, device_data):
        with nfp_ctx_mgr.NovaContextManager as ncm:
            metadata = ncm.retry(self.compute_handler_nova.get_image_metadata,
                                 token,
                                 admin_tenant_id,
                                 image_name)
        provider_metadata = self._verify_provider_metadata(
            image_name, metadata)
        if not provider_metadata:
            return {}
        return provider_metadata

    def _update_self_with_provider_metadata(self, provider_metadata, attr):
        attr_value = getattr(self, attr)
        if attr in provider_metadata:
            setattr(self, attr, provider_metadata[attr])
        else:
            LOG.debug("Provider metadata specified in image, doesn't contains "
                      "%s value, proceeding with default value "
                      "%s" % (attr, attr_value))

    def _update_provider_metadata(self, device_data, token=None):
        provider_metadata = {}
        try:
            image_name = self._get_image_name(device_data)
            provider_metadata = self._get_provider_metadata(device_data,
                                                            image_name)
            LOG.debug("Provider metadata, specified in image: %s"
                      % provider_metadata)
            if provider_metadata:
                self._update_self_with_provider_metadata(
                    provider_metadata,
                    nfp_constants.MAXIMUM_INTERFACES)
                self._update_self_with_provider_metadata(
                    provider_metadata,
                    nfp_constants.SUPPORTS_HOTPLUG)
            else:
                LOG.debug("No provider metadata specified in image,"
                          " proceeding with default values")
        except Exception:
            LOG.error(_LE("Error while getting metadata for image name:"
                          "%(image_name)s, proceeding with default values"),
                      {'image_name': image_name})
        return provider_metadata

    def _update_provider_metadata_fast(self, token, admin_tenant_id,
                                       image_name, device_data):
        provider_metadata = None
        try:
            provider_metadata = self._get_provider_metadata_fast(
                token, admin_tenant_id, image_name, device_data)
            LOG.debug("Provider metadata, specified in image: %s"
                      % provider_metadata)
            if provider_metadata:
                self._update_self_with_provider_metadata(
                    provider_metadata,
                    nfp_constants.MAXIMUM_INTERFACES)
                self._update_self_with_provider_metadata(
                    provider_metadata,
                    nfp_constants.SUPPORTS_HOTPLUG)
            else:
                LOG.debug("No provider metadata specified in image,"
                          " proceeding with default values")
        except Exception:
            LOG.error(_LE("Error while getting metadata for image name: "
                          "%(image_name)s, proceeding with default values"),
                      {'image_name': image_name})
        return provider_metadata

    def _get_image_name(self, device_data):
        if device_data['service_details'].get('image_name'):
            image_name = device_data['service_details']['image_name']
        else:
            LOG.debug("No image name provided in service profile's "
                      "service flavor field, image will be selected "
                      "based on service vendor's name : %s"
                      % (device_data['service_details']['service_vendor']))
            image_name = device_data['service_details']['service_vendor']
            image_name = '%s' % image_name.lower()
            device_data['service_details']['image_name'] = image_name
        return image_name

    def _get_service_type(self, token, service_profile_id, network_handler):
        service_profile = network_handler.get_service_profile(
            token, service_profile_id)
        return service_profile['service_type']

    def _get_device_service_types_map(self, token, devices, network_handler):
        device_service_types_map = defaultdict(set)
        for device in devices:
            for network_function in device['network_functions']:
                service_type = self._get_service_type(
                    token,
                    network_function['service_profile_id'],
                    network_handler)
                device_service_types_map[device['id']].add(service_type)
        return device_service_types_map

    def get_image_id(self, nova, token, admin_tenant_id, image_name):
        try:
            image_id = nova.get_image_id(token, admin_tenant_id, image_name)
            return image_id
        except Exception as e:
            LOG.error(_LE('Failed to get image id for device creation.'
                          ' image name: %(image_name)s. Error: %(error)s'),
                      {'image_name': image_name, 'error': e})

    def create_instance(self, nova, token, admin_tenant_id,
                        image_id, flavor, interfaces_to_attach,
                        instance_name, volume_support,
                        volume_size, files=None, user_data=None,
                        server_grp_id=None):
        try:
            instance_id = nova.create_instance(
                token, admin_tenant_id, image_id, flavor,
                interfaces_to_attach, instance_name, volume_support,
                volume_size, files=files, userdata=user_data,
                server_grp_id=server_grp_id)
            return instance_id
        except Exception as e:
            LOG.error(_LE('Failed to create instance.'
                          'Error: %(error)s'), {'error': e})

    def get_neutron_port_details(self, network_handler, token, port_id):
        try:
            (mgmt_ip_address,
             mgmt_mac, mgmt_cidr, gateway_ip,
             mgmt_port, mgmt_subnet) = (
                network_handler.get_neutron_port_details(token, port_id))

            result = {'neutron_port': mgmt_port['port'],
                      'neutron_subnet': mgmt_subnet['subnet'],
                      'ip_address': mgmt_ip_address,
                      'mac': mgmt_mac,
                      'cidr': mgmt_cidr,
                      'gateway_ip': gateway_ip}
            return result
        except Exception as e:
            import sys
            import traceback
            exc_type, exc_value, exc_traceback = sys.exc_info()
            LOG.error(traceback.format_exception(exc_type, exc_value,
                                                 exc_traceback))
            LOG.error(_LE('Failed to get management port details. '
                          'Error: %(error)s'), {'error': e})

    @_set_network_handler
    def create_network_function_device(self, device_data,
                                       network_handler=None):
        """ Create a NFD

        :param device_data: NFD data
        :type device_data: dict

        :returns: None -- when there is a failure in creating NFD
        :return: dict -- NFD created

        :raises: exceptions.IncompleteData,
                 exceptions.ComputePolicyNotSupported
        """
        self._validate_create_nfd_data(device_data)

        token = device_data['token']
        admin_tenant_id = device_data['admin_tenant_id']
        image_name = self._get_image_name(device_data)

        pre_launch_executor = nfp_executor.TaskExecutor(jobs=3)

        image_id_result = {}
        provider_metadata_result = {}

        pre_launch_executor.add_job('UPDATE_PROVIDER_METADATA',
                                    self._update_provider_metadata_fast,
                                    token, admin_tenant_id,
                                    image_name, device_data,
                                    result_store=provider_metadata_result)
        pre_launch_executor.add_job('GET_INTERFACES_FOR_DEVICE_CREATE',
                                    self._get_interfaces_for_device_create,
                                    token, admin_tenant_id,
                                    network_handler, device_data)
        pre_launch_executor.add_job('GET_IMAGE_ID',
                                    self.get_image_id,
                                    self.compute_handler_nova, token,
                                    admin_tenant_id,
                                    image_name, result_store=image_id_result)

        pre_launch_executor.fire()

        interfaces, image_id, provider_metadata = (
            self._validate_pre_launch_executor_results(
                network_handler,
                device_data,
                image_name,
                image_id_result,
                provider_metadata_result))
        if not interfaces:
            return None

        management_interface = interfaces[0]
        flavor = self._get_service_instance_flavor(device_data)

        interfaces_to_attach = []
        try:
            for interface in interfaces:
                interfaces_to_attach.append({'port': interface['port_id']})
            if provider_metadata.get('supports_hotplug') is False:
                self._update_interfaces_for_non_hotplug_support(
                    network_handler,
                    interfaces,
                    interfaces_to_attach,
                    device_data)
        except Exception as e:
            LOG.error(_LE('Failed to fetch list of interfaces to attach'
                          ' for device creation %(error)s'), {'error': e})
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None

        instance_name = device_data['name']

        create_instance_executor = nfp_executor.TaskExecutor(jobs=3)
        instance_id_result = {}
        port_details_result = {}
        volume_support = device_data['volume_support']
        volume_size = device_data['volume_size']
        create_instance_executor.add_job(
            'CREATE_INSTANCE', self.create_instance,
            self.compute_handler_nova, token,
            admin_tenant_id, image_id, flavor,
            interfaces_to_attach, instance_name,
            volume_support, volume_size,
            files=device_data.get('files'),
            user_data=device_data.get('user_data'),
            result_store=instance_id_result)

        create_instance_executor.add_job(
            'GET_NEUTRON_PORT_DETAILS',
            self.get_neutron_port_details,
            network_handler, token,
            management_interface['port_id'],
            result_store=port_details_result)

        create_instance_executor.fire()

        instance_id, mgmt_neutron_port_info = (
            self._validate_create_instance_executor_results(
                network_handler,
                device_data,
                interfaces,
                instance_id_result,
                port_details_result))
        if not instance_id:
            return None

        mgmt_ip_address = mgmt_neutron_port_info['ip_address']
        return {'id': instance_id,
                'name': instance_name,
                'provider_metadata': provider_metadata,
                'mgmt_ip_address': mgmt_ip_address,
                'mgmt_port_id': interfaces[0],
                'mgmt_neutron_port_info': mgmt_neutron_port_info,
                'max_interfaces': self.maximum_interfaces,
                'interfaces_in_use': len(interfaces_to_attach),
                'description': ''}  # TODO(RPM): what should be the description

    def _validate_create_nfd_data(self, device_data):
        if (
            any(key not in device_data
                for key in ['service_details',
                            'name',
                            'management_network_info',
                            'ports']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            any(key not in device_data['management_network_info']
                for key in ['id']) or

            type(device_data['ports']) is not list or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            raise exceptions.IncompleteData()

        if (
            device_data['service_details']['device_type'] !=
            nfp_constants.NOVA_MODE
        ):
            raise exceptions.ComputePolicyNotSupported(
                compute_policy=device_data['service_details']['device_type'])

    def _validate_pre_launch_executor_results(self, network_handler,
                                              device_data,
                                              image_name,
                                              image_id_result,
                                              provider_metadata_result,
                                              server_grp_id_result=None):
        interfaces = device_data.pop('interfaces', None)
        if not interfaces:
            LOG.exception(_LE('Failed to get interfaces for device creation.'))
            return None, _, _

        image_id = image_id_result.get('result', None)
        if not image_id:
            LOG.error(_LE('Failed to get image id for device creation.'))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None, _, _

        if server_grp_id_result and not server_grp_id_result.get('result'):
            LOG.error(_LE('Validation failed for Nova anti-affinity '
                          'server group.'))
            return None, _, _

        provider_metadata = provider_metadata_result.get('result', None)
        if not provider_metadata:
            LOG.warning(_LW('Failed to get provider metadata for'
                            ' device creation.'))
            provider_metadata = {}

        return interfaces, image_id, provider_metadata

    def _get_service_instance_flavor(self, device_data):
        if device_data['service_details'].get('flavor'):
            flavor = device_data['service_details']['flavor']
        else:
            LOG.debug("No Device flavor provided in service profile's "
                      "service flavor field, using default "
                      "flavor: m1.medium")
            flavor = 'm1.medium'
        return flavor

    def _update_interfaces_for_non_hotplug_support(self, network_handler,
                                                   interfaces,
                                                   interfaces_to_attach,
                                                   device_data):
        token = device_data['token']
        enable_port_security = device_data.get('enable_port_security')
        if not device_data['interfaces_to_attach']:
            for port in device_data['ports']:
                if (port['port_classification'] ==
                        nfp_constants.PROVIDER):
                    if (device_data['service_details'][
                        'service_type'].lower()
                        in [nfp_constants.FIREWALL.lower(),
                            nfp_constants.VPN.lower()]):
                        network_handler.set_promiscuos_mode(
                            token, port['id'], enable_port_security)
                    port_id = network_handler.get_port_id(
                        token, port['id'])
                    interfaces_to_attach.append({'port': port_id})
            for port in device_data['ports']:
                if (port['port_classification'] ==
                        nfp_constants.CONSUMER):
                    if (device_data['service_details'][
                        'service_type'].lower()
                        in [nfp_constants.FIREWALL.lower(),
                            nfp_constants.VPN.lower()]):
                        network_handler.set_promiscuos_mode(
                            token, port['id'], enable_port_security)
                    port_id = network_handler.get_port_id(
                        token, port['id'])
                    interfaces_to_attach.append({'port': port_id})
        else:
            for interface in device_data['interfaces_to_attach']:
                interfaces_to_attach.append(
                    {'port': interface['port']})
                interfaces.append({'id': interface['id']})

    def _validate_create_instance_executor_results(self,
                                                   network_handler,
                                                   device_data,
                                                   interfaces,
                                                   instance_id_result,
                                                   port_details_result):
        token = device_data['token']
        admin_tenant_id = device_data['admin_tenant_id']
        instance_id = instance_id_result.get('result', None)
        if not instance_id:
            LOG.error(_LE('Failed to create instance with device data:'
                          '%(data)s.'),
                      {'data': device_data})
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None, _

        mgmt_neutron_port_info = port_details_result.get('result', None)

        if not mgmt_neutron_port_info:
            LOG.error(_LE('Failed to get management port details. '))
            with nfp_ctx_mgr.NovaContextManager as ncm:
                ncm.retry(self.compute_handler_nova.delete_instance,
                          token,
                          admin_tenant_id,
                          instance_id)
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None, _
        return instance_id, mgmt_neutron_port_info

    @_set_network_handler
    def delete_network_function_device(self, device_data,
                                       network_handler=None):
        """ Delete the NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- Both on success and Failure

        :raises: exceptions.IncompleteData,
                 exceptions.ComputePolicyNotSupported
        """
        if (
            any(key not in device_data
                for key in ['service_details',
                            'mgmt_port_id']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            type(device_data['mgmt_port_id']) is not dict or

            any(key not in device_data['mgmt_port_id']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            raise exceptions.IncompleteData()

        if (
            device_data['service_details']['device_type'] !=
            nfp_constants.NOVA_MODE
        ):
            raise exceptions.ComputePolicyNotSupported(
                compute_policy=device_data['service_details']['device_type'])

        token = self._get_token(device_data.get('token'))

        if not token:
            return None

        if device_data.get('id'):
            # delete the device instance
            #
            # this method will be invoked again
            # once the device instance deletion is completed
            with nfp_ctx_mgr.NovaContextManager.new(
                    suppress=(Exception,)) as ncm:

                ncm.retry(self.compute_handler_nova.delete_instance,
                          token,
                          device_data['tenant_id'],
                          device_data['id'])
        else:
            # device instance deletion is done, delete remaining resources
            try:
                interfaces = [device_data['mgmt_port_id']]
                self._delete_interfaces(device_data,
                                        interfaces,
                                        network_handler=network_handler)
            except Exception as e:
                LOG.error(_LE('Failed to delete the management data port(s). '
                              'Error: %(error)s'), {'error': e})

    def get_network_function_device_status(self, device_data,
                                           ignore_failure=False):
        """ Get the status of NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- On failure
        :return: str -- status string

        :raises: exceptions.IncompleteData,
                 exceptions.ComputePolicyNotSupported
        """
        if (
            any(key not in device_data
                for key in ['id',
                            'service_details']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode'])
        ):
            raise exceptions.IncompleteData()

        if (
            device_data['service_details']['device_type'] !=
            nfp_constants.NOVA_MODE
        ):
            raise exceptions.ComputePolicyNotSupported(
                compute_policy=device_data['service_details']['device_type'])

        token = self._get_token(device_data.get('token'))

        if not token:
            return None

        with nfp_ctx_mgr.NovaContextManager.new(suppress=(Exception,)) as ncm:
            device = ncm.retry(self.compute_handler_nova.get_instance,
                               device_data['token'],
                               device_data['tenant_id'],
                               device_data['id'])

            return device['status']

    @_set_network_handler
    def plug_network_function_device_interfaces(self, device_data,
                                                network_handler=None):
        """ Attach the network interfaces for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: bool -- False on failure and True on Success

        :raises: exceptions.IncompleteData,
                 exceptions.ComputePolicyNotSupported
        """

        if (
            any(key not in device_data
                for key in ['id',
                            'service_details',
                            'ports']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            type(device_data['ports']) is not list or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            raise exceptions.IncompleteData()

        if (
            device_data['service_details']['device_type'] !=
            nfp_constants.NOVA_MODE
        ):
            raise exceptions.ComputePolicyNotSupported(
                compute_policy=device_data['service_details']['device_type'])

        token = device_data['token']
        tenant_id = device_data['tenant_id']
        provider_metadata = device_data['provider_metadata']
        enable_port_security = device_data.get('enable_port_security')

        if provider_metadata.get('supports_hotplug') is False:
            return True
        try:
            executor = nfp_executor.TaskExecutor(jobs=10)

            for port in device_data['ports']:
                if port['port_classification'] == nfp_constants.PROVIDER:
                    service_type = device_data[
                        'service_details']['service_type'].lower()
                    if service_type.lower() in [
                            nfp_constants.FIREWALL.lower(),
                            nfp_constants.VPN.lower()]:
                        executor.add_job(
                            'SET_PROMISCUOS_MODE',
                            network_handler.set_promiscuos_mode_fast,
                            token, port['id'], enable_port_security)
                    executor.add_job(
                        'ATTACH_INTERFACE',
                        self.compute_handler_nova.attach_interface,
                        token, tenant_id, device_data['id'],
                        port['id'])
                    break
            executor.fire()

            for port in device_data['ports']:
                if port['port_classification'] == nfp_constants.CONSUMER:
                    service_type = device_data[
                        'service_details']['service_type'].lower()
                    if service_type.lower() in [
                            nfp_constants.FIREWALL.lower(),
                            nfp_constants.VPN.lower()]:
                        executor.add_job(
                            'SET_PROMISCUOS_MODE',
                            network_handler.set_promiscuos_mode_fast,
                            token, port['id'], enable_port_security)
                    executor.add_job(
                        'ATTACH_INTERFACE',
                        self.compute_handler_nova.attach_interface,
                        token, tenant_id, device_data['id'],
                        port['id'])
                    break
            executor.fire()

        except Exception as e:
            LOG.error(_LE('Failed to plug interface(s) to the device.'
                          'Error: %(error)s'), {'error': e})
            return None
        else:
            return True

    @_set_network_handler
    def unplug_network_function_device_interfaces(self, device_data,
                                                  network_handler=None):
        """ Detach the network interfaces for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: bool -- False on failure and True on Success

        :raises: exceptions.IncompleteData,
                 exceptions.ComputePolicyNotSupported
        """

        if (
            any(key not in device_data
                for key in ['id',
                            'service_details',
                            'ports']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            raise exceptions.IncompleteData()

        if (
            device_data['service_details']['device_type'] !=
            nfp_constants.NOVA_MODE
        ):
            raise exceptions.ComputePolicyNotSupported(
                compute_policy=device_data['service_details']['device_type'])

        token = self._get_token(device_data.get('token'))

        if not token:
            return None

        image_name = self._get_image_name(device_data)
        provider_metadata = {}
        if image_name:
            provider_metadata = (
                self._update_provider_metadata_fast(token,
                                                    device_data['tenant_id'],
                                                    image_name,
                                                    device_data))

        if not provider_metadata:
            LOG.debug('Failed to get provider metadata for'
                      ' device deletion.')

        if provider_metadata.get('supports_hotplug') is False:
            return True

        with nfp_ctx_mgr.NovaContextManager.new(suppress=(Exception,)) as ncm:
            for port in device_data['ports']:
                port_id = network_handler.get_port_id(token, port['id'])
                ncm.retry(self.compute_handler_nova.detach_interface,
                          token,
                          device_data['tenant_id'],
                          device_data['id'],
                          port_id)
            return True

    @_set_network_handler
    def get_delete_device_data(self, device_data, network_handler=None):
        """ Get the configuration information for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- On Failure
        :returns: dict

        :raises: exceptions.IncompleteData

        """

        if (
            any(key not in device_data
                for key in ['service_details',
                            'mgmt_ip_address',
                            'ports']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            type(device_data['ports']) is not list or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            LOG.error(_LE('Incomplete device data received for delete '
                          'network function device.'))
            return None

        token = self._get_token(device_data.get('token'))
        if not token:
            return None

        provider_ip = None
        provider_mac = None
        provider_cidr = None
        consumer_ip = None
        consumer_mac = None
        consumer_cidr = None
        consumer_gateway_ip = None

        for port in device_data['ports']:
            if port['port_classification'] == nfp_constants.PROVIDER:
                try:
                    (provider_ip, provider_mac, provider_cidr, dummy, _, _) = (
                        network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    LOG.error(_LE('Failed to get provider port details'
                                  ' for get device config info operation'))
                    return None
            elif port['port_classification'] == nfp_constants.CONSUMER:
                try:
                    (consumer_ip, consumer_mac, consumer_cidr,
                     consumer_gateway_ip, _, _) = (
                        network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    LOG.error(_LE('Failed to get consumer port details'
                                  ' for get device config info operation'))
                    return None

        device_data.update({
            'provider_ip': provider_ip, 'provider_mac': provider_mac,
            'provider_cidr': provider_cidr, 'consumer_ip': consumer_ip,
            'consumer_mac': consumer_mac, 'consumer_cidr': consumer_cidr,
            'consumer_gateway_ip': consumer_gateway_ip})

        return device_data

    @_set_network_handler
    def get_network_function_device_config(self, device_data,
                                           resource_type, is_delete=False,
                                           network_handler=None):
        """ Get the configuration information for NFD

        :returns: dict

        """

        if is_delete:
            device_data = self.get_delete_device_data(
                device_data, network_handler=network_handler)
            if not device_data:
                return None

        return df.get_network_function_info(
            device_data, resource_type)
