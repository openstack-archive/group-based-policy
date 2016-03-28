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
import collections
from neutron import i18n
from oslo_utils import excutils

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.core import executor as nfp_executor
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.orchestrator.coal.networking import (
    nfp_neutron_network_driver as nfp_neutron_network_driver)
from gbpservice.nfp.orchestrator.coal.networking import nfp_gbp_network_driver
from gbpservice.nfp.orchestrator.openstack import openstack_driver

LOG = nfp_logging.getLogger(__name__)
_LE = i18n._LE
_LI = i18n._LI


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
                 supports_hotplug=False, max_interfaces=10):
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
        try:
            if not token:
                token = self.identity_handler.get_admin_token()
            admin_tenant_id = self.identity_handler.get_tenant_id(
                token,
                self.config.keystone_authtoken.admin_tenant_name)
            return admin_tenant_id
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to get admin's tenant ID"))

    def _get_token(self, device_data_token):

        try:
            token = (device_data_token
                     if device_data_token
                     else self.identity_handler.get_admin_token())
        except Exception:
            LOG.error(_LE('Failed to get token'))
            return None
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

    def _verify_vendor_data(self, image_name, metadata):
        vendor_data = {}
        try:
            for attr in metadata:
                if attr in nfp_constants.METADATA_SUPPORTED_ATTRIBUTES:
                    vendor_data[attr] = ast.literal_eval(metadata[attr])
        except Exception as e:
            LOG.error(_LE('Wrong metadata: %(metadata)s provided for '
                          'image name: %(image_name)s. Error: %(error)s'),
                      {'image_name': image_name, 'metadata': metadata,
                       'error': e})
            return None
        return vendor_data

    def _get_vendor_data(self, device_data, image_name):
        token = self._get_token(device_data.get('token'))
        if not token:
            return None
        try:
            metadata = self.compute_handler_nova.get_image_metadata(
                token,
                self._get_admin_tenant_id(token=token),
                image_name)
        except Exception as e:
            LOG.error(_LE('Failed to get image metadata for image '
                          'name: %(image_name)s. Error: %(error)s'),
                      {'image_name': image_name, 'error': e})
            return None
        vendor_data = self._verify_vendor_data(image_name, metadata)
        if not vendor_data:
            return None
        return vendor_data

    def _get_vendor_data_fast(self, token,
                            admin_tenant_id, image_name, device_data):
        try:
            metadata = self.compute_handler_nova.get_image_metadata(
                token,
                admin_tenant_id,
                image_name)
        except Exception as e:
            LOG.error(_LE('Failed to get image metadata for image '
                          'name: %(image_name)s. Error: %(error)s'),
                      {'image_name': image_name, 'error': e})
            return None
        vendor_data = self._verify_vendor_data(image_name, metadata)
        if not vendor_data:
            return None
        return vendor_data

    def _update_self_with_vendor_data(self, vendor_data, attr):
        attr_value = getattr(self, attr)
        if attr in vendor_data:
            setattr(self, attr, vendor_data[attr])
        else:
            LOG.info(_LI("Vendor data specified in image, doesn't contains "
                         "%(attr)s value, proceeding with default value "
                         "%(default)s"),
                     {'attr': attr, 'default': attr_value})

    def _update_vendor_data(self, device_data, token=None):
        try:
            image_name = self._get_image_name(device_data)
            vendor_data = self._get_vendor_data(device_data, image_name)
            LOG.info(_LI("Vendor data, specified in image: %(vendor_data)s"),
                     {'vendor_data': vendor_data})
            if vendor_data:
                self._update_self_with_vendor_data(
                    vendor_data,
                    nfp_constants.MAXIMUM_INTERFACES)
            else:
                LOG.info(_LI("No vendor data specified in image, "
                             "proceeding with default values"))
        except Exception:
            LOG.error(_LE("Error while getting metadata for image name:"
                          "%(image_name)s, proceeding with default values"),
                     {'image_name': image_name})

    def _update_vendor_data_fast(self, token, admin_tenant_id,
                               image_name, device_data):
        try:
            vendor_data = self._get_vendor_data_fast(
                token, admin_tenant_id, image_name, device_data)
            LOG.info(_LI("Vendor data, specified in image: %(vendor_data)s"),
                     {'vendor_data': vendor_data})
            if vendor_data:
                self._update_self_with_vendor_data(
                    vendor_data,
                    nfp_constants.MAXIMUM_INTERFACES)
            else:
                LOG.info(_LI("No vendor data specified in image, "
                             "proceeding with default values"))
        except Exception:
            LOG.error(_LE("Error while getting metadata for image name: "
                          "%(image_name)s, proceeding with default values"),
                     {'image_name': image_name})

    def _get_image_name(self, device_data):
        if device_data['service_details'].get('image_name'):
            image_name = device_data['service_details']['image_name']
        else:
            LOG.info(_LI("No image name provided in service profile's "
                         "service flavor field, image will be selected "
                         "based on service vendor's name : %(vendor)s"),
                    {'vendor':
                        device_data['service_details']['service_vendor']})
            image_name = device_data['service_details']['service_vendor']
            image_name = '%s' % image_name.lower()
            device_data['service_details']['image_name'] = image_name
        return image_name

    def _get_service_type(self, token, service_profile_id, network_handler):
        service_profile = network_handler.get_service_profile(
            token, service_profile_id)
        return service_profile['service_type']

    def _get_device_service_types_map(self, token, devices, network_handler):
        device_service_types_map = collections.defaultdict(set)
        for device in devices:
            for network_function in device['network_functions']:
                service_type = self._get_service_type(
                    token,
                    network_function['service_profile_id'],
                    network_handler)
                device_service_types_map[device['id']].add(service_type)
        return device_service_types_map

    def get_network_function_device_sharing_info(self, device_data):
        """ Get filters for NFD sharing

        :param device_data: NFD data
        :type device_data: dict

        :returns: None -- when device sharing is not supported
        :returns: dict -- It has the following scheme
        {
            'filters': {
                'key': 'value',
                ...
            }
        }

        :raises: exceptions.IncompleteData
        """

        if (
            any(key not in device_data
                for key in ['tenant_id',
                            'service_details']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor'])
        ):
            raise exceptions.IncompleteData()

        if not self._is_device_sharing_supported():
            return None

    @_set_network_handler
    def select_network_function_device(self, devices, device_data,
                                       network_handler=None):
        """ Select a NFD which is eligible for sharing

        :param devices: NFDs
        :type devices: list
        :param device_data: NFD data
        :type device_data: dict

        :returns: None -- when device sharing is not supported, or
                          when no device is eligible for sharing
        :return: dict -- NFD which is eligible for sharing

        :raises: exceptions.IncompleteData
        """

        if (
            any(key not in device_data
                for key in ['ports']) or

            type(device_data['ports']) is not list or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model']) or

            type(devices) is not list or

            any(key not in device
                for device in devices
                for key in ['interfaces_in_use'])
        ):
            raise exceptions.IncompleteData()

        token = self._get_token(device_data.get('token'))
        if not token:
            return None
        image_name = self._get_image_name(device_data)
        if image_name:
            self._update_vendor_data(device_data,
                                     device_data.get('token'))
        if not self._is_device_sharing_supported():
            return None

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
                        instance_name):
        try:
            instance_id = nova.create_instance(
                token, admin_tenant_id,
                image_id, flavor, interfaces_to_attach, instance_name)
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

        token = device_data['token']
        admin_tenant_id = device_data['admin_tenant_id']
        image_name = self._get_image_name(device_data)

        executor = nfp_executor.TaskExecutor(jobs=3)

        image_id_result = {}

        executor.add_job('UPDATE_VENDOR_DATA',
                         self._update_vendor_data_fast,
                         token, admin_tenant_id, image_name, device_data)
        executor.add_job('GET_INTERFACES_FOR_DEVICE_CREATE',
                         self._get_interfaces_for_device_create,
                         token, admin_tenant_id, network_handler, device_data)
        executor.add_job('GET_IMAGE_ID',
                         self.get_image_id,
                         self.compute_handler_nova, token, admin_tenant_id,
                         image_name, result_store=image_id_result)

        executor.fire()

        interfaces = device_data.pop('interfaces', None)
        if not interfaces:
            LOG.exception(_LE('Failed to get interfaces for device creation.'))
            return None
        else:
            management_interface = interfaces[0]

        image_id = image_id_result.get('result', None)
        if not image_id:
            LOG.error(_LE('Failed to get image id for device creation.'))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None

        if device_data['service_details'].get('flavor'):
            flavor = device_data['service_details']['flavor']
        else:
            LOG.info(_LI("No Device flavor provided in service profile's "
                         "service flavor field, using default "
                         "flavor: m1.medium"))
            flavor = 'm1.medium'

        interfaces_to_attach = []
        for interface in interfaces:
            interfaces_to_attach.append({'port': interface['port_id']})

        instance_name = device_data['name']
        instance_id_result = {}
        port_details_result = {}

        executor.add_job('CREATE_INSTANCE',
                         self.create_instance,
                         self.compute_handler_nova,
                         token, admin_tenant_id, image_id, flavor,
                         interfaces_to_attach, instance_name,
                         result_store=instance_id_result)

        executor.add_job('GET_NEUTRON_PORT_DETAILS',
                         self.get_neutron_port_details,
                         network_handler, token,
                         management_interface['port_id'],
                         result_store=port_details_result)

        executor.fire()

        instance_id = instance_id_result.get('result', None)
        if not instance_id:
            LOG.error(_LE('Failed to create %(device_type)s instance.'))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None

        mgmt_ip_address = None
        mgmt_neutron_port_info = port_details_result.get('result', None)

        if not mgmt_neutron_port_info:
            LOG.error(_LE('Failed to get management port details. '))
            try:
                self.compute_handler_nova.delete_instance(
                    token,
                    admin_tenant_id,
                    instance_id)
            except Exception as e:
                LOG.error(_LE('Failed to delete %(device_type)s instance.'
                              'Error: %(error)s'),
                          {'device_type': (
                              device_data['service_details']['device_type']),
                           'error': e})
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            return None

        mgmt_ip_address = mgmt_neutron_port_info['ip_address']
        return {'id': instance_id,
                'name': instance_name,
                'mgmt_ip_address': mgmt_ip_address,
                'mgmt_port_id': interfaces[0],
                'mgmt_neutron_port_info': mgmt_neutron_port_info,
                'max_interfaces': self.maximum_interfaces,
                'interfaces_in_use': len(interfaces_to_attach),
                'description': ''}  # TODO(RPM): what should be the description

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

        image_name = self._get_image_name(device_data)
        if image_name:
            self._update_vendor_data(device_data,
                                     device_data.get('token'))
        token = self._get_token(device_data.get('token'))
        if not token:
            return None

        if device_data.get('id'):
            # delete the device instance
            #
            # this method will be invoked again
            # once the device instance deletion is completed
            try:
                self.compute_handler_nova.delete_instance(
                    token,
                    self._get_admin_tenant_id(
                        token=token),
                    device_data['id'])
            except Exception:
                LOG.error(_LE('Failed to delete %(instance)s instance'),
                         {'instance':
                             device_data['service_details']['device_type']})
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

        try:
            device = self.compute_handler_nova.get_instance(
                device_data['token'],
                device_data['tenant_id'],
                device_data['id'])
        except Exception:
            if ignore_failure:
                return None
            LOG.error(_LE('Failed to get %(instance)s instance details'),
                     {device_data['service_details']['device_type']})
            return None  # TODO(RPM): should we raise an Exception here?

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
                            token, port['id'])
                    executor.add_job(
                        'ATTACH_INTERFACE',
                        self.compute_handler_nova.attach_interface,
                        token, tenant_id, device_data['id'],
                        port['id'])
                    break

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
                            token, port['id'])
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

    def _set_promiscous_mode(self, token, service_type,
                             port_ids, network_handler=None):
        for port_id in port_ids:
            if (service_type.lower() in [nfp_constants.FIREWALL.lower(),
                                         nfp_constants.VPN.lower()]):
                network_handler.set_promiscuos_mode(token, port_id)

    def _get_data_port_ids(self, token, ports, service_type,
                           network_handler=None, set_promiscous_mode=False):
        # return data_port_ids in sequential format i.e.
        # provider port_id, then consumer port_id
        data_port_ids = []

        for port in ports:
            if port['port_classification'] == nfp_constants.PROVIDER:
                provider_port_id = network_handler.get_port_id(token,
                                                               port['id'])
                data_port_ids.append(provider_port_id)
                break
        for port in ports:
            if port['port_classification'] == nfp_constants.CONSUMER:
                consumer_port_id = network_handler.get_port_id(token,
                                                               port['id'])
                data_port_ids.append(consumer_port_id)

        if set_promiscous_mode:
            self._set_promiscous_mode(token, service_type, data_port_ids,
                                      network_handler)
        return data_port_ids

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

        image_name = self._get_image_name(device_data)
        if image_name:
            self._update_vendor_data(device_data,
                                     device_data.get('token'))

        token = self._get_token(device_data.get('token'))
        if not token:
            return None

        try:
            for port in device_data['ports']:
                port_id = network_handler.get_port_id(token, port['id'])
                self.compute_handler_nova.detach_interface(
                    token,
                    self._get_admin_tenant_id(token=token),
                    device_data['id'],
                    port_id)

        except Exception as e:
            LOG.error(_LE('Failed to unplug interface(s) from the device.'
                          'Error: %(error)s'), {'error': e})
            return None
        else:
            return True

    def get_network_function_device_healthcheck_info(self, device_data):
        """ Get the health check information for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: dict -- It has the following scheme
        {
            'config': [
                {
                    'resource': 'healthmonitor',
                    'resource_data': {
                        ...
                    }
                }
            ]
        }

        :raises: exceptions.IncompleteData
        """
        if (
            any(key not in device_data
                for key in ['id',
                            'mgmt_ip_address'])
        ):
            raise exceptions.IncompleteData()

        return {
            'config': [
                {
                    'resource': nfp_constants.HEALTHMONITOR_RESOURCE,
                    'resource_data': {
                        'vmid': device_data['id'],
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'periodicity': 'initial'
                    }
                }
            ]
        }

    @_set_network_handler
    def get_network_function_device_config_info(self, device_data,
                                                network_handler=None):
        """ Get the configuration information for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- On Failure
        :returns: dict -- It has the following scheme
        {
            'config': [
                {
                    'resource': 'interfaces',
                    'resource_data': {
                        ...
                    }
                },
                {
                    'resource': 'routes',
                    'resource_data': {
                        ...
                    }
                }
            ]
        }

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
            raise exceptions.IncompleteData()

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
                    (provider_ip, provider_mac, provider_cidr, dummy) = (
                        network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    LOG.error(_LE('Failed to get provider port details'
                                  ' for get device config info operation'))
                    return None
            elif port['port_classification'] == nfp_constants.CONSUMER:
                try:
                    (consumer_ip, consumer_mac, consumer_cidr,
                     consumer_gateway_ip) = (
                        network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    LOG.error(_LE('Failed to get consumer port details'
                                  ' for get device config info operation'))
                    return None

        return {
            'config': [
                {
                    'resource': nfp_constants.INTERFACE_RESOURCE,
                    'resource_data': {
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'provider_ip': provider_ip,
                        'provider_cidr': provider_cidr,
                        'provider_interface_index': 2,
                        'stitching_ip': consumer_ip,
                        'stitching_cidr': consumer_cidr,
                        'stitching_interface_index': 3,
                        'provider_mac': provider_mac,
                        'stitching_mac': consumer_mac,
                    }
                },
                {
                    'resource': nfp_constants.ROUTES_RESOURCE,
                    'resource_data': {
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'source_cidrs': ([provider_cidr, consumer_cidr]
                                         if consumer_cidr
                                         else [provider_cidr]),
                        'destination_cidr': consumer_cidr,
                        'provider_mac': provider_mac,
                        'gateway_ip': consumer_gateway_ip,
                        'provider_interface_index': 2
                    }
                }
            ]
        }

    @_set_network_handler
    def get_create_network_function_device_config_info(self, device_data,
                                                       network_handler=None):
        """ Get the configuration information for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- On Failure
        :returns: dict -- It has the following scheme
        {
            'config': [
                {
                    'resource': 'interfaces',
                    'resource_data': {
                        ...
                    }
                },
                {
                    'resource': 'routes',
                    'resource_data': {
                        ...
                    }
                }
            ]
        }

        :raises: exceptions.IncompleteData
        """

        mgmt_ip = device_data.get('mgmt_ip', None)
        provider_ip = device_data.get('provider_ip', None)
        provider_mac = device_data.get('provider_mac', None)
        provider_cidr = device_data.get('provider_cidr', None)
        consumer_ip = device_data.get('consumer_ip', None)
        consumer_mac = device_data.get('consumer_mac', None)
        consumer_cidr = device_data.get('consumer_cidr', None)
        consumer_gateway_ip = device_data.get('consumer_gateway_ip', None)

        return {
            'config': [
                {
                    'resource': nfp_constants.INTERFACE_RESOURCE,
                    'resource_data': {
                        'mgmt_ip': mgmt_ip,
                        'provider_ip': provider_ip,
                        'provider_cidr': provider_cidr,
                        'provider_interface_index': 2,
                        'stitching_ip': consumer_ip,
                        'stitching_cidr': consumer_cidr,
                        'stitching_interface_index': 3,
                        'provider_mac': provider_mac,
                        'stitching_mac': consumer_mac,
                    },

                },
                {
                    'resource': nfp_constants.ROUTES_RESOURCE,
                    'resource_data': {
                        'mgmt_ip': mgmt_ip,
                        'source_cidrs': ([provider_cidr, consumer_cidr]
                                         if consumer_cidr
                                         else [provider_cidr]),
                        'destination_cidr': consumer_cidr,
                        'provider_mac': provider_mac,
                        'gateway_ip': consumer_gateway_ip,
                        'provider_interface_index': 2
                    }
                }
            ]
        }
