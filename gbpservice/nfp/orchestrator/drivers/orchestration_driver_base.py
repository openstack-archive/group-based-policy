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

from neutron._i18n import _LE
from neutron._i18n import _LI

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.orchestrator.coal.networking import (
    nfp_gbp_network_driver
)
from gbpservice.nfp.orchestrator.coal.networking import (
    nfp_neutron_network_driver
)
from gbpservice.nfp.orchestrator.openstack import openstack_driver

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)


def _set_network_handler(f):
    def wrapped(self, *args, **kwargs):
        device_data = args[0]
        if device_data.get('service_details'):
            network_mode = device_data['service_details'].get('network_mode')
            if network_mode:
                kwargs['network_handler'] = self.network_handlers[network_mode]
        return f(self, *args, **kwargs)
    return wrapped


class OrchestrationDriverBase(object):
    """Generic Driver class for orchestration of virtual appliances

    Does not support sharing of virtual appliance for different chains
    Does not support hotplugging interface to devices
    Launches the VM with all the management and data ports and a new VM
    is launched for each Network Service Instance
    """
    def __init__(self, config, supports_device_sharing=False,
                 supports_hotplug=False, max_interfaces=5):
        self.service_vendor = 'general'
        self.supports_device_sharing = supports_device_sharing
        self.supports_hotplug = supports_hotplug
        self.maximum_interfaces = max_interfaces

        # TODO(MAGESH): Try to move the following handlers to
        # NDO manager rather than having here in the driver
        self.identity_handler = openstack_driver.KeystoneClient(config)
        self.compute_handler_nova = openstack_driver.NovaClient(config)
        self.network_handlers = {
            nfp_constants.GBP_MODE:
                nfp_gbp_network_driver.NFPGBPNetworkDriver(config),
            nfp_constants.NEUTRON_MODE:
                nfp_neutron_network_driver.NFPNeutronNetworkDriver(config)
        }

        # statistics available
        # - instances
        # - management_interfaces
        # - keystone_token_get_failures
        # - image_details_get_failures
        # - port_details_get_failures
        # - instance_launch_failures
        # - instance_details_get_failures
        # - instance_delete_failures
        # - interface_plug_failures
        # - interface_unplug_failures
        self.stats = {}

    def _get_admin_tenant_id(self, token=None):
        try:
            (dummy,
             dummy,
             admin_tenant_name,
             dummy) = self.identity_handler.get_keystone_creds()
            if not token:
                token = self.identity_handler.get_admin_token()
            admin_tenant_id = self.identity_handler.get_tenant_id(
                                                            token,
                                                            admin_tenant_name)
            return admin_tenant_id
        except Exception:
            LOG.error(_LE("Failed to get admin's tenant ID"))
            raise

    def _increment_stats_counter(self, metric, by=1):
        # TODO(RPM): create path and delete path have different driver objects.
        # This will not work in case of increment and decrement.
        # So, its no-operation now
        return
        try:
            self.stats.update({metric: self.stats.get(metric, 0) + by})
        except Exception:
            LOG.error(_LE("Statistics failure. Failed to increment"
                          " '%(metric)s' by %(by)d")
                      % {'metric': metric, 'by': by})

    def _decrement_stats_counter(self, metric, by=1):
        # TODO(RPM): create path and delete path have different driver objects.
        # This will not work in case of increment and decrement.
        # So, its no-operation now
        return
        try:
            self.stats.update({metric: self.stats[metric] - by})
        except Exception:
            LOG.error(_LE("Statistics failure. Failed to decrement"
                          " '%(metric)s' by %(by)d")
                      % {'metric': metric, 'by': by})

    def _is_device_sharing_supported(self):
        return self.supports_device_sharing and self.supports_hotplug

    def _create_management_interface(self, device_data, network_handler=None):
        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for management interface'
                          ' creation'))
            return None

        name = 'mgmt_interface'  # TODO(RPM): Use proper name
        mgmt_interface = network_handler.create_port(
                token,
                self._get_admin_tenant_id(token=token),
                device_data['management_network_info']['id'],
                name=name)

        return {'id': mgmt_interface['id'],
                'port_model': (nfp_constants.GBP_PORT
                               if device_data['service_details'][
                                                        'network_mode'] ==
                               nfp_constants.GBP_MODE
                               else nfp_constants.NEUTRON_PORT),
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': None}

    def _delete_management_interface(self, device_data, interface,
                                     network_handler=None):
        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for management interface'
                          ' deletion'))
            return None

        network_handler.delete_port(token, interface['id'])

    def _get_interfaces_for_device_create(self, device_data,
                                          network_handler=None):
        mgmt_interface = self._create_management_interface(
                device_data,
                network_handler=network_handler
        )

        return [mgmt_interface]

    def _delete_interfaces(self, device_data, interfaces,
                           network_handler=None):
        for interface in interfaces:
            if interface['port_classification'] == nfp_constants.MANAGEMENT:
                self._delete_management_interface(
                        device_data, interface,
                        network_handler=network_handler
                )

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
        if not self._is_device_sharing_supported():
            return None

        if (
            any(key not in device_data
                for key in ['tenant_id',
                            'service_details']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor'])
        ):
            raise exceptions.IncompleteData()

        return {
                'filters': {
                    'tenant_id': [device_data['tenant_id']],
                    'service_vendor': [device_data['service_details'][
                                                        'service_vendor']],
                    'status': [nfp_constants.ACTIVE]
                }
        }

    def select_network_function_device(self, devices, device_data):
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
        if not self._is_device_sharing_supported():
            return None

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

        hotplug_ports_count = 1  # for provider interface (default)
        if any(port['port_classification'] == nfp_constants.CONSUMER
               for port in device_data['ports']):
            hotplug_ports_count = 2

        for device in devices:
            if (
                (device['interfaces_in_use'] + hotplug_ports_count) <=
                self.maximum_interfaces
            ):
                return device
        return None

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

        try:
            interfaces = self._get_interfaces_for_device_create(
                    device_data,
                    network_handler=network_handler
            )
        except Exception:
            LOG.exception(_LE('Failed to get interfaces for device creation'))
            return None
        else:
            self._increment_stats_counter('management_interfaces',
                                          by=len(interfaces))

        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token, for device creation'))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            self._decrement_stats_counter('management_interfaces',
                                          by=len(interfaces))
            return None

        if device_data['service_details'].get('image_name'):
            image_name = device_data['service_details']['image_name']
        else:
            LOG.info(_LI("No image name provided in service profile's "
                         "service flavor field, image will be selected "
                         "based on service vendor's name : %s")
                     % (device_data['service_details']['service_vendor']))
            image_name = device_data['service_details']['service_vendor']
            image_name = '%s' % image_name.lower()
        try:
            image_id = self.compute_handler_nova.get_image_id(
                    token,
                    self._get_admin_tenant_id(token=token),
                    image_name)
        except Exception:
            self._increment_stats_counter('image_details_get_failures')
            LOG.error(_LE('Failed to get image id for device creation.'
                          ' image name: %s')
                      % (image_name))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            self._decrement_stats_counter('management_interfaces',
                                          by=len(interfaces))
            return None

        if device_data['service_details'].get('flavor'):
            flavor = device_data['service_details']['flavor']
        else:
            LOG.info(_LI("No Device flavor provided in service profile's "
                         "service flavor field, using default "
                         "flavor: m1.medium"))
            flavor = 'm1.medium'
        interfaces_to_attach = []
        try:
            for interface in interfaces:
                port_id = network_handler.get_port_id(token, interface['id'])
                interfaces_to_attach.append({'port': port_id})

            if not self.supports_hotplug:
                for port in device_data['ports']:
                    if port['port_classification'] == nfp_constants.PROVIDER:
                        port_id = network_handler.get_port_id(
                                                        token, port['id'])
                        interfaces_to_attach.append({'port': port_id})
                for port in device_data['ports']:
                    if port['port_classification'] == nfp_constants.CONSUMER:
                        port_id = network_handler.get_port_id(
                                                        token, port['id'])
                        interfaces_to_attach.append({'port': port_id})
        except Exception:
            self._increment_stats_counter('port_details_get_failures')
            LOG.error(_LE('Failed to fetch list of interfaces to attach'
                          ' for device creation'))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            self._decrement_stats_counter('management_interfaces',
                                          by=len(interfaces))
            return None

        instance_name = device_data['name']
        try:
            instance_id = self.compute_handler_nova.create_instance(
                    token, self._get_admin_tenant_id(token=token),
                    image_id, flavor,
                    interfaces_to_attach, instance_name)
        except Exception:
            self._increment_stats_counter('instance_launch_failures')
            LOG.error(_LE('Failed to create %s instance')
                      % (device_data['service_details']['device_type']))
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            self._decrement_stats_counter('management_interfaces',
                                          by=len(interfaces))
            return None
        else:
            self._increment_stats_counter('instances')

        mgmt_ip_address = None
        try:
            for interface in interfaces:
                if interface['port_classification'] == (
                                                    nfp_constants.MANAGEMENT):
                    (mgmt_ip_address,
                     dummy, dummy,
                     dummy) = network_handler.get_port_details(
                                                        token, interface['id'])
        except Exception:
            self._increment_stats_counter('port_details_get_failures')
            LOG.error(_LE('Failed to get management port details'))
            try:
                self.compute_handler_nova.delete_instance(
                                            token,
                                            self._get_admin_tenant_id(
                                                                token=token),
                                            instance_id)
            except Exception:
                self._increment_stats_counter('instance_delete_failures')
                LOG.error(_LE('Failed to delete %s instance')
                          % (device_data['service_details']['device_type']))
            self._decrement_stats_counter('instances')
            self._delete_interfaces(device_data, interfaces,
                                    network_handler=network_handler)
            self._decrement_stats_counter('management_interfaces',
                                          by=len(interfaces))
            return None

        return {'id': instance_id,
                'name': instance_name,
                'mgmt_ip_address': mgmt_ip_address,
                'mgmt_port_id': interfaces[0],
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

        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for device deletion'))
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
                self._increment_stats_counter('instance_delete_failures')
                LOG.error(_LE('Failed to delete %s instance')
                          % (device_data['service_details']['device_type']))
            else:
                self._decrement_stats_counter('instances')
        else:
            # device instance deletion is done, delete remaining resources
            try:
                self._delete_interfaces(device_data,
                                        [device_data['mgmt_port_id']],
                                        network_handler=network_handler)
            except Exception:
                LOG.error(_LE('Failed to delete the management data port(s)'))
            else:
                self._decrement_stats_counter('management_interfaces')

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
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for get device status'
                          ' operation'))
            return None

        try:
            device = self.compute_handler_nova.get_instance(
                            token,
                            self._get_admin_tenant_id(token=token),
                            device_data['id'])
        except Exception:
            if ignore_failure:
                return None
            self._increment_stats_counter('instance_details_get_failures')
            LOG.error(_LE('Failed to get %s instance details')
                      % (device_data['service_details']['device_type']))
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
        if not self.supports_hotplug:
            # Nothing to do here.
            return True

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

        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for plug interface to device'
                          ' operation'))
            return False  # TODO(RPM): should we raise an Exception here?

        try:
            for port in device_data['ports']:
                if port['port_classification'] == nfp_constants.PROVIDER:
                    if (
                        device_data['service_details']['service_type'].lower()
                        in [nfp_constants.FIREWALL.lower()]
                    ):
                        network_handler.set_promiscuos_mode(token, port['id'])
                    port_id = network_handler.get_port_id(token, port['id'])
                    self.compute_handler_nova.attach_interface(
                                token,
                                self._get_admin_tenant_id(token=token),
                                device_data['id'],
                                port_id)
                    break
            for port in device_data['ports']:
                if port['port_classification'] == nfp_constants.CONSUMER:
                    if (
                        device_data['service_details']['service_type'].lower()
                        in [nfp_constants.FIREWALL.lower()]
                    ):
                        network_handler.set_promiscuos_mode(token, port['id'])
                    port_id = network_handler.get_port_id(token, port['id'])
                    self.compute_handler_nova.attach_interface(
                                token,
                                self._get_admin_tenant_id(token=token),
                                device_data['id'],
                                port_id)
                    break
        except Exception:
            self._increment_stats_counter('interface_plug_failures')
            LOG.error(_LE('Failed to plug interface(s) to the device'))
            return False  # TODO(RPM): should we raise an Exception here?
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
        if not self.supports_hotplug:
            # Nothing to do here.
            return True

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

        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token for unplug interface from'
                          ' device operation'))
            return False  # TODO(RPM): should we raise an Exception here?

        try:
            for port in device_data['ports']:
                port_id = network_handler.get_port_id(token, port['id'])
                self.compute_handler_nova.detach_interface(
                            token,
                            self._get_admin_tenant_id(token=token),
                            device_data['id'],
                            port_id)
        except Exception:
            self._increment_stats_counter('interface_unplug_failures')
            LOG.error(_LE('Failed to unplug interface(s) from the device'))
            return False  # TODO(RPM): should we raise an Exception here?
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
                    'resource': 'healthmonitor',
                    'resource_data': {
                        'vmid': device_data['id'],
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'periodicity': 'initial'
                    }
                }
            ]
        }

    def get_network_function_device_config_info(self, device_data,
                                                network_handler=None):
        """ Get the configuration information for NFD

        Child class should implement this
        """
        pass
