# Copyright (c) 2014 Cisco Systems Inc.
# All Rights Reserved.
#
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

import contextlib
import netaddr

from apicapi import exceptions as exc
from neutron.common import constants as n_constants
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic as ma

from gbp.neutron.services.grouppolicy.drivers.cisco.apic import apic_mapping

LOG = log.getLogger(__name__)


class APICMechanismGBPDriver(ma.APICMechanismDriver):

    def initialize(self):
        # initialize apic
        self.apic_manager = apic_mapping.ApicMappingDriver.get_apic_manager()
        self.name_mapper = self.apic_manager.apic_mapper
        self.apic_manager.ensure_infra_created_on_apic()
        self.apic_manager.ensure_bgp_pod_policy_created_on_apic()
        self._apic_gbp = None

    @staticmethod
    @contextlib.contextmanager
    def gbp_context_injected(context):
        gbp_plugin = manager.NeutronManager.get_service_plugins().get(
            "GROUP_POLICY")
        ml2_plugin = context._plugin
        context._plugin = gbp_plugin
        yield context
        context._plugin = ml2_plugin

    @property
    def apic_gbp(self):
        if not self._apic_gbp:
            self._apic_gbp = (apic_mapping.ApicMappingDriver.
                              get_initialized_instance())
        return self._apic_gbp

    @lockutils.synchronized('apic-portlock')
    def _perform_path_port_operations(self, context, port):
        # hosts on which this vlan is provisioned
        host = context.host
        if not host:
            # the port is not bound yet
            return
        port_details = self.apic_gbp.get_gbp_details(context._plugin_context,
                                                     port_id=port['id'],
                                                     host=host)
        if port_details:
            with APICMechanismGBPDriver.gbp_context_injected(context) as ctx:
                epg = self.name_mapper.endpoint_group(ctx,
                                                      port_details['epg_id'])
                bd = self.name_mapper.l2_policy(ctx,
                                                port_details['l2_policy_id'])

            seg = port_details['segmentation_id']
            tenant_id = context.current['tenant_id']
            tenant_id = self.name_mapper.tenant(context, tenant_id)
            # Create a static path attachment for the host/epg/switchport combo
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.ensure_path_created_for_port(
                    tenant_id, epg, host, seg, bd_name=bd,
                    transaction=trs)

    def _perform_port_operations(self, context):
        # Get port
        port = context.current
        # Check if a compute port
        if (port.get('device_owner', '').startswith('compute') or
            port.get('device_owner') == n_constants.DEVICE_OWNER_DHCP):
            self._perform_path_port_operations(context, port)

    def _delete_path_if_last(self, context):
        if not self._get_active_path_count(context):
            atenant_id = self.name_mapper.tenant(context,
                                                 context.current['tenant_id'])
            with APICMechanismGBPDriver.gbp_context_injected(context) as ctx:
                epg = self.apic_gbp._port_id_to_epg(context._plugin_context,
                                                    context.current['id'])
                epg_id = self.name_mapper.endpoint_group(ctx,
                                                         epg['l2_policy_id'])

            self._delete_port_path(context, atenant_id, epg_id)

    def _get_subnet_info(self, context, subnet):
        tenant_id = subnet['tenant_id']
        network_id = subnet['network_id']
        l2_p = self._apic_gbp._network_id_to_l2p(context._plugin_context,
                                                 network_id)
        if l2_p:
            cidr = netaddr.IPNetwork(subnet['cidr'])
            gateway_ip = '%s/%s' % (subnet['gateway_ip'], str(cidr.prefixlen))

            # Convert to APIC IDs
            with APICMechanismGBPDriver.gbp_context_injected(context) as ctx:
                tenant_id = self.name_mapper.tenant(ctx, tenant_id)
                l2p = self.name_mapper.l2_policy(ctx, l2_p['id'])
                return tenant_id, l2p, gateway_ip

    def create_port_postcommit(self, context):
        if (context.current.get('device_owner') ==
                n_constants.DEVICE_OWNER_DHCP):
            with APICMechanismGBPDriver.gbp_context_injected(context) as ctx:
                self.apic_gbp.create_dhcp_endpoint_if_needed(ctx)
        super(APICMechanismGBPDriver, self).create_port_postcommit(context)

    def create_port_precommit(self, context):
        pass

    def update_port_precommit(self, context):
        orig = context.original
        curr = context.current
        if (orig['device_owner'] and
                (orig['device_owner'] != curr['device_owner'])
                or orig['device_id'] and (
                        orig['device_id'] != curr['device_id'])):
            raise exc.ApicOperationNotSupported(
                resource='Port', msg='Port device owner and id cannot be '
                                     'changed.')

    def update_port_postcommit(self, context):
        super(APICMechanismGBPDriver, self).update_port_postcommit(context)

    def delete_port_postcommit(self, context):
        port = context.current
        # Check if a compute port
        if (port.get('device_owner', '').startswith('compute') or
            port.get('device_owner') == n_constants.DEVICE_OWNER_DHCP):
                self._delete_path_if_last(context)

    def delete_port_precommit(self, context):
        super(APICMechanismGBPDriver, self).delete_port_precommit(context)

# Adding any parent method in order to override some operations that should be
# noop now.

    def create_network_postcommit(self, context):
        pass

    def create_network_precommit(self, context):
        pass

    def delete_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        pass

    def update_network_precommit(self, context):
        pass

    def update_network_postcommit(self, context):
        pass

    def create_subnet_postcommit(self, context):
        super(APICMechanismGBPDriver, self).create_subnet_postcommit(context)

    def create_subnet_precommit(self, context):
        super(APICMechanismGBPDriver, self).create_subnet_precommit(context)

    def update_subnet_postcommit(self, context):
        super(APICMechanismGBPDriver, self).update_subnet_postcommit(context)

    def update_subnet_precommit(self, context):
        super(APICMechanismGBPDriver, self).update_subnet_precommit(context)

    def delete_subnet_postcommit(self, context):
        super(APICMechanismGBPDriver, self).delete_subnet_postcommit(context)

    def delete_subnet_precommit(self, context):
        super(APICMechanismGBPDriver, self).delete_subnet_precommit(context)
