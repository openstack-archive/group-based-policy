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

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.plugins.ml2 import rpc as ml2_rpc
from opflexagent import rpc as o_rpc
from oslo_db import api as oslo_db_api
from oslo_log import log

from gbpservice._i18n import _LE
from gbpservice._i18n import _LW
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)

LOG = log.getLogger(__name__)
MAX_RETRIES = 5

db_exc_retry = oslo_db_api.wrap_db_retry(max_retries=MAX_RETRIES,
                                         retry_on_request=True,
                                         retry_on_deadlock=True)


class AIMMappingRPCMixin(ha_ip_db.HAIPOwnerDbMixin):
    """RPC mixin for AIM mapping.

    Collection of all the RPC methods consumed by the AIM mapping.
    By defining the mixin requirements, we can potentially move the RPC
    handling between GBP and Neutron preserving the same code base. Such
    requirements might be easier to implement in some places (eg. won't
    require model extensions) compared to others, based on the visibility
    that each module has over the network abstraction.
    """

    def setup_opflex_rpc_listeners(self):
        self.notifier = o_rpc.AgentNotifierApi(topics.AGENT)
        LOG.debug("Set up Opflex RPC listeners.")
        self.opflex_endpoints = [
            o_rpc.GBPServerRpcCallback(self, self.notifier)]
        self.opflex_topic = o_rpc.TOPIC_OPFLEX
        self.opflex_conn = n_rpc.create_connection()
        self.opflex_conn.create_consumer(
            self.opflex_topic, self.opflex_endpoints, fanout=False)
        self.opflex_conn.consume_in_threads()

    @db_exc_retry
    def _retrieve_vrf_details(self, context, **kwargs):
        with context.session.begin(subtransactions=True):
            details = {'l3_policy_id': kwargs['vrf_id']}
            details['_cache'] = {}
            self._add_vrf_details(context, details['l3_policy_id'], details)
            details.pop('_cache', None)
        return details

    def _get_vrf_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling _get_vrf_details for: %s", kwargs)
        try:
            return self._retrieve_vrf_details(context, **kwargs)
        except Exception as e:
            vrf = kwargs.get('vrf_id')
            LOG.error(_LE("An exception has occurred while retrieving vrf "
                          "gbp details for %s"), vrf)
            LOG.exception(e)
            return {'l3_policy_id': vrf}

    def get_vrf_details(self, context, **kwargs):
        return self._get_vrf_details(context, **kwargs)

    def request_vrf_details(self, context, **kwargs):
        return self._get_vrf_details(context, **kwargs)

    def get_gbp_details(self, context, **kwargs):
        LOG.debug("APIC AIM MD handling get_gbp_details for: %s", kwargs)
        try:
            return self._get_gbp_details(context, kwargs, kwargs.get('host'))
        except Exception as e:
            device = kwargs.get('device')
            LOG.error(_LE("An exception has occurred while retrieving device "
                          "gbp details for %s"), device)
            LOG.exception(e)
            return {'device': device}

    def request_endpoint_details(self, context, **kwargs):
        LOG.debug("APIC AIM handling get_endpoint_details for: %s", kwargs)
        try:
            request = kwargs.get('request')
            host = kwargs.get('host')
            result = {'device': request['device'],
                      'timestamp': request['timestamp'],
                      'request_id': request['request_id'],
                      'gbp_details': self._get_gbp_details(context, request,
                                                           host),
                      'neutron_details': ml2_rpc.RpcCallbacks(
                          None, None).get_device_details(context, **request)}
            return result
        except Exception as e:
            LOG.error(_LE("An exception has occurred while requesting device "
                          "gbp details for %s"), request.get('device'))
            LOG.exception(e)
            return None

    # Child class needs to support:
    # - self._send_port_update_notification(context, port)
    def ip_address_owner_update(self, context, **kwargs):
        if not kwargs.get('ip_owner_info'):
            return
        ports_to_update = self.update_ip_owner(kwargs['ip_owner_info'])
        for p in ports_to_update:
            LOG.debug("APIC ownership update for port %s", p)
            self._send_port_update_notification(context, p)

    # Things you need in order to run this Mixin:
    # - self._core_plugin: attribute that points to the Neutron core plugin;
    # - self._is_port_promiscuous(context, port): define whether or not
    # a port should be put in promiscuous mode;
    # - self._get_port_epg(context, port): returns the AIM EPG for the specific
    # port
    # for both Neutron and GBP.
    # - self._is_dhcp_optimized(context, port);
    # - self._is_metadata_optimized(context, port);
    # - self._set_dhcp_lease_time(details)
    @db_exc_retry
    def _get_gbp_details(self, context, request, host):
        with context.session.begin(subtransactions=True):
            device = request.get('device')

            core_plugin = self._core_plugin
            port_id = core_plugin._device_to_port_id(context, device)
            port_context = core_plugin.get_bound_port_context(context, port_id,
                                                              host)
            if not port_context:
                LOG.warning(_LW("Device %(device)s requested by agent "
                                "%(agent_id)s not found in database"),
                            {'device': port_id,
                             'agent_id': request.get('agent_id')})
                return {'device': request.get('device')}
            port = port_context.current

            # NOTE(ivar): removed the PROXY_PORT_PREFIX hack.
            # This was needed to support network services without hotplug.

            epg = self._get_port_epg(context, port)

            details = {'device': request.get('device'),
                       'enable_dhcp_optimization': self._is_dhcp_optimized(
                           context, port),
                       'enable_metadata_optimization': (
                           self._is_metadata_optimized(context, port)),
                       'port_id': port_id,
                       'mac_address': port['mac_address'],
                       'app_profile_name': epg.app_profile_name,
                       'tenant_id': port['tenant_id'],
                       'host': host,
                       # TODO(ivar): scope names, possibly through AIM or the
                       # name mapper
                       'ptg_tenant': epg.tenant_name,
                       'endpoint_group_name': epg.name,
                       'promiscuous_mode': self._is_port_promiscuous(context,
                                                                     port),
                       'extra_ips': [],
                       'floating_ip': [],
                       'ip_mapping': [],
                       # Put per mac-address extra info
                       'extra_details': {}}

            # Set VM name if needed.
            if port['device_owner'].startswith(
                    'compute:') and port['device_id']:
                vm = nclient.NovaClient().get_server(port['device_id'])
                details['vm-name'] = vm.name if vm else port['device_id']
            mtu = self._get_port_mtu(context, port)
            if mtu:
                details['interface_mtu'] = mtu

            # NOTE(ivar): having these methods cleanly separated actually makes
            # things less efficient by requiring lots of calls duplication.
            # we could alleviate this by passing down a cache that stores
            # commonly requested objects (like EPGs). 'details' itself could
            # be used for such caching.
            details['_cache'] = {}
            vrf = self._get_port_vrf(context, port, details)
            details['l3_policy_id'] = '%s %s' % (vrf.tenant_name, vrf.name)
            self._add_subnet_details(context, port, details)
            self._add_allowed_address_pairs_details(context, port, details)
            self._add_vrf_details(context, details['l3_policy_id'], details)
            self._add_nat_details(context, port, host, details)
            self._add_extra_details(context, port, details)
            self._add_segmentation_label_details(context, port, details)
            self._set_dhcp_lease_time(details)
            details.pop('_cache', None)

        LOG.debug("Details for port %s : %s", (port['id'], details))
        return details

    def _get_owned_addresses(self, plugin_context, port_id):
        return set(self.ha_ip_handler.get_ha_ipaddresses_for_port(port_id))

    # Child class needs to support:
    # - self._get_subnet_details(context, port, details)
    def _add_subnet_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - subnets;
        details['subnets'] = self._get_subnet_details(context, port, details)

    def _add_nat_details(self, context, port, host, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - floating_ip;
        # - ip_mapping;
        # - host_snat_ips.
        (details['floating_ip'], details['ip_mapping'],
            details['host_snat_ips']) = self._get_nat_details(
                context, port, host, details)

    # Child class needs to support:
    # - self._get_aap_details(context, port, details)
    def _add_allowed_address_pairs_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - allowed_address_pairs
        # This should take care of realizing whether a given address is
        # active in the specific port
        details['allowed_address_pairs'] = self._get_aap_details(context, port,
                                                                 details)

    # Child class needs to support:
    # - self._get_vrf_subnets(context, vrf_tenant_name, vrf_name, details):
    # Subnets managed by the specific VRF.
    def _add_vrf_details(self, context, vrf_id, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - l3_policy_id;
        # - vrf_tenant;
        # - vrf_name;
        # - vrf_subnets.
        tenant_name, name = vrf_id.split(' ')
        details['vrf_tenant'] = tenant_name
        details['vrf_name'] = name
        details['vrf_subnets'] = self._get_vrf_subnets(context, tenant_name,
                                                       name, details)

    # Child class needs to support:
    # - self._get_segmentation_labels(context, port, details)
    def _add_segmentation_label_details(self, context, port, details):
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill the following result parameters:
        # - segmentation_labels
        # apic_segmentation_label is a GBP driver extension configured
        # for the aim_mapping driver
        details['segmentation_labels'] = self._get_segmentation_labels(
            context, port, details)

    def _add_extra_details(self, context, port, details):
        # TODO(ivar): Extra details depend on HA and SC implementation
        # This method needs to define requirements for this Mixin's child
        # classes in order to fill per-mac address extra information.

        # What is an "End of the Chain" port for Neutron?
        pass
