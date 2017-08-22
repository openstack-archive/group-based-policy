# Copyright (c) 2014 OpenStack Foundation
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

from oslo_config import cfg


apic_opts = [
    cfg.BoolOpt('enable_optimized_dhcp', default=True),
    cfg.BoolOpt('enable_optimized_metadata', default=False),
    cfg.StrOpt('keystone_notification_exchange',
               default='keystone',
               help=("The exchange used to subscribe to Keystone "
                     "notifications")),
    cfg.StrOpt('keystone_notification_topic',
               default='notifications',
               help=("The topic used to subscribe to Keystone "
                     "notifications")),
    cfg.IntOpt('apic_optimized_dhcp_lease_time', default=0,
               help=("Number of seconds for the optimized DHCP lease time. "
                     "Default is 0 which means using opflex agent's default "
                     "value.")),
    cfg.BoolOpt('enable_keystone_notification_purge',
                default=False,
                help=("This will enable purging all the resources including "
                      "the tenant once a keystone project.deleted "
                      "notification is received.")),
]


cfg.CONF.register_opts(apic_opts, "ml2_apic_aim")


# oslo_config limits ${var} expansion to global variables
# That is why apic_system_id as a global variable
global_opts = [
    cfg.StrOpt('apic_system_id',
               default='openstack',
               help=_("Prefix for APIC domain/names/profiles created")),
]


cfg.CONF.register_opts(global_opts)


apic_opts = [
    cfg.ListOpt('apic_hosts',
                default=[],
                help=_("An ordered list of host names or IP addresses of "
                       "the APIC controller(s).")),
    cfg.StrOpt('apic_username',
               help=_("Username for the APIC controller")),
    cfg.StrOpt('apic_password',
               help=_("Password for the APIC controller"), secret=True),
    cfg.StrOpt('apic_name_mapping',
               default='use_uuid',
               help=_("Name mapping strategy to use: use_uuid | use_name")),
    cfg.BoolOpt('apic_use_ssl',
                default=True,
                help=_("Use SSL to connect to the APIC controller")),
    cfg.StrOpt('apic_domain_name',
               default='${apic_system_id}',
               help=_("Name for the domain created on APIC")),
    cfg.StrOpt('apic_app_profile_name',
               default='${apic_system_id}_app',
               help=_("Name for the app profile used for Openstack")),
    cfg.StrOpt('apic_vlan_ns_name',
               default='${apic_system_id}_vlan_ns',
               help=_("Name for the vlan namespace to be used for Openstack")),
    cfg.StrOpt('apic_node_profile',
               default='${apic_system_id}_node_profile',
               help=_("Name of the node profile to be created")),
    cfg.StrOpt('apic_entity_profile',
               default='${apic_system_id}_entity_profile',
               help=_("Name of the entity profile to be created")),
    cfg.StrOpt('apic_function_profile',
               default='${apic_system_id}_function_profile',
               help=_("Name of the function profile to be created")),
    cfg.StrOpt('apic_lacp_profile',
               default='${apic_system_id}_lacp_profile',
               help=_("Name of the LACP profile to be created")),
    cfg.ListOpt('apic_host_uplink_ports',
                default=[],
                help=_('The uplink ports to check for ACI connectivity')),
    cfg.ListOpt('apic_vpc_pairs',
                default=[],
                help=_('The switch pairs for VPC connectivity')),
    cfg.StrOpt('apic_vlan_range',
               default='2:4093',
               help=_("Range of VLAN's to be used for Openstack")),
    cfg.FloatOpt('apic_agent_report_interval',
                 default=60,
                 help=_('Interval between agent status updates (in sec)')),
    cfg.FloatOpt('apic_agent_poll_interval',
                 default=60,
                 help=_('Interval between agent poll for topology (in sec)')),
    cfg.BoolOpt('integrated_topology_service', default=False,
                help=_("Use integrated topology service for better host "
                       "mobility in ACI.")),
    cfg.BoolOpt('per_tenant_context', default=True,
                help=_("If True, one L3 CTX per tenant will be created "
                       "instead of a global one. This will enable overlapping "
                       "IPs across tenants (but not within the same one).")),
    cfg.BoolOpt('single_tenant_mode', default=False,
                help=_("All the Openstack tenants will be described by a "
                       "single ACI tenant.")),
    cfg.StrOpt('single_tenant_name',
               default='${apic_system_id}',
               help=_("The ACI tenant name which will be used when the "
                      "single_tenant_mode is enabled.")),
    cfg.StrOpt('network_constraints_filename',
               default=None,
               help=_("Complete path of file containing network constraints")),
    cfg.BoolOpt('l3_cisco_router_plugin',
                default=False,
                help=_("Set to true when using the Cisco Router "
                       "plugin for L3")),
    cfg.ListOpt('vrf_per_router_tenants',
                default=[],
                help=_('Project regexes in which each router maps to a '
                       'separate VRF')),
]


cfg.CONF.register_opts(apic_opts, "ml2_cisco_apic")


def _get_specific_config(prefix):
    """retrieve config in the format [<prefix>:<value>]."""
    conf_dict = {}
    multi_parser = cfg.MultiConfigParser()
    multi_parser.read(cfg.CONF.config_file)
    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item.startswith(prefix):
                switch, switch_id = parsed_item.split(':')
                if switch.lower() == prefix:
                    conf_dict[switch_id] = parsed_file[parsed_item].items()
    return conf_dict


def create_switch_dictionary():
    switch_dict = {}
    conf = _get_specific_config('apic_switch')
    for switch_id in conf:
        switch_dict[switch_id] = switch_dict.get(switch_id, {})
        for host_list, port in conf[switch_id]:
            hosts = host_list.split(',')
            port = port[0]
            switch_dict[switch_id][port] = (
                switch_dict[switch_id].get(port, []) + hosts)
    return switch_dict


def create_vpc_dictionary():
    vpc_dict = {}
    for pair in cfg.CONF.ml2_cisco_apic.apic_vpc_pairs:
        pair_tuple = pair.split(':')
        if (len(pair_tuple) != 2 or
                any(map(lambda x: not x.isdigit(), pair_tuple))):
            # Validation error, ignore this item
            continue
        vpc_dict[pair_tuple[0]] = pair_tuple[1]
        vpc_dict[pair_tuple[1]] = pair_tuple[0]
    return vpc_dict


def create_external_network_dictionary():
    router_dict = {}
    conf = _get_specific_config('apic_external_network')
    for net_id in conf:
        router_dict[net_id] = router_dict.get(net_id, {})
        for key, value in conf[net_id]:
            router_dict[net_id][key] = value[0] if value else None

    return router_dict
