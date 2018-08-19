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

# Register apic_system_id
# REVISIT(ivar): would be nice to remove dependency from apic_ml2 in GBP, and
# register option directly here.
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import config  # noqa


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
    cfg.BoolOpt('enable_iptables_firewall',
                default=False,
                help=("This will enable the iptables firewall implementation "
                      "on all the compute nodes.")),
    # TODO(kentwu): Need to define the external routed domain
    # AIM object instead.
    cfg.StrOpt('l3_domain_dn', default='',
               help=("The DN of the APIC external routed domain used by the "
                     "auto l3out created for the SVI networks.")),
    cfg.StrOpt('apic_router_id_pool', default='199.199.199.1/24',
               help=("The pool of IPs where we allocate the APIC "
                     "router ID from while creating the SVI interface.")),
    cfg.DictOpt('migrate_ext_net_dns', default={},
                help="DNs for external networks being migrated from legacy "
                "plugin, formatted as a dictionary mapping Neutron external "
                "network IDs (UUIDs) to ACI external network distinguished "
                "names."),
]


cfg.CONF.register_opts(apic_opts, "ml2_apic_aim")
