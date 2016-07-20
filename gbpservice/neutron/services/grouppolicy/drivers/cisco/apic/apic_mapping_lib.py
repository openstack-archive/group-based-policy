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

import copy

from neutron.common import constants as n_constants

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as g_const


ALLOWING_ACTIONS = [g_const.GP_ACTION_ALLOW, g_const.GP_ACTION_REDIRECT]
REVERSIBLE_PROTOCOLS = [n_constants.PROTO_NAME_TCP.lower(),
                        n_constants.PROTO_NAME_UDP.lower(),
                        n_constants.PROTO_NAME_ICMP.lower()]
ICMP_REPLY_TYPES = ['echo-rep', 'dst-unreach', 'src-quench', 'time-exceeded']


def get_filter_entries_for_policy_rule(context):
    entries = {'forward_rules': None, 'reverse_rules': None}
    action = context._plugin.get_policy_action(
        context._plugin_context, context.current['policy_actions'][0])
    classifier = context._plugin.get_policy_classifier(
        context._plugin_context,
        context.current['policy_classifier_id'])
    if action['action_type'] in ALLOWING_ACTIONS:
        port_min, port_max = (
            gpdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                classifier['port_range']))
        f_attrs = {'etherT': 'unspecified'}
        if classifier['protocol']:
            f_attrs['etherT'] = 'ip'
            f_attrs['prot'] = classifier['protocol'].lower()
        if port_min and port_max:
            f_attrs['dToPort'] = port_max
            f_attrs['dFromPort'] = port_min
        entries['forward_rules'] = [f_attrs]
        # Also create reverse rule
        if f_attrs.get('prot') in REVERSIBLE_PROTOCOLS:
            r_entries = []
            r_attrs = copy.deepcopy(f_attrs)
            if r_attrs.get('dToPort') and r_attrs.get('dFromPort'):
                r_attrs.pop('dToPort')
                r_attrs.pop('dFromPort')
                r_attrs['sToPort'] = port_max
                r_attrs['sFromPort'] = port_min
            if r_attrs['prot'] == n_constants.PROTO_NAME_TCP.lower():
                # Only match on established sessions
                r_attrs['tcpRules'] = 'est'
            if r_attrs['prot'] == n_constants.PROTO_NAME_ICMP.lower():
                # create more entries:
                for reply_type in ICMP_REPLY_TYPES:
                    r_entry = copy.deepcopy(r_attrs)
                    r_entry['icmpv4T'] = reply_type
                    r_entries.append(r_entry)
            entries['reverse_rules'] = r_entries
    return entries


def get_arp_filter_entry():
    return {'etherT': 'arp'}


def get_service_contract_filter_entries():
    entries = {}
    # DNS
    dns_attrs = {'etherT': 'ip',
                 'prot': 'udp',
                 'dToPort': 'dns',
                 'dFromPort': 'dns'}
    entries['dns'] = dns_attrs
    r_dns_attrs = {'etherT': 'ip',
                   'prot': 'udp',
                   'sToPort': 'dns',
                   'sFromPort': 'dns'}
    entries['r-dns'] = r_dns_attrs

    # HTTP
    http_attrs = {'etherT': 'ip',
                  'prot': 'tcp',
                  'dToPort': 80,
                  'dFromPort': 80}
    entries['http'] = http_attrs
    r_http_attrs = {'etherT': 'ip',
                    'prot': 'tcp',
                    'sToPort': 80,
                    'sFromPort': 80}
    entries['r-http'] = r_http_attrs

    icmp_attrs = {'etherT': 'ip',
                  'prot': 'icmp'}
    entries['icmp'] = icmp_attrs

    # DHCP
    dhcp_attrs = {'etherT': 'ip',
                  'prot': 'udp',
                  'dToPort': 68,
                  'dFromPort': 68,
                  'sToPort': 67,
                  'sFromPort': 67}
    entries['dhcp'] = dhcp_attrs
    r_dhcp_attrs = {'etherT': 'ip',
                    'prot': 'udp',
                    'dToPort': 67,
                    'dFromPort': 67,
                    'sToPort': 68,
                    'sFromPort': 68}
    entries['r-dhcp'] = r_dhcp_attrs

    # ARP
    arp_attrs = get_arp_filter_entry()

    entries['arp'] = arp_attrs
    return entries
