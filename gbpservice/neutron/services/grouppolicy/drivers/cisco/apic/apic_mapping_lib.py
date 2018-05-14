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
import six

from neutron_lib import constants as n_constants

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc


ALLOWING_ACTIONS = [g_const.GP_ACTION_ALLOW, g_const.GP_ACTION_REDIRECT]
REVERSE_PREFIX = 'reverse-'
SERVICE_PREFIX = 'Svc-'
IMPLICIT_PREFIX = 'implicit-'
PER_PROJECT = 'per-project'
REVERSIBLE_PROTOCOLS = [n_constants.PROTO_NAME_TCP.lower(),
                        n_constants.PROTO_NAME_UDP.lower(),
                        n_constants.PROTO_NAME_ICMP.lower(), None]
ICMP_REPLY_TYPES = ['echo-rep', 'dst-unreach', 'src-quench', 'time-exceeded']
CP_ENTRY = 'os-entry'


class ExplicitSubnetAssociationNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Explicit subnet association not supported by APIC driver.")


class HierarchicalContractsNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Hierarchical contracts not supported by APIC driver.")


class MultipleExternalPoliciesForL3Policy(gpexc.GroupPolicyBadRequest):
    message = _("Potential association of multiple external policies to "
                "an L3 Policy.")


class SharedExternalPolicyUnsupported(gpexc.GroupPolicyBadRequest):
    message = _("APIC mapping driver does not support sharing of "
                "external policies.")


class OnlyOneL3PolicyIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one L3 Policy per ES is supported when NAT is disabled "
                "on the ES.")


class OnlyOneAddressIsAllowedPerExternalSegment(gpexc.GroupPolicyBadRequest):
    message = _("Only one ip address on each ES is supported on "
                "APIC GBP driver.")


def get_filter_entries_for_policy_classifier(classifier):
    # forward_rules and reverse_rules is each a dict of filter_entries
    # with each entry in the dict having the filter_entry name as the
    # key and the filter_entry attributes as the value
    entries = {'forward_rules': None, 'reverse_rules': None}
    x = 0
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
    entries['forward_rules'] = {_get_filter_entry_name(x): f_attrs}
    # Also create reverse rule
    if not f_attrs.get('prot') or (
        f_attrs.get('prot') in REVERSIBLE_PROTOCOLS):
        r_entries = {}
        if f_attrs.get('prot') == n_constants.PROTO_NAME_TCP.lower() or (
            f_attrs.get('prot') == n_constants.PROTO_NAME_UDP.lower()):
            r_attrs = copy.deepcopy(f_attrs)
            if f_attrs.get('dToPort') and f_attrs.get('dFromPort'):
                r_attrs.pop('dToPort')
                r_attrs.pop('dFromPort')
                r_attrs['sToPort'] = port_max
                r_attrs['sFromPort'] = port_min
            if f_attrs.get('prot') == n_constants.PROTO_NAME_TCP.lower():
                # Only match on established sessions for tcp
                r_attrs['tcpRules'] = 'est'
            r_entries[_get_filter_entry_name(x)] = r_attrs
        if not f_attrs.get('prot'):
            # when no protocol is specified add reverse tcp rule
            # only for established sessions
            r_attrs = copy.deepcopy(f_attrs)
            r_attrs['etherT'] = 'ip'
            r_attrs['prot'] = n_constants.PROTO_NAME_TCP.lower()
            r_attrs['tcpRules'] = 'est'
            r_entries[_get_filter_entry_name(x)] = r_attrs
            # add another reverse rulw for UDP
            r_attrs = copy.deepcopy(f_attrs)
            r_attrs['etherT'] = 'ip'
            r_attrs['prot'] = n_constants.PROTO_NAME_UDP.lower()
            x += 1
            r_entries[_get_filter_entry_name(x)] = r_attrs
        if f_attrs.get('prot') == n_constants.PROTO_NAME_ICMP.lower() or (
            not f_attrs.get('prot')):
            # create more entries for icmp and no protocol cases
            for reply_type in ICMP_REPLY_TYPES:
                x += 1
                r_entry = copy.deepcopy(f_attrs)
                r_entry['etherT'] = 'ip'
                r_entry['prot'] = n_constants.PROTO_NAME_ICMP.lower()
                r_entry['icmpv4T'] = reply_type
                r_entries[_get_filter_entry_name(x)] = r_entry
        entries['reverse_rules'] = r_entries
    return entries


def get_filter_entries_for_policy_rule(context):
    # forward_rules and reverse_rules is each a dict of filter_entries
    # with each entry in the dict having the filter_entry name as the
    # key and the filter_entry attributes as the value
    entries = {'forward_rules': None, 'reverse_rules': None}
    action = context._plugin.get_policy_action(
        context._plugin_context, context.current['policy_actions'][0])
    classifier = context._plugin.get_policy_classifier(
        context._plugin_context,
        context.current['policy_classifier_id'])
    if action['action_type'] in ALLOWING_ACTIONS:
        entries = get_filter_entries_for_policy_classifier(classifier)
    return entries


def get_arp_filter_entry():
    return {'arp': {'etherT': 'arp'}}


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

    icmpv6_attrs = {'etherT': 'ip',
                    'prot': 58}
    entries['icmpv6'] = icmpv6_attrs

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

    dhcpv6_attrs = {'etherT': 'ip',
                    'prot': 'udp',
                    'dToPort': 546,
                    'dFromPort': 546,
                    'sToPort': 547,
                    'sFromPort': 547}
    entries['dhcpv6'] = dhcpv6_attrs
    r_dhcpv6_attrs = {'etherT': 'ip',
                      'prot': 'udp',
                      'dToPort': 547,
                      'dFromPort': 547,
                      'sToPort': 546,
                      'sFromPort': 546}
    entries['r-dhcpv6'] = r_dhcpv6_attrs

    # ARP
    arp_entries = get_arp_filter_entry()
    for k, v in six.iteritems(arp_entries):
        entries[k] = v

    return entries


def map_to_aim_filter_entry(entry):
    mapped_keys = {'etherT': 'ether_type',
                   'prot': 'ip_protocol',
                   'dToPort': 'dest_to_port',
                   'dFromPort': 'dest_from_port',
                   'sToPort': 'source_to_port',
                   'sFromPort': 'source_from_port',
                   'icmpv4T': 'icmpv4_type',
                   'tcpRules': 'tcp_flags'}
    return dict((mapped_keys[k], v) for (k, v) in six.iteritems(entry))


def _get_filter_entry_name(entry_number):
    return CP_ENTRY + '-' + str(entry_number)
