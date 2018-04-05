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

from networking_sfc.cli import port_pair_group


# Removing field limitation
def add_known_arguments(self, parser):
    parser.add_argument(
        'name',
        metavar='NAME',
        help=_('Name of the Port Pair Group.'))
    port_pair_group.add_common_arguments(parser)
    parser.add_argument(
        '--port-pair-group-parameters',
        metavar='[lb_fields=LB_FIELDS, ppg_n_tuple_mapping=TUPLE_VALUES]',
        type=port_pair_group.utils.str2dict,
        help=_('Dictionary of Port pair group parameters. '
               'Currently, only \'&\' separated string of the lb_fields '
               'and ppg_n_tuple_mapping are supported. For '
               'ppg_n_tuple_mapping the supported command is '
               '\'key=value\' separated by \'&\'. Support '
               'ppg_n_tuple_mapping keys are: source_ip_prefix_ingress, '
               'source_ip_prefix_egress, destination_ip_prefix_ingress, '
               'destination_ip_prefix_egress, source_port_ingress, '
               'source_port_egress, destination_port_ingress, '
               'destination_port_egress.'))


port_pair_group.PortPairGroupCreate.add_known_arguments = add_known_arguments
