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

API_NAME = 'sfc_patch'
API_VERSION_OPTION = ''


def build_option_parser(parser):
    """Hook to add global options"""
    return parser

try:
    from networking_sfc.cli import port_pair_group
    from networking_sfc.osc.sfc import port_pair_group as osc_ppg

    # Removing field limitation
    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            metavar='NAME',
            help=port_pair_group._('Name of the Port Pair Group.'))
        port_pair_group.add_common_arguments(parser)
        parser.add_argument(
            '--port-pair-group-parameters',
            type=port_pair_group.utils.str2dict,
            help=port_pair_group._(
                'Dictionary of Port pair group parameters. '))

    def get_parser(self, prog_name):
        parser = super(osc_ppg.CreatePortPairGroup, self).get_parser(prog_name)
        parser.add_argument(
            'name',
            metavar='NAME',
            help=osc_ppg._('Name of the Port Pair Group.'))
        parser.add_argument(
            '--description',
            help=osc_ppg._('Description for the Port Pair Group.'))
        parser.add_argument(
            '--port-pair',
            metavar='PORT-PAIR',
            dest='port_pairs',
            default=[],
            action='append',
            help=osc_ppg._('ID or name of the Port Pair.'
                           'This option can be repeated.'))
        parser.add_argument(
            '--port-pair-group-parameters',
            type=osc_ppg.nc_utils.str2dict,
            help=osc_ppg._('Dictionary of Port pair group parameters. '))
        return parser

    port_pair_group.PortPairGroupCreate.add_known_arguments = (
        add_known_arguments)
    osc_ppg.CreatePortPairGroup.get_parser = get_parser
except ImportError:
    pass
