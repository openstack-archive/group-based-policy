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

OPTS = [
    cfg.IntOpt(
        'workers',
        default=1,
        help=_('Number of event worker process to be created.')
    ),
    cfg.StrOpt(
        'rpc_loadbalancer',
        default='StickyRoundRobin',
        choices=['RoundRobin', 'StickyRoundRobin'],
        help=_('Select one of the available loadbalancers for'
               'rpc loadbalancing, Check sc / core / lb.py'
               'for supported rpc lb algos')
    ),
    cfg.StrOpt(
        'modules_dir',
        default='gbpservice.nfp.core.test',
        help=_('Path for NFP modules.'
               'All modules from this path are autloaded by framework')
    ),
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Interval for event polling task in seconds.'
               'Polling task wakesup with this interval and'
               'checks for timedout events.')
    ),
    cfg.IntOpt(
        'reportstate_interval',
        default=10,
        help=_('Interval for report state task in seconds.'
               'Reporting task will report neutron agents state'
               'to the plugins at this interval')
    )
]
