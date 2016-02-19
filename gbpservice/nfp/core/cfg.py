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

es_openstack_opts = [
    cfg.StrOpt('auth_host',
               default='localhost',
               help='Openstack controller IP Address'),
    cfg.StrOpt('admin_user',
               help='Admin user name to create service VMs'),
    cfg.StrOpt('admin_password',
               help='Admin password to create service VMs'),
    cfg.StrOpt('admin_tenant_name',
               help='Admin tenant name to create service VMs'),
    cfg.StrOpt('admin_tenant_id',
               help='Admin tenant ID to create service VMs'),
    cfg.StrOpt('auth_protocol',
               default='http', help='Auth protocol used.'),
    cfg.IntOpt('auth_port',
               default='5000', help='Auth protocol used.'),
    cfg.IntOpt('bind_port',
               default='9696', help='Auth protocol used.'),
    cfg.StrOpt('auth_version',
               default='v2.0', help='Auth protocol used.'),
    cfg.StrOpt('auth_uri',
               default='', help='Auth URI.'),
]

OPTS = [
    cfg.IntOpt(
        'workers',
        default=4,
        help='Number of event worker process to be created.'
    ),
    cfg.StrOpt(
        'modules_dir',
        default='gbpservice.nfp.core.test',
        help='Path for NFP modules.'
        'All modules from this path are autloaded by framework'
    ),
    cfg.IntOpt(
        'periodic_interval',
        default=2,
        help='Interval for event polling task in seconds.'
        'Polling task wakesup with this interval and'
        'checks for timedout events.'
    ),
    cfg.IntOpt(
        'reportstate_interval',
        default=10,
        help='Interval for report state task in seconds.'
        'Reporting task will report neutron agents state'
        'to the plugins at this interval'
    ),
    cfg.BoolOpt(
        'core_debug',
        default=False,
        help='Main debug'
    )
]
