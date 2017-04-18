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
from oslo_config import cfg as oslo_config

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.core import context
from gbpservice.nfp.orchestrator import context as module_context

context.NfpContext = module_context.NfpContext

openstack_opts = [
    oslo_config.StrOpt('auth_host',
                       default='localhost',
                       help='Openstack controller IP Address'),
    # REVISIT: In future, use nfp_user with admin role instead of admin_user
    oslo_config.StrOpt('admin_user',
                       help='Admin user name to create service VMs'),
    oslo_config.StrOpt('admin_password',
                       help='Admin password to create service VMs'),
    # REVISIT: In future, use nfp_tenant_name instead of admin_tenant_name
    oslo_config.StrOpt('admin_tenant_name',
                       help='Admin tenant name to create service VMs'),
    oslo_config.StrOpt('admin_tenant_id',
                       help='Admin tenant ID to create service VMs'),
    oslo_config.StrOpt('auth_protocol',
                       default='http', help='Auth protocol used.'),
    oslo_config.IntOpt('auth_port',
                       default='5000', help='Auth protocol used.'),
    oslo_config.IntOpt('bind_port',
                       default='9696', help='Auth protocol used.'),
    oslo_config.StrOpt('auth_version',
                       default='v2.0', help='Auth protocol used.'),
    oslo_config.StrOpt('auth_uri',
                       default='', help='Auth URI.'),
]

oslo_config.CONF.register_opts(openstack_opts, "nfp_keystone_authtoken")

nfp_orchestrator_opts = [
    oslo_config.ListOpt(
        'supported_vendors',
        default=[nfp_constants.VYOS_VENDOR, nfp_constants.HAPROXY_VENDOR,
                 nfp_constants.HAPROXY_LBAASV2, nfp_constants.NFP_VENDOR],
        help="Supported service vendors for nfp"),
    oslo_config.StrOpt('monitoring_ptg_l3policy_id',
                       default='')
]

oslo_config.CONF.register_opts(nfp_orchestrator_opts, 'orchestrator')

device_orchestrator_opts = [
    oslo_config.BoolOpt('volume_support',
                        default=False, help='cinder volume support'),
    oslo_config.StrOpt('volume_size',
                       default='2', help='cinder volume size')
]

oslo_config.CONF.register_opts(device_orchestrator_opts, 'device_orchestrator')
