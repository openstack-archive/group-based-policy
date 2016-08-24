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

es_openstack_opts = [
    oslo_config.StrOpt('auth_host',
                       default='localhost',
                       help='Openstack controller IP Address'),
    oslo_config.StrOpt('admin_user',
                       help='Admin user name to create service VMs'),
    oslo_config.StrOpt('admin_password',
                       help='Admin password to create service VMs'),
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

oslo_config.CONF.register_opts(es_openstack_opts, "keystone_authtoken")

nfp_orchestrator_opts = [
    oslo_config.ListOpt(
        'supported_vendors',
        default=[nfp_constants.VYOS_VENDOR, nfp_constants.HAPROXY_VENDOR,
                 nfp_constants.HAPROXY_LBAASV2, nfp_constants.NFP_VENDOR],
        help="Supported service vendors for nfp")]

oslo_config.CONF.register_opts(nfp_orchestrator_opts)
