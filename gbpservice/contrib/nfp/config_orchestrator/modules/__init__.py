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
