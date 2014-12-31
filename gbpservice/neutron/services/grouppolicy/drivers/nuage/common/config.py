# Copyright 2014 Alcatel-Lucent USA Inc.
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

from oslo.config import cfg


restproxy_opts = [
    cfg.StrOpt('server', default='localhost:8800',
               help=_("IP Address and Port of Nuage's VSD server")),
    cfg.StrOpt('serverauth', default='username:password',
               secret=True,
               help=_("Username and password for authentication")),
    cfg.BoolOpt('serverssl', default=False,
                help=_("Boolean for SSL connection with VSD server")),
    cfg.StrOpt('base_uri', default='/',
               help=_("Nuage provided base uri to reach out to VSD")),
    cfg.StrOpt('organization', default='system',
               help=_("Organization name in which VSD will orchestrate "
                      "network resources using openstack")),
    cfg.StrOpt('auth_resource', default='',
               help=_("Nuage provided uri for initial authorization to "
                      "access VSD")),
    cfg.StrOpt('application', default = 'gbp_application',
               help=_("Application name in which group based policy "
                      "is going to get defined"))
]


def nuage_register_cfg_opts():
    cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
