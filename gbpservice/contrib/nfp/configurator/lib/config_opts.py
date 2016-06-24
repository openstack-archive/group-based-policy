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

opts = [
    cfg.StrOpt(
        'log_forward_ip_address',
        default=None,
        help=('IP address to forward logs to')),
    cfg.IntOpt(
        'log_forward_port',
        default=514,
        help=("port to forward logs to")),
    cfg.StrOpt(
        'log_level',
        default='debug',
        help=('log level for logs forwarding'))]
