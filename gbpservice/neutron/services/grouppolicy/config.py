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


group_policy_opts = [
    cfg.ListOpt('policy_drivers',
                default=['dummy'],
                help=_("An ordered list of group policy driver "
                       "entrypoints to be loaded from the "
                       "gbpservice.neutron.group_policy.policy_drivers "
                       "namespace.")),
    cfg.ListOpt('extension_drivers',
                default=[],
                help=_("An ordered list of extension driver "
                       "entrypoints to be loaded from the "
                       "gbpservice.neutron.group_policy.extension_drivers "
                       "namespace.")),
]


cfg.CONF.register_opts(group_policy_opts, "group_policy")
