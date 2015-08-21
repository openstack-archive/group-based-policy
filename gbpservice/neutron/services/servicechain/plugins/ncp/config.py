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


service_chain_opts = [
    cfg.ListOpt('node_drivers',
                default=['node_dummy'],
                help=_("An ordered list of service chain node drivers "
                       "entrypoints to be loaded from the "
                       "gbpservice.neutron.servicechain.ncp_drivers "
                       "namespace.")),
    cfg.StrOpt('node_plumber',
               default='dummy_plumber',
               help=_("The plumber used by the Node Composition Plugin "
                      "for service plumbing. Entrypoint loaded from the "
                      "gbpservice.neutron.servicechain.ncp_plumbers "
                      "namespace."))
]


cfg.CONF.register_opts(service_chain_opts, "node_composition_plugin")
