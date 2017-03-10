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

nfp_configurator_extra_opts = [
    oslo_config.StrOpt('log_forward_ip_address',
                       default='', help='Log collector host IP address'),
    oslo_config.IntOpt('log_forward_port',
                       default='514', help='Log collector port number'),
    oslo_config.StrOpt('log_level',
                       default='debug',
                       help='Log level info/error/debug/warning')]

oslo_config.CONF.register_opts(nfp_configurator_extra_opts, "configurator")


nfp_configurator_config_drivers_opts = [
    oslo_config.ListOpt(
        'drivers',
        default=['gbpservice.contrib.nfp.configurator.drivers'],
        help='List of config driver directories')]

oslo_config.CONF.register_opts(nfp_configurator_config_drivers_opts,
                               "CONFIG_DRIVERS")

nfp_configurator_config_agents_opts = [
    oslo_config.ListOpt(
        'agents',
        default=['gbpservice.contrib.nfp.configurator.agents'],
        help='Config agents directory')]

oslo_config.CONF.register_opts(nfp_configurator_config_agents_opts,
                               "CONFIG_AGENTS")
