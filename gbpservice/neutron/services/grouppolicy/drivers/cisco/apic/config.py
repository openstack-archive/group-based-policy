# Copyright (c) 2019 Cisco Systems Inc.
# All Rights Reserved.
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

from oslo_config import cfg

from gbpservice._i18n import _


# REVISIT: Auto-PTG is currently config driven to align with the
# config driven behavior of the older driver but is slated for
# removal.
opts = [
    cfg.BoolOpt('create_auto_ptg',
                default=True,
                help=_("Automatically create a PTG when a L2 Policy "
                       "gets created. This is currently an aim_mapping "
                       "policy driver specific feature.")),
    cfg.BoolOpt('create_per_l3p_implicit_contracts',
                default=True,
                help=_("This configuration is set to True to migrate a "
                       "deployment that has l3_policies without implicit "
                       "AIM contracts (these are deployments which have "
                       "AIM implicit contracts per tenant). A Neutron server "
                       "restart is required for this configuration to take "
                       "effect. The creation of the implicit contracts "
                       "happens at the time of the AIM policy driver "
                       "initialization. The configuration can be set to "
                       "False to avoid recreating the implicit contracts "
                       "on subsequent Neutron server restarts. This "
                       "option will be removed in the O release")),
    cfg.BoolOpt('advertise_mtu',  # REVISIT: Move to apic_aim MD.
                default=True,
                help=_('If True, advertise network MTU values if core plugin '
                       'calculates them. MTU is advertised to running '
                       'instances via DHCP and RA MTU options.')),
    cfg.IntOpt('nested_host_vlan',  # REVISIT: Move to apic_aim MD.
               default=4094,
               help=_("This is a locally siginificant VLAN used to provide "
                      "connectivity to the OpenStack VM when configured "
                      "to host the nested domain (Kubernetes/OpenShift).  "
                      "Any traffic originating from the VM and intended "
                      "to go on the Neutron network, is tagged with this "
                      "VLAN. The VLAN is stripped by the Opflex installed "
                      "flows on the integration bridge and the traffic is "
                      "forwarded on the Neutron network.")),
]


cfg.CONF.register_opts(opts, "aim_mapping")
