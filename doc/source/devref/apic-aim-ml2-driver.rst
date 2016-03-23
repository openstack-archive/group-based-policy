..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

APIC-AIM ML2 Driver
===================

The APIC-AIM ML2 mechanism driver and associated extension driver
utilize the ACI Integration Module (AIM) library to provide improved
integration between Neutron and the Cisco APIC. The most significant
advantage of the APIC-AIM ML2 drivers over the previous APIC ML2
drivers is that they are intended to coexist with the AIM GBP policy
driver, providing full simultaneous support for both Neutron and GBP
APIs within the same OpenStack deployment, including sharing of
resources between Neutron and GBP workflows where appropriate.

Additionally, the AIM-based mechanism and policy driver architecture
is completely transactional, and thus provides improved robustness,
performance, and scalability. A set of replicated AIM daemons is
responsible for continually maintaining consistency between the AIM DB
state specified by the drivers and the APIC state.

ML2Plus Plugin
--------------

The ML2Plus core plugin extends the ML2 plugin with several driver API
features that are needed for APIC AIM support. An extended
MechanismDriver abstract base class adds an ensure_tenant() method
that is called before any transaction creating a new resource, and
(soon) adds precommit and postcommit calls for operations on
additional resources such as address scope. An extended
ExtensionDriver base class will support extending those additional
resources.

ML2 configuration is unchanged, and compatibility is maintained with
all existing ML2 drivers.

APIC-AIM Mechanism Driver
-------------------------

The apic-aim ML2 mechanism driver maps Neutron resources to the APIC
resource configurations that provide the required Neutron networking
semantics. Currently, the following Neutron -> AIM mappings are
implemented:

 tenant -> Tenant, ApplicationProfile
 network -> BridgeDomain, default EndpointGroup
 subnet -> Subnet

Neutron ports are realized as Endpoints within an APIC
EndpointGroup. A port created using Neutron APIs belongs to the
network's default EndpointGroup. A port created as a GBP PolicyTarget
does not use its PolicyTargetGroup's L2Policy's network's default
EndpointGroup, but instead belongs to an APIC EndpointGroup mapped
from its PolicyTargetGroup.

Additional mappings that are under development include:

 address scope -> VRF
 router -> contract rules

Port binding for the OpFlex L2 agent and support for the
get_gbp_details RPC are implemented. DVS port binding and other RPCs
remain to be implemented.

APIC-AIM Extension Driver
-------------------------

The apic-aim ML2 extension driver provides administrators with read
access to the distinguished names of the set of APIC resources to
which each Neutron resource is mapped, as well as to APIC-specific
status and AIM daemon synchronization status for those resources.

The extension driver may eventually also allow DNs of existing APIC
resources to be specified when creating Neutron resources.

DevStack Support
----------------

The ML2Plus core plugin and APIC-AIM mechanism and extension drivers
can be configured by including the following in local.conf when
running devstack::

    enable_plugin gbp https://git.openstack.org/openstack/group-based-policy master

    ENABLE_APIC_AIM=True

Note that the GBP devstack plugin installs the python-opflex-agent
repo, but does not yet configure or run the OpFlex L2 agent.
