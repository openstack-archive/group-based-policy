..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Neutron QoS Support
===================

Quality of Service (QoS) support is available in GBP using the Neutron API
(via the GBP Neutron Resource Mapping Driver).

This feature can be used by creating Network Service Policies (NSP) with the
following NSP parameter types:
- `qos_maxrate`: maximum bandwidth limiting rate for a Policy Target (in Kbps)
- `qos_burstrate`: burst bandwidth limiting rate for a Policy Target (in Kbps)

When a NSP contains one or both of the previous parameter types, and is
associated to a Policy Target Group (PTG), all Policy Targets part of that PTG
will individually inherit the QoS definitions intended. In other words, each
Policy Target will have their bandwidth limited by the amounts specified in
`qos_maxrate` and `qos_burstrate`, independently of the network activity in
other Policy Targets of the same PTG.

The QoS NSP parameter types expect a numerical value bound by Neutron's QoS.

Resource Mapping Driver
-----------------------
When a NSP contains one or both of the supported parameter types, and a
respective numerical value, the Resource Mapping Driver will automatically be
called to create one QoS Policy resource and one QoS Bandwidth Limit Rule
resource, via Neutron's REST API.

The Resource Mapping Driver includes the NSP Manager as a mixin, which
provides the data model and methods for creating mappings from GBP to QoS
resources in Neutron, as explained in more detail below.

This driver also handles the association of each Policy Target (part of a PTG
having a NSP that includes QoS parameters) to the actual QoS Policies that
have been created in Neutron. The Neutron Ports already mapped to Policy
Targets will be updated to include the correct Neutron QoS Policy that was
previously created and mapped to GBP.

NSP Manager
-----------
A special resource exists in GBP, `ServicePolicyQosPolicyMapping`, which keeps
track of the mapping between NSPs in GBP and QoS Policies in Neutron, and is
specifically defined inside the NSP Manager file (`nsp_manager.py`).

Furthermore, `NetworkServicePolicyMappingMixin` includes the database
operations for creating, deleting and reading these mappings.

DevStack Support
----------------
The GBP DevStack plugin will automatically enable QoS support.
