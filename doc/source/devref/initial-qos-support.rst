..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
Initial QoS Support
==========================================


Problem description
===================
Group-Based Policy for OpenStack currently does not offer any way to set QoS
(Quality of Service) policies, either within or across Policy Target Groups.
This spec intends to describe a first implementation for QoS in GBP, relying
on existing Neutron QoS policies support.

Proposed change
===============
Neutron has a QoS API since Liberty [1] and allows maximum bandwidth rate and
burst bandwidth rate to be set.

It does so at the Neutron Port level.

It is also possible to set it to Neutron Networks, in which case the child
Ports will inherit that policy (unless it is overridden by applying the policy
directly to the Port.

So, QoS policies cannot be applied to specific classifications of traffic.

There are 2 major places to apply QoS in GBP: Within a PTG and Across PTGs.
GBP already has a Policy Action Type "QoS" expressed through the Horizon
dashboard [2] - this would be the the "Across PTGs" scenario - but no
underlying implementation on the server to back it up.

As part of an initial QoS support in GBP, it is achievable to have QoS within
PTGs, i.e. to configure QoS rules for Policy Targets, since they map back to
Neutron ports.

However, to support QoS across PTGs, the classification set as part of the
providing or consuming PRS would essentially be ignored, so at this point only
the ANY classifier could be supported. Unfortunately, since the QoS policies
supported by Neutron apply at the Port level, it would have a non-trivial
meaning when set as an Action of a PRS. One of the possible outcomes could be
that a consuming PTG of the PRS whose action is QoS, would have all its PTs
be automatically configured to respect the QoS policy.

The first candidate for the proposed change on QoS for GBP is the hereafter
called PoC 01: Inherited QoS for Policy Targets via Network Service Policy.
This PoC will implement working QoS support for the scenario where QoS rules
are configured for Policy Targets. However, it will be done by inheriting from
a new kind of Network Service Policy (NSP) that will be assigned to a PTG.

The NSP resource mapping logic will proceed to create the corresponding QoS
policies/rules in Neutron to reflect what is specified in the NSPs, and then
map these to the Policy Targets that needs to share the QoS policies/rules.

This change will be attempted in a specific feature branch based on GBP master
supporting upstream Neutron Liberty integration.

Data model impact
-----------------
To implement PoC 01, NSPs will need to be defined with new types of the
Network Service Params attribute assigned to NSPs.
The following are the new types to be supported:
- "qos_maxrate"
- "qos_burstrate"

Furthermore, these types will have, as value, the number of Kilobits per
second that are to be associated with the specific type (either max Kbps rate
or burst Kbps rate).

In order to map the new kinds of NSPs, and respective Network Service Params,
to the Neutron QoS resources, a new mapping between Policy Targets and QoS
policies in Neutron must be created in the NSP Manager (nsp_manager.py):

::

  +-------------------+
  |                   |
  | gp_policy_targets |
  |                   |
  +-------------------+
           |1
           |
           |*
  +---------------------------+       +--------------+
  |                           |*     1|              |
  | gpm_pt_qospolicy_mappings +-------+ qos_policies |
  |                           |       |              |
  +---------------------------+       +--------------+


REST API impact
---------------
To support the new QoS Action type, a specific QoS policy needs to be
specified for that action. Since there is already an action_value field in the
Policy Action resource, it can be reused to point to the specific QoS policy.
It can either point directly to the Neutron's QoS policy resource uuid or to
an intermediate new GBP resource that keeps track of the QoS policies created.
The latter option would be better to avoid tight-coupling of the GBP resources
with Neutron. By pointing to an own resource, all the workflow could be
provided by GBP itself, and it would enable the eventual support of additional
QoS policy rule types not supported in Neutron itself. These could be provided
by specific implementations configurable as drivers, where Neutron would be
one of these drivers. Apart from that, a new resource would give the freedom
to better customize the workflow for the user, by eventually having additional
information for each of the QoS policies.

If QoS is to be applied directly to a PTG, the Network Service Policy's
network_service_params could be reused to support a new kind of param pointing
to a QoS Policy.


Security impact
---------------

Notifications impact
--------------------

Other end user impact
---------------------
After further discussion.


Performance impact
------------------
After further discussion.


Other deployer impact
---------------------
After further discussion.


Developer impact
----------------

Community impact
----------------

Alternatives
------------
If QoS policies are applied as Policy Actions in a PRS, here's how it could
look like (early strawman).

::

 +-----------------+             +----------------+
 |                 |             |                |
 |  Policy Action  |             |   QoS Action   |
 |                 |             |                |
 |  action_type    +-------------+ id             |
 |  action_value   |             | name           |
 |                 |             | description    |
 |                 |             | type           |
 |                 |             | shared         |
 |                 |             | tenant_id      |
 |                 |             | attributes     |
 |                 |             |                |
 +-----------------+             +----------------+

The attributes section relates to the specifics of the QoS Action.
It may either be an "attributes" field as in the figure, or it may be a set of
diferent attributes or a single attribute with a different name depending on
the type specified in the QoS Action. It can also be the same as what lives in
Neutron. Either way, it would then need to be mapped to Neutron, to create and
manage the corresponding resources there.

A scheme like the one where the NSP specifies the QoS policies (PoC 01), could
be used for for Policy Actions too. The network_service_params could define a
global qos_policy type with a value pointing to the specific QoS Action like
the one specified in the diagram above.

To support the new QoS Action type, a specific QoS policy needs to be
specified for that action. Since there is already an action_value field in the
Policy Action resource, it can be reused to point to the specific QoS policy.
It can either point directly to the Neutron's QoS policy resource uuid or to
an intermediate new GBP resource that keeps track of the QoS policies created.
The latter option would be better to avoid tight-coupling of the GBP resources
with Neutron. By pointing to an own resource, all the workflow could be
provided by GBP itself, and it would enable the eventual support of additional
QoS policy rule types not supported in Neutron itself. These could be provided
by specific implementations configurable as drivers, where Neutron would be
one of these drivers. Apart from that, a new resource would give the freedom
to better customize the workflow for the user, by eventually having additional
information for each of the QoS policies.

If QoS is to be applied directly to a PTG, the Network Service Policy's
network_service_params could be reused to support a new kind of param pointing
to a QoS Policy.

Implementation
==============

Assignee(s)
-----------
igordcard


Work items
----------


Dependencies
============
Neutron QoS API from Liberty.

Testing
=======

Tempest Tests
-------------


Functional Tests
----------------


API Tests
---------


Documentation impact
====================

User Documentation
------------------
Documentation will be impacted to address how QoS policies can be applied.


Developer Documentation
-----------------------


References
==========
[1] https://specs.openstack.org/openstack/neutron-specs/specs/liberty/qos-api-extension.html
[2] http://git.openstack.org/cgit/openstack/group-based-policy-ui/tree/gbpui/panels/application_policy/forms.py

