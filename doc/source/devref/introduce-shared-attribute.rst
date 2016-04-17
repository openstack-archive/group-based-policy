..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

===================================
Introduce globally shared resources
===================================

Launchpad blueprints:

https://blueprints.launchpad.net/group-based-policy/+spec/introduce-shared-attribute
https://blueprints.launchpad.net/group-based-policy/+spec/share-servicechain-objects

Today, it's not possible to create shared GBP resources.
This is especially useful in order to avoid duplication of policies
among tenants.

This blueprint introduces a "shared" attribute to certain GBP resources.

Problem description
===================

In the context of concerns separation, it's very important that a user
(e.g. the admin) shares some of the resources he created in order for
different kind of users to be able to consume them.

To achieve this, the API should be able to offer a way to specify
whether a resource is shared or not. This behavior doesn't exist
in our current Group Based Policy implementation.

Proposed change
===============

This change proposes the introduction of a "shared" attribute for the
following GBP resources:

- Policy Rule Sets;
- Policy Target Groups;
- L2 Policies;
- L3 Policies;
- Network Service policies;
- Policy Rules;
- Policy Classifiers;
- Policy Actions;
- Service Chain Nodes;
- Service Chain Specs.

The behavior will be consistent with Neutron's already existing
sharing policy. Which means that a given resource can be either
consumable by a single tenant or shared globally.
Shared resources will be modifiable only by the owner or the
admin when applied.
The Policy Target resource has been excluded from the list above
since it is intrinsically something that the user creates and
consumes for himself.

The sharing constraints are the following:

- A shared resource can only be associated with other shared
  resources. For example, a shared L2_Policy can only exist on
  a shared L3_Policy;
- A shared resource can be CRUD  based on the
  rules described by the policy.json file;
- A shared resource can't be reverted to non shared if being
  used by either shared or other tenants' resources.
- Although the model provides as much flexibility as possible
  (constrained by the above rules) each driver should limit
  the sharing capabilities based on their own implementations.

The proposed default policy.json follows::

 {
     "context_is_admin":  "role:admin",
     "admin_or_owner": "rule:context_is_admin or tenant_id:%(tenant_id)s",
     "admin_only": "rule:context_is_admin",
     "regular_user": "",
     "default": "rule:admin_or_owner",
     "shared_ptg": "field:policy_target_groups:shared=True",
     "shared_pt": "field:policy_targets:shared=True",
     "shared_prs": "field:policy_rule_sets:shared=True",
     "shared_l3p": "field:l3_policies:shared=True",
     "shared_l2p": "field:l2_policies:shared=True",
     "shared_es": "field:external_segments:shared=True",
     "shared_ep": "field:external_policies:shared=True",
     "shared_pc": "field:policy_classifiers:shared=True",
     "shared_pa": "field:policy_actions:shared=True",
     "shared_pr": "field:policy_rules:shared=True",
     "shared_np": "field:nat_pools:shared=True",
     "shared_nsp": "field:network_service_policies:shared=True",
     "shared_scn": "field:servicechain_nodes:shared=True",
     "shared_scs": "field:servicechain_specs:shared=True",

     "create_policy_target_group": "",
     "create_policy_target_group:shared": "rule:admin_only",
     "get_policy_target_group": "rule:admin_or_owner or rule:shared_ptg",
     "update_policy_target_group:shared": "rule:admin_only",

     "create_l2_policy": "",
     "create_l2_policy:shared": "rule:admin_only",
     "get_l2_policy": "rule:admin_or_owner or rule:shared_l2p",
     "update_l2_policy:shared": "rule:admin_only",

     "create_l3_policy": "",
     "create_l3_policy:shared": "rule:admin_only",
     "get_l3_policy": "rule:admin_or_owner or rule:shared_l3p",
     "update_l3_policy:shared": "rule:admin_only",

     "create_policy_classifier": "",
     "create_policy_classifier:shared": "rule:admin_only",
     "get_policy_classifier": "rule:admin_or_owner or rule:shared_pc",
     "update_policy_classifier:shared": "rule:admin_only",

     "create_policy_action": "",
     "create_policy_action:shared": "rule:admin_only",
     "get_policy_action": "rule:admin_or_owner or rule:shared_pa",
     "update_policy_action:shared": "rule:admin_only",

     "create_policy_rule": "",
     "create_policy_rule:shared": "rule:admin_only",
     "get_policy_rule": "rule:admin_or_owner or rule:shared_pr",
     "update_policy_rule:shared": "rule:admin_only",

     "create_policy_rule_set": "",
     "create_policy_rule_set:shared": "rule:admin_only",
     "get_policy_rule_set": "rule:admin_or_owner or rule:shared_prs",
     "update_policy_rule_set:shared": "rule:admin_only",

     "create_network_service_policy": "",
     "create_network_service_policy:shared": "rule:admin_only",
     "get_network_service_policy": "rule:admin_or_owner or rule:shared_nsp",
     "update_network_service_policy:shared": "rule:admin_only",

     "create_external_segment": "",
     "create_external_segment:shared": "rule:admin_only",
     "get_external_segment": "rule:admin_or_owner or rule:shared_es",
     "update_external_segment:shared": "rule:admin_only",

     "create_external_policy": "",
     "create_external_policy:shared": "rule:admin_only",
     "get_external_policy": "rule:admin_or_owner or rule:shared_ep",
     "update_external_policy:shared": "rule:admin_only",

     "create_nat_pool": "",
     "create_nat_pool:shared": "rule:admin_only",
     "get_nat_pool": "rule:admin_or_owner or rule:shared_np",
     "update_nat_pool:shared": "rule:admin_only",

     "create_servicechain_node": "",
     "create_servicechain_node:shared": "rule:admin_only",
     "get_servicechain_node": "rule:admin_or_owner or rule:shared_scn",
     "update_servicechain_node:shared": "rule:admin_only",

     "create_servicechain_spec": "",
     "create_servicechain_spec:shared": "rule:admin_only",
     "get_servicechain_spec": "rule:admin_or_owner or rule:shared_scs",
     "update_servicechain_spec:shared": "rule:admin_only",

     "create_servicechain_instance": "",
     "get_servicechain_instance": "rule:admin_or_owner",
     "update_servicechain_instance:shared": "rule:admin_only"
 }

Any datapath impact caused by a shared resource has to be
defined by the driver itself.

The Neutron mapping driver refactor will include sharing of the
following resources:

- L3_Policy: only usable by the same tenant;
- L2_Policy: only usable by the same tenant;
- PTG: usable by any tenant when shared for PT placement;
- Policy Classifiers: usable by any tenant when shared;
- Policy Actions: usable by any tenant when shared;
- Policy Rules: usable by any tenant when shared;
- Service Chain Specs: usable by any tenant when shared;
- Service Chain Nodes: usable by any tenant when shared.

L3 and L2 policies need to be sharable to allow PTG sharing.
However, no external tenant could use them because there's no
way today in Neutron to share a Router.
Security groups are also not sharable in Neutron, therefore
PRS is not listed above.

One use case for sharing PTG is when the could admin provides a
common management PTG to all the tenants. They could then create
multi-homed VMs and use it according to the policies.


Alternatives
------------

At this time there's no alternative proposal.

Data model impact
-----------------

A "shared" field is added to the resources listed in
the "Proposed change" section.

REST API impact
---------------

The REST API will show the "shared" attribute for the
resource listed in the "Proposed change" section.

Security impact
---------------

This blueprint has no security impact.

Notifications impact
--------------------

This blueprint has no impact on notifications.

Other end user impact
---------------------

The end user will now be able to see and consume
shared resources.

Performance impact
------------------

This blueprint does not have significant impact on performance.

Other deployer impact
---------------------

This blueprint does not have deployment impact

Developer impact
----------------

GBP driver's developers should now be aware that some
resources could be shared among tenants and therefore
should program accordingly.

Implementation
==============

Assignee(s)
-----------

Primary assignee:
  mmaleckk

Other contributors:
  None

Work items
----------

* Add resource attribute to REST API;

* Add model fields to the proper resources;

* Refactor Neutron resource mapping driver to support shared resources.

Dependencies
============

None

Testing
=======

Unit tests will be added to verify the resource visibility
and usability.

Documentation impact
====================

Eventual GBP documentation will need to provide explanations
on how the "shared" attribute works and examples on how to
use it.

References
==========

None
