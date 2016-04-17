..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Shared Resources
================

In the context of concerns separation, it's very important that a user
(e.g. the admin) shares some of the resources he created in order for
different kind of users to be able to consume them.

To achieve this, the API offers a way to specify whether a resource is shared
or not. The behavior is consistent with Neutron's already existing sharing
policy, which means that a given resource can be either consumable by a single
tenant or shared globally. This documents defines what a shared resource means
in the context of GBP and each individual resource type.

The following resources can be shared:

* Policy Rule Sets;
* Policy Target Groups;
* L2 Policies;
* L3 Policies;
* Network Service policies;
* Policy Rules;
* Policy Classifiers;
* Policy Actions;
* Service Chain Nodes;
* Service Chain Specs.


Shared resources are modifiable only by the owner or the
admin when applied.

The Policy Target resource has been excluded from the list above
since it is intrinsically something that the user creates and
consumes for himself.

One use case for sharing PTG is when the could admin provides a
common management PTG to all the tenants. They could then create
multi-homed VMs and use it according to the policies.

Requirements
------------

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

Any datapath impact caused by a shared resource has to be
defined by the driver itself.

The Neutron mapping driver refactor includes sharing of the
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
Security groups are also not shareable in Neutron, therefore
PRS is not listed above.