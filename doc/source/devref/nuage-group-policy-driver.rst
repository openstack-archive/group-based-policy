===================================================
Group Based Policy Driver for Nuage Networks
===================================================

Launchpad blueprint:
https://blueprints.launchpad.net/group-based-policy/+spec/nuage-gbp

Group based policy driver for Nuage Networks

Problem description
===================

Nuage's Virtualized Services Platform(VSP) [1] supports
policy based orchestration which fits well with
newly defined group based policy framework in openstack.
It will enrich the VSP solution by extending its usage through openstack.
And also allow openstack user to take advantage of Nuage's
fully baked policy driven, application centric service architecture.

Proposed change
===============

We propose the addition of a new GBP driver to support Nuage.
It will implement the PolicyDriver interface as defined in the
abstract base class services.group_policy_driver_api.PolicyDriver:

We will support CRUD operation on policy-target, policy-target-group,
policy-classifier, policy-action and policy-rule resources.

The proposed GBP driver will interface with the Nuage's VSD using ReST
channel similar to how its done in Nuage's monolithic plugin. Library will
be re-used to avoid code duplication.

Alternatives
------------

None

Data model impact
-----------------

None (existing GBP model should suffice)

REST API impact
---------------

None

Security impact
---------------

None

Notifications impact
--------------------

None

Other end user impact
---------------------

None

Performance impact
------------------

This driver should allow for more efficient and scalable solution
for group based policy control of deployments using Nuage's VSP.

Other deployer impact
---------------------

None

Developer impact
----------------

None


Implementation
==============
Nuage's VSD has an inbuilt application centric APIs which will fit nicely with
GBP. The driver will act as a proxy for managing coresponding objects on VSD.
Nuagenetlib (private python library) will be used to make this call. This is inline
with implementation model for nuage's core plugin and ml2 driver. The supported
list of resources are mentioned in "Proposed change" section.

Assignee(s)
-----------

Ronak Shah (ronak-malav-shah)

Work items
----------

1. Developing the Nuage GBP driver
2. Writing corresponding Unit and functional tests

Dependencies
============

Group Based Policy Plugin

Testing
=======

Unit tests will be provided.
Nuage CI may need to be enhanced to support this feature.

Documentation impact
====================

Documentation needs to be updated to reflect the addition of a new
GBP driver and its configuration parameters.

References
==========

[1] http://www.nuagenetworks.net/products/

