..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

========================================
 Heat Support for grouppolicy resources
========================================

https://blueprints.launchpad.net/group-based-policy-automation/+spec/group-based-policy-automation

Add support for group based policy resources in heat.

Problem description
===================

Openstack networking is being extended with policy and connectivity
abstractions to enable simplified application oriented interfaces. The
resources include policy and connectivity abstractions.

Proposed change
===============

Adding the following group based policy resources to heat:
Endpoint
Endpoint-Group
L3Policy
L2Policy

Policy-Actions
Policy-Classifiers
Policy-Rules

Contracts
Contract-Scopes
Filters
Capabilities
Roles
Selectors
Policy-Labels

Alternatives
------------

None

Data model impact
-----------------

None

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

None

Other deployer impact
---------------------

None

Developer impact
----------------

None

Implementation
==============

Assignee(s)
-----------

Susaant Kondapaneni (susaant)

Work items
----------

1. Implement resources for Endpoint, EndpointGroup, L3Policy and L2Policy
2. Implement resources for Policy-Actions, Policy-Rules and Policy-classifiers
3. Implement resources for Contracts, Contract-Scopes, Policy-Labels
4. Implement resources for Filters, Selectors, Capabilities, Roles

Dependencies
============

- [1] Group-based policy abstractions: https://review.openstack.org/#/c/123494

Testing
=======

None

Documentation impact
====================

None

References
==========

None
