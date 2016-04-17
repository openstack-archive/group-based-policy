..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=====================================================
Group Based Policy Refactor: Use Neutron RESTful APIs
=====================================================

Launchpad blueprint:
https://blueprints.launchpad.net/group-based-policy/+spec/neutron-rest-api-refactor

This blueprint proposes using neutron RESTful APIs in resource mapping driver.

Problem description
===================
The current (Juno) GBP RMD interacts with neutron directly through
neutron-plugin calls. This tight coupling prevents GBP from being
instantiated as separate process/service.

This blueprint proposes a loose coupling by moving GBP to use the neutron
RESTful APIs. More specifically, a neutron RESTful API client wrapper will be
implemented, and the neutron internal APIs previously used in GBP will be
replaced by calls to this client wrapper.

Proposed change
===============
The proposed change will:

1. Add neutron v2 API module. This module will provide APIs to neutron
resources' CRUD operation. This code will be added to:
gbpservice/network/neutronv2
This will be similar to how nova is doing it [2].
2. Refactor resource mapping driver code to replace neutron neutron-plugin
calls with the neutron v2 API calls.

Alternatives
------------
None.

Data model impact
-----------------
Re-factoring the resource mapping driver code with the neutron RESTful APIs
are invisible to users, therefore should not by itself require structural
changes to the data model currently defined in the group based policy.

REST API impact
---------------
None.

Security impact
---------------
None.

Notifications impact
--------------------
None.

Other end user impact
---------------------
None.

Performance impact
------------------
There will be some minimal performance imapct after refactoring as RESTful
APIs are used.

Other deployer impact
---------------------
None.

Developer impact
----------------
None.

Implementation
==============

Assignee(s)
-----------
Yapeng Wu

Yi Yang

Work items
----------
1. Add neutron v2 API module.
2. In RMD, replace neutron-plugin calls with neutron v2 API calls.

Dependencies
============
Neutron Python Client (minimum version 2.3.9) and plan to move to later
version.

Testing
=======
1. UT for the Neutron Client Wrapper:
Additional UT for the Neutron RESTful API wrapper will be provided.

2. UT for the Resource Mapping Driver:
In current RMD UT implementation, when a call such as "create_policy_target"[3]
is made, the RMD UT is making neutron-plugin call. With the proposed RMD
changes, those neutron-plugin calls will get replaced with the ClientWrapping
class methods. To get this work in the UT environment, the ClientWraping class
methods will be patched with neutron-plugin calls.

Another type calls in current RMD UT implementation are neutron-wsgi calls (
"new_*_request") [4]. These calls are implemented in Neutron test framework[5]
via WSGI requests. These calls will stay as they are.

3. Long Term Plan
When GBP becomes an independent server, the neutron-wsgi calls will being
refactored. These refactor can be handled in the spec for the independent
server.

Documentation impact
====================
None

References
==========
[1]
http://git.openstack.org/cgit/stackforge/group-based-policy-specs/tree/specs/juno/group-based-policy-abstraction.rst
[2] https://github.com/openstack/nova/tree/master/nova/network/neutronv2
[3] https://github.com/stackforge/group-based-policy/blob/master/gbpservice/neutron/tests/unit/services/grouppolicy/test_resource_mapping.py#L317
[4] https://github.com/stackforge/group-based-policy/blob/master/gbpservice/neutron/tests/unit/services/grouppolicy/test_resource_mapping.py#L339
[5] https://github.com/openstack/neutron/blob/master/neutron/tests/unit/test_db_plugin.py#L200-L249
