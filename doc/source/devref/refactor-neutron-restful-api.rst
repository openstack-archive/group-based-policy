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