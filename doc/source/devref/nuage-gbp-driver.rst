..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Nuage Networks GBP Driver
=========================

Nuage's Virtualized Services Platform(VSP) [1] supports
policy based orchestration which fits well with the Group-Based Policy
project. The VSP solution can thus be used through OpenStack.
It also allows OpenStack users to take advantage of Nuage's
fully baked policy driven, application centric service architecture.

Since the GBP plugin defines a multi-driver based framework
to support various implementation technologies (like ML2 for L2 support),
a GBP driver is available to support Nuage's solution. This driver
interfaces with the Nuage's VSD using the ReST channel similar to how its
done in Nuage's monolithic plugin.

Terminology
-----------

Requirements
------------

Database models
---------------

Internals
---------
The PolicyDriver interface is defined in the abstract base class
gbpservice/neutron/services/grouppolicy/group_policy_driver_api.py:
PolicyDriver.

Nuage's VSD has an inbuilt application centric APIs which fits nicely with
GBP. The driver acts as a proxy for managing coresponding objects on VSD.
Nuagenetlib (private python library) is used to make this call. This is in
line with the implementation model for nuage's core plugin and ml2 driver.

Configuration
-------------

References
----------
