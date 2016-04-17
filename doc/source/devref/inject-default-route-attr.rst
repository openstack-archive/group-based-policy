..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
Allow control of default route injection
==========================================

Launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/inject-default-route

Problem description
===================

For every PTG that is created and associated with a subnet, a default
gateway is set for that subnet. A route to this default gateway is 
injected automtically whenever a VM obtains a DHCP IP.

When a VM is associated with more than one PTG, it can get a default
route for the subnet associated every PTG. This can lead to one default
route overriding another one and might not be desirable in certain cases.


Proposed change
===============

It is proposed to add a new attribute to the l2_policy resource, that will allow
suppressing the default route propagation for all PTGs associated with this
l2_policy. The current default behavior will be maintained that the default
route is always propagated. This change will be backward compatible.

Data model impact
-----------------

A new boleean attribute "inject_default_route" will be added to the L2Policy
table.

REST API impact
---------------

A new optional attribute "inject_default_route" is added to the l2_policy resource:

        'inject_default_route': {'allow_post': True, 'allow_put': True,
                                 'default': True, 'is_visible': True,
                                 'convert_to': attr.convert_to_boolean,
                                 'required': False},


Security impact
---------------


Notifications impact
--------------------


Other end user impact
---------------------


Performance impact
------------------


Other deployer impact
---------------------


Developer impact
----------------


Community impact
----------------


Alternatives
------------


Implementation
==============


Assignee(s)
-----------

* Sumit Naiksatam (snaiksat)

Work items
----------


Dependencies
============


Testing
=======

Tempest tests
-------------


Functional tests
----------------


API tests
---------


Documentation impact
====================

User documentation
------------------


Developer documentation
-----------------------


References
==========

