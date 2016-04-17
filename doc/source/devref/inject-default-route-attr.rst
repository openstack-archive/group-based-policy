..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Allow control of default route injection
========================================

For every PTG that is created and associated with a subnet, a default
gateway is set for that subnet. A route to this default gateway is
injected automtically whenever a VM obtains a DHCP IP.

When a VM is associated with more than one PTG, it can get a default
route for the subnet associated with every PTG. This can lead to one default
route overriding another one and might not be desirable in certain cases.

To overcome that, the attribute "inject_default_route" of the l2_policy
resource can be used, suppressing the default route propagation for all PTGs
associated with the l2_policy.

Terminology
-----------

Requirements
------------

Database models
---------------
The following attribute is part of the l2_policy resources and is defined as::

    'inject_default_route': {'allow_post': True, 'allow_put': True,
                             'default': True, 'is_visible': True,
                             'convert_to': attr.convert_to_boolean,
                             'required': False},

Internals
---------

Configuration
-------------

References
----------
