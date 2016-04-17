..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

===========================================================================
Group Based Policy Service Chain Driver for One Convergence NVSD Controller
===========================================================================

https://blueprints.launchpad.net/group-based-policy/+spec/gbp-oc-nvsd-servicechain-driver

This blueprint proposes a Group Based Policy (GBP) Service Chain driver to
realize GBP Service Chain APIs with One Convergence NVSD controller.

Problem description
===================

One Convergence NVSD controller implements an overlay fabric to provide
virtual networks and enable the deployment of network services in the
virtual networks. GBP Service Chain APIs define the abstractions for
specifying a chain of services that can be used as a target in GBP
Policy Rules. GBP Service Chain plugin framework provides the capability to
use different drivers to render the Service Chain definition using a specific
technology. One Convergence GBP Service Chain driver is required to implement
the GBP Service Chain APIs [2] using the connectivity, policy flow and service
insertion primitives provided by NVSD controller.

Proposed change
===============

We propose the addition of a new GBP Service Chain driver to implement the
GBP Service Chain APIs [2] and render the Service Chain using the NVSD
controller. This driver will proxy the APIs via REST interface to the NVSD
controller. The GBP Service Chain driver for NVSD controller will implement
the Service Chain driver interface based on the null implementation provided
in services.servicechain.drivers.dummy_driver.NoopDriver.

Alternatives
------------

None

Data model impact
-----------------

None (existing GBP Service Chain model is used)

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

The driver will reuse the configuration for NVSD Neutron plugin [2] to access
the NVSD controller.

Performance impact
------------------

This driver should allow for a more extensive rendering of GBP Service Chain
definitions using the One Convergence NVSD controller.

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

Magesh GV (magesh-gv)

Hemanth Ravi (hemanth-ravi)

Subrahmanyam Ongole (songole)


Work items
----------

1. Developing the NVSD GBP Service Chain driver

Dependencies
============

Group Based Policy Plugin
Group Based Policy Service Chain Plugin

Testing
=======

Unit tests will be provided.

The 3rd party One Convergence CI setup will be enhanced to cover the
testing of NVSD GBP Service Chain driver using the NVSD controller.

Documentation impact
====================

Documentation needs to be updated to reflect the addition of a new
GBP Service Chain driver and it's configuration parameters.

References
==========

.. [1] Group-based Policy Abstractions: https://review.openstack.org/#/c/123494/

.. [2] Group based Policy Network Service Chaining:
       https://review.openstack.org/#/c/125876/

.. [3] NVSD Neutron Plugin: https://review.openstack.org/#/c/69246/
