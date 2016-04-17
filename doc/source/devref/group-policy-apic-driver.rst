===================================================
Group Based Policy Driver for Cisco APIC Controller
===================================================

Launchpad blueprint:
https://blueprints.launchpad.net/neutron/+spec/group-policy-apic-driver


This blueprint proposes a Group Based Policy (GBP) driver to enable
GBP plugin to be used with Cisco APIC controller.

Problem description
===================

Cisco APIC controller enables you to create an application centric fabric.
If you require a policy driven network control in an OpenStack deployment
using the ACI fabric, the reference driver for GBP can not leverage the
efficiency or scalability provided by the native fabric interfaces available
in the APIC controller.

Since the GBP plugin defines a multi-driver based framework
to support various implementation technologies (like ML2 for L2 support),
a GBP driver is available to support the APIC controller. This driver
interfaces with the APIC controller and allows efficient and scalable use of
the ACI fabric for policy based control from the GBP plugin.

This driver should allow for more efficient and scalable solution
for group based policy control of deployments using an ACI fabric.

Internals
---------

The PolicyDriver interface is defined in the abstract base class
gbpservice/neutron/services/grouppolicy/group_policy_driver_api.py:
PolicyDriver.

Configuration
-------------

The configuration files require specific information to using this driver.
These parameters include the addresses, credentials, and any configuration
required for accessing or using the APIC controller. Where possible, it
shares the configuration with the APIC ML2 driver.