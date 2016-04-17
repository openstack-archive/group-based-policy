..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=====================================================
Group Based Policy Driver for OpenDaylight Controller
=====================================================

Launchpad blueprint:
https://blueprints.launchpad.net/group-based-policy/+spec/gbp-odl-driver

GBP plugin has defined a multi-driver based framework to support
various implementation technologies (like ML2 has done for L2 support).
This blueprint proposes a Group Based Policy (GBP) driver to enable GBP
plugin to be used with OpenDaylight (ODL) controller.

Problem description
===================
The Group Based Policy blueprint has proposed new application centric APIs for
Neutron. Similar to the work in Neutron, there is work in the OpenDaylight
project to implement these APIs as well. With the APIs being implenented in
both of these open source projects, we propose a GBP driver to allow OpenStack GBP to orchrestrate ODL GBP

Proposed change
===============
The proposed change will:
1. Add a new ODL GBP Policy Mapping Driver to support OpenDaylight GBP. It will implement the PolicyDriver interface as defined in the abstract base class services.group_policy_driver_api.PolicyDriver, as documented in the GBP BP. The proposed GBP/ODL Mapping Driver will interface with ODL controller for GBP related operations, and with Neutron ML2 for network/subnet/port related operations.

2. Add a new ODL GBP Mechanism Driver for Neutron ML2 Plugin. Such a mechanism driver will provide a feedback loop to the ODL GBP Policy Mapping Driver to trigger policy target related operations when a VM is plugged into the Neutron port.