..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Group Based Policy Driver for OpenDaylight Controller
=====================================================

GBP plugin defines a multi-driver based framework to support
various implementation technologies (like ML2 has done for L2 support).
One of theses drivers is meant to be used with
the OpenDaylight (ODL) controller.

Internals
---------

An ODL GBP Policy Mapping Driver supports OpenDaylight GBP. It implements the PolicyDriver interface as defined in the abstract base class services.group_policy_driver_api.PolicyDriver. The GBP/ODL Mapping Driver interfaces with the ODL controller for GBP related operations, and with Neutron ML2 for network/subnet/port related operations.

An ODL GBP Mechanism Driver for Neutron ML2 Plugin provides a feedback loop to the ODL GBP Policy Mapping Driver to trigger policy target related operations when a VM is plugged into the Neutron port.