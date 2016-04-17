..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.
 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
GBP Floating IP Policy
==========================================

Launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/gbp-floating-ip-support


Problem description
===================

The existing GBP APIs do not provide a way of defining a policy to create or associate floating IPs with a Policy Target.

Proposed change
===============

The Network Service Policy resource in GBP, at present supports allocating a single IP address from a given PTG subnet. This is achieved by creating a Network Service Parameters dictionary with type ip_single and value self_subnet to indicate that a single IP Address has to be allocated from the PTG subnet to which the Network Service Policy is attached.
This is used in Network Services, where when we have a redirect to a Loadbalancer, the IP for the VIP comes from GBP.
This network_service_params in Network Service Policy will be extended to add a new type ip_pool and a new value nat_pool to represent the Floating IP Allocation Policy.
When we have a something like a Advanced Services management PTG, where we require all PTs on that PTG to get a floating IP associated to the port. This will be achieved by attaching a Network Service Policy of type ip_pool and value nat_pool to the PTG.
Another use case to be supported is a PTG whose PTs provide a particular service and there is a Loadbalancer in front. In this case, the Loadbalancer VIP requires a floating IP to be associated if it is for North-South traffic. This will be achieved by attaching a Network Service Policy of type ip_single and value nat_pool to the Provider PTG. The allocated floating IP in this case will be sent in config_param_values to Service Chain.

Reference Implementation:
When a PT is created, the Resource Mapping Driver shall retrieve the Network Service Policy defined for the PTG. If there is a Network Service Parameter with type ip_pool and value nat_pool, the external segment is retrieved from the L3 Policy the PTG belongs to. From the external segment the nat pool is fetched and then a Floating IP is allocated out of the nat pool and associated with the PT port.
For backward compatibility with Juno, the nat_pool resource will be forced to have the same ip_pool CIDR as the external subnet.

Network Service Policy create or update operations shall raise an error if an external segment having a nat pool is not associated with the L3Policy for the PTGs the NSP refers to.

Alternatives
------------

All PTGs on a L3Policy that has a external segment configured with a nat pool shall get floating IP associated with all the PTs without the need for a Network Service Policy. The main disadvantage with this approach is that there is no fine grained control with the Floating IP association with implicit external segment association with a L3Policy, in which case all the PTs will end up getting a Floating IP.

Data model impact
-----------------

None.

REST API impact
---------------

None

Security impact
---------------

Policy Targets within the cloud reach the external world and outside world can reach
the Policy Targets when they get a FIP.
The security implications depend on the way the PRS are composed by the cloud admin.
or the Policy Target Group's policy targets to be accessible at their floating IPs from the external world, the PTG needs to have the following properties:
- The L3P it belongs to must have at least one external segment and one nat pool associated with the external segment.
- The External Segment must have at least one route.
- An External Policy should be associated with the External Segment.
- The PTG should provide/consume a PRS that allows traffic with a specific classifier.
- The External Policy should consume/provide that particular PRS.
- Traffic destined to the Floating IP, and satisfying the PRS criteria, will be NAT'ed and will reach the corresponding internal IP in the PTG.

Notifications impact
--------------------
This blueprint has no impact on notifications.

Notifications impact
--------------------

This blueprint has no impact on notifications.

Other end user impact
---------------------

The python client and the UI have to expose the new model
to the end user.

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

Primary assignee:
 Magesh GV (magesh-gv)

Other contributors:
  None

Work items
----------

- Database and API;
- Neutron mapping driver;

Dependencies
============

None

Testing
=======

New unit tests will be added for the floating IP model, and existing
unit tests for the mapping will be updated when needed.

Documentation impact
====================

Eventual GBP documentation will need to address configuration
of Network Service Policy to associate floating IP.

References
==========

None
