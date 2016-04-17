..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.
 http://creativecommons.org/licenses/by/3.0/legalcode

Floating IP Support
===================

The Network Service Policy resource in GBP supports different features through
the definition of the associated Network Service Parameters, a dictionary that
includes a type and a value.

To allocate a single IP address from a given PTG subnet, the NSP should be
created with type ip_single and value self_subnet, indicating that a single
IP Address has to be allocated from the PTG subnet to which the
Network Service Policy is attached. This is used in Network Services, where
when we have a redirect to a Loadbalancer, the IP for the VIP comes from GBP.

To represent a Floating IP Allocation (FIP) Policy, the NSP type ip_pool is
used alongside the value nat_pool. This allows something like an Advanced
Services management PTG, where we require all PTs on that PTG to get a
floating IP associated to the port.

Requirements
------------

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

Internals
---------
When a PT is created, the Resource Mapping Driver retrieves the Network Service Policy defined for the PTG. If there is a Network Service Parameter with type ip_pool and value nat_pool, the external segment is retrieved from the L3 Policy the PTG belongs to. From the external segment the nat pool is fetched and then a Floating IP is allocated out of the nat pool and associated with the PT port.
For backward compatibility with Juno, the nat_pool resource is forced to have the same ip_pool CIDR as the external subnet.

Network Service Policy create or update operations raise an error if an external segment having a nat pool is not associated with the L3Policy for the PTGs the NSP refers to.
