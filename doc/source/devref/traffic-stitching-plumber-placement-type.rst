..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Traffic Stitching Plumber - Placement Type
==========================================

As part of the service chain refactor effort, GBP now supports the ability to provision
"node centric" service chains that are composed of interoperable multi-vendor service
nodes linked by a Plumber, which takes care of placing the services in the underlying
infrastructure in a way that complies with the user intent.
Each Node Driver will expose a set of networking requirements via the get_plumbing_info
API, that will be used by the plumber to ensure that the traffic flows correctly.

But how does get_plumbing_info work?

Let's go through all the use cases and iteratively define what a get_plumbing_info
call should provide in order for any Plumber (and so TScP) to be able to do its job.

Get Plumbing Info
 The plumbing info is defined as a collection of needed policy targets on a specific role,
 this may vary based on the node (obtained from the NodeDriverContext) that the specific
 driver is asked to deploy. An example of plumbing info is the following::

  {
     "management": <list of updated PT body dicts, one for each needed>,
     "provider": <list of updated PT body dicts, one for each needed>,
     "consumer": <list of updated PT body dicts, one for each needed>
  }

 The role (key of the above dictionary) specifies in which "side" the policy target has to
 exist. Depending on the kind of chaining the Neutron port could actually be placed somewhere else!
 The value is a list of attributes intended to override the PT body. This could be used, for example,
 for providing explicit Neutron Ports when the driver requires it or for establishing a naming
 convention for the PTs. An empty dictionary will be mostly used in this case, which will
 indicate a basic PT creation::

  {
     "management": [{}],  # One PT needed in the management
     "provider": [{}, {port_id: 'a'}],  # Two PT needed in the provider
     "consumer": []  # Zero PT needed in the consumer
  }

The above dictionary tells the plumber how many interfaces the node needs and where to place them.
What it doesn't tell, however, is how this service will behave in the network, which is a fundamental
information when it comes to define the interaction with its neighbors (services).
The proposal is to add a "plumbing_type" attribute to the above dictionary that defines some well known
placement options for nodes. For every option, there has to be a rationale to identify how all the services of
that class will work, what kind of neighbors they require (or disallow) and at least one supporting plumber
has to exist in order to validate that the placement works as expected. Last but not least, a clear
use case should be brought up in the form of an example service.
Possibly, limitations and behaviors of all the plumbing_types will be the same across plumbers.

In this iteration, to be supported by TScP, the following plumbing/placement types are available:

Endpoint
 * Rationale: An Endpoint needs to be directly reachable by the consumers, it is basically a traditional PT presented
   in the form of a service. This kind of services are typically useful only when directly addressed, and
   are irrelevant to the traffic course otherwise. The Endpoint Services typically get a VIP on the provider subnet.
 * Neighborhood Limitations: Because of the above, the provider side interface of an Endpoint Service typically
   is the provider itself (ie first node of the chain).
 * Cardinality Limitations: Because of the above, the number of Endpoint Services in any given chain should be one.
   Having more than one Endpoint is certainly possible, but it will defy the definition of "chain" since the consumers can
   only address one of them at a time.
 * Initial Supporting Plumber(s): Traffic Stitching Plumber
 * Example Services: L4-7 Load Balancer (Reverse Proxy)

Gateway
 * Rationale: A gateway service is a router that the PTs will use for reaching certain (or all the) destinations.
   This kind of service usually works on the packets that it's entitled to route, never modifying the Source IP Address.
   Traffic can indeed be dropped, inspected or otherwise manipulated by this kind of service.
 * Neighborhood Limitations: None
 * Cardinality Limitations: None
 * Initial Supporting Plumber(s): Traffic Stitching Plumber
 * Example Services: Router, Firewall, -Transport- Mode VPN

Transparent
 * Rationale: A transparent service is either a L2 or a BITW service. This kind of service usually has 2 logical data
   interfaces, and everything that is received in either of them is pushed on the other after processing. The 2 interfaces
   typically exist in the same subnet, so traffic is not router but switched (or simply mirrored) instead.
 * Neighborhood Limitations: None
 * Cardinality Limitations: None
 * Initial Supporting Plumber(s): Traffic Stitching Plumber
 * Example Services: Transparent FW, IDS, IPS

TODO: We have defined a service such as a tunnel mode VPN to be characterizable as a Gateway + a Floating IP (somehow similar
to a Gateway+Endpoint kind of service). We will add this new plumbing type in a subsequent update once completely define.