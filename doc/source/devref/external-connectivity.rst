..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

External Connectivity
=====================

Group-Based Policy includes API objects to model the external
connectivity policy. Although the objective is always to capture
the user's intent, it has to be noted that this particular case usually
requires a lot of manual configuration by the admin *outside* the cloud
boundaries (e.g. configuring external router), which means that the
usual automation provided by GBP has to be paired with meaningful tools
which allow detailed configuration when needed.

Terminology
-----------

**NAT Policy** A pool of IP addresses (range/CIDR) that will be used
by the drivers to implement NAT capabilities when needed.

**External Segment** A CIDR representing the L3 policy interface
to a given portion of the external world. The L3 Policy needs to provide
which address it has to expose on a given external access segment.

**External Route** A combination of a CIDR and a next hop
representing a portion of the external world reachable by the L3 Policy
via a given next hop.

**External Policy** A collection of ESs that provides and
consumes Policy Rule Sets in order to define the data path filtering
for the north-south traffic.

Requirements
------------

In order to talk to the external world, a given Policy Target Group
needs to satisfy the following:

- The L3P it belongs to must have at least one external access segment
  and one IP allocated;
- The External Segment must have at least one route;
- the External Segment must have an External Policy;
- The PTG must provide/consume a PRS provided/consumed by the said EP;
- The traffic has to satisfy the filtering rules defined in the PRS;

Notes and restrictions on the Neutron resource mapping side:

- The external segment maps to a Neutron subnet;
- The network in which the ES's subnet resides must be external;
- To avoid to overload the model, in this iteration the external
  subnet must always be explicit;
- Restriction: Only one External Policy per tenant is allowed
  (side effect of https://bugs.launchpad.net/group-based-policy/+bug/1398156)
- Restriction: Only one ES per EP is allowed;
- Restriction: Only one ES per L3P is allowed;
- When no nexthop is specified in a ER, the subnet GW IP will be used;
- When no address is specified by the L3P when a ES is added, one will be
  assigned automatically if available;
- Restriction: In this cycle, any NAT policy operation is completely ignored.

Database models
---------------

External connectivity is represented with::

 +----------+
 | External |
 | Policy   |
 +----+-----+
      |m
      |
      |n
 +----+-------+          +---------+
 | Ext.       |1        m| NAT     |
 | Segment    +----------+ Policy  |
 +----+-------+          +---------+
      |
      |                  +---------+
      |1                n| Ext.    |
      +------------------+ Route   |
      |                  +---------+
      |
      |                  +------------+
      |1               n | L3P Address|
      +------------------+ Allocation |
                         +------------+

All objects (excluded ER and L3PAA) have the following common attributes:
  * id - standard object uuid
  * name - optional name
  * description - optional annotation
  * shared - whether the object is shared or not

External Segment
  * ip_version - [4, 6]
  * cidr - string on the form <subnet>/<prefix_length> which describes
    the external segment subnet
  * l3_policies - a list of l3_policies UUIDs
  * port_address_translation - boolean, specifies whether PAT needs to be performed
    using the addresses allocated for the L3P

NAT Policy
  * ip_version - [4,6]
  * ip_pool - string, IPSubnet with mask used to pull addresses from
    for NAT purposes
  * external_segments - UUID list of the ESs using this NAT policy

External Route
  * cidr - string, IPSubnet with mask used to represent a portion of the
    external world
  * netx_hop - string, ip address describing where the traffic should be sent
    in order to reach cidr
  * external_segment_id - UUID of the ES through which this ER is
    consumable

External Policy
  * external_segments - a list of external access segments UUIDs
  * provided_policy_rules_set - a list of provided policy rules set UUIDs
  * consumed_policy_rules_set - a list of consumed policy rules set UUIDs

L3P Address Allocation
  * external_segment_id - ES UUID
  * l3_policy_id - L3P UUI
  * allocated_address - IP address belonging to the ES subnet

Furthermore, L3 Policies contain the following relevant attribute:
  * external_segments - A dictionary in the form
    {<es_uuid>: [<my_es_ip>, ...]}. It represents which ES the L3P is connected
    through, and which addresses it uses on it.