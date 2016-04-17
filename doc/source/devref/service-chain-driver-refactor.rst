..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
Service Chain Driver Refactor
==========================================


Problem description
===================
Current service chain driver is a monolithic entity that couples the service
chaining logic along with the service configuration logic. Decoupling of these
entities will allow development of a service configuration driver independent
of the chaining mechanism.

Proposed change
===============
At a high level the following changes are proposed:

1. Refactor current Service Chain Service structure in order to
   easily accommodate new plugins;

2. Create a new API object called "Service Profile". This object
   contains a set of attributes that can describe the service
   (eg. service_type, vendor, insertion_mode and so forth).
   Service Profile will be extensible from day one;

3. Replace the "service_type" attribute on the Service Chain Node
   with the "service_profile" attribute. The latter is an UUID
   pointing to an existing Service Profile object;

4. Create a new "Node Composition Plugin". The Plugin can load one or
   multiple "Node Driver(s)". A Node Driver is capable of deploying,
   destroying and updating Service Chain Node instances depending
   on their profile;

5. The plumbing info of all the scheduled nodes will be used by the
   NCP for traffic stitching/steering. This will be a pluggable module
   (NodePlumber);

6. Define Service Configuration and Management driver interface;

7. Implement 2 reference implementations of Node Drivers.
   They will use Nova (for NFV) and Neutron in the backend.

The relationship between the Services Plugin and Node Drivers is as shown below:


The Node Composition Plugin  implementation is designed as the following class
hierarchy:

asciiflow::

 +--------------------------------------+      +-----------------------------------------+
 |NodeComposPlugin(ServiceChainDbPlugin)|      |      NodeDriverBase                     |
 |                                      |      |                                         |
 |                                      |      |                                         |
 |                                      |      |                                         |
 |                                      |      |                                         |
 |                                      |      |                                         |
 |                                      |      |                                         |
 |                                      |1    N|                                         |
 |                                      +------+                                         |
 +--------------------------------------+      +-----------------------------------------+
 | *create       *update      *delete   |      | *get_plumbing_info()                    |
 |    *SCI          *SCI         *SCI   |      | *validate_create(NodeContext)           |
 |    *SCS          *SCS         *SCS   |      | *validate_update(NodeContext)           |
 |    *SCN          *SCN         *SCN   |      | *create(NodeContext)                    |
 +-----------------+--------------------+      | *delete(NodeContext)                    |
                   |                           | *update(NodeContext)                    |
 +-----------------+--------------------+      | *update_policy_target_added(NContext,PT)|
 |NodePlumber                           |      | *update_policy_target_removed(...)      |
 |                                      |      |                                         |
 |                                      |      |                                         |
 +--------------------------------------+      |                                         |
 |                                      |      +---------v----------v----------v---------+
 | *plug_services(NContext,Deployment)  |                |          |          |
 | *unplug_services(NContext,Deployment)|                |          |          |
 |                                      |         +------+------+   |   +------+------+
 +--------------------------------------+         |             |   |   |             |
                                                  | Nova        |   |   | Neutron     |
 +--------------------------------------+         | Node        |   |   | Node        |
 |            NodeContext               |         | Driver      |   |   | Driver      |
 |                                      |         |             |   |   |             |
 | *core plugin                         |         |             |   |   |             |
 | *sc plugin                           |         +-----v-------+   |   +------v------+
 | *provider ptg                        |               |           |          |
 | *consumer ptg                        |               |           |          |
 | *policy target(s)                    |               |           |          |
 | *management ptg                      |         +-----+----+ +----+---+ +----+-----+
 | *service chain instance              |         | SC Node  | | SC Node| | SC Node  |
 | *service chain node                  |         | Driver   | | Driver | | Driver   |
 | *service chain spec                  |         +----------+ +--------+ +----------+
 | *service_targets                     |
 | *l3_plugin                           |
 | *gbp_plugin                          |
 |                                      |
 +--------------------------------------+
 |                                      |
 |                                      |
 +--------------------------------------+


Node Driver Base
This supports operations for CRUD of a service, and to query the number of
data-path and management interfaces required for this service.
Also supports call backs for notifications on added and removed Policy Targets
on a relevant PTG. This can be used for example to support auto-scaling by
adding new members to a loadbalancer pool.

Node Context
Provides useful attributes and methods for the Node Driver to use.
CRUD on "service targets" are useful to create service specific
Policy Targets in defined PTGs (provider/consumer/management)

The Node Driver operations are called as pre-/post-commit hooks.

Service Targets
This is an *internal only* construct. It's basically a normal Policy Target
but with some metadata which makes easy to understand which service it
belongs to, in which order, on which side of the relationship, for which
Node, deployed by which driver. Will require a new table to store all
these info.

Nova Node Driver
This provides a reusable implementation for managing the lifecycle of a
service VM.

Neutron Node Driver
This provides a reusable implementation for managing existing Neutron
services.

Node Driver
This configures the service based on the “config” provided in the Service
Node definition.

Node Plumber
The Node Plumber is a pluggable module that performs the network orchestration
required to insert the service nodes, and plumb traffic to them per the user's
intent captured in the service chain specification. It achieves this by creating
the appropriate Neutron and GBP constructs (e.g. Ports, Networks, Policy Targets,
Policy Target Groups) based on the requirements of the Node Driver and in the
context of realizing the Service Chain.

Deployment (input parameter in plug and unplug services methods)
A deployment is a list composed as follows::

 [{'context': node_context,
  'driver': deploying_driver,
  'plumbing_info': node_plumbing_needs},
   ...]

The position of a given node in the service chain can be retrieved by the Node Driver
using node_context.current_position

Management Policy Target Group
A PTG can be marked for service management by setting the newly added "service_management"
attribute to True. In the default policy.json this operation can be only done by an Admin,
who can create (and only one) Management PTG per tenant plus a globally shared one.
Whenever a SCI is created the NCP will first look for an existing Management PTG on the SCI
owner tenant. If none, the NCP plugin will query for an existing shared PTG, which could potentially
belong to any tenant (typically one with admin capabilities). If no Management PTG is found, the
service instantiation will proceed without it and it's the Node Driver's duty to refuse a service
instantiation if it requires a Management PTG.


Data model impact
-----------------

Service Target
  * policy_target_id - PT UUID
  * service_chain_instance_id - SCI UUID
  * service_chain_node_id - SCN UUID, the one of the specific node this ST belongs to
  * relationship - Enum, PROVIDER|CONSUMER|MANAGEMENT
  * order - Int, order of the node within the chain

Service Profile
  * id - standard object uuid
  * name - optional name
  * description - optional annotation
  * shared - whether the object is shared or not
  * vendor - optional string indicating the vendor
  * insertion_mode - string L2|L3|BITW|TAP
  * service_type -  generic string (eg. LOADBALANCER|FIREWALL|...)
  * service_flavor - generic string (eg. m1.tiny)

Service Chain Node
  * REMOVE service_type
  * service_profile_id - SP UUID

Policy Target Group
  * service_management - bool (default False)

Service Chain Instance
  * management_ptg_id - PTG UUID

REST API impact
---------------

The REST API changes look like follows::

 SERVICE_PROFILES: {
     'id': {'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid': None}, 'is_visible': True,
            'primary_key': True},
     'name': {'allow_post': True, 'allow_put': True,
              'validate': {'type:string': None},
              'default': '', 'is_visible': True},
     'description': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True, 'default': ''},
     'tenant_id': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:string': None},
                   'required_by_policy': True, 'is_visible': True},
     attr.SHARED: {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
     'vendor': {'allow_post': True, 'allow_put': True,
                'validate': {'type:string': None},
                'is_visible': True, 'default': ''},
     'insertion_mode': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:values':
                                     scc.VALID_INSERTION_MODES},
                        'is_visible': True, 'default': None},
     'service_type': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:string': None},
                      'is_visible': True, 'required': True},
     'service_flavor': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'required': True},
 }

The following is added to servicechain node::

 SERVICECHAIN_NODES: {
      'service_profile_id': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid': None},
                             'required': True, 'is_visible': True},
  }

The following is added to policy target group::

 POLICY_TARGET_GROUPS: {
      'service_management': {'allow_post': True, 'allow_put': True,
                             'default': False,
                             'convert_to': attr.convert_to_boolean,
                             'is_visible': True, 'required_by_policy': True,
                             'enforce_policy': True},
 }

The following is added to service chain isntance::

 SERVICECHAIN_INSTANCES: {
     'management_ptg_id': {'allow_post': True, 'allow_put': False,
                           'validate': {'type:uuid_or_none': None},
                           'is_visible': True, 'default': None,
                           'required': True}
 }

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

TBD

Developer impact
----------------

TBD

Community impact
----------------


Alternatives
------------


Implementation
==============

Assignee(s)
-----------

* Ivar Lazzaro (mmaleckk)

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


