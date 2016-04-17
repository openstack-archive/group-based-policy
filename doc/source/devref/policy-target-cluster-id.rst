..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
Policy Target HA mode
==========================================


Problem description
===================
With the introduction of more sophisticated network services and service chaining
modes, one limitation that we encountered was the impossibility for GBP to describe
a cluster of HA endpoints, defined as a collection of Policy Target that can freely
interchange their datapath identity (MAC and IP address) to the end of replacing
one another whenever the network service requires so (for example, during an HA
failover).

In the GBP universe, members of the same PTG share the same policy characteristics,
such as security, quality or connectivity constraints. This however does not cover
sharing the same network "identity", qualified as Mac or IP address in the datapath.
We need a way to allow a Policy Target to impersonate another Policy Target in the
network.

Proposed change
===============
The proposal is to introduce a new attribute to the PT description, called
"cluster_id". A cluster ID is none other but a string which identifies that a specific
Policy Target belongs to an HA cluster.
Whenever cluster_id is set, the PTs that share the same cluster identity will be
able to impersonate one another depending on the backend implementation.

In the reference implementation (Neutron) this is achieved by leveraging Neutron's
"allowed-address-pair" extension. In the first iteration, for the resource_mapping driver,
cluster_id will not be allowed to be just any generic string, but a UUID pointing
to an existing Policy Target. That Policy Target will be identified as the "Master"
of the cluster. Any member of the cluster will be added the ability to impersonate
the Master by setting its IP and MAC addresses in the "allowed-address-pair" of
the member's Neutron Port.

a "Master" PT (defined as a PT pointed by the cluster_id field of another PT) could
be itseld part of the same cluster (for debugability purpose) although it's not
mandatory.

By default, this attribute will be only exposed to the Admin role.


Data model impact
-----------------

Policy Target:
    * cluster_id: String


REST API impact
---------------

Changes to the PT API::

 POLICY_TARGETS: {
         'cluster_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '', 'is_visible': True}
 }

Security impact
---------------

As a Policy Target can now impersonate another PT in the datapath, that includes
a potential risk when done for malicious reasons. The API however will be open
only to Admins, and its scope limited in a single PTG (so no Group escape can
happen).

Notifications impact
--------------------

When notifying a member of the cluster of a Datapath change, all the cluster's
members should be notified in order to take coherent action.

Other end user impact
---------------------

None

Performance impact
------------------

None

Other deployer impact
---------------------

None

Developer impact
----------------

Node Drivers' developers can use this API with an admin context in order to
aggregate PTs for their advanced network services.

Community impact
----------------

None

Alternatives
------------

This kind of problem seems to fit very well in the Label or Multi-Group realm,
to which it can eventually migrate (requires wider discussion)

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

None

Developer documentation
-----------------------

See developer impact

References
==========

[0] https://github.com/stackforge/group-based-policy-specs/blob/master/specs/kilo/gbp-service-chain-driver-refactor.rst
[1] http://specs.openstack.org/openstack/neutron-specs/specs/api/allowed_address_pairs.html
