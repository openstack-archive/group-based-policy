..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Policy Target HA mode
=====================

With the introduction of more sophisticated network services and service
chaining modes, one limitation that we encountered was the impossibility for
GBP to describe a cluster of HA endpoints, defined as a collection of Policy
Target that can freely interchange their datapath identity
(MAC and IP address) to the end of replacing one another whenever the network
service requires so (for example, during an HA failover).

In the GBP universe, members of the same PTG share the same policy
characteristics, such as security, quality, connectivity constraints or
sharing the same network "identity", qualified as MAC or IP address in the
datapath. Policy Targets can impersonate other Policy Targets in the network.

Internals
---------

The attribute "cluster_id" of the PT description is none other but a string
which identifies that a specific Policy Target belongs to an HA cluster.
Whenever cluster_id is set, the PTs that share the same cluster identity will
be able to impersonate one another depending on the backend implementation.

In the reference implementation (Neutron) this is achieved by leveraging
Neutron's "allowed-address-pair" extension. In the current iteration, for the
resource_mapping driver, cluster_id will not be allowed to be just any generic
string, but a UUID pointing to an existing Policy Target. That Policy Target
will be identified as the "Master" of the cluster. Any member of the cluster
will be added the ability to impersonate the Master by setting its IP and MAC
addresses in the "allowed-address-pair" of the member's Neutron Port.

A "Master" PT (defined as a PT pointed by the cluster_id field of another PT)
can itself be part of the same cluster (for debuggability purposes) although
it's not mandatory.

By default, this attribute is only exposed to the Admin role.

Database models
---------------

Policy Target:
    * cluster_id: String


REST API
--------

Changes to the PT API::

 POLICY_TARGETS: {
         'cluster_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '', 'is_visible': True}
 }

Security
--------

As a Policy Target can now impersonate another PT in the datapath, that
includes a potential risk when done for malicious reasons. The API however is
open only only to Admins, and its scope limited in a single PTG (so no Group
escape can happen).

Notifications
-------------

When notifying a member of the cluster of a Datapath change, all the cluster's
members are notified in order to take coherent action.