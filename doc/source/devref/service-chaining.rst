..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=========================================================================
Group Based Policy Specification for Network Service Chaining
=========================================================================

URL of the launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/group-based-policy-service-chaining

Group Based Policy provides the intent based application-oriented
abstractions for the specification of networking requirements to
deploy applications. Network Services are an essential component for
the deployment of applications. This blueprint defines how
policy-based redirection can be made to a chain of network services
based on the deployment requirements of applications. We propose an
API, Resource and DB model, and a high level design for the
implementation of this feature.

One common use-case for using multiple services can be described as a
"service-chain" - that is, application of specific services in a specific
order for every packet on a specific datapath. This API provides an
abstraction to specify that behavior with clear definition of the expected
semantics.

The goal of this specification is to provide the user with a tool that
captures their high level intent without getting coupled with incidental
details of their specific deployment. This then provides a path for migrating
such services across technology changes or for hybrid deployments. By design,
this specification does not mandate the technology used to providethat service.

Problem description
===================

Typical scenarios for combining services can usually be specified quite
succinctly (as traffic on this interface must first inspected by a firewall
and then processed by a loadbalancer). Unfortunately specifying that can many
times get mired in incidental complexity around service insertion and traffic
steering issues. If the user was able to describe that intent, we could
orchestrate the required service lifecycle events and steer the traffic as
required without exposing that complexity (and the resulting coupling)
outside the specific implementation details.

This has the added benefits that:

1. As we are only specifying the intent, it is back-end technology agnostic
2. The additional information allows us to provide technology upgrade without
   breaking service usage from a user perspective
3. It can support hybrid deployments, or migrations across vendors, even
   when the underlying technology used by those vendors is different.

Also, when specifying abstractions that are required to be implemented across
technologies, it is critical that the semantics that are expected by the API
(or implied) be clearly defined so that the usage can actually be portable
across those technologies.

Proposed change
===============

1. An API to specify a service-chain
2. An API to instantiate/delete an instance of a service-chain
3. Database updates (new resources) to support that API
4. Configuration of service-chain-providers in ini file
5. Implementation of Redirect Action (this will require
   support in the GBP mapping drivers)

Alternatives
------------

As identified in the problem statement, service insertion and traffic steering
provide a more general solution. This is a simpler use-case that does not
require those technologies to be enabled. Where traffic steering is available,
it can be used as a provider for this API.

Data model impact
-----------------

The following new resources are proposed:

1. ServiceChainNode

+-------------------+--------+---------+----------+-------------+---------------+
|Attribute          |Type    |Access   |Default   |Validation/  |Description    |
|Name               |        |         |Value     |Conversion   |               |
+===================+========+=========+==========+=============+===============+
|id                 |string  |RO, all  |generated |N/A          |identity       |
|                   |(UUID)  |         |          |             |               |
+-------------------+--------+---------+----------+-------------+---------------+
|name               |string  |RW, all  |''        |string       |human-readable |
|                   |        |         |          |             |name           |
+-------------------+--------+---------+----------+-------------+---------------+
|type               |string  |RW, all  |required  |foreign-key  |service-type   |
|(flavor?)          |        |         |          |             |               |
|                   |        |         |          |             |               |
+-------------------+--------+---------+----------+-------------+---------------+
|config             |string  |RW, all  |''        |string       | service       |
|                   |        |         |          |             | configuration |
|                   |        |         |          |             | (as a HEAT    |
|                   |        |         |          |             | template)     |
|                   |        |         |          |             | [1]_          |
+-------------------+--------+---------+----------+-------------+---------------+
|service_params     |list of |RW, all  |''        |list of      |list of        |
|                   |strings |         |          |strings      |required       |
|                   |        |         |          |             |service config |
|                   |        |         |          |             |param names    |
+-------------------+--------+---------+----------+-------------+---------------+

2. ServiceChainSpec

+-------------------+--------+---------+----------+-------------+-----------------+
|Attribute          |Type    |Access   |Default   |Validation/  |Description      |
|Name               |        |         |Value     |Conversion   |                 |
+===================+========+=========+==========+=============+=================+
|id                 |string  |RO, all  |generated |N/A          |identity         |
|                   |(UUID)  |         |          |             |                 |
+-------------------+--------+---------+----------+-------------+-----------------+
|name               |string  |RW, all  |''        |string       |human-readable   |
|                   |        |         |          |             |name             |
+-------------------+--------+---------+----------+-------------+-----------------+
|nodes              |string  |RW, all  |required  |list of      |list of          |
|                   |        |         |          |strings      |ServiceChainNode |
|                   |        |         |          |(UUIDs)      |                 |
+-------------------+--------+---------+----------+-------------+-----------------+
|service_params     |list of |RO, all  |generated |N/A          |list of required |
|                   |strings |         |          |             |service config   |
|                   |        |         |          |             |parameter names  |
+-------------------+--------+---------+----------+-------------+-----------------+

service_params is generated by aggregating the service_params of each of
the ServiceChainNodes in the ServiceChainSpec. The parameter is not specified
in the API to create the ServiceChainSpec resource.

3. ServiceChainInstance

+--------------------+-------+---------+---------+-----------------+-----------------+
|Attribute           |Type   |Access   |Default  |Validation/      |Description      |
|Name                |       |         |Value    |Conversion       |                 |
+====================+=======+=========+=========+=================+=================+
|id                  |string |RO, all  |generated|N/A              |identity         |
|                    |(UUID) |         |         |                 |                 |
+--------------------+-------+---------+---------+-----------------+-----------------+
|name                |string |RW, all  |''       |string           |human-readable   |
|                    |       |         |         |                 |name             |
+--------------------+-------+---------+---------+-----------------+-----------------+
|service-chain-spec  |string |RW, all  |required |foreign-key for  |service-chain    |
|                    |       |         |         |ServiceChainSpec |spec for this    |
|                    |       |         |         |                 |instance         |
+--------------------+-------+---------+---------+-----------------+-----------------+
|provider_ptg        |string |RW, all  |required |foreign-key      |Destination      |
|                    |(UUID) |         |         |                 |PolicyTargetGroup|
|                    |       |         |         |                 |                 |
+--------------------+-------+---------+---------+-----------------+-----------------+
|consumer_ptg        |string |RW, all  |required |foreign-key      |Source           |
|                    |(UUID) |         |         |                 |PolicyTargetGroup|
|                    |       |         |         |                 |                 |
+--------------------+-------+---------+---------+-----------------+-----------------+
|classifier          |string |RW, all  |required |foreign-key      |Classifier       |
|                    |(UUID) |         |         |                 |                 |
|                    |       |         |         |                 |                 |
+--------------------+-------+---------+---------+-----------------+-----------------+
|service_param_values|string |RW, all  |required |dictionary       |configuration    |
|                    |       |         |         |                 |parameter names  |
|                    |       |         |         |                 |and values       |
+--------------------+-------+---------+---------+-----------------+-----------------+

SEMANTICS:

The expected semantics would be equivalent of:

1. As if the services were created to process traffic from consumer_ptg
   to provider_ptg that matches the classifier
   NOTE: This is just specifying that the service chain needs to be
   applied to all traffic that is traversing between the PolicyTargetGroups.
   The provider may implement it using any valid insertion strategy.
2. In the order of ServiceChainNodes in the ServiceChainSpec for
   inbound traffic to the Destination PolicyTargetGroup, and in opposite order
   for outbound traffic from the Destination PolicyTargetGroup
3. Not all providers will honor arbitrary ordering of services
   for application of the service.
   In that case, the provider will raise a "NotImplemented"
   exception.

USAGE WORKFLOW:

1. Assume a application policy that defines connectivity between
   a provider PolicyTargetGroup (ptg1) and a consumer PolicyTargetGroup (ptg2)
2. Assume that the semantics that I want to provide are of having
   all traffic from ptg1 to/from ptg2 needs to be (a) first inspected
   by a firewall, and then (b) load balanced by a load balancer.
3. Then I would create a ServiceChainSpec with 2 ServiceChainNodes.
   The first node would be of type FW and the second one LB.
   The FW node would have config string as the HEAT template for
   FWaaS configuration and the LB would have the config string as
   the HEAT template for the LBaaS configuration. CLI for that
   would look like::

       gbp servicechain-node-create --type flavor_id --config_file fw_heat_template fw_node
       gbp servicechain-node-create --type flavor_id --config_file lb_heat_template lb_node

       gbp servicechain-spec-create --nodes "fw_node;lb_node" fwlb_spec

   This creates the ordered-list ["FW", "LB"] as the list of services in the
   chain.
4. The spec fwlb_spec created in step 3 would be used as the target of a
   policy-rule in the application policy
5. Finally the GBP provider would create a ServiceChainInstance from
   this ServiceChainSpec. A equivalent CLI command for that would look
   like::

       gbp servicechain-instance-create --servicechain_spec_id fwlb_spec --provider_ptg ptg1 --consumer_ptg ptg2 --classifier classifier-all --config_param_values "vip=IP1" service-chain

   This creates a chain that applies services in the order:

   * FW->LB->ptg1 for ingress traffic, and
   * ptg1->LB->FW for egress traffic.


REST API impact
---------------

1. CRUD for ServiceChainNode
2. CRUD for ServiceChain
3. CRUD for ServiceChainInstance

Security impact
---------------

CRUD API is provided using existing API model, no new surface is exposed.

Service/Service configuration is provided by underlying services,
so no new surface is exposed.

Notifications impact
--------------------

1. All updates to service-chain-spec resources need to be relayed to the
configured service-chain-providers

2. Updates to ServiceChainNode or ServiceChainSpec need to generate
notification to backend to "fixup" the ServiceChainInstances as required.

3. It is assumed that the existing notifications exception handling
meets the needs for this API and no new constructs are specified.

Other end user impact
---------------------

1. The CLI/UI impact of this new API (not captured in this blueprint)

2. Additional configuration for service-chain-providers in ini file
   (configuration of service-chain-providers will be specific to
   service-chain-providers and is not in the scope of this BP).

Performance impact
------------------

No significant performance impact is expected.

Other deployer impact
---------------------

No other deployment impacts are expected

Developer impact
----------------

Devstack will have to be updated for service-chain-providers.

Implementation
==============

Assignee(s)
-----------

The following people are working on several different aspects of the proposed
framework:

  Hemanth Ravi (hemanth-ravi)

  Subrahmanyam Ongole (osms69)

  Magesh GV (magesh-gv)

  Prasad Vellanki (prasad-vellanki)

  Mandeep Dhami (mandeep-dhami)

  Sumit Naiksatam (snaiksat)

Work items
----------

1. Build API
2. Update Datamodel
3. Build unit-tests
4. Update Mapping driver implementation
5. Update documentation

Dependencies
============

None

Testing
=======

Unit Tests will be provided.

Documentation impact
====================

Documentation will need to be updated for:

1. Services chain model and usage
2. Configuration of service-chain-providers

References
==========

.. [1] Openstack Heat
   https://wiki.openstack.org/wiki/Heat
