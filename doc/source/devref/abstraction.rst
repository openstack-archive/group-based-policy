..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Group-Based Policy Abstraction
==============================

The current OpenStack networking  model of networks, ports, subnets, routers,
and security groups provides the necessary building blocks to build a logical
network topology for connectivity. However, it does not provide the right level
of abstraction for an application administrator who understands the
application's details (like application port numbers), but not the
infrastructure details likes networks and routes. Not only that, the current
abstraction puts the burden of maintaining the consistency of the network
topology on the user.  The lack of application developer/administrator focussed
abstractions supported by a declarative model make it hard for those users
to consume the existing connectivity layer.

The GBP framework complements the current OpenStack networking  model with the
notion of policies that can be applied between groups of network endpoints.
As users look beyond basic connectivity, richer network services with diverse
implementations and network properties are naturally expressed as policies.
Examples include service chaining, QoS, path properties, access control, etc.

The model allows application administrators to express their networking
requirements using group and policy abstractions, with the specifics of policy
enforcement and implementation left to the underlying policy driver. The main
advantage of the extensions described is that they allow for an
application-centric interface to OpenStack networking that complements the
existing network-centric interface.

These abstractions achieve the following:

* Show clear separation of concerns between application and infrastructure
  administrator.

  - The application administrator can then deal with a higher level abstraction
    that does not concern itself with networking specifics like
    networks/routers/etc.

  - The infrastructure administrator will deal with infrastructure specific
    policy abstractions and not have to understand application specific concerns
    like specific ports that have been opened or which of them expect to be
    limited to secure or insecure traffic. The infrastructure admin will also
    have ability to direct which technologies and approaches used in rendering.
    For example, if VLAN or VxLAN is used.

  - Allow the infrastructure admin to introduce connectivity constraints
    without the application administrator having to be aware of it (e.g. audit
    all traffic between two application tiers).

* Allow for independent provider/consumer model with late binding and n-to-m
  relationships between them.

* Allow for automatic orchestration that can respond to changes in policy or
  infrastructure without requiring human interaction to translate intent to
  specific actions.

* Complement the governance model proposed in the OpenStack Congress project by
  making Policy Tags available for enforcement.

Terminology
-----------

**Policy Target (PT):** It is the smallest unit of resource abstraction at
which policy can be applied.

**Policy Target Group (PTG):** A collection of policy targets.

**Policy Rule Set (PRS):** It defines how the application services provided by
a PTG can be accessed. In effect it specifies how a PTG communicates with other
PTGs. A Policy Rule Set consists of Policy Rules.

**Policy Rule (PR):** These are individual rules used to define the communication
criteria between PTGs. Each rule contains a Filter, Classifier, and Action.

**Classifier:** Characterizes the traffic that a particular Policy Rule acts on.
Corresponding action is taken on traffic that satisfies this classification
criteria.

**Action:** The action that is taken for a matching Policy Rule defined in a
Policy Rule Set.

**Filter:** Provides a way to tag a Policy Rule with Capability and Role tags.

**Capability:** It is a Policy Label that defines what part of a Policy Rule Set a
particular PTG provides.

**Role:** It is a Policy Label that defines what part of a Policy Rule Set a PTG wants
to consume.

**Policy Rule Set Scope:** An PTG conveys its intent to provide or consume a Policy Rule Set
(or its part) by defining a Policy Rule Set Scope which references the target
Policy Rule Set.

**Selector:** A Policy Rule Set Scope can define additional constraints around choosing
the matching provider or consumer PTGs for a Policy Rule Set via a Selector.

**Policy Tags:** These are labels contained within a namespace hierarchy and
used to define Capability and Role tags used in Filters.

**L2 Policy (L2P):** Used to define a L2 boundary and impose additional
constraints (such as no broadcast) within that L2 boundary.

**L3 Policy (L3P):** Used to define a non-overlapping IP address space.

**Network Service Policy (NSP):** Used to define policies that are used for
assigning resources in a PTG to be consumed by network services.

Requirements
---------------

The connectivity model used here is consistent with OpenStack/Neutron's current
white list model - that is, there is no connectivity outside a PTG unless
explicitly allowed.

The rendering of the proposed new abstractions happens via existing Security
Groups and Firewall as a Service constructs. As such, there are no constructs
or implementations that directly affect the current security framework.

* Does this change touch sensitive data such as tokens, keys, or user data?

  No

* Does this change alter the API in a way that may impact security, such as
  a new way to access sensitive information or a new way to login?

  No

* Does this change involve cryptography or hashing?

  No

* Does this change require the use of sudo or any elevated privileges?

  No

* Does this change involve using or parsing user-provided data? This could
  be directly at the API level or indirectly such as changes to a cache layer.

  No

* Can this change enable a resource exhaustion attack, such as allowing a
  single API interaction to consume significant server resources? Some examples
  of this include launching subprocesses for each connection, or entity
  expansion attacks in XML.

  The exposed risk here is no different from the existing APIs and would largely
  depend on the Policy Driver implementation.

Database models
---------------

Database Objects to support Group-Based Policy:

::

 +–––––––––––––+     +–––––––––––––––+      +–––––––––––+
 |   Policy    |     |   PRS         |      |  Policy   |
 |   Target    |     |   Providing/  |      |  Rule     |
 |   Groups    +–––––+   Consuming   +––––––+  Sets(PRS)|
 |             |     |   Scopes      |      +–––––+–––––+
 +––––––+––––––+     +–––––––––––––––+            |
        |                                   +–––––+–––––+
        |                                   |  Policy   |
 +––––––+––––––+                            |  Rules    |
 |  Policy     |                            |           |
 |  Targets    |                      +–––––+––––––+––––+––––––––+
 |             |                      |            |             |
 +–––––––––––––+                      |            |             |
                                      |            |             |
                                +–––––+––+  +––––––+–––––+ +–––––+––+
                                |Filters |  |Classifiers | |Actions |
                                |        |  |            | |        |
                                +––––––––+  +––––––––––––+ +––––––––+

All objects have the following common attributes:
  * id - standard object uuid
  * name - optional name
  * description - optional annotation

PolicyTarget
  * ptg_id - UUID of the PolicyTargetGroup (PTG) that this PolicyTarget (PT) belongs to
  * policy_tags - a list of PolicyTag uuids

PolicyTargetGroup
  * policy_targets - list of PolicyTarget uuids
  * policy_rule_set_providing_scopes - list of PolicyRuleSetProvidingScope uuids
  * policy_rule_set_consuming_scopes - list of PolicyRuleSetConsumingScope uuids

PolicyRuleSet
  * policy_rules - ordered list of PolicyRule uuids
  * policy_rule_set_providing_scopes - list of PolicyRuleSetProvidingScope uuids
  * policy_rule_set_consuming_scopes - list of PolicyRuleSetConsumingScope uuids
  * child_policy_rule_sets - ordered list of PolicyRuleSet uuids

PolicyRuleSetProvidingScope
  * policy_rule_set_id - uuid of the PolicyRuleSet that is being provided by the PTG
  * selectors - list of Selectors uuids
  * capabilites - list of PolicyTag uuids
  * providing_ptg - PolicyTargetGroup uuid

PolicyRuleSetConsumingScope
  * policy_rule_set_id - uuid of the PolicyRuleSet that is being consumed by the PTG
  * selectors - list of Selectors uuids
  * roles - list of PolicyTags
  * consuming_ptg - PolicyTargetGroup uuid

Selector
  * scope - enum: GLOBAL, TENANT, PTG
  * value - None for GLOBAL, or uuid of tenant/PTG

PolicyTag
  * namespace - string, a namespace identifier for policy tags
  * name - string, not optional
  * values - list of PolicyValue uuids

PolicyValue
  * value - String

PolicyRule
  * filter - uuid of Filter
  * classifier - uuid of Classifier
  * actions - list of Action uuids

Filter
  * provider_capablilities - list of PolicyTag uuids
  * consumer_roles - list of PolicyTag uuids

Classifier
  * protocol - enum: TCP, IP, ICMP
  * port_range - single port number or range (as used in FWaaS firewall_rule)
  * direction - enum: IN, OUT, BI

Action
  * type - enum: ALLOW, REDIRECT, QOS, LOG, MARK, COPY
  * value - uuid of a resource that performs the action, for example in the
    case of REDIRECT, its the uuid of the Service Chain

L2Policy
  * policy_target_groups - list of PolicyTargetGroup uuids
  * l3_policy_id - uuid of the l3_policy

L3Policy
  * l2_policies - list of L2Policy uuids
  * ip_version - enum, v4 or v6
  * ip_pool - string, IPSubnet with mask, used to pull subnets from if the
    user creates a PTG without specifying a subnet
  * subnet_prefix_length - int, used as the default subnet length if
    the user creates a PTG without a subnet

The way ip_pool and subnet_prefix_length work is as follows: When
creating L3Policy a default ip_pool and default_subnet_prefix_length are
created. If a user creates a PTG, a subnet will be pulled from ip_pool using
default_subnet_prefix_length.

NetworkServicePolicy
  * policy_target_groups - list of PolicyTargetGroup uuids
  * network_service_params - list of ServiceArgument uuids

NetworkServiceParams
  * type - String, enum, ip_single, ip_pool, string
  * name - String, e.g. vip
  * value - String, e.g. self_subnet or external_subnet when the type is
    ip_single or ip_pool; a string value when the type is string
    The type and value are validated, the name is treated as a literal.
    The name of the param is chosen by the service chain implementation,
    and as such is validated by the service chain provider.
    The supported types are: ip_single, ip_pool, string.
    The supported values are: self_subnet and external_subnet,
    but the values are not validated when the tpye is 'string'.
    Valid combinations are:
    ip_single, self_subnet: Allocate a single IP addr from ptg subnet,
    e.g. VIP (in the private network)
    ip_single, external_subnet: Allocate a single floating-ip addr,
    e.g. Public address for the VIP
    ip_pool, external_subnet: Allocate a floating-ip for every PT in PTG


Objects to support Mapping to existing Neutron resources:

PolicyTargetPortBinding (extends PolicyTarget)
  * neutron_port_id - uuid of Neutron Port that this PT maps to

PolicyTargetGroupNetworkBinding (extends PolicyTargetGroup)
  * neutron_subnets - list of Neutron Subnet uuids

L2PolicyBinding (extends l2_policy)
  * neutron_network_id - reference to a Neutron network

L3PolicyBinding (extends l3_policy)
  * neutron_routers - list of Neutron Router uuids


Internals
---------

The following defines the mapping to classical (existing) Neutron resources
using attribute extension:

.. code-block:: python

  EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGETS: {
        'port_id': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True, 'default': None},
    },
    gp.POLICY_TARGET_GROUPS: {
        'subnets': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'is_visible': True, 'default': None},
    },
    gp.L2_POLICIES: {
        'network_id': {'allow_post': True, 'allow_put': False,
                       'validate': {'type:uuid_or_none': None},
                       'is_visible': True, 'default': None},
    },
    gp.L3_POLICIES: {
        'routers': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'is_visible': True, 'default': None},
    }
  }

The GBP plugin class is located at `gbpservice/neutron/services/grouppolicy/plugin.py:GroupPolicyPlugin`.
The GBP plugin driver that maps resources to Neutron is located at `gbpservice/neutron/services/grouppolicy/drivers/resource_mapping.py:ResourceMappingDriver`.
  
Configuration
-------------

References
----------
