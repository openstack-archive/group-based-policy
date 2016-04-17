..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==============================================
Group-based Policy Abstractions for Networking
==============================================

Launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/group-based-policy-abstraction

This blueprint proposes a networking API with a declarative policy driven
connectivity model that presents simplified application-oriented
interfaces to the user.

Problem description
===================

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

Proposed change
===============

The policy framework described in this blueprint complements the current
OpenStack networking  model with the notion of policies that can be applied
between groups of network endpoints. As users look beyond basic connectivity,
richer network services with diverse implementations and network properties are
naturally expressed as policies. Examples include service chaining, QoS, path
properties, access control, etc.

This proposal suggests a model that allows application administrators to
express their networking requirements using group and policy abstractions, with
the specifics of policy enforcement and implementation left to the underlying
policy driver. The main advantage of the extensions described in this blueprint
is that they allow for an application-centric interface to OpenStack networking that
complements the existing network-centric interface.

More specifically the new abstractions will achieve the following:

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

The following new terminology is being introduced:

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

Here is an example of how a three tier application would look like:

::

 +–––––––––+          +–––––––+          +–––––––+          +–––––––+
 |         |          | Web   |          | App   |          |DB     |
 | Outside |          | PTG   |          | PTG   |          |PTG    |
 | Public  | +––––––––+  +––+ | +––––––––+  +––+ | +––––––––+  +––+ |
 | Network +–+Web     |  |VM| +–+App     |  |VM| +–+DB      |  |VM| |
 | PTG     | |PRS     |  +––+ | |PRS     |  +––+ | |PRS     |  +––+ |
 |         | +––––––––+       | +––––––––+       | +––––––––+       |
 |         |          |  +––+ |          |  +––+ |          |  +––+ |
 |         |          |  |VM| |          |  |VM| |          |  |VM| |
 |         |          |  +––+ |          |  +––+ |          |  +––+ |
 +–––––––––+          +–––––––+          +–––––––+          +–––––––+

Example CLI:

(exmaple only shows access to the Web Server Tier from the Outside Network)

Create Classifier

::

 neutron classifier-create Insecure-Web-Access --port 80 --protocol TCP
 --direction IN

Create Policy Rule Set using the Classifier

::

 neutron policy-rule-set-create Web-Server-PRS --classifier Insecure-Web-Access
 --action ALLOW

Create PTG providing the Policy Rule Set

::

 neutron ptg-create Web-Server-PTG --provides-policy-rule-set Web-Server-PRS

Create PT in PTG

::

 neutron pt-create --epg Web-Server-PTG

Launch Web Server VM using PT in PTG

::

 nova boot --image cirros --flavor m1.nano --nic port-id=<PT-NAME> Web-Server

Specify connectivity of Outside world VMs to Web Server

::

 neutron ptg-create Outside-PTG --consumes-policy-rule-set Web-Server-PRS

Note that the Policy Rule Set Provider/Consuming Scopes are not explicitly shown in
the above diagram but define each providing and consuming relation between an
PTG and a Policy Rule Set as shown below:

::

         +––––––––––+
         |Web       |
         |PRS       |
         |Consuming |
         |Scope     |
         +–––+––––––+
 +–––––––––+ |               +––––––––––+
 |         | |               | Web      |
 | Outside | |               | PTG      |
 | Public  | | +––––––––+    |  +––+    |
 | Network +–+–+Web     +––+–+  |VM|PT  |
 | PTG     |   |PRS     |  | |  +––+    |
 |         |   +––––––––+  | |          |
 |         |               | |  +––+    |
 |         |               | |  |VM|PT  |
 |         |               | |  +––+    |
 +–––––––––+               | |          |
                           | +––––––––––+
                           +
                      +––––+–––––+
                      |Web       |
                      |PRS       |
                      |Providing |
                      |Scope     |
                      +––––––––––+

Alternatives
------------

Since a new level of abstraction is being proposed here, a direct alternate
does not exist in the current model.

Data model impact
-----------------

New Database Objects to support Group Policy:

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

Objects to support Mapping to existing Neutron resources

PolicyTargetPortBinding (extends PolicyTarget)
  * neutron_port_id - uuid of Neutron Port that this PT maps to

PolicyTargetGroupNetworkBinding (extends PolicyTargetGroup)
  * neutron_subnets - list of Neutron Subnet uuids

L2PolicyBinding (extends l2_policy)
  * neutron_network_id - reference to a Neutron network

L3PolicyBinding (extends l3_policy)
  * neutron_routers - list of Neutron Router uuids

Appropriate foreign key constraints will be added to maintain the referential
integrity of the model.

Database migrations:
New tables are being added to the schema, however the existing schema remains
unchanged.

REST API impact
---------------

The following new resources are being introduced:

.. code-block:: python

  gp_supported_actions = [None, 'ALLOW', 'REDIRECT']
  gp_supported_directions = [None, 'IN', 'OUT', 'BI']
  gp_supported_protocols = [None, 'TCP', 'UDP', 'ICMP']
  gp_supported_scopes = [None, 'GLOBAL', 'TENANT', 'PTG']

  POLICY_TARGETS = 'policy_targets'
  POLICY_TARGET_GROUPS = 'policy_target_groups'
  POLICY_RULE_SETS = 'policy_rule_sets'
  POLICY_RULE_SET_PROVIDING_SCOPES = 'policy_rule_set_providing_scopes'
  POLICY_RULE_SET_CONSUMING_SCOPES = 'policy_rule_set_consuming_scopes'
  POLICY_RULES = 'policy_rules'
  FILTERS = 'filters'
  CLASSIFIERS = 'classifiers'
  ACTIONS = 'actions'
  SELECTORS = 'selectors'
  POLICY_TAGS = 'policy_tags'
  L2_POLICIES = 'l2_policies'
  L3_POLICIES = 'l3_policies'
  NETWORK_SERVICE_POLICIES = 'network_service_policies'

  RESOURCE_ATTRIBUTE_MAP = {
      POLICY_TARGETS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None}, 'is_visible': True,
                 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None}, 'default': '',
                   'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True, 'is_visible': True},
          'policy_target_group_id': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:uuid__or_none': None},
                                     'required': True, 'is_visible': True},
      },
      POLICY_TARGET_GROUPS: {
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
          'policy_targets': {'allow_post': False, 'allow_put': False,
                             'validate': {'type:uuid_list': None},
                             'convert_to': attr.convert_none_to_empty_list,
                             'default': None, 'is_visible': True},
          'l2_policy_id': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_or_none': None},
                           'default': None, 'is_visible': True},
          'network_service_policy_id': {'allow_post': True, 'allow_put': True,
                                        'validate': {'type:uuid_or_none': None},
                                        'default': None, 'is_visible': True},
          'provided_policy_rule_set_scopes': {'allow_post': True, 'allow_put': True,
                                              'validate': {'type:uuid_list': None},
                                              'convert_to':
                                              attr.convert_none_to_empty_list,
                                              'default': None, 'is_visible': True},
          'consumed_policy_rule_set_scopes': {'allow_post': True, 'allow_put': True,
                                              'validate': {'type:uuid_list': None},
                                              'convert_to':
                                              attr.convert_none_to_empty_list,
                                              'default': None, 'is_visible': True},
      },
      POLICY_RULE_SETS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True,
                 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '',
                   'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'child_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                     'default': None,
                                     'validate': {'type:uuid_list': None},
                                     'convert_to': attr.convert_none_to_empty_list,
                                     'required': True, 'is_visible': True},
          'policy_rules': {'allow_post': True, 'allow_put': True,
                           'default': None,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'required': True, 'is_visible': True},
      },
      POLICY_RULE_SET_PROVIDING_SCOPES: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True,
                 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '',
                   'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'policy_target_group_id': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:uuid': None},
                                     'required': True, 'is_visible': True},
          'policy_rule_set_id': {'allow_post': True, 'allow_put': True,
                                 'validate': {'type:uuid': None},
                                 'required': True, 'is_visible': True},
          'selector_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:uuid_or_none': None},
                          'required': True, 'is_visible': True},
          'capabilities': {'allow_post': True, 'allow_put': True,
                           'default': None,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'required': True, 'is_visible': True},
      },
      POLICY_RULE_SET_CONSUMING_SCOPES: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True, 'primary_key': True},
            'name': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'default': '',
                     'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'policy_target_group_id': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:uuid': None},
                                     'required': True, 'is_visible': True},
          'policy_rule_set_id': {'allow_post': True, 'allow_put': True,
                                 'validate': {'type:uuid': None},
                                 'required': True, 'is_visible': True},
          'selector_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:uuid_or_none': None},
                          'required': True, 'is_visible': True},
          'roles': {'allow_post': True, 'allow_put': True,
                    'default': None,
                    'validate': {'type:uuid_list': None},
                    'convert_to': attr.convert_none_to_empty_list,
                    'required': True, 'is_visible': True},
      },
      POLICY_RULES: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True, 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '', 'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'enabled': {'allow_post': True, 'allow_put': True,
                      'default': True, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True},
          'filter_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid_or_none': None},
                        'required': True, 'is_visible': True},
          'classifier_id': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:uuid': None},
                            'required': True, 'is_visible': True},
          'actions': {'allow_post': True, 'allow_put': True,
                      'default': None,
                      'validate': {'type:uuid_list': None},
                      'convert_to': attr.convert_none_to_empty_list,
                      'required': True, 'is_visible': True},
      },
      FILTERS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True, 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '', 'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'provider_capabilities': {'allow_post': True, 'allow_put': True,
                                    'validate': {'type:uuid_list': None},
                                    'convert_to':
                                    attr.convert_none_to_empty_list,
                                    'required': True, 'is_visible': True},
          'consumer_roles': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid_list': None},
                             'convert_to': attr.convert_none_to_empty_list,
                             'required': True, 'is_visible': True},
      },
      CLASSIFIERS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True, 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '', 'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'protocol': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': None,
                       'convert_to': convert_protocol,
                       'validate': {'type:values': gp_supported_protocols}},
          'port_range': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:port_range': None},
                         'convert_to': convert_port_to_string,
                         'default': None, 'is_visible': True},
          'direction': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': gp_supported_directions},
                        'default': None, 'is_visible': True},
      },
      ACTIONS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True,
                 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '', 'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'action_type': {'allow_post': True, 'allow_put': True,
                          'convert_to': convert_action_to_case_insensitive,
                          'validate': {'type:values': gp_supported_actions},
                          'is_visible': True, 'default': 'allow'},
          'action_value': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_or_none': None},
                           'is_visible': True},
      },
      SELECTORS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True,
                 'primary_key': True},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'default': '', 'is_visible': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'scope': {'allow_post': True, 'allow_put': True,
                    'convert_to': convert_scope_to_case_insensitive,
                    'validate': {'type:values': gp_supported_scopes},
                    'is_visible': True, 'default': 'tenant'},
          'value': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True},
      },
      POLICY_TAGS: {
          'id': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:uuid': None},
                 'is_visible': True,
                 'primary_key': True},
          'description': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True, 'default': ''},
          'tenant_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:string': None},
                        'required_by_policy': True,
                        'is_visible': True},
          'namespace': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
          'name': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'required': True, 'is_visible': True},
          'values': {'allow_post': True, 'allow_put': True,
                     'default': None,
                     'validate': {'type:uuid_list': None},
                     'convert_to': attr.convert_none_to_empty_list,
                     'is_visible': True},
      },
      L2_POLICIES: {
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
          'policy_target_groups': {'allow_post': False, 'allow_put': False,
                                   'validate': {'type:uuid_list': None},
                                   'convert_to': attr.convert_none_to_empty_list,
                                   'default': None, 'is_visible': True},
          'l3_policy_id': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_or_none': None},
                           'default': None, 'is_visible': True,
                           'required': True},
      },
      L3_POLICIES: {
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
          'ip_version': {'allow_post': True, 'allow_put': False,
                         'convert_to': attr.convert_to_int,
                         'validate': {'type:values': [4, 6]},
                         'is_visible': True},
          'ip_pool': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:subnet': None},
                      'default': '10.0.0.0/8', 'is_visible': True},
          'subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                   'convert_to': attr.convert_to_int,
                                   'validate': {
                                   # for ipv4 legal values are 2 to 30
                                   # for ipv6 legal values are 2 to 127
                                   'default': 24, 'is_visible': True},
          'l2_policies': {'allow_post': False, 'allow_put': False,
                          validate': {'type:uuid_list': None},
                          'convert_to': attr.convert_none_to_empty_list,
                          'default': None, 'is_visible': True},
      },
      NETWORK_SERVICE_POLICIES: {
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
          'policy_target_groups': {'allow_post': False, 'allow_put': False,
                              'validate': {'type:uuid_list': None},
                              'convert_to': attr.convert_none_to_empty_list,
                              'default': None, 'is_visible': True},
          # A valid network_svc_params list is:
          # [{'type': <param_type>, 'name': <param_name>, 'value':
          # <param_value>}]
          # e.g. [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]
          'network_service_params': {'allow_post': True, 'allow_put': True,
                                     'validate': {'type:list': None},
                                     'convert_to':
                                      attr.convert_none_to_empty_list,
                                     'default': None, 'is_visible': True},
      },
  }

The following defines the mapping to classical (existing) Neutron resources
using attribute extension:

.. code-block:: python

  EXTENDED_ATTRIBUTES_2_0 = {
      gpolicy.POLICY_TARGETS: {
          'neutron_port_id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid_or_none': None},
                              'is_visible': True, 'default': None},
      },
      gpolicy.POLICY_TARGET_GROUPS: {
          'neutron_subnets': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_list': None},
                              'convert_to': attr.convert_none_to_empty_list,
                              'default': None, 'is_visible': True},
      },
      gpolicy.L2_POLICIES: {
          'neutron_network_id': {'allow_post': True, 'allow_put': False,
                                 'validate': {'type:uuid_or_none': None},
                                 'is_visible': True, 'default': None},
      },
      gpolicy.L3_POLICIES: {
          'neutron_routers': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid_list': None},
                              'convert_to': attr.convert_none_to_empty_list,
                              'default': None, 'is_visible': True},
      },
  }

Security impact
---------------

The connectivity model used here is consistent with OpenStack/Neutron's current
white list model - that is, there is no connectivity outside a PTG unless
explicitly allowed.

The rendering of the proposed new abstractions happens via existing Security
Groups and Firewall as a Service constructs. As such, no new constructs or
implementation that will directly affect the current security framework are
being introduced.

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

Notifications impact
--------------------

None

Other end user impact
---------------------

Integration with following projects will be required:

* python-neutronclient
* horizon
* heat
* devstack

Performance impact
------------------

A new layer of abstraction is being introduced. All performance considerations
that are relevant to existing Neutron will apply and be taken into
consideration during the implementation. It should be noted though that the use
of this new layer of abstraction/extensions is optional, and as such will not
affect the performance of the existing implementation if the former is not
used.

Other deployer impact
---------------------

* Config additions

  - Policy Plugin class

  - Policy Plugin driver class

Developer impact
----------------

This will be a new API, and will not affect existing API.

Implementation
==============

Assignee(s)
-----------

  Sumit Naiksatam (snaiksat) - Launchpad blueprint assignee

  Robert Kukura (rkukura)

  Mandeep Dhami (mandeep-dhami)

  Ivar Lazzaro (mmaleckk)

  Mohammad Banikazemi (banix)

  Stephen Wong (s3wong)

  Prasad Vellanki (prasad-vellanki)

  Hemanth Ravi (hemanth-ravi)

  Subrahmanyam Ongole (osms69)

  Magesh GV (magesh-gv)

  Ronak Shah (ronak-malav-shah)

  Rudra Rugge (rudrarugge)

  Kanzhe Jiang (kanzhe-jiang)

  Kevin Benton (kevinbenton)

Work items
----------

  Policy Manager
  Policy Driver

Dependencies
============

None

Testing
=======

Both, functional and, system tests will be added.

Documentation impact
====================

Both, API and, Admin guide will be updated.

References
==========

* Weekly IRC meetings wherein this blueprint has been discussed since Nov 2013

  - https://wiki.openstack.org/wiki/Meetings/Neutron_Group_Policy

* Group Policy Wiki - https://wiki.openstack.org/wiki/Neutron/GroupPolicy
