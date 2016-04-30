..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Group-Based Policy Abstraction
==============================

The OpenStack networking  model of networks, ports, subnets, routers,
and security groups provides the necessary building blocks to build a logical
network topology for connectivity. However, it does not provide the right level
of abstraction for an application administrator who understands the
application's details (like application port numbers), but not the
infrastructure details likes networks and routes. Not only that, the current
abstraction puts the burden of maintaining the consistency of the network
topology on the user.  The lack of application developer/administrator focussed
abstractions supported by a declarative model make it hard for those users
to consume the existing connectivity layer.

The GBP framework complements the OpenStack networking  model with the
notion of policies that can be applied between groups of network endpoints.
As users look beyond basic connectivity, richer network services with diverse
implementations and network properties are naturally expressed as policies.
Examples include service chaining, QoS, path properties, access control, etc.

The model allows application administrators to express their networking
requirements using group and policy abstractions, with the specifics of policy
enforcement and implementation left to the underlying policy driver. The main
advantage of the abstractions described here is that they allow for an
application-centric interface to OpenStack networking.

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

**Policy Classifier:** Characterizes the traffic that a particular Policy Rule acts on.
Corresponding action is taken on traffic that satisfies this classification
criteria.

**Policy Action:** The action that is taken for a matching Policy Rule defined in a
Policy Rule Set.

**L2 Policy (L2P):** Used to define a L2 boundary and impose additional
constraints (such as no broadcast) within that L2 boundary.

**L3 Policy (L3P):** Used to define a non-overlapping IP address space.

**Network Service Policy (NSP):** Used to define policies that are used for
assigning resources in a PTG to be consumed by network services.

Resource Model
---------------

.. code-block:: python

 RESOURCE_ATTRIBUTE_MAP = {
    POLICY_TARGETS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None}, 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'policy_target_group_id': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:uuid_or_none': None},
                                   'required': True, 'is_visible': True},
        'cluster_id': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': None},
                       'default': '', 'is_visible': True}
    },
    POLICY_TARGET_GROUPS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
        'provided_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      attr.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        'consumed_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:dict_or_none': None},
                                      'convert_to':
                                      attr.convert_none_to_empty_dict,
                                      'default': None, 'is_visible': True},
        'network_service_policy_id': {'allow_post': True, 'allow_put': True,
                                      'validate': {'type:uuid_or_none': None},
                                      'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        'service_management': {'allow_post': True, 'allow_put': True,
                               'default': False,
                               'convert_to': attr.convert_to_boolean,
                               'is_visible': True, 'required_by_policy': True,
                               'enforce_policy': True},
    },
    L2_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
        'inject_default_route': {'allow_post': True, 'allow_put': True,
                                 'default': True, 'is_visible': True,
                                 'convert_to': attr.convert_to_boolean,
                                 'required': False},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
                    'required': False},
    },
    L3_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
                       'default': 4, 'is_visible': True},
        'ip_pool': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:subnet': None},
                    'default': '10.0.0.0/8', 'is_visible': True},
        'subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                 'convert_to': attr.convert_to_int,
                                 # for ipv4 legal values are 2 to 30
                                 # for ipv6 legal values are 2 to 127
                                 'default': 24, 'is_visible': True},
        'l2_policies': {'allow_post': False, 'allow_put': False,
                        'validate': {'type:uuid_list': None},
                        'convert_to': attr.convert_none_to_empty_list,
                        'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
        'external_segments': {
            'allow_post': True, 'allow_put': True, 'default': None,
            'validate': {'type:external_dict': None},
            'convert_to': attr.convert_none_to_empty_dict, 'is_visible': True},
    },
    POLICY_CLASSIFIERS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
                     'convert_to': convert_protocol},
        'port_range': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:gbp_port_range': None},
                       'convert_to': convert_port_to_string,
                       'default': None, 'is_visible': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:values': gp_supported_directions},
                      'default': gp_constants.GP_DIRECTION_BI,
                      'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_ACTIONS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'action_type': {'allow_post': True, 'allow_put': False,
                        'convert_to': convert_action_to_case_insensitive,
                        'validate': {'type:values': gp_supported_actions},
                        'is_visible': True, 'default': 'allow'},
        'action_value': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:uuid_or_none': None},
                         'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_RULES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '', 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
        'policy_classifier_id': {'allow_post': True, 'allow_put': True,
                                 'validate': {'type:uuid': None},
                                 'is_visible': True, 'required': True},
        'policy_actions': {'allow_post': True, 'allow_put': True,
                           'default': None, 'is_visible': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    POLICY_RULE_SETS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'parent_id': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'child_policy_rule_sets': {'allow_post': True, 'allow_put': True,
                                   'default': None, 'is_visible': True,
                                   'validate': {'type:uuid_list': None},
                                   'convert_to':
                                   attr.convert_none_to_empty_list},
        'policy_rules': {'allow_post': True, 'allow_put': True,
                         'default': None, 'validate': {'type:uuid_list': None},
                         'convert_to': attr.convert_none_to_empty_list,
                         'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    },
    NETWORK_SERVICE_POLICIES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:gbp_resource_name': None},
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
        'network_service_params': {'allow_post': True, 'allow_put': False,
                                   'validate':
                                   {'type:network_service_params': None},
                                   'default': None, 'is_visible': True},
        attr.SHARED: {'allow_post': True, 'allow_put': True,
                      'default': False, 'convert_to': attr.convert_to_boolean,
                      'is_visible': True, 'required_by_policy': True,
                      'enforce_policy': True},
    }

The following defines the mapping to Neutron resources using attribute extension:

.. code-block:: python

  EXTENDED_ATTRIBUTES_2_0 = {
    gp.POLICY_TARGETS: {
        'port_id': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True, 'default': None},
        'fixed_ips': {'allow_post': True, 'allow_put': True,
                      'default': attr.ATTR_NOT_SPECIFIED,
                      'convert_list_to': attr.convert_kvp_list_to_dict,
                      'validate': {'type:fixed_ips': None},
                      'enforce_policy': True,
                      'is_visible': True},
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

All resources have the following common attributes:
  * id - standard object uuid
  * name - optional name
  * description - optional annotation

The ip_pool in L2Policies is a supernet used for implicitly assigning subnets
to PTGs.

The subnet_prefix_length in L2Policies is the default subnet length used when
implicitly assigning a subnet to a PTG.

The way ip_pool and subnet_prefix_length work is as follows: When
creating L3Policy a default ip_pool and default_subnet_prefix_length are
created. If a user creates a PTG, a subnet will be pulled from ip_pool using
default_subnet_prefix_length.

The protocol in PolicyClassifier supports names “tcp”, “icmp”, “udp” and
protocol numbers 0 to 255 are supported.

The port range in PolicyClassifier port range can be a single port number
or a range (separated by a colon).

The direction in PolicyClassifier direction can be “in”, “out”, or “bi”.

The type in PolicyAction type can be “allow” or “redirect”.

The value in PolicyAction is used only in the case of “redirect” and
corresponds to a service_chain_spec.

The default route injection in VMs can be controlled by using the
inject_default_route in the L2Policies. This is set to True by default.
When set to False, the default route propagation is suppressed for all
the PTGs belonging to a specific L2Policy. This is useful in the cases
when a VM is associated with more than one PTG, and we want it to get a
specific default route and suppress others.

NetworkServiceParams
  * type - Is one of “ip_single”, “ip_pool”, “string”
  * name - A user-defined string, e.g. vip
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

Database models
---------------

Database Objects to support Group-Based Policy:

::

  +----------+        +-------------+
  |          |        |             |
  |  Policy  |        |  Policy     |
  |  Target  |1      *|  Rule       |
  |  Groups  +-------->  Sets       |
  |  (PTG)   |        |  (PRS)      |
  |          |        |             |
  +----------+        +-------------+
       1|                   1|
        |                    |
        |*                   |*
  +-----v----+        +------v------+       +-------------+
  |          |        |             |       |             |
  |  Policy  |        |  Policy     |1     *| Policy      |
  |  Targets |        |  Rules      +-------> Actions     |
  |  (PT)    |        |  (PR)       |       | (PA)        |
  |          |        |             |       |             |
  +----------+        +-------------+       +-------------+
                            1|
                             |
                             |1
                      +------v------+
                      |             |
                      | Policy      |
                      | Classifiers |
                      | (PC)        |
                      |             |
                      +-------------+

   * [0..n]

Internals
---------

The GBP plugin class is located at `gbpservice/neutron/services/grouppolicy/plugin.py:GroupPolicyPlugin`.
The GBP plugin driver that maps resources to Neutron is located at `gbpservice/neutron/services/grouppolicy/drivers/resource_mapping.py:ResourceMappingDriver`.
