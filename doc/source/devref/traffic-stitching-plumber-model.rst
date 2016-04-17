..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Traffic Stitching Plumber
=========================

As part of the service chain refactor effort, GBP now supports the ability to provision
"node centric" service chains that are composed of interoperable multi-vendor service
nodes linked by a Plumber, which takes care of placing the services in the underlying
infrastructure in a way that complies with the user intent.
Each Node Driver will expose a set of networking requirements via the get_plumbing_info
API, that will be used by the plumber to ensure that the traffic flows correctly.

The Traffic Stitching Plumber (TScP) uses the GBP underlying constructs in
order to guarantee a correct traffic flow across services from their provider
to the consumer and vice versa. The output of the plumbing operations are
either the creation or deletion of a set of Service Targets, which effectively
result in creation of Policy Targets exposed to the specific Node Driver for
its own use. In addition to that, TScP creates a set of L2Ps and/or PTGs
that are "stitched" together and host the actual service PTs.

Internals
---------

The PROXY_GROUP driver extension, is an extension of the base
GBP API that introduces a way to "proxy" a PTG with another that "eats" all
the incoming and outgoing traffic from the original PTG. The Resource Mapping
Driver is already compliant with the PROXY_GROUP extension.

The TScP exclusively makes use of existing GBP constructs
(and proxy_group extension) in order to deploy a chain. This guarantees
interoperability across multiple backend solutions.

PROXY_GROUP driver extension.
    The main functionality exposed by this extension is the ability to put a PTG
    "in front" of an existing one (in a linked list fashion). Whenever a PTG
    proxies another, all the traffic going to the original PTG will have to go
    through the proxy fist. Traffic from the Proxy through the original group will
    go through a special PT that has the proxy_gateway flag set to True.
    In addition to the above, a new "group_default_gateway" attribute is introduced
    for PTs, that indicates a special PT that will take the default gateway address
    for a given group (typically enforced by reserving the corresponding Neutron
    Subnet address). The flow representation below describes how traffic flows
    from a L3P (for simplicity) to a PTG proxied by another:

    asciiflow::

     +---+                    +-------+
     |   |                    |       |                 +-------+
     |   |     +--------------+       +-----------+     |       |
     |PTG<-----> proxy_gateway| PROXY | group dgw <----->  L3P  |
     |   |     +--------------+       +-----------+     |       |
     |   |                    |       |                 +-------+
     +---+                    +-------+


    There are two types of Proxies: L2 and L3 proxy. A L2 proxy will share the
    same subnets as the original group (at least at the CIDR level, may be different
    Neutron's subnets). In a L2 Proxy traffic is supposed to go through the proxy
    without being routed. A L3 proxy will route traffic to the original group,
    and will have its own subnet coming from a proxy_ip_pool, new attribute that
    extends the L3P.

    Note that this extension will be exclusively for *internal* use! Meaning that
    the TScP is likely the only entity that will even make use of this API.


RMD compliance with PROXY_GROUP extension.
    The RMD will use existing Neutron constructs for implementing the PROXY_GROUP
    extension using the semantic described above. More specifically, whenever a
    Proxy is put in front of a PTG, the latter will be detached from the L3P router and
    replaced by the Proxy. Is then expected that a proxy_gateway PT is created and
    a proper function (depending from the proxy type) is created for ensuring traffic
    flow.

    In case of L3 proxies, the subnet allocation will happen just like it does for
    normal PTGs, but from a different Pool (proxy_ip_pool). Also, routes need
    to be updated properly across the Neutron subnets/routers when a L3 Proxy
    is used.

TScP implementation.
    The last step of the implementation is the TScP itself. By using the new
    PROXY_GROUP constructs, the TScP plumber will take care of setting up the
    Service Chain datapath.
    Depending on the plumbing type used (defined in a different blueprint) the
    TScP will create the correct proxy type and PTs to be provided to the node
    driver for the actual service plugging to happen. Support for a management
    PTG will also be implemented.

Database models
---------------

A number of tables are created for the PROXY_GROUP extension to work:

GroupProxyMapping (gp_group_proxy_mappings):
    * policy_target_group_id - proxy PTG UUID;
    * proxied_group_id - UUID of the proxied PTG
    * proxy_group_id - UUID of the current PTG's proxy
    * proxy_type - ENUM (L2/L3)


ProxyGatewayMapping(gp_proxy_gateway_mappings):
    * policy_target_id - PT UUID
    * proxy_gateway - Bool indicating whether this PT is a gateway to proxy
    * group_default_gateway - Bool indicating whether this PT is the DG for its PTG


ProxyIPPoolMapping(gp_proxy_ip_pool_mapping):
    * l3_policy_id - L3P UUID
    * proxy_ip_pool - IP pool (address/cidr) to be used for L3 proxies
    * proxy_subnet_prefix_length - Iterger value, prefix len for the proxy subnets

REST API
--------

The REST API changes look like follows (note that they only ally if the PROXY_GROUP
extension is configured)::

 EXTENDED_ATTRIBUTES_2_0 = {
     gp.POLICY_TARGET_GROUPS: {
         'proxied_group_id': {
             'allow_post': True, 'allow_put': False,
             'validate': {'type:uuid_or_none': None}, 'is_visible': True,
             'default': attr.ATTR_NOT_SPECIFIED,
             'enforce_policy': True},
         'proxy_type': {
             'allow_post': True, 'allow_put': False,
             'validate': {'type:values': ['l2', 'l3', None]},
             'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED,
             'enforce_policy': True},
         'proxy_group_id': {
             'allow_post': False, 'allow_put': False,
             'validate': {'type:uuid_or_none': None}, 'is_visible': True,
             'enforce_policy': True},
         # TODO(ivar): The APIs should allow the creation of a group with a
         # custom subnet prefix length. It may be useful for both the proxy
         # groups and traditional ones.
     },
     gp.L3_POLICIES: {
         'proxy_ip_pool': {'allow_post': True, 'allow_put': False,
                           'validate': {'type:subnet': None},
                           'default': '192.168.0.0/16', 'is_visible': True},
         'proxy_subnet_prefix_length': {'allow_post': True, 'allow_put': True,
                                        'convert_to': attr.convert_to_int,
                                        # for ipv4 legal values are 2 to 30
                                        # for ipv6 legal values are 2 to 127
                                        'default': 29, 'is_visible': True},
         # Proxy IP version is the same as the standard L3 pool ip version
     },
     gp.POLICY_TARGETS: {
         # This policy target will be used to reach the -proxied- PTG
         'proxy_gateway': {
             'allow_post': True, 'allow_put': False, 'default': False,
             'convert_to': attr.convert_to_boolean,
             'is_visible': True, 'required_by_policy': True,
             'enforce_policy': True},
         # This policy target is the default gateway for the -current- PTG
         # Only for internal use.
         'group_default_gateway': {
             'allow_post': True, 'allow_put': False, 'default': False,
             'convert_to': attr.convert_to_boolean,
             'is_visible': True, 'required_by_policy': True,
             'enforce_policy': True},
     },
 }