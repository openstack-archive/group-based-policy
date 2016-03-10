Group Based Policy (GBP) provides declarative abstractions for achieving
scalable intent-based infrastructure automation.

GBP complements the OpenStack networking model with the notion of policies
that can be applied between groups of network endpoints. As users look beyond
basic connectivity, richer network services with diverse implementations and
network properties are naturally expressed as policies. Examples include
service chaining, QoS, path properties, access control, etc.

GBP allows application administrators to express their networking requirements
using a Group and a Policy Rules-Set abstraction. The specifics of policy
rendering are left to the underlying pluggable policy driver.

GBP model also supports a redirect operation that makes it easy to abstract
and consume complex network service chains and graphs.

Checkout the GBP wiki page for more detailed information:
<http://wiki.openstack.org/GroupBasedPolicy>

The latest code is available at:
<http://git.openstack.org/cgit/openstack/group-based-policy>.

GBP project management (blueprints, bugs) is done via Launchpad:
<http://launchpad.net/group-based-policy>

For help using or hacking on GBP, you can send mail to
<mailto:openstack-dev@lists.openstack.org>.

Acronyms used in code for brevity:

- PT:  Policy Target
- PTG: Policy Target Group
- PR:  Policy Rule
- PRS: Policy Rule Set
- L2P: L2 Policy
- L3P: L3 Policy
- NSP: Network Service Policy
- EP: External Policy
- ES: External Segment