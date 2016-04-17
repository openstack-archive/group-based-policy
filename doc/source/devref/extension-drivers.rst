..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
GBP Extension Drivers
==========================================

Launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/gbp-extension-drivers

The existing group-policy-mapping extension makes assumptions that are
not valid for all GBP policy drivers. Also, certain policy drivers may
need to extend the GBP API to enable capabilities not common to all
policy drivers. To address both these issues, this blueprint adds an
extension driver framework to GBP, and re-factors the
group-policy-mapping extension as an optional driver within this
framework.

Problem description
===================

Currently, both the group-policy and group-policy-mapping extensions
are hardwired into the GBP plugin implementation. The group-policy
extension defines the core GBP API resources, while the
group-policy-mapping extension adds attributes to these resources
exposing a specific mapping from the GBP resources to Neutron
resources. Since GBP policy drivers are likely to vary in whether and
how they map GBP resources to Neutron resources, the set of attributes
defined in the group-policy-mapping extension are not likely to all be
meaningful for all policy drivers. Additional mapping attributes may
be also needed.

Also, there is currently no way to extend GBP resource APIs with
attributes enabling capabilities that are not common to all policy
drivers, without building those attributes into the GBP service plugin
itself.


Proposed change
===============

First, the extension driver framework from ML2 will be ported to GBP,
allowing GBP resources to be extended with additional attributes. An
ExtensionDriver abstract base class will be added to the
group_policy_driver_api module with the following methods and
properties:

* initialize(self) - Perform driver initialization.

* extension_alias(self) - Supported extension alias.

* process_create_<resource>(self, session, data, result) - Process
  extended attributes for <resource> creation.

* process_update_<resource>(self, session, data, result) - Process
  extended attributes for <resource> update.

* extend_<resource>_dict(self, session, result) - Add extended
  attributes to <resource> dictionary.

See the ML2 extension driver specification and code review listed
below in the references for more details.

Then GBP's current mapping extension will be re-factored as a driver
within this framework, allowing the GBP plugin to be configured with
or without this extension, or with additional or alternative resource
mapping extensions.

Either as part of this blueprint or as a follow-on blueprint, the
existing group-policy-mapping extension may be split into a
group-policy-base-mapping extension that defines only the mapping from
policy target to port, and a separate extension that defines the
remainder of the mapping exposed by the resource_mapping policy
driver.


Alternatives
------------

The alternatives considered include:

* Don't change anything in the GBP service plugin. Individual policy
  drivers can chose whether to allow each group-policy-mapping
  attribute to be set during create and update operations or to raise
  an exception when the attribute value is supplied. If they don't use
  or want to expose a specific group-policy-mapping attribute, they
  can avoid setting any value for it in the DB. No additional GBP API
  extensions are possible.

* As above, but remove attributes from the group-policy-mapping
  extension that are not applicable to most or all policy
  drivers. Most likely, only the mapping for policy target to Neutron
  port would remain.

Data model impact
-----------------

Adding the extension driver framework has no direct data model
impact. Extension drivers implemented within the framework each have
their own data models.

Re-factoring the existing group-policy-mapping extension as an
extension driver should not by itself require structural changes to
the data model currently defined in group_policy_mapping_db.py. But
making the mapping attributes optional may require using separate
tables instead of extending the existing group-policy tables as is
currently done. Since we don't yet support upgrades between GBP
releases, existing DB migrations will be modified as necessary.

REST API impact
---------------

The group-policy-mapping extension is no longer built into the GBP
service plugin, and therefore may not always be available as part of
its REST API. This blueprint itself does not require any specific REST
API changes.

Security impact
---------------

This blueprint has no security impact.

Notifications impact
--------------------

This blueprint has no impact on notifications.

Other end user impact
---------------------

The python client will need to handle the possibility that different
extensions are available based on which extension drivers are
configured.

Performance impact
------------------

This blueprint should have minimal impact on performance. The GBP
service plugin will make calls on the registered extension drivers
during all REST operations. The group-policy-mapping extension
attributes that are now implemented within the same tables as the GBP
resources will be moved to separate tables.

Other deployer impact
---------------------

A new extension_drivers configuration variable will need to be set to
enable any extensions required driver(s) specified in the
policy_drivers configuration variable.

Developer impact
----------------

Developers of policy drivers will now be able to define any needed
extensions to the GBP API by defining extension drivers.

Implementation
==============

Assignee(s)
-----------

Primary assignee:
  rkukura

Other contributors:
  None

Work items
----------

* Port extension driver API and unit tests from ML2 to GBP, with
  support for extending the policy target, policy target group, l2
  policy, and l3 policy resources.

* Re-factor the group-policy-mapping extension as an extension driver.

* Possibly add support for extending additional resource.

* Possibly split the group-policy-mapping extension into two separate
  extensions implemented by corresponding drivers.


Dependencies
============

* This blueprint enables
  https://blueprints.launchpad.net/openstack/?searchtext=mapping-extension-refactor.

Testing
=======

New unit tests will be added for the extension driver framework
itself, and existing unit tests for the mapping will be updated to
configure the required extension driver(s).

Documentation impact
====================

Eventual GBP documentation will need to address configuring extension
drivers and the fact that different policy drivers may require
different API extensions.

References
==========

* ML2 extension driver blueprint:
  https://blueprints.launchpad.net/neutron/+spec/extensions-in-ml2

* ML2 extension driver specification:
  http://git.openstack.org/cgit/openstack/neutron-specs/tree/specs/juno/neutron-ml2-mechanismdriver-extensions.rst

* ML2 extension driver code review: https://review.openstack.org/#/c/89211/
