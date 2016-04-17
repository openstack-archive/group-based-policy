..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Extension Drivers
=================

The extension driver framework in GBP works much like Neutron's ML2, allowing
GBP resources to be extended with additional attributes.

Requirements
------------

Eventual GBP documentation will need to address configuring extension
drivers and the fact that different policy drivers may require
different API extensions.

Database models
---------------

Extension drivers implemented within the framework each have
their own data models.

Internals
---------

An ExtensionDriver abstract base class exists within the
group_policy_driver_api module and contains the following methods and
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

Developers of policy drivers are able to define any needed
extensions to the GBP API by defining extension drivers.

Configuration
-------------

The extension_drivers configuration variable will need to be set to
enable any extensions required driver(s) specified in the
policy_drivers configuration variable.

References
----------

* ML2 extension driver blueprint:
  https://blueprints.launchpad.net/neutron/+spec/extensions-in-ml2

* ML2 extension driver specification:
  http://git.openstack.org/cgit/openstack/neutron-specs/tree/specs/juno/neutron-ml2-mechanismdriver-extensions.rst

* ML2 extension driver code review: https://review.openstack.org/#/c/89211/
