..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
Status for GBP Resources
==========================================

Launchpad blueprint:

https://blueprints.launchpad.net/group-based-policy/+spec/resource-status


Problem description
===================

GBP supports a configurable Policy Driver based design. Rendering of the GBP
policy model can be performed by the Policy Driver in an asynchronous manner.
However, currently there is no mechanism to reflect the state of a particular
resource while it's being rendered and/or after its successful completion or
failure. This requirement has also come up in the context of the service chain
support [#]_.


Proposed change
===============

Reflecting the operational state of a resource is typically achieved in
OpenStack projects by maintaining a ``status`` attribute [#]_ [#]_.

The status value will reflect one of the following states:

ACTIVE: The backend state of the resource is healthy and the user should expect
the configured state of the resource to be in effect

ERROR: The backend state of the resource is in error and the user should not
expect this resource to be operational

BUILD: The backend state of the resource is transient and may not be
operational but not in error state

The state transition diagram for the above states is as follows:

::

               +-----------+
    +----------+           +--------+
    |          |  BUILD    |        |
    |     +---->           <--+     |
    |     |    +-----------+  |     |
    |     |                   |     |
    |     |                   |     |
 +--v-----+---+          +----+-----v-+
 |            +---------->            |
 |  ERROR     |          |  ACTIVE    |
 |            <----------+            |
 +------------+          +------------+

In addition to the status attribute it is proposed to also add a
``status_details`` attribute. This will be a free form string of a reasonable
length that provides more granular and likely more backend-specific information
about the status.

Both ``status`` and ``status_details`` attributes will be read-only attributes
in the API and updated only by the internal implementation.

For backward compatibility, we will allow these two attributes to be set to
None. When this attribute is not set, it implies that the backend
implementation does not support the ``status`` attribute.

The changes in the backend state of a resource could be either provided by an
asynchronouse update (by the backend), or could be pulled on demand. In the
latter case, there needs to be a trigger to initiate the pull. The GET request
on a resource can serve as this trigger. However, in the current framework,
the GET request is satisfied by the plugin layer, and not relayed to the
policy driver(s). This spec proposes an update to the policy driver API which
will allow relaying the GET request the drivers.

It should be noted that if the status needs to be composed by multiple drivers,
this would be the responsibility of the participating drivers. The framework
changes proposed here would allow the status changes to be passed sequentially
between the configured drivers (in the same way that a context is passed for
the CREATE, UPDATE, and DELETE calls).

If the status, after invoking the last driver in the chain of drivers, is
different from the persisted status, the persisted status is updated
accordingly and made available to the caller.


Data model impact
-----------------

The new attributes will be modeled in the DB as follows:

::

 import sqlalchemy as sa

 sa.Column('status', sa.Enum('active', 'build', 'error',
           name='resource_status'), nullable=True)

 sa.Column('status_details', sa.String(length=4096), nullable=True)


REST API impact
---------------

The following update will be made to each resource's attribute map definition:

::

        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'status_details': {'allow_post': False, 'allow_put': False,
                           'is_visible': True},

Security impact
---------------

None


Notifications impact
--------------------

None


Other end user impact
---------------------


Performance impact
------------------

None anticipated.


Other deployer impact
---------------------

Mitaka GBP client will be needed to read resource status.

Developer impact
----------------

Policy driver implementation should appropriately set the status for GBP
resources.

The following API calls will be added to the Policy Driver API:

::
  def get_<resource>_status(self, <resource_context>):

As is the cases with CREATE, UPDATE, DELETE operations, the GBP Plugin will
sequentially call the configured drivers with this API in response to a GET
call. The initial <resource_context> is created with the state of the resource
stored in the DB, and subsequently the <resource_context> processed by each
policy driver is passed to the subsequently configured policy driver.

Community impact
----------------

Helps to achieve asynchronous behavior with GBP API.


Alternatives
------------

None


Implementation
==============

The initial patch will only update the GBP resource and DB model. The
setting of resource status will be implemented in the planned asynchronous
policy driver [#]_.

Client will be updated to report status attributes. Updates to UI and Heat will be
performed as follow up patches.

Assignee(s)
-----------

snaiksat


Work items
----------

API and DB layer updates to GBP Resources. Service Chain resources will also be
updated. Changes to the Service Chain driver will need to be handled
separately.


Dependencies
============

None


Testing
=======

Relevant UTs will be added.

Tempest Tests
-------------

None


Functional Tests
----------------

Functional tests will be added in follow up patches (as the policy drivers
start populating the status).


API Tests
---------

UTs


Documentation impact
====================

User Documentation
------------------

Will provided with the new async policy driver.


Developer Documentation
-----------------------

Devref document will be added.

References
==========

.. [#] https://bugs.launchpad.net/group-based-policy/+bug/1479706
.. [#] https://github.com/openstack/neutron/blob/master/neutron/common/constants.py#L18-L26
.. [#] http://docs.openstack.org/developer/nova/vmstates.html
.. [#] https://blueprints.launchpad.net/group-based-policy/+spec/async-policy-driver
