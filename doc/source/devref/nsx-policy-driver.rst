..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

NSX Policy Driver
===================

The NSX Policy driver utilizes VMWare NSX Policy API to provide integration
between Neutron and the VMWare NSX policy solution. The driver assumes
NSXv3 core plugin, which operates against NSXv3 manager.
First phase of support configures security resources on NSX Policy. Connectivity
configuration is enforced via neutron objects, using behavior inerited from
resource mapping driver.
Currently, the following GBP -> NSX Policy mappings are implemented:

 project -> domain, deployment map
 policy classifier -> service
 policy rule set -> communication profile
 group -> group, communication maps

Note that while neutron security groups are not created to enforce inter-group
connectivity, a single security group per GBP group will be created, for the sake
of connectivity within the group.

DevStack Support
----------------

In order to enable NSX Policy driver, add the following to local.conf when
running devstack::

    enable_plugin gbp https://git.openstack.org/openstack/group-based-policy master

    ENABLE_NSX_POLICY=True
    NSX_POLICY_MANAGER = <policy ip address>
    NSX_POLICY_USERNAME = <username>
    NSX_POLICY_PASSWORD = <password>
    NSX_MANAGER_THUMBPRINT = <thumbprint>
