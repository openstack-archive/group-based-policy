============
Installation
============

At the command line::

    $ pip install gbpservice

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv gbpservice
    $ pip install gbpservice

Using DevStack
--------------

First, clone the latest ``stable/mitaka`` branch of DevStack:

    $ git clone -b stable/mitaka https://git.openstack.org/openstack-dev/devstack
    $ cd devstack

Then, create a basic ``local.conf`` including at least the following lines:

    [[local|localrc]]
    enable_plugin gbp https://git.openstack.org/openstack/group-based-policy master

Finally, you are ready to run ``stack.sh``.
