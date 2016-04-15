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

First, clone the latest ``stable/mitaka`` branch of DevStack::

    $ git clone -b stable/mitaka https://git.openstack.org/openstack-dev/devstack
    $ cd devstack

Then, create a basic ``local.conf`` including at least the following lines::

    [[local|localrc]]
    enable_plugin gbp https://git.openstack.org/openstack/group-based-policy master

Finally, you are ready to run ``stack.sh``.

Here is an example of a working Group-Based Policy DevStack local.conf file
with logging, a custom password for all services and a custom git remote
pointing to GitHub::

    [[local|localrc]]
    SERVICE_TOKEN=password
    ADMIN_PASSWORD=password
    DATABASE_PASSWORD=password
    RABBIT_PASSWORD=password
    SERVICE_PASSWORD=$ADMIN_PASSWORD

    LOGFILE=$DEST/logs/stack.sh.log
    LOGDAYS=2

    GIT_BASE=https://github.com
    RECLONE=True

    enable_plugin gbp https://github.com/openstack/group-based-policy.git master

