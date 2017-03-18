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

First, clone the latest ``stable/newton`` branch of DevStack::

    $ git clone -b stable/newton https://git.openstack.org/openstack-dev/devstack
    $ cd devstack

Then, create a basic ``local.conf`` including at least the following lines::

    [[local|localrc]]
    enable_plugin group-based-policy https://git.openstack.org/openstack/group-based-policy master

Or, if you need install from a patch under review::

    [[local|localrc]]
    enable_plugin group-based-policy https://git.openstack.org/openstack/group-based-policy <GITREF>

where, GITREF is the patchset reference of the patchset under review. E.g.::

    [[local|localrc]]
    enable_plugin group-based-policy https://git.openstack.org/openstack/group-based-policy refs/changes/65/353265/2

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

    enable_plugin group-based-policy https://github.com/openstack/group-based-policy.git master
