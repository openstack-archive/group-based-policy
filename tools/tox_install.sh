#!/usr/bin/env bash

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

cd /home/zuul/src/git.openstack.org/openstack/requirements
git checkout stable/pike

set -e
set -x

install_cmd="pip install -c$1"
shift

$install_cmd -U $*
exit $?
