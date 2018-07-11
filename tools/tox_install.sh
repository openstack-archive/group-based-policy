#!/usr/bin/env bash

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

DIR=/home/zuul/src/git.openstack.org/openstack/requirements
if [ -d "$DIR" ]; then
    cd $DIR
    git checkout stable/queens
fi

set -e
set -x

install_cmd="pip install -c$1"
shift

$install_cmd -U $*
exit $?
