#!/usr/bin/env bash

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

DIR=/home/zuul/src/git.openstack.org/openstack/requirements
echo "running Tox Install1!!"
if [ -d "$DIR" ]; then
    cd $DIR
    echo "Checking out stable/queens!!!"
    git checkout stable/queens
fi

set -e
set -x

install_cmd="pip install -c$1"
shift

$install_cmd -U $*
exit $?
