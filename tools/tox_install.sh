#!/usr/bin/env bash

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

DIR=/home/zuul/src/git.openstack.org/openstack/requirements
if [ -d "$DIR" ]; then
    pushd $DIR
    echo "tox_install checking out stable/queens of requirements"
    git checkout stable/queens
    popd
fi

set -e
set -x

install_cmd="pip install -c$1"
echo "tox_install install_cmd is $install_cmd"
shift

echo "tox_install running $install_cmd -U $*"
$install_cmd -U $*
exit $?
