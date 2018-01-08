#!/bin/bash

CONTRIB_DIR="$BASE/new/group-based-policy/gbpservice/tests/contrib"
cp $CONTRIB_DIR/functions-gbp .
source functions-gbp

set -x

trap prepare_logs ERR

# temporary fix for bug 1693689
export IPV4_ADDRS_SAFE_TO_USE=${DEVSTACK_GATE_IPV4_ADDRS_SAFE_TO_USE:-${DEVSTACK_GATE_FIXED_RANGE:-10.1.0.0/20}}

prepare_gbp_aim_devstack
FORCE=yes $TOP_DIR/stack.sh

# Use devstack functions to install mysql and psql servers
source $TOP_DIR/stackrc
source $TOP_DIR/lib/database
disable_service postgresql
enable_service mysql
initialize_database_backends
install_database
