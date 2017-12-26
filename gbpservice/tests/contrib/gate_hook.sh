#!/bin/bash

CONTRIB_DIR="$BASE/new/group-based-policy/gbpservice/tests/contrib"
cp $CONTRIB_DIR/functions-gbp .
source functions-gbp

set -x

trap prepare_logs ERR

# Make the workspace owned by the stack user
sudo chown -R $STACK_USER:$STACK_USER $BASE

# temporary fix for bug 1693689
export IPV4_ADDRS_SAFE_TO_USE=${DEVSTACK_GATE_IPV4_ADDRS_SAFE_TO_USE:-${DEVSTACK_GATE_FIXED_RANGE:-10.1.0.0/20}}

prepare_gbp_devstack
FORCE=yes $TOP_DIR/stack.sh

# Use devstack functions to install mysql and psql servers
source $TOP_DIR/stackrc
source $TOP_DIR/lib/database
disable_service postgresql
enable_service mysql
initialize_database_backends
install_database

# Set up the 'openstack_citest' user and database in each backend
tmp_dir=`mktemp -d`

cat << EOF > $tmp_dir/mysql.sql
CREATE DATABASE openstack_citest;
CREATE USER 'openstack_citest'@'localhost' IDENTIFIED BY 'openstack_citest';
CREATE USER 'openstack_citest' IDENTIFIED BY 'openstack_citest';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest';
FLUSH PRIVILEGES;
EOF
/usr/bin/mysql -u root < $tmp_dir/mysql.sql
