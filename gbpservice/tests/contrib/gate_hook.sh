#!/bin/bash

set -ex

find . -type d
cd $BASE/new/
sudo git clone http://github.com/group-policy/devstack -b kilo-gbp devstack-gbp
TOP_DIR=$BASE/new/devstack
cd $TOP_DIR
sudo git checkout stable/juno
sudo cp $BASE/new/devstack-gbp/lib/gbp lib/gbp
sudo cp $BASE/new/devstack-gbp/lib/infra lib/infra
sudo cp $BASE/new/devstack-gbp/stack.sh stack.sh

CONTRIB_DIR="$BASE/new/group-based-policy/gbpservice/tests/contrib"

$BASE/new/devstack-gate/devstack-vm-gate.sh

# Add a rootwrap filter to support test-only
# configuration (e.g. a KillFilter for processes that
# use the python installed in a tox env).
FUNC_FILTER=$CONTRIB_DIR/filters.template
sed -e "s+\$BASE_PATH+$BASE/new/group-based-policy/.tox/dsvm-functional+" \
    $FUNC_FILTER | sudo tee /etc/neutron/rootwrap.d/functional.filters > /dev/null

# Use devstack functions to install mysql and psql servers
cd $TOP_DIR
source $TOP_DIR/functions
source $TOP_DIR/lib/config
source $TOP_DIR/stackrc
source $TOP_DIR/lib/database
source $TOP_DIR/localrc

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
