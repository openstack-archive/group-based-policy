#!/bin/bash

source functions-gbp

set -x

trap prepare_logs ERR

sudo git --git-dir=/opt/stack/new/neutron/.git --work-tree=/opt/stack/new/neutron show --name-only
sudo git --git-dir=/opt/stack/new/neutron/.git --work-tree=/opt/stack/new/neutron status
sudo pip show neutron-lib
sudo git --git-dir=/opt/stack/new/group-based-policy/.git --work-tree=/opt/stack/new/group-based-policy show --name-only
sudo git --git-dir=/opt/stack/new/group-based-policy/.git --work-tree=/opt/stack/new/group-based-policy status

# Run exercise scripts
$TOP_DIR/exercise.sh
exercises_exit_code=$?

# Check if exercises left any resources undeleted
check_residual_resources admin admin
check_residual_resources admin demo
check_residual_resources demo demo

# Run gbpfunc integration tests
echo "Running gbpfunc test suite"
export PYTHONPATH="$GBP_FUNC_DIR:${PYTHONPATH}"
cd $GBP_FUNC_DIR/testcases
# Run shared_resource tests as admin cred
source_creds $TOP_DIR/openrc admin admin
python suite_admin_run.py
gbpfunc_admin_exit_code=$?
# Run rest of the tests as non-admin cred
source_creds $TOP_DIR/openrc demo demo
python suite_non_admin_run.py upstream
gbpfunc_non_admin_exit_code=$?

# Prepare the log files for Jenkins to upload
prepare_logs

exit $(($exercises_exit_code+$gbpfunc_admin_exit_code+$gbpfunc_non_admin_exit_code))
