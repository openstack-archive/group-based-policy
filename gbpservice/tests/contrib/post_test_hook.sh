#!/bin/bash

source functions-gbp

set -x

trap prepare_logs ERR

# Check if any gbp exercises failed
exercises_exit_code=0
if grep -qs "FAILED gbp*" $LOGS_DIR/*; then
    exercises_exit_code=1
fi

# Run integration tests
echo "Running gbpfunc test suite"
cd $NEW_BASE/devstack
source openrc demo demo
cd $NEW_BASE
sudo git clone https://github.com/noironetworks/devstack -b jishnub/testsuites gbpfunctests
cd gbpfunctests/testcases/testcases_func
python suite_run.py -s func
gbpfunc_exit_code=$?

# Run functional tests
cd $GBP_DIR
echo "Running group-based-policy dsvm-functional test suite"
sudo -H tox -e dsvm-functional
testr_exit_code=$?

# Collect and parse results
generate_testr_results

# Prepare the log files for Jenkins to upload
prepare_logs

exit $(($exercises_exit_code+$gbpfunc_exit_code+$testr_exit_code))
