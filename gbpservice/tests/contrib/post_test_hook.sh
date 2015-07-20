#!/bin/bash

source functions-gbp

set -x

trap prepare_logs ERR

# Run exercise scripts
$TOP_DIR/exercise.sh
# Check if any gbp exercises failed
exercises_exit_code=0
if grep -qs "FAILED gbp*" $LOGS_DIR/*; then
    exercises_exit_code=1
fi

# Check if exercises left any resources undeleted
check_residual_resources admin admin
check_residual_resources admin demo
check_residual_resources demo demo

# Run gbpfunc integration tests
echo "Running gbpfunc test suite"
cd $NEW_BASE
sudo git clone http://github.com/group-policy/gbpfunctests gbpfunctests
export PYTHONPATH="${PYTHONPATH}:/"
cd gbpfunctests/testcases
python suite_run.py upstream
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
