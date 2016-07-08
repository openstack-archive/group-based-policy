#!/bin/bash

source functions-gbp

set -x

trap prepare_logs ERR

# Run exercise scripts
$TOP_DIR/exercise.sh
exercises_exit_code=$?

source $TOP_DIR/lib/nfp
delete_nfp_gbp_resources $TOP_DIR

# Check if exercises left any resources undeleted
check_residual_resources neutron service
check_residual_resources admin admin
check_residual_resources admin demo
check_residual_resources demo demo

# Prepare the log files for Jenkins to upload
prepare_logs

exit $(($exercises_exit_code))
