#!/bin/bash

# Temporary - remove when patch is out of WIP
exit

source functions-gbp

set -x

trap prepare_logs ERR

run_gbp_rally
exit_code=$?

# Prepare the log files for Jenkins to upload
prepare_logs

exit $exit_code
