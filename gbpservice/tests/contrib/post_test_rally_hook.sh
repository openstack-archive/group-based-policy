#!/bin/bash

source functions-gbp

set -x

trap prepare_logs ERR

run_gbp_rally
exit_code=$?

# Prepare the log files for Jenkins to upload
prepare_logs

exit $exit_code
