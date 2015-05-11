#!/bin/bash

set -xe

NEW_BASE="$BASE/new"
GBP_DIR="$NEW_BASE/group-based-policy"
SCRIPTS_DIR="/usr/local/jenkins/slave_scripts"
LOGS_DIR="$NEW_BASE/logs"

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H chmod o+rw .
    sudo -H chmod o+rw -R .testrepository
    if [ -f ".testrepository/0" ] ; then
        .tox/dsvm-functional/bin/subunit-1to2 < .testrepository/0 > ./testrepository.subunit
        .tox/dsvm-functional/bin/python $SCRIPTS_DIR/subunit2html.py ./testrepository.subunit testr_results.html
        gzip -9 ./testrepository.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}


function dsvm_functional_prep_func {
    :
}

# Check if any gbp exercises failed
set +e
exercises_exit_code=0
if grep -qs "FAILED gbp*" $LOGS_DIR/*; then
    exercises_exit_code=1
fi
set -e

prep_func="dsvm_functional_prep_func"

# Run tests
echo "Running gbpfunc test suite"
set +e
cd $NEW_BASE/devstack
source openrc demo demo
cd $NEW_BASE
sudo git clone https://github.com/noironetworks/devstack -b jishnub/testsuites gbpfunctests
cd gbpfunctests/testcases/testcases_func
python suite_run.py -s func
gbpfunc_exit_code=$?
set -e

cd $GBP_DIR
# Prep the environment according to job's requirements.
$prep_func

# Run tests
echo "Running group-based-policy dsvm-functional test suite"
set +e
sudo -H tox -e dsvm-functional
testr_exit_code=$?
set -e

# Collect and parse results
generate_testr_results

# Prepare the log files for Jenkins to upload
set +e
cd $LOGS_DIR
sudo mv screen/screen*.*.log .
sudo rm -rf screen
for f in $(find . -name "*.20*.log"); do
    sudo mv $f ${f/.log/.txt}
done
sudo gzip -9fk `find . -maxdepth 1 \! -type l -name "*.txt" | xargs ls -d`
mv *.gz /opt/stack/logs/
set -e

exit $(($exercises_exit_code+$gbpfunc_exit_code+$testr_exit_code))
