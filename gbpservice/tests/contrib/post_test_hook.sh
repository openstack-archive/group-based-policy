#!/bin/bash

set -xe

GBP_DIR="$BASE/new/group-based-policy"
TEMPEST_DIR="$BASE/new/tempest"
SCRIPTS_DIR="/usr/local/jenkins/slave_scripts"

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .testrepository
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


owner=stack
prep_func="dsvm_functional_prep_func"

# Set owner permissions according to job's requirements.
cd $GBP_DIR
sudo chown -R $owner:stack $GBP_DIR
# Prep the environment according to job's requirements.
$prep_func

# Run tests
echo "Running group-based-policy dsvm-functional test suite"
set +e
sudo -H -u $owner tox -e dsvm-functional
testr_exit_code=$?
set -e

# Collect and parse results
generate_testr_results

# Prepare the log files for Jenkins to upload
set +e
cd $BASE/new/logs
for f in $(find . -name "*.log.2*"); do
    sudo mv $f ${f/.log.*/.txt}
done
sudo gzip -9fk `find . -maxdepth 1 \! -type l -name "*.txt" | xargs ls -d`
mv *.gz /opt/stack/logs/
set -e

exit $testr_exit_code
