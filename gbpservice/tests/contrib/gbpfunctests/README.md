# gbpfunctests: Integration and functional tests for OpenStack GBP

Instructions:

1. Make sure the library imports successfully:
export PYTHONPATH="${PYTHONPATH}:<gbpfunctest_dir>"

2. Navigate to the testcases directory:
cd <gbpfunctest_dir>/testcases

3. Run the full suite by executing:
python suite_run.py"

4. Each GBP resource can tested by running:
python tc_gbp_<resource_name>

or to test all resources:

python tc_gbp_*

