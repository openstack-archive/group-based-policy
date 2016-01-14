#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import commands
import subprocess
import sys


def main():
    """
    Main: Wrapper for shared_func tests
    """
    # Usage: python suite_admin_run.py
    print ("Functional Test Script to execute Shared Resource Testcases")
    cmd_list = ["sudo sh -c 'cat /dev/null > test_results_admin.txt'",
                "sudo chmod 777 test_results_admin.txt "]
    for cmd in cmd_list:
        commands.getoutput(cmd)
    test_list = ['tc_gbp_pr_pc_pa_shared_func.py',
                 'tc_gbp_prs_pr_shared_func.py']
    for test in test_list:
        cmd = 'python %s' % (test)
        print (cmd)
        subprocess.call(cmd, shell=True)
    results_file = open("test_results_admin.txt")
    contents = results_file.read()
    results_file.close()
    print (contents)
    print ("\n\nTotal Number of Shared Resource TestCases Executed= %s" % (
        contents.count("_SHARED_")))
    print ("\n\nNumber of TestCases Passed= %s" % (contents.count("PASSED")))
    print ("\n\nNumber of TestCases Failed= %s" % (contents.count("FAILED")))
    if contents.count("FAILED") > 0:
        sys.exit(1)
    else:
        return 0

if __name__ == "__main__":
    main()
