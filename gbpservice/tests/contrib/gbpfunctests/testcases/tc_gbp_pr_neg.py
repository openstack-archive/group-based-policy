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
import logging
import os
import sys

from libs import config_libs
from libs import utils_libs
from libs import verify_libs


def main():

    # Run the Testcases:
    test = test_gbp_pr_neg()
    if test.test_gbp_pr_neg_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_NEG_1')
    if test.test_gbp_pr_neg_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_NEG_2')
    if test.test_gbp_pr_neg_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_NEG_3')
    if test.test_gbp_pr_neg_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_NEG_4')
    test.cleanup()
    utils_libs.report_results('test_gbp_pr_neg', 'test_results.txt')
    sys.exit(1)


class test_gbp_pr_neg(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pr_neg.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pr_neg.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):
        """
        Init def
        """
        self._log.info("\n START OF GBP POLICY_RULE NEGATIVE TESTSUITE")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_pa'
        self.cls_name = 'demo_pc'
        self.rule_name = 'demo_pr'
        self._log.info('\n## Step 1: Create a PC needed for PR Testing ##')
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if self.cls_uuid == 0:
            self._log.info(
                "\nReqd Classifier Create Failed, hence GBP Policy Rule "
                "Negative Test Suite Run ABORTED\n")
            os._exit(1)
        self._log.info('\n## Step 1: Create a PA needed for PR Testing ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name)
        if self.act_uuid == 0:
            self._log.info(
                "\nReqd Action Create Failed, hence GBP Policy Rule "
                "Negative Test Suite Run ABORTED\n")
            os._exit(1)

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_pr_neg_1(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PR_NEG_1: TO CREATE/VERIFY a POLICY RULE with "
            "INVALID PC\n"
            "TEST_STEP::\n"
            "Create Policy Rule Object with Invalid PC\n"
            "Verify PR creation failed and was rolled back\n"
            "###################################################\n")

        # Testcase work-flow starts
        self._log.info("\n## Step 1: Create Rule with Invalid PC##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                1, 'rule', self.rule_name, classifier="INVALID") != 0:
            self._log.info(
                "\n## Step 1: Create Policy Rule with Invalid Policy "
                "Classifier did NOT Fail")
            return 0
        self._log.info("\n## Step 1A: Verify Policy Rule has been rolled back")
        if self.gbpverify.gbp_policy_verify_all(
                1, 'rule', self.rule_name) != 0:
            self._log.info(
                "\n## Step 1B: Verify Policy Rule did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_NEG_1: PASSED")
        return 1

    def test_gbp_pr_neg_2(self):

        self._log.info(
            "\n#################################################\n"
            "TESTCASE_GBP_PR_NEG_2: TO CREATE/VERIFY/ POLICY RULE with "
            "VALIC PC but INVALID PA\n"
            "TEST_STEP::\n"
            "Create Policy Rule Object with Valid PC but Invalid PA\n"
            "Verify the Policy Rule creation fails and config is rolled back\n"
            "#################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Policy Rule with Valid PC & Invalid PA ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'rule',
                self.rule_name,
                classifier=self.cls_name,
                action='INVALID') != 0:
            self._log.info(
                "\n## Step 1: Create Policy Rule with Invalid PA did NOT Fail")
            return 0
        self._log.info("\n## Step 1A: Verify Policy Rule has been rolled back")
        if self.gbpverify.gbp_policy_verify_all(
                1, 'rule', self.rule_name) != 0:
            self._log.info(
                "\n## Step 1A: Verify Policy Rule did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_NEG_2: PASSED")
        return 1

    def test_gbp_pr_neg_3(self):

        self._log.info(
            "\n################################################\n"
            "TESTCASE_GBP_PR_NEG_3: TO CREATE/UPDATE/VERIFY/ POLICY RULE "
            "with Invalid PC and PA ##\n"
            "TEST_STEP::\n"
            "Create Policy Rule with Valid PC and Valid PR\n"
            "Update the Policy Rule's PA by an Invalid PA\n"
            "Verify the Policy Rule's Update failed and config rolled back "
            "to original attr values\n"
            "Update the Policy Rule's PC by an Invalid PC\n"
            "Verify the Policy Rule's Update failed and config rolled back "
            "to original attr values\n"
            "#################################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create Policy Rule with PA and PC##\n')
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'rule', self.rule_name, classifier=self.cls_name,
            action=self.act_name)
        if rule_uuid != 0:
            self._log.info(
                "Step 1: Create Rule Passed, UUID == %s\n" %
                (rule_uuid))
        else:
            self._log.info("# Step 1: Create Rule == Failed")
            return 0
        self._log.info(
            '\n## Step 2: Update Policy Rule with Invalid PA and Invalid '
            'PC one at a time ##\n')
        attrib_list = [{'classifier': 'INVALID'}, {'action': 'INVALID'}]
        for attr_val in attrib_list:
            if self.gbpcfg.gbp_policy_cfg_upd_all(
                    'rule', rule_uuid, attr_val) != 0:
                self._log.info(
                    "\nStep 2: Updating Policy Rule's Attribute %s with "
                    "Invalid Value did NOT Fail" %
                    (attr_val))
                return 0
        # Verify starts
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                rule_uuid,
                name=self.rule_name,
                policy_classifier_id=self.cls_uuid,
                policy_actions=self.act_uuid) == 0:
            self._log.info(
                "# Step 2B: Verify Policy Rule Updated did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_NEG_3: PASSED")
        return 1

    def test_gbp_pr_neg_4(self):

        self._log.info(
            "\n###############################################\n"
            "TESTCASE_GBP_PR_NEG_4: DELETE NON-EXISTENT/INVALID POLICY RULE \n"
            "TEST_STEP::\n"
            "Delete unknown/invalid policy-rule\n"
            "##############################################\n")

        self._log.info("\n## Step 1: Delete non-existent Polic Rule  ##")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'rule', 'INVALID') != 0:
            self._log.info(
                "\n## Step 1: Delete Non-existent policy rule did NOT Fail")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_NEG_4: PASSED")
        return 1

if __name__ == '__main__':
    main()
