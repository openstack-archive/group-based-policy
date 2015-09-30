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
import sys

from libs import config_libs
from libs import utils_libs
from libs import verify_libs


def main():

    # Run the Testcases:
    test = test_gbp_prs_neg()
    if test.test_gbp_prs_neg_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_NEG_1')
    if test.test_gbp_prs_neg_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_NEG_2')
    if test.test_gbp_prs_neg_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_NEG_3')
    test.cleanup()
    utils_libs.report_results('test_gbp_prs_neg', 'test_results.txt')
    sys.exit(1)


class test_gbp_prs_neg(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_prs_neg.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_prs_neg.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):
        """
        Init def
        """
        self._log.info(
            "\n## START OF GBP POLICY_RULE_SET NEGATIVE TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_pa'
        self.cls_name = 'demo_pc'
        self.rule_name = 'demo_pr'
        self.ruleset_name = 'demo_prs'
        self._log.info('\n## Step 1: Create a PC needed for PRS Testing ##')
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if self.cls_uuid == 0:
            self._log.info(
                "\nReqd Policy Classifier Create Failed, "
                "hence GBP Policy Rule-Set Negative Test Suite Run ABORTED\n")
            return
        self._log.info('\n## Step 1: Create a PA needed for PRS Testing ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name)
        if self.act_uuid == 0:
            self._log.info(
                "\nReqd Policy Action Create Failed, hence GBP "
                "Policy Rule-Set Negative Test Suite Run ABORTED\n")
            return
        self._log.info('\n## Step 1: Create a PR needed for PRS Testing ##')
        self.rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'rule', self.rule_name, classifier=self.cls_name,
            action=self.act_name)
        if self.rule_uuid == 0:
            self._log.info(
                "\nReqd Policy Rule Create Failed, hence GBP "
                "Policy Rule-Set Negative Test Suite Run ABORTED\n ")
            return

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['ruleset', 'rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_prs_neg_1(self):

        self._log.info(
            "\n#################################################\n"
            "TESTCASE_GBP_PRS_NEG_1: TO CREATE/VERIFY POLICY "
            "RULESET with INVALID POLICY RULE\n"
            "TEST_STEPS::\n"
            "Create Policy RuleSet Object with Invalid PR\n"
            "Verify the create FAILs and config rolls back\n"
            "#################################################\n")

        # Testcase work-flow starts
        self._log.info("\n## Step 1: Create Policy RuleSet with Invalid PR ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'ruleset',
                self.ruleset_name,
                policy_rules='INVALID') != 0:
            self._log.info(
                "# Step 1: Create RuleSet with Invalid PR did NOT Fail")
            return 0
        self._log.info('# Step 1A: Verify Policy RuleSet config rolled back')
        if self.gbpverify.gbp_policy_verify_all(
                1, 'ruleset', self.ruleset_name) != 0:
            self._log.info(
                "# Step 1A: Verify RuleSet config roll back did NOT Fail")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_NEG_1: PASSED")
        return 1

    def test_gbp_prs_neg_2(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PRS_NEG_2: TO CREATE/VERIFY POLICY "
            "RULESET with mix of VALID and  INVALID POLICY RULE\n"
            "TEST_STEPS::\n"
            "Create Policy RuleSet with a mix of Valid and Invalid PR\n"
            "Verify the create FAILs and config rolls back\n"
            "##################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Policy RuleSet with mix of Valid "
            "and Invalid PR ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'ruleset',
                self.ruleset_name,
                policy_rules="'%s INVALID'" %
                (self.rule_uuid)) != 0:
            self._log.info(
                "# Step 1: Create RuleSet with mix of Valid and "
                "Invalid PR did NOT Fail")
            return 0
        self._log.info('# Step 1A: Verify Policy RuleSet config rolled back')
        if self.gbpverify.gbp_policy_verify_all(
                1, 'ruleset', self.ruleset_name) != 0:
            self._log.info(
                "# Step 1A: Verify RuleSet config roll back did NOT Fail")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_NEG_2: PASSED")
        return 1

    def test_gbp_prs_neg_3(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PRS_NEG_3: TO UPDATE/VERIFY POLICY "
            "RULE with VALID and INVALID PR\n"
            "TEST_STEPS::\n"
            "Create a Policy RuleSet with default attribute\n"
            "Update the Policy RuleSet with a mix of Valid and Invalid PR\n"
            "Verify the update fails and config roll backs to "
            "original values of the PRS\n"
            "##################################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create a PRS with default attribute ##\n')
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', self.ruleset_name)
        if ruleset_uuid == 0:
            self._log.info(
                "\n## Step 1: Create RuleSet with default attr == Failed")
            return 0
        self._log.info(
            "\n## Step 2: Update the PRS with VALID PR and INVALID PR")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'ruleset', ruleset_uuid, policy_rule='"%s INVALID"' %
                (self.rule_name)) != 0:
            self._log.info(
                "\n## Step 2: Updating Policy RuleSet with VALID "
                "and INVALID Policy Rules did NOT Fail")
            return 0
        self._log.info(
            '# Step 2A: Verify RuleSet config update has been rolled back')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                self.ruleset_name,
                id=ruleset_uuid,
                policy_rules=self.rule_uuid,
                shared='False') != 0:
            self._log.info("# Step 2A: Verify RuleSet roll back did NOT Fail")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_NEG_3: PASSED")
        return 1

if __name__ == '__main__':
    main()
