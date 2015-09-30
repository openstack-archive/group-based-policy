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
    print('For now skipping this entire suite ..')
    sys.exit(1)
    # Run the Testcases:
    test = test_gbp_prs_pr_shared_func()
    if test.test_gbp_prs_pr_shared_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_PR_SHARED_INTEG_1')
    if test.test_gbp_prs_pr_shared_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_PR_SHARED_INTEG_2')
    test.cleanup()
    utils_libs.report_results('test_gbp_prs_pr_shared_func',
                              'test_results.txt')
    sys.exit(1)


class test_gbp_prs_pr_shared_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_prs_pr_shared_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_prs_pr_shared_func.log')
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
            "\n## START OF GBP POLICY_RULE_SET FUNCTIONALITY TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_pa'
        self.cls_name = 'demo_pc'
        self.rule_name = 'demo_pr'
        self.ruleset_name = 'demo_prs'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['ruleset', 'rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_prs_pr_shared_func_1(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_PR_SHARED_INTEG_1: TO "
            "CREATE/UPDATE/VERIFY/DELETE/ ASSOCIATING MULTIPLE PRs to 1 "
            "POLICY RULESET \n"
            "TEST_STEP::\n"
            "Create Multiple Policy Rules with shared=True\n"
            "Create Policy RuleSet by associating all the Policy "
            "Rules and shared=False(default)\n"
            "Verify that multiple Policy Rules are associated to "
            "the Policy RuleSet\n"
            "Update the Policy RuleSet with shared=True\n"
            "Verify the Policy RuleSet's shared=True\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info(
            '\n## Step 1A: Create new PA ,new PC, 4 PRs using the '
            'same PA & PC##\n')
        new_cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'grppol_pc1', shared='True')
        if new_cls_uuid == 0:
            self._log.info(
                "\nNew Classifier Create Failed, hence "
                "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
            return 0
        new_act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'grppol_pa1', shared='True')
        if new_act_uuid == 0:
            self._log.info(
                "\nNew Action Create Failed, hence "
                "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
            return 0
        rule_uuid_list = []
        for i in range(4):
            new_rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
                1,
                'rule',
                'grppol_pr_%s' %
                (i),
                classifier=new_cls_uuid,
                action=new_act_uuid,
                description="'For devstack demo'",
                shared="True")
            if new_rule_uuid == 0:
                self._log.info(
                    "\nNew Rule Create Failed, hence "
                    "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
                return 0
            rule_uuid_list.append(new_rule_uuid)
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'ruleset',
            'grppol_prs_many',
            policy_rule='"%s %s %s %s"' %
            (rule_uuid_list[0],
             rule_uuid_list[1],
             rule_uuid_list[2],
             rule_uuid_list[3]),
            description="'For devstack demo'",
            shared='False')
        if ruleset_uuid == 0:
            self._log.info(
                "\nStep 2: Creating Policy RuleSet with multiple "
                "PRs(shared=True) and shared=False , Failed")
            return 0
        # Verify starts
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs_many',
                description='For devstack demo',
                shared='False') == 0:
            self._log.info(
                "# Step 2B: Verify Policy RuleSet and its "
                "shared='False' == Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) == 0:
            self._log.info(
                "# Step 2C: Verify Policy RuleSet and its "
                "Multiple PRs using -show option == Failed")
            return 0
        # Update the Policy RuleSet with shared=True and update should fail
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'ruleset', 'grppol_prs_many', shared='True') != 0:
            self._log.info(
                "# Step 3: Updating Policy RuleSet's Attribute "
                "shared=True DID NOT Fail")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) != 0:
            self._log.info(
                "# Step 3A: Verify Policy RuleSet and its "
                "Multiple PRs, == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs_many',
                description='For devstack demo',
                shared='False') == 0:
            self._log.info(
                "# Step 3B: Verify Policy RuleSet and its "
                "shared=False, == Failed")
            return 0

        self._log.info("\nTESTCASE_GBP_PRS_PR_SHARED_INTEG_1: PASSED")
        return 1

    def test_gbp_prs_pr_shared_func_2(self):
        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_PR_SHARED_INTEG_2: TO "
            "CREATE/UPDATE/VERIFY/DELETE/ ASSOCIATING MULTIPLE "
            "PRs to 1 POLICY RULESET\n"
            "TEST_STEP::\n"
            "Create Multiple Policy Rules witha mix of shared=True "
            "and shared=False\n"
            "Create Policy RuleSet by associating all the Policy "
            "Rules and shared=False(default)\n"
            "Verify that multiple Policy Rules are associated to "
            "the Policy RuleSet\n"
            "Update the Policy RuleSet with shared=True and update "
            "should fail\n"
            "Verify the Policy RuleSet's continues with attribute "
            "shared=False\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info(
            '\n## Step 1A: Create new PA ,new PC, 4 PRs using the '
            'same PA & PC##\n')
        new_cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'grppol_pc1', shared='True')
        if new_cls_uuid == 0:
            self._log.info(
                "\nNew Classifier Create Failed, hence "
                "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
            return 0
        new_act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'grppol_pa1', shared='True')
        if new_act_uuid == 0:
            self._log.info(
                "\nNew Action Create Failed, hence "
                "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
            return 0
        rule_uuid_list = []
        shared_flag = ['True', 'False', 'True', 'False']
        for i in range(4):
            new_rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
                1,
                'rule',
                'grppol_pr_%s' %
                (i),
                classifier=new_cls_uuid,
                action=new_act_uuid,
                description="'For devstack demo'",
                shared=shared_flag[i])
            if new_rule_uuid == 0:
                self._log.info(
                    "\nNew Rule Create Failed, hence "
                    "TESTCASE_GBP_PRS_PR_SHARED_INTEG_4 ABORTED\n")
                return 0
            rule_uuid_list.append(new_rule_uuid)
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'ruleset',
            'grppol_prs_many',
            policy_rule='"%s %s %s %s"' %
            (rule_uuid_list[0],
             rule_uuid_list[1],
             rule_uuid_list[2],
             rule_uuid_list[3]),
            description="'For devstack demo'",
            shared='False')
        if ruleset_uuid == 0:
            self._log.info(
                "\nStep 2: Creating Policy RuleSet with multiple "
                "PRs(shared=True) and shared=False , Failed")
            return 0
        # Verify starts
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs_many',
                description='For devstack demo',
                shared='False') == 0:
            self._log.info(
                "# Step 2B: Verify Policy RuleSet and its "
                "shared='False' == Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) == 0:
            self._log.info(
                "# Step 2C: Verify Policy RuleSet and its "
                "Multiple PRs using -show option == Failed")
            return 0
        # Update and Verify the PRS by updating the PRs(removing few existing
        # ones)
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'ruleset', 'grppol_prs_many', shared='True') == 0:
            self._log.info(
                "# Step 3: Updating Policy RuleSet's"
                " Attribute shared=True , Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) != 0:
            self._log.info(
                "# Step 3A: Verify Policy RuleSet and its "
                "Multiple PRs using -show option == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs_many',
                description='For devstack demo',
                shared='True') == 0:
            self._log.info(
                "# Step 3B: Verify Policy RuleSet and its "
                "shared=True, == Failed")
            return 0

        self._log.info("\nTESTCASE_GBP_PRS_PR_SHARED_INTEG_2: PASSED")
        return 1

if __name__ == '__main__':
    main()
