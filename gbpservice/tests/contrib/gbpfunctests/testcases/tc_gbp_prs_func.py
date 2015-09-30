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
    test = test_gbp_prs_func()
    if test.test_gbp_prs_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_1')
    if test.test_gbp_prs_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_2')
    if test.test_gbp_prs_func_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_3')
    if test.test_gbp_prs_func_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_4')
    if sys.argv[1] == 'aci':
        test._log.info(
            "\nTESTCASE_GBP_PRS_FUNC_5: TO CREATE/VERIFY/DELETE/VERIFY "
            "a PARENT and CHILD POLICY RULESET\n")
        test._log.info("\nTESTCASE_GBP_PRS_FUNC_5: NOT SUPPORTED in ACI")
        test._log.info(
            "\nTESTCASE_GBP_PRS_FUNC_6: TO CHANGE/UPDATE/DELETE/VERIFY "
            "PARENT and CHILD POLICY RULESET\n")
        test._log.info("\nTESTCASE_GBP_PRS_FUNC_6: NOT SUPPORTED in ACI")
    else:
        if test.test_gbp_prs_func_5() == 0:
            test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_5')
        if test.test_gbp_prs_func_6() == 0:
            test.cleanup(tc_name='TESTCASE_GBP_PRS_FUNC_6')
    test.cleanup()
    utils_libs.report_results('test_gbp_prs_func', 'test_results.txt')
    sys.exit(1)


class test_gbp_prs_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_prs_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_prs_func.log')
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
        self._log.info('\n## Step 1: Create a PC needed for PRS Testing ##')
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if self.cls_uuid == 0:
            self._log.info(
                "\nReqd Policy Classifier Create Failed, hence GBP "
                "Policy Rule-Set Functional Test Suite Run ABORTED\n")
            return
        self._log.info('\n## Step 1: Create a PA needed for PRS Testing ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name)
        if self.act_uuid == 0:
            self._log.info(
                "\nReqd Policy Action Create Failed, hence GBP "
                "Policy Rule-Set Functional Test Suite Run ABORTED\n")
            return
        self._log.info('\n## Step 1: Create a PR needed for PRS Testing ##')
        self.rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'rule', self.rule_name, classifier=self.cls_name,
            action=self.act_name)
        if self.rule_uuid == 0:
            self._log.info(
                "\nReqd Policy Rule Create Failed, hence GBP "
                "Policy Rule-Set Functional Test Suite Run ABORTED\n ")
            return

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['ruleset', 'rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_prs_func_1(
            self,
            name_uuid='',
            ruleset_uuid='',
            rep_cr=0,
            rep_del=0):

        if rep_cr == 0 and rep_del == 0:
            self._log.info(
                "\n########################################################\n"
                "TESTCASE_GBP_PRS_FUNC_1: TO CREATE/VERIFY/DELETE/VERIFY "
                "a POLICY RULESET with DEFAULT ATTRIB VALUE\n"
                "TEST_STEP::\n"
                "Create Policy RuleSet Object\n"
                "Verify the attributes & value, show & list cmds\n"
                "Delete Policy RuleSet using Name\n"
                "Verify that PR has got deleted, show & list cmds\n"
                "##########################################################\n")

        if name_uuid == '':
            name_uuid = self.ruleset_name
        # Testcase work-flow starts
        if rep_cr == 0 or rep_cr == 1:
            self._log.info(
                '\n## Step 1: Create RuleSet with default attrib vals##\n')
            ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
                1, 'ruleset', name_uuid)
            if ruleset_uuid == 0:
                self._log.info("# Step 1: Create RuleSet == Failed")
                return 0
            self._log.info('# Step 2A: Verify RuleSet using -list cmd')
            if self.gbpverify.gbp_policy_verify_all(
                    0, 'ruleset', name_uuid, ruleset_uuid) == 0:
                self._log.info(
                    "# Step 2A: Verify RuleSet using -list option == Failed")
                return 0
            self._log.info('# Step 2B: Verify RuleSet using -show cmd')
            if self.gbpverify.gbp_policy_verify_all(
                    1, 'ruleset', name_uuid, id=ruleset_uuid,
                    shared='False') == 0:
                self._log.info(
                    "# Step 2B: Verify RuleSet using -show option == Failed")
                return 0
        #######
        if rep_del == 0 or rep_del == 1:
            self._log.info('\n## Step 3: Delete RuleSet using name  ##\n')
            if self.gbpcfg.gbp_policy_cfg_all(0, 'ruleset', name_uuid) == 0:
                self._log.info("# Step 3: Delete RuleSet == Failed")
                return 0
            if self.gbpverify.gbp_policy_verify_all(
                    0, 'ruleset', name_uuid, ruleset_uuid) != 0:
                self._log.info(
                    "# Step 3A: Verify RuleSet is Deleted using -list "
                    "option == Failed")
                return 0
            if self.gbpverify.gbp_policy_verify_all(
                    1, 'ruleset', name_uuid, id=ruleset_uuid,
                    shared='False') != 0:
                self._log.info(
                    "# Step 3B: Verify RuleSet is Deleted using "
                    "-show option == Failed")
                return 0
            if rep_cr == 0 and rep_del == 0:
                self._log.info("\nTESTCASE_GBP_PRS_FUNC_1: PASSED")
        return 1

    def test_gbp_prs_func_2(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_FUNC_2: TO CREATE/VERIFY/DELETE/VERIFY "
            "a POLICY RULESET with POLICY RULE\n"
            "TEST_STEP::\n"
            "Create Policy RuleSet Object with GBP PR\n"
            "Verify the attributes & value, show & list cmds\n"
            "Delete Policy RuleSet using Name\n"
            "Verify that PR has got deleted, show & list cmds\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info("\n## Step 1: Create Policy RuleSet with PR ##")
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', self.ruleset_name, policy_rules=self.rule_name)
        if ruleset_uuid == 0:
            self._log.info("# Step 1: Create RuleSet == Failed")
            return 0
        self._log.info('# Step 2A: Verify RuleSet using -list cmd')
        if self.gbpverify.gbp_policy_verify_all(
                0, 'ruleset', self.ruleset_name, ruleset_uuid) == 0:
            self._log.info(
                "# Step 2A: Verify RuleSet using -list option == Failed")
            return 0
        self._log.info('# Step 2B: Verify RuleSet using -show cmd')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                self.ruleset_name,
                id=ruleset_uuid,
                policy_rules=self.rule_uuid,
                shared='False') == 0:
            self._log.info(
                "# Step 2B: Verify RuleSet using -show option == Failed")
            return 0
        self.test_gbp_prs_func_1(ruleset_uuid=ruleset_uuid, rep_cr=2)
        self._log.info("\nTESTCASE_GBP_PRS_FUNC_2: PASSED")
        return 1

    def test_gbp_prs_func_3(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_FUNC_3: TO UPDATE/VERIFY/DELETE/VERIFY "
            "EACH ATTRIB of a POLICY RULESET\n"
            "TEST_STEP::\n"
            "Create Policy RuleSet using Default param values\n"
            "Update Each the Policy Rule's editable params\n"
            "Verify the Policy Rule's attributes & values, show & list cmds\n"
            "Delete the Policy Rule\n"
            "Verify Policy RuleSet successfully deleted\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create Policy RuleSet with PR ##\n')
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', self.ruleset_name, policy_rules=self.rule_name)
        if ruleset_uuid != 0:
            self._log.info(
                "Step 1: Create RuleSet Passed, UUID == %s\n" %
                (ruleset_uuid))
        else:
            self._log.info("# Step 1: Create RuleSet == Failed")
            return 0
        self._log.info('\n## Step 1A: Create new PA ,new PC, new PR##\n')
        new_cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'grppol_pc1')
        if new_cls_uuid == 0:
            self._log.info(
                "\nNew Classifier Create Failed, hence "
                "TESTCASE_GBP_PRS_FUNC_3 ABORTED\n")
            return 0
        new_act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'grppol_pa1')
        if new_act_uuid == 0:
            self._log.info(
                "\nNew Action Create Failed, hence "
                "TESTCASE_GBP_PRS_FUNC_3 ABORTED\n")
            return 0
        new_rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            'grppol_pr',
            classifier=new_cls_uuid,
            action=new_act_uuid,
            description="'For devstack demo'")
        if new_rule_uuid == 0:
            self._log.info(
                "\nNew Rule Create Failed, hence "
                "TESTCASE_GBP_PRS_FUNC_3 ABORTED\n")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs',
                policy_rule=new_rule_uuid,
                description="'For devstack demo'") == 0:
            self._log.info(
                "\nStep 2: Updating Policy RuleSet's Attributes , Failed")
            return 0
        # Verify starts
        if self.gbpverify.gbp_policy_verify_all(
                0, 'ruleset', 'grppol_prs', ruleset_uuid) == 0:
            self._log.info(
                "# Step 2A: Verify Policy RuleSet Updated "
                "Attributes using -list option == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs',
                policy_rules=new_rule_uuid,
                description='For devstack demo') == 0:
            self._log.info(
                "# Step 2B: Verify Policy RuleSet Updated "
                "Attributes using -show option == Failed")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_FUNC_3: PASSED")
        return 1

    def test_gbp_prs_func_4(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_FUNC_4: TO CREATE/UPDATE/VERIFY/DELETE/ "
            "ASSOCIATING MULTIPLE PRs to 1 POLICY RULESET \n"
            "TEST_STEP::\n"
            "Create Multiple Policy Rules\n"
            "Create Policy RuleSet by associating all the Policy Rules\n"
            "Verify that multiple Policy Rules are associated to the "
            "Policy RuleSet\n"
            "Update the Policy RuleSet such that few Policy Rules "
            "are unmapped\n"
            "Verify the Policy Rule's attributes & values, show & list cmds\n"
            "Update the Policy RuleSet such that all Policy Rules "
            "association removed\n"
            "Verify the Policy Rule's attributes & values, show & list cmds\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info(
            '\n## Step 1A: Create new PA ,new PC, 4 PRs using the '
            'same PA & PC##\n')
        new_cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'grppol_pc1')
        if new_cls_uuid == 0:
            self._log.info(
                "\nNew Classifier Create Failed, hence "
                "TESTCASE_GBP_PRS_FUNC_4 ABORTED\n")
            return 0
        new_act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'grppol_pa1')
        if new_act_uuid == 0:
            self._log.info(
                "\nNew Action Create Failed, hence "
                "TESTCASE_GBP_PRS_FUNC_4 ABORTED\n")
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
                description="'For devstack demo'")
            if new_rule_uuid == 0:
                self._log.info(
                    "\nNew Rule Create Failed, hence "
                    "TESTCASE_GBP_PRS_FUNC_4 ABORTED\n")
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
            description="'For devstack demo'")
        if ruleset_uuid == 0:
            self._log.info(
                "\nStep 2: Updating Policy RuleSet's Attributes , Failed")
            return 0
        # Verify starts
        if self.gbpverify.gbp_policy_verify_all(
                0, 'ruleset', 'grppol_prs_many', ruleset_uuid) == 0:
            self._log.info(
                "# Step 2A: Verify Policy RuleSet Updated Attributes "
                "using -list option == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                ruleset_uuid,
                name='grppol_prs_many',
                description='For devstack demo') == 0:
            self._log.info(
                "# Step 2B: Verify Policy RuleSet Updated Attributes "
                "using -show option == Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) == 0:
            self._log.info(
                "# Step 2C: Verify Policy RuleSet and its Multiple PRs "
                "using -show option == Failed")
            return 0
        # Update and Verify the PRS by updating the PRs(removing few existing
        # ones)
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'ruleset', 'grppol_prs_many', policy_rule='"%s %s"' %
                (rule_uuid_list[0], rule_uuid_list[2])) == 0:
            self._log.info(
                "# Step 3: Updating Policy RuleSet's Attributes , Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) != 0:
            self._log.info(
                "# Step 3A: Verify Policy RuleSet and its Multiple "
                "PRs using -show option == Failed")
            return 0
        # Update and Verify the PRS by updating the PRs=NULL(unmapping all PRs)
        if self.gbpcfg.gbp_policy_cfg_all(2, 'ruleset', 'grppol_prs_many',
                                          policy_rule='""') == 0:
            self._log.info(
                "# Step 4: Upmapping All Policy Rule from Policy "
                "RuleSet , Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
                'ruleset', 'grppol_prs_many', 'policy_rules',
                rule_uuid_list) != 0:
            self._log.info(
                "# Step 4A: Verify All Policy Rules have been Removed "
                "from Policy RuleSet using --show option == Failed")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_FUNC_4: PASSED")
        return 1

    def test_gbp_prs_func_5(self):
        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_FUNC_5: TO CREATE/VERIFY/DELETE/VERIFY "
            "a PARENT and CHILD POLICY RULESET\n"
            "TEST_STEP::\n"
            "Create 1 Policy RuleSet using the same PA & PC\n"
            "Create the 2nd Policy RuleSet using the same PA, "
            "PC and associate PRS-1 as CHILD\n"
            "Verify the Child PRS reflect the Parent PRS and viceversa\n"
            "Delete the Child PRS\n"
            "Verify the Parent PRS has no CHILD\n"
            "Create the CHild PRS, associate to the Parent PRS\n"
            "Verify the association is established b/e Child and Parent\n"
            "Delete the Parent PRS\n"
            "Verify the Parent PRS association removed the Child PRS\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info("\n## Step 1: Create Policy RuleSet with PR ##")
        child_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', 'demo_child_prs', policy_rules=self.rule_name)
        if child_uuid == 0:
            self._log.info(
                "\n## Step 1: Create Child Policy RuleSet == Failed")
            return 0
        parent_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'ruleset',
            'demo_par_prs',
            policy_rules=self.rule_name,
            child_policy_rule_sets=child_uuid)
        if parent_uuid == 0:
            self._log.info(
                "\n## Step 2: Create Parent Policy RuleSet == Failed")
            return 0
        self._log.info(
            '# Step 2A: Verify Parent and Child Policy RuleSet '
            'using -show cmd')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_par_prs',
                id=parent_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                child_policy_rule_sets=child_uuid) == 0:
            self._log.info(
                "\n## Step 2A: Verify Parent RuleSet using -show "
                "option == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_child_prs',
                id=child_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                parent_id=parent_uuid) == 0:
            self._log.info(
                "\n## Step 2B: Verify Parent RuleSet using -show "
                "option == Failed")
            return 0
        # Delete Child PRS
        if self.gbpcfg.gbp_policy_cfg_all(0, 'ruleset', 'demo_child_prs') == 0:
            self._log.info("# Step 3: Delete Child Policy RuleSet == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_par_prs',
                id=parent_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                child_policy_rule_sets=child_uuid) != 0:
            self._log.info(
                "# Step 3A: Verify Parent PRS after Delete of Child "
                "PRS using -show option == Failed")
            return 0
        # Create Child PRS,Associate to Parent and Verify
        child_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', 'demo_child_prs', policy_rules=self.rule_name)
        if child_uuid == 0:
            self._log.info("# Step 4: Create Child Policy RuleSet == Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'ruleset',
                'demo_par_prs',
                child_policy_rule_sets=child_uuid) == 0:
            self._log.info(
                "# Step 5: Associating Child PRS by Updating Parent "
                "PRS == Failed")
            return 0
        self._log.info(
            '# Step 5A: Verify Parent and Child Policy RuleSet '
            'using -show cmd')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_par_prs',
                id=parent_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                child_policy_rule_sets=child_uuid) == 0:
            self._log.info(
                "# Step 5A: Verify Parent RuleSet using -show "
                "option == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_child_prs',
                id=child_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                parent_id=parent_uuid) == 0:
            self._log.info(
                "# Step 5B: Verify Parent RuleSet using -show "
                "option == Failed")
            return 0
        # Delete Parent PRS and Verify
        if self.gbpcfg.gbp_policy_cfg_all(0, 'ruleset', 'demo_par_prs') == 0:
            self._log.info("# Step 6: Delete Parent Policy RuleSet == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'ruleset',
                'demo_child_prs',
                id=child_uuid,
                policy_rules=self.rule_uuid,
                shared='False',
                parent_id=parent_uuid) != 0:
            self._log.info(
                "# Step 6A: Verify Child PRS after Delete of "
                "Parent PRS using -show option == Failed")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_FUNC_5: PASSED")
        return 1

    def test_gbp_prs_func_6(self):
        """
        Changing parent-child prs mapping
        Create 4 PRS, two are parent and two are child
        Update the one of the parent such that both childs are mapped
        Verify
        Delete both child PRS
        Verify the parent PRS
        """
        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PRS_FUNC_6: TO CHANGE/UPDATE/DELETE/VERIFY "
            "PARENT and CHILD POLICY RULESET\n"
            "TEST_STEP::\n"
            "Changing parent-child prs mapping\n"
            "Create 4 PRS, two are parent and two are child\n"
            "Update the one of the parent such that both childs are mapped\n"
            "Verify\n"
            "Delete both child PRS\n"
            "Verify the parent PRS\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create 4 Policy RuleSets, 2 Parent & 2 "
            "Child with PR ##")
        ch_uuids, par_uuids = [], []
        for i in range(1, 3):
            child_name, par_name = 'child_%s_prs' % (i), 'par_%s_prs' % (i)
            child_uuid = self.gbpcfg.gbp_policy_cfg_all(
                1, 'ruleset', child_name, policy_rules=self.rule_name)
            if child_uuid == 0:
                self._log.info(
                    "\n## Step 1: Create Child Policy RuleSet == Failed")
                return 0
            parent_uuid = self.gbpcfg.gbp_policy_cfg_all(
                1,
                'ruleset',
                par_name,
                policy_rules=self.rule_name,
                child_policy_rule_sets=child_uuid)
            if parent_uuid == 0:
                self._log.info(
                    "\n## Step 2: Create Parent Policy RuleSet == Failed")
                return 0
            ch_uuids.append(child_uuid)
            par_uuids.append(parent_uuid)
        # Update One of the Parent with two Child PRSs
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'ruleset', 'par_1_prs', child_policy_rule_sets='"%s %s"' %
                (ch_uuids[0], ch_uuids[1])) == 0:
            self._log.info(
                "\n## Step 3: Update Parent Policy RuleSet == Failed")
            return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
            'ruleset', 'par_1_prs', 'child_policy_rule_sets', [
                ch_uuids[0], ch_uuids[1]]) == 0:
            self._log.info("\n## Step 3A: Child PRS NOT Found in Parent PRS")
            return 0
        # Delete Child PRSs
        for i in range(2):
            if self.gbpcfg.gbp_policy_cfg_all(0, 'ruleset', ch_uuids[i]) == 0:
                self._log.info(
                    "\n## Step 5: Delete of Child PRS child_%s_prs" %
                    (i))
                return 0
        if self.gbpverify.gbp_obj_ver_attr_all_values(
            'ruleset', 'par_1_prs', 'child_policy_rule_sets', [
                ch_uuids[0], ch_uuids[1]]) != 0:
            self._log.info(
                "\n## Step 5A: Stale Child PRS Mapping still "
                "persists in Parent PRS")
            return 0
        self._log.info("\nTESTCASE_GBP_PRS_FUNC_6: PASSED")
        return 1

if __name__ == '__main__':
    main()
