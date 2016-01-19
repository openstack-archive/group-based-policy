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
    test = test_gbp_pr_pc_pa_shared_func()
    if test.test_gbp_pr_pc_pa_shared_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_1')
    if test.test_gbp_pr_pc_pa_shared_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_2')
    if test.test_gbp_pr_pc_pa_shared_func_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_3')
    if test.test_gbp_pr_pc_pa_shared_func_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_4')
    test.cleanup()
    utils_libs.report_results('test_gbp_pr_pc_pa_shared_func',
                              'test_results_admin.txt')
    sys.exit(1)


class test_gbp_pr_pc_pa_shared_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pr_pc_pa_shared_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pr_pc_pa_shared_func.log')
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
            "\n## START OF GBP POLICY_RULE,POLICY_CLASS,POLICY_ACTION SHARED "
            "RESOURCE INTEGRITY TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_pa'
        self.cls_name = 'demo_pc'
        self.rule_name = 'demo_pr'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('%s: FAILED' % (tc_name))
        for obj in ['rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_pr_pc_pa_shared_func_1(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_1: "
            "TO CREATE/VERIFY/UPDATEE/VERIFY INTEGRITY "
            "B/W PR,PC,PA as 'shared' \n"
            "TEST_STEP::\n"
            "Create Policy Action,Policy Class & Policy Rule "
            "with param shared=True\n"
            "Verify the attributes & value, show & list cmds\n"
            "Update the Policy Rule param shared=False\n"
            "Verify that PR param shared got updated\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create PA,PC,PR
        self._log.info('\n## Step 1A: Create a PC with shared=True ##')
        obj_uuid = {}
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name, shared=True)
        if self.cls_uuid == 0:
            self._log.info(
                "\n Creation of Policy Classifier with shared=True, Failed\n")
            return 0
        obj_uuid['classifier'] = self.cls_uuid
        self._log.info('\n## Step 1B: Create a PA with shared=True ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name, shared=True)
        if self.act_uuid == 0:
            self._log.info(
                "\n Creation of Policy Action with shared=True, Failed\n")
            return 0
        obj_uuid['action'] = self.act_uuid
        self._log.info(
            "\n## Step 1C: Create Policy Rule with PC & PA with "
            "shared=True ##")
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            self.rule_name,
            classifier=self.cls_uuid,
            action=self.act_uuid,
            shared=True)
        if rule_uuid == 0:
            self._log.info(
                "# Step 1: Creation of Policy Rule with shared=True, Failed")
            return 0
        # Verify PA,PC,PR
        self._log.info(
            '## Step 2: Verify Policy Rule, Policy Classifier, Policy '
            'Action with shared=True')
        for obj, uuid in obj_uuid.iteritems():
            if self.gbpverify.gbp_policy_verify_all(
                    1, obj, uuid, shared=True) == 0:
                self._log.info(
                    "# Step 2A_%s: Verify Policy %s.upper() with "
                    "shared=True, Failed" %
                    (obj, obj))
                return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                self.rule_name,
                id=rule_uuid,
                policy_classifier_id=self.cls_uuid,
                enabled='True',
                policy_actions=self.act_uuid,
                shared=True) == 0:
            self._log.info(
                "# Step 2B: Verify Policy Rule with shared=True, Failed")
            return 0
        # Update PR
        self._log.info("\n## Update the Policy Rule with shared=False ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'rule', rule_uuid, shared=False) == 0:
            self._log.info(
                "\nStep 3: Updating Policy Rule's shared=False, Failed")
            return 0
        # Verify the PR after update
        if self.gbpverify.gbp_policy_verify_all(
                1, 'rule', rule_uuid, shared=False) == 0:
            self._log.info(
                "# Step 4: Verify Policy Rule with shared=False, Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_1: PASSED")
        self.cleanup()
        return 1

    def test_gbp_pr_pc_pa_shared_func_2(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_2: TO CREATE/UPDATE/ "
            "POLICY RULE with shared/non-shared PA & PCs\n"
            "TEST_STEP::\n"
            "Create Policy Classifier and Policy Action with "
            "shared=False(default)\n"
            "Create another set of Policy Classifier & Policy "
            "Action with shared=True\n"
            "Create Policy Rule using the 2nd set of PA & PC "
            "and shared=True\n"
            "Update the Policy Rule with 1st set of PA & PC "
            "and verify update failed\n"
            "Update the Policy Rule by setting shared=False "
            "and verify it passed\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create PA,PC with shared=False
        self._log.info(
            '\n## Step 1A: Create a PC with shared=False(default) ##')
        obj_uuid_false = {}
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'cls_shared')
        if self.cls_uuid == 0:
            self._log.info(
                "\n Creation of Policy Classifier with shared=False, Failed\n")
            return 0
        obj_uuid_false['classifier'] = self.cls_uuid
        self._log.info(
            '\n## Step 1B: Create a PA with shared=False(default) ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'act_shared')
        if self.act_uuid == 0:
            self._log.info(
                "\n Creation of Policy Action with shared=False, Failed\n")
            return 0
        obj_uuid_false['action'] = self.act_uuid
        # Create PA,PC with shared=True
        self._log.info('\n## Step 2A: Create a PC with shared=True ##')
        obj_uuid_true = {}
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name, shared=True)
        if self.cls_uuid == 0:
            self._log.info(
                "\n Step 2A: Creation of Policy Classifier with "
                "shared=True, Failed\n")
            return 0
        obj_uuid_true['classifier'] = self.cls_uuid
        self._log.info('\n## Step 2B: Create a PA with shared=True ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name, shared=True)
        if self.act_uuid == 0:
            self._log.info(
                "\n Step 2B: Creation of Policy Action with "
                "shared=True, Failed\n")
            return 0
        obj_uuid_true['action'] = self.act_uuid
        # Create PR(shared=True) with PA+PC(shared=True)
        self._log.info(
            "\n## Step 3: Create Policy Rule with PC & PA with shared=True ##")
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            'pr_true',
            classifier=obj_uuid_true['classifier'],
            action=obj_uuid_true['action'],
            shared=True)
        if rule_uuid == 0:
            self._log.info(
                "# Step 3: Creation of Policy Rule with shared=True "
                "using attributes PA+PC(shared=True), Failed")
            return 0
        # Update and Verify the PR(shared=True) with PA+PC(shared=False)
        self._log.info(
            "\n## Step 4A: Update the Policy Rule with PC & PA which "
            "are with shared=False ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'rule',
                rule_uuid,
                classifier=obj_uuid_false['classifier'],
                action=obj_uuid_false['action']) != 0:
            self._log.info(
                "# Step 4A: Updating Policy Rule(shared=True) by attributes "
                "PA+PC(shared=False) DID NOT Fail")
            return 0
        self._log.info(
            "\n## Step 4B: Verify the Policy Rule initial attributes "
            "PA,PC,shared=True ##")
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                'pr_true',
                id=rule_uuid,
                policy_classifier_id=obj_uuid_true['classifier'],
                enabled='True',
                policy_actions=obj_uuid_true['action'],
                shared=True) == 0:
            self._log.info(
                "# Step 4B: Verify Policy Rule with shared=True, Failed")
            return 0
        # Update and Verify the PR(shared=False) with PA+PC(shared=False)
        self._log.info(
            "\n## Step 5A: Update the Policy Rule's shared=False  along "
            "with PC+PA(shared=False) ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'rule',
                rule_uuid,
                classifier=obj_uuid_false['classifier'],
                action=obj_uuid_false['action'],
                shared=False) == 0:
            self._log.info(
                "# Step 5A: Updating Policy Rule(shared=False) by "
                "attributes PA+PC(shared=False), Failed")
            return 0
        self._log.info(
            "\n## Step 5B: Verify the Policy Rule attributes "
            "PA,PC,shared=False ##")
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                'pr_true',
                id=rule_uuid,
                policy_classifier_id=obj_uuid_false['classifier'],
                enabled='True',
                policy_actions=obj_uuid_false['action'],
                shared=False) == 0:
            self._log.info(
                "# Step 5B: Verify Policy Rule with shared=False, Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_2: PASSED")
        self.cleanup()
        return 1

    def test_gbp_pr_pc_pa_shared_func_3(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_3: TO "
            "CREATE/VERIFY//VERIFY a POLICY RULE with POLICY "
            "ACTION & CLASSIFIER\n"
            "TEST_STEP::\n"
            "Create Policy Action with shared=False, while Policy "
            "Classifier with shared=True\n"
            "Create Policy Rule with PA & PC and shared=True and "
            "verify it failed to create\n"
            "Retry Create Policy Rule with above PA,PC and "
            "shared=False and verify it success\n"
            "Update the Policy Action with shared=True \n"
            "Create Policy Rule with shared=True with above PA+PC "
            "and verify it success\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create PA & PC with shared+False & True resp
        self._log.info('\n## Step 1A: Create a PC with shared=True ##')
        obj_uuid = {}
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'cls_true', shared=True)
        if self.cls_uuid == 0:
            self._log.info(
                "\n Creation of Policy Classifier with shared=False, Failed\n")
            return 0
        obj_uuid['classifier'] = self.cls_uuid
        self._log.info('\n## Step 1B: Create a PA with shared=False ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'act_false')
        if self.act_uuid == 0:
            self._log.info(
                "\n Creation of Policy Action with shared=False, Failed\n")
            return 0
        obj_uuid['action'] = self.act_uuid
        # Create/Retry a PR using above PA & PC, once with shared= True & False
        self._log.info(
            "\n## Step 2A: Create Policy Rule(shared=True) with "
            "PA(shared=False) & PC(shared=True) ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'rule',
                'true_pr',
                classifier=obj_uuid['classifier'],
                action=obj_uuid['action'],
                shared=True) != 0:
            self._log.info(
                "# Step 2A: Creation of Policy Rule with shared=True using "
                "attributes PA(shared=False)+PC(shared=True) did NOT Fail")
            return 0
        self._log.info(
            "\n## Step 2B: Create Policy Rule(shared=False) with "
            "PA(shared=False) & PC(shared=True)& Verify ##")
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            'true_pr',
            classifier=obj_uuid['classifier'],
            action=obj_uuid['action'])
        if rule_uuid == 0:
            self._log.info(
                "# Step 2B: Creation of Policy Rule with "
                "shared=False(default) using attributes "
                "PA(shared=False)+PC(shared=True), Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                rule_uuid,
                policy_classifier_id=obj_uuid['classifier'],
                enabled='True',
                policy_actions=obj_uuid['action'],
                shared=False) == 0:
            self._log.info(
                "# Step 2C: Verify Policy Rule with shared=False, Failed")
            return 0
        # Update the Policy Action with shared=True
        self._log.info(
            "\n## Step 3: Update the Policy Action with shared=True\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'action', self.act_uuid, shared=True) == 0:
            self._log.info(
                "# Step 3A: Update of Policy Action shared=True, Failed")
            return 0
        # Create and Verify a PR with shared=True using above
        # PA+PC(shared=True)
        self._log.info(
            "\n## Step 4: Create and Verify a PR with shared=True "
            "using above PA+PC(shared=True)\n")
        true_rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            'true_pr',
            classifier=obj_uuid['classifier'],
            action=obj_uuid['action'],
            shared=True)
        if true_rule_uuid == 0:
            self._log.info(
                "# Step : Creation of Policy Rule with shared=True "
                "using attributes PA+PC(shared=True), Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                true_rule_uuid,
                policy_classifier_id=obj_uuid['classifier'],
                enabled='True',
                policy_actions=obj_uuid['action'],
                shared=True) == 0:
            self._log.info(
                "# Step 4B: Verify Policy Rule with shared=True, Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_3: PASSED")
        self.cleanup()
        return 1

    def test_gbp_pr_pc_pa_shared_func_4(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_4: TO "
            "CREATE/VERIFY/UPDATE/VERIFY a POLICY ACTION & "
            "CLASSIFIER for a POLICY RULE\n"
            "TEST_STEP::\n"
            "Create Policy Action & Policy Classifier with shared=False\n"
            "Create Policy Rule with PA & PC and shared=True "
            "and verify creation fails\n"
            "Update the above Policy Action & Classifier with "
            "shared=True and verify it success\n"
            "Create the Policy Rule with shared=True using above PA & PC \n"
            "Update Policy Action and Classifier with "
            "shared=False and verify it failed to upudate\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create PA,PC with shared=False
        self._log.info(
            '\n## Step 1A: Create a PC with shared=False(default) ##')
        obj_uuid_false = {}
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', 'cls_false')
        if self.cls_uuid == 0:
            self._log.info(
                "\n Creation of Policy Classifier with shared=False, Failed\n")
            return 0
        obj_uuid_false['classifier'] = self.cls_uuid
        self._log.info(
            '\n## Step 1B: Create a PA with shared=False(default) ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', 'act_false')
        if self.act_uuid == 0:
            self._log.info(
                "\n Creation of Policy Action with shared=False, Failed\n")
            return 0
        obj_uuid_false['action'] = self.act_uuid
        # Create & Verify PR with shared=True and above PA & PC and create
        # should fail
        self._log.info(
            "\n## Step 2B: Create Policy Rule(shared=True) "
            "with PA(shared=False) & PC(shared=True)& create fails ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'rule',
                'pr_true',
                classifier=obj_uuid_false['classifier'],
                action=obj_uuid_false['action'],
                shared=True) != 0:
            self._log.info(
                "# Step 2B: Creation of Policy Rule with "
                "shared=True using attributes PA+PC(shared=False) "
                "DID NOT Fail")
            return 0
        # Update the Policy Action & Policy CLassifier with shared=True
        self._log.info(
            "\n## Step 3A: Update the Policy Action with shared=True\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'action', self.act_uuid, shared=True) == 0:
            self._log.info(
                "# Step 3A: Update of Policy Action shared=True, Failed")
            return 0
        self._log.info(
            "\n## Step 3B: Update the Policy Classifer with shared=True\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', self.cls_uuid, shared=True) == 0:
            self._log.info(
                "# Step 3B: Update of Policy Classifier shared=True, Failed")
            return 0
        # Create and verify the Policy Rule with shared=True
        self._log.info(
            "\n## Step 4: Create the Policy Rule with shared=True using "
            "PA+PC(shared=True)\n")
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'rule',
            'pr_true',
            classifier=obj_uuid_false['classifier'],
            action=obj_uuid_false['action'],
            shared=True)
        if rule_uuid == 0:
            self._log.info(
                "# Step 4: Create of Policy Rule shared=True, Failed")
            return 0
        self._log.info(
            "\n## Step 4A: Verify the Policy Rule got updated shared=True\n")
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'rule',
                rule_uuid,
                policy_classifier_id=obj_uuid_false['classifier'],
                enabled='True',
                policy_actions=obj_uuid_false['action'],
                shared=True) == 0:
            self._log.info(
                "# Step 4A: Verify Policy Rule with shared=True, Failed")
            return 0
        # Update Policy Action and Classifier with shared=False and verify it
        # failed to upudate
        self._log.info(
            "\n## Step 5A: Update the Policy Action with shared=False\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'action', self.act_uuid, shared=False) != 0:
            self._log.info(
                "# Step 5A: Update of Policy Action shared=False "
                "DID NOT Fail")
            return 0
        self._log.info(
            "\n## Step 5B: Update the Policy Classifer with shared=False\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', self.cls_uuid, shared=False) != 0:
            self._log.info(
                "# Step 5B: Update of Policy Classifier shared=False "
                "DID NOT Fail")
            return 0
        # Verify the shared attributes of Policy Action & Classifier as True
        if self.gbpverify.gbp_policy_verify_all(
                1, 'action', self.act_uuid, shared='True') == 0:
            self._log.info(
                "# Step 6: Policy Action verify shows that shared "
                "attribute changed to False")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'classifier', self.cls_uuid, shared='True') == 0:
            self._log.info(
                "# Step 6: Policy Classifier verify shows that shared "
                "attribute changed to False")
            return 0
        self._log.info("\n## TESTCASE_GBP_PR_PC_PA_SHARED_INTEG_4: PASSED")
        self.cleanup()
        return 1


if __name__ == '__main__':
    main()
