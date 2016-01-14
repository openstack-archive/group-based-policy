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

    # Run the Testcase:
    test = test_gbp_pa_neg()
    if test.test_pa_invalid_act_type() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_1')
    if test.test_pa_valid_type_inval_val() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_2')
    if test.test_pa_invalid_act_value() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_3')
    if test.test_pa_update_act_type() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_4')
    if test.test_pa_update_invalid_act_val() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_5')
    if test.test_pa_delete_invalid_pa() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PA_NEG_6')
    test.cleanup()
    utils_libs.report_results('test_gbp_pa_neg', 'test_results.txt')
    sys.exit(1)


class test_gbp_pa_neg(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pa_neg.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pa_neg.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):
        """
        Init def
        """
        self._log.info("\n## START OF GBP POLICY_ACTION NEGATIVE TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_act'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('%s: FAILED' % (tc_name))
        for obj in ['ruleset', 'rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_pa_invalid_act_type(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_1: INVALID Action TYPE\n"
            "TEST_STEPS::\n"
            "Create and Verify Policy Action Errors Out for Invalid "
            "Action Type as Attr\n"
            "Invalid Action Type: Null string and string "
            "!= 'allow'/'redirect'\n"
            "###################################################\n")
        for _type in ["", "INVALID"]:
            if self.gbpcfg.gbp_action_config(
                    1, self.act_name, action_type=_type) != 0:
                self._log.info(
                    "\n## Step 1: Create Action with invalid Action Type=%s "
                    "did NOT Fail" %
                    (_type))
                return 0
            if self.gbpverify.gbp_action_verify(1, self.act_name) != 0:
                self._log.info(
                    "\n## Step 1A: Rollback of invalid Action create Failed")
                return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_1: PASSED")

    def test_pa_valid_type_inval_val(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_2: INVALID Action VALUE for "
            "VALID act_type \n"
            "TEST_STEPS::\n"
            "Create and Verify Policy Action Errors Out for Invalid "
            "Action Value for type=REDIRECT\n"
            "###################################################\n")
        if self.gbpcfg.gbp_action_config(
                1,
                self.act_name,
                action_type='redirect',
                action_value='INVALID') != 0:
            self._log.info(
                "\n## Step 1: Create Action with invalid Action Value "
                "did NOT Fail")
            return 0
        if self.gbpverify.gbp_action_verify(1, self.act_name) != 0:
            self._log.info(
                "\n## Step 1A: Rollback of Invalid Action create Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_2: PASSED")

    def test_pa_invalid_act_value(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_3: INVALID Action VALUE \n"
            "TEST_STEPS::\n"
            "Create and Verify Policy Action Errors Out for Invalid "
            "Action Value\n"
            "###################################################\n")
        if self.gbpcfg.gbp_action_config(
                1, self.act_name, action_value='INVALID') != 0:
            self._log.info(
                "\n## Step 1: Create Action with invalid Action Value "
                "did NOT Fail")
            return 0
        if self.gbpverify.gbp_action_verify(1, self.act_name) != 0:
            self._log.info(
                "\n## Step 1A: Rollback of Invalid Action create Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_3: PASSED")

    def test_pa_update_act_type(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_4: UPDATE Immutable ATTR act_type\n"
            "TEST_STEPS::\n"
            "Create a valid Policy Action with default action type\n"
            "Update name and act_type and Verify that it has failed to "
            "update the Policy Action\n"
            "###################################################\n")
        act_uuid = self.gbpcfg.gbp_action_config(1, self.act_name)
        if act_uuid == 0:
            self._log.info("## Step 1: Create Action == Failed")
            return 0
        if self.gbpcfg.gbp_action_config(
                2,
                act_uuid,
                name='grppol_act',
                action_type='redirect') != 0:
            self._log.info(
                "\n##Step 2: Updating Policy Action's Attrs name & "
                "action_type did NOT Fail")
            return 0
        if self.gbpverify.gbp_action_verify(
                1,
                self.act_name,
                id=act_uuid,
                action_type='allow',
                shared='False') == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Action Attrs are NOT "
                "updated == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_4: PASSED")

    def test_pa_update_invalid_act_val(self):

        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_5: UPDATE act_value with Invalid "
            "value for act-type=redirect \n"
            "TEST_STEPS::\n"
            "Create a valid Policy Action with 'redirect' action type\n"
            "Update the attributes act_val='invalid value' and name\n"
            "Verify that the update failed and all attrs are having "
            "their original vals\n"
            "###################################################\n")

        act_uuid = self.gbpcfg.gbp_action_config(
            1, 'new_act', action_type='redirect')
        if act_uuid == 0:
            self._log.info("## Step 1: Create Action == Failed")
            return 0
        if self.gbpcfg.gbp_action_config(
                2,
                act_uuid,
                name='grppol_act',
                action_value='INVALID') != 0:
            self._log.info(
                "\n##Step 2: Updating Policy Action's Attrs name & "
                "action_type did NOT Fail")
            return 0
        if self.gbpverify.gbp_action_verify(
                1,
                'new_act',
                id=act_uuid,
                action_type='redirect',
                shared='False') == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Action Attrs are NOT "
                "updated == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_5: PASSED")

    def test_pa_delete_invalid_pa(self):
        """
        Delete non-existent Policy Action
        """
        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_NEG_6: DELETE NON-EXISTENT/INVALID "
            "POLICY ACTION\n"
            "TEST_STEPS::\n"
            "Delete non-existent Policy Action\n"
            "###################################################\n")
        if self.gbpcfg.gbp_action_config(0, 'grppol_act') != 0:
            self._log.info(
                "\n## Step 1: Expected Error during deletion on "
                "non-existent Policy Action == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_NEG_6: PASSED")

if __name__ == '__main__':
    main()
