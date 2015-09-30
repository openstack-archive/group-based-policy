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
    test = test_gbp_pc_neg()
    if test.test_gbp_pc_neg_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_1')
    if test.test_gbp_pc_neg_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_2')
    if test.test_gbp_pc_neg_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_3')
    if test.test_gbp_pc_neg_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_4')
    if test.test_gbp_pc_neg_5() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_5')
    if test.test_gbp_pc_neg_6() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_NEG_6')
    test.cleanup()
    utils_libs.report_results('test_gbp_pc_neg', 'test_results.txt')
    sys.exit(1)


class test_gbp_pc_neg(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pc_neg.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pc_neg.log')
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
            "\n## START OF GBP POLICY_CLASSIFIER NEGATIVE TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.cls_name = 'demo_pc'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s FAILED' % (tc_name))
        for obj in ['classifier']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_pc_neg_1(self):

        self._log.info(
            "\n#######################################################\n"
            "TESTCASE_GBP_PC_NEG_1: CREATE/VERIFY a "
            "POLICY CLASSIFIER with INVALID PROTO \n"
            "TEST_STEP::\n"
            "Create Policy Classifier with Invalid "
            "Proto(any proto other than tcp,udp,icmp)\n"
            "Verify that the create fails and rollbacks\n"
            "#######################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with invalid protocol##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                1, 'classifier', self.cls_name, protocol='http') != 0:
            self._log.info(
                "\n## Step 1: Create Classifier with Invalid Protocol "
                "did NOT Fail")
            return 0
        self._log.info("\n## Step 1A: Verify classifier has been rolled back")
        if self.gbpverify.gbp_classif_verify(1, self.cls_name) != 0:
            self._log.info("\n## Step 1A: Classifier did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_1: PASSED")
        return 1

    def test_gbp_pc_neg_2(self):

        self._log.info(
            "\n#######################################################\n"
            "TESTCASE_GBP_PC_NEG_2: CREATE/VERIFY a POLICY CLASSIFIER with "
            "INVALID PORT-RANGE \n"
            "TEST_STEP::\n"
            "Create Policy Classifier with Valid Proto BUT Invalid "
            "Port-range\n"
            "Verify that the create fails and rollbacks\n"
            "#######################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with invalid protocol##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'classifier',
                self.cls_name,
                protocol='tcp',
                port_range='80:50') != 0:
            self._log.info(
                "\n## Step 1: Create Classifier with Invalid Port-Range "
                "did NOT Fail")
            return 0
        self._log.info("\n## Step 1A: Verify classifier has been rolled back")
        if self.gbpverify.gbp_classif_verify(1, self.cls_name) != 0:
            self._log.info("\n## Step 1A: Classifier did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_2: PASSED")
        return 1

    def test_gbp_pc_neg_3(self):

        self._log.info(
            "\n#######################################################\n"
            "TESTCASE_GBP_PC_NEG_3: DELETE NON-EXISTENT/INVALID "
            "POLICY CLASSIFICER\n"
            "TEST_STEP::\n"
            "Delete unknown/invalid policy-classifier\n"
            "#######################################################\n")

        self._log.info("\n## Step 1: Delete non-existent Classifier  ##")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', self.cls_name) != 0:
            self._log.info(
                "\n## Step 1: Delete Non-existent policy classifier "
                "did NOT Fail")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_3: PASSED")
        return 1

    def test_gbp_pc_neg_4(self):

        self._log.info(
            "\n#######################################################\n"
            "TESTCASE_GBP_PC_NEG_4: CREATE/VERIFY POLICY CLASSIFIER "
            "with INVALID DIRECTION \n"
            "TEST_STEP::\n"
            "Create Policy Classifier using Invalid Direction\n"
            "Verify that the create fails and rollbacks\n"
            "######################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with Invalid Direction##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'classifier',
                self.cls_name,
                direction='redirect') != 0:
            self._log.info(
                "\n## Step 1: Create Classifier with Invalid Direction "
                "did NOT Fail")
            return 0
        self._log.info("\n## Step 1A: Verify classifier has been rolled back")
        if self.gbpverify.gbp_classif_verify(1, self.cls_name) != 0:
            self._log.info("\n## Step 1A: Classifier did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_4: PASSED")
        return 1

    def test_gbp_pc_neg_5(self):

        self._log.info(
            "\n#######################################################\n"
            "TESTCASE_GBP_PC_NEG_5: UPDATE/VERIFY/ POLICY CLASSIFIER "
            "with INVALID PROTOCOL \n"
            "TEST_STEP::\n"
            "Create Policy Classifier using non-default protocol\n"
            "Update Policy Classifier with Invalid Protocol\n"
            "Verify that the update fails and rollbacks to original values\n"
            "######################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with non-default protocol ##\n")
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name, protocol='tcp')
        if self.cls_uuid != 0:
            self._log.info(
                "\n## Step 1: Create Classifier Passed, UUID == %s\n" %
                (self.cls_uuid))
        else:
            self._log.info("\n## Step 1: Create Classifier == Failed")
            return 0
        self._log.info(
            "\n## Step 2: Update Policy Classifier with Invalid Protocol##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'classifier',
                self.cls_uuid,
                name='grppol_pc',
                protocol='http') != 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's with "
                "Invalid Protocol did NOT Fail ")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1, self.cls_name, id=self.cls_uuid, protocol='tcp') == 0:
            self._log.info(
                "\n## Step 2A: Verify Policy Classifier did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_5: PASSED")
        return 1

    def test_gbp_pc_neg_6(self):

        self._log.info(
            "\n######################################################\n"
            "TESTCASE_GBP_PC_NEG_6: UPDATE/VERIFY/ POLICY CLASSIFIER "
            "with INVALID PORT-RANGE \n"
            "TEST_STEP::\n"
            "Update Policy Classifier with Invalid Port-Range\n"
            "Verify that the update fails and rollbacks to original values\n"
            "#####################################################\n")

        # Testcase work-flow starts
        self._log.info(
            "\n## Step 2: Update Policy Classifier with Invalid "
            "Port-Range##\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'classifier',
                self.cls_uuid,
                name='grppol_pc',
                port_range='4000:80') != 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's with "
                "Invalid Port-Range did NOT Fail ")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1,
                self.cls_name,
                id=self.cls_uuid,
                protocol='tcp',
                port_range='4000:80') != 0:
            self._log.info(
                "\n## Step 2A: Verify Policy Classifier did NOT roll back")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_NEG_6: PASSED")
        return 1

if __name__ == '__main__':
    main()
