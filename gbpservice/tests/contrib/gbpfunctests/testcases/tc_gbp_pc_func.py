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

    # Run the Testcase:
    test = test_gbp_pc_func()
    if test.test_gbp_pc_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_FUNC_1')
    if test.test_gbp_pc_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_FUNC_2')
    if test.test_gbp_pc_func_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_FUNC_3')
    if test.test_gbp_pc_func_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PC_FUNC_4')
    test.cleanup()
    utils_libs.report_results('test_gbp_pc_func', 'test_results.txt')
    sys.exit(1)


class test_gbp_pc_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pc_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pc_func.log')
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
            "\n## START OF GBP POLICY_CLASSIFIER FUNCTIONALITY TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.cls_name = 'demo_pc'
        self.act_name = 'demo_pa'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['rule', 'classifier', 'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_pc_func_1(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PC_FUNC_1: CREATE/VERIFY/DELETE/VERIFY a POLICY "
            "CLASSIFIER with DEFAULT ATTRIB VALUE\n"
            "TEST_STEPS::\n"
            "Create Policy Classifier Object,default params\n"
            "Verify the attributes & value, show & list cmds\n"
            "Delete Policy Classifier using Name\n"
            "Verify that PC has got deleted, show & list cmds\n"
            "Recreate Policy Classifier Object inorder to test Delete "
            "using UUID\n"
            "Delete using UUID\n"
            "Verify that PC has got deleted, show & list cmds\n"
            "##############################################################\n")
        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with default attrib vals##\n")
        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if cls_uuid != 0:
            self._log.info(
                "\n## Step 1: Create Classifier Passed, UUID == %s\n" %
                (cls_uuid))
        else:
            self._log.info("\n## Step 1: Create Classifier == Failed")
            return 0
        self._log.info("\n## Step 4A: Verify Classifier using -list cmd")
        if self.gbpverify.gbp_classif_verify(0, self.cls_name, cls_uuid) == 0:
            self._log.info(
                "\n## Step 4A: Verify Classifier using -list option == Failed")
            return 0
        self._log.info("\n## Step 4B: Verify Classifier using -show cmd")
        if self.gbpverify.gbp_classif_verify(
                1, self.cls_name, id=cls_uuid) == 0:
            self._log.info(
                "\n## Step 4B: Verify Classifier using -show option == Failed")
            return 0

        ######
        self._log.info("\n## Step 3: Delete Classifier using name  ##")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', self.cls_name):
            self._log.info(
                "\n## Step 3: Delete Classifier using Name == %s, Passed" %
                (self.cls_name))
        else:
            self._log.info(
                "\n## Step 3: Delete Classifier using Name == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(0, self.cls_name, cls_uuid) != 0:
            self._log.info(
                "\n## Step 3A: Verify Classifier is Deleted using -list "
                "option == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1, self.cls_name, id=cls_uuid, shared='False') != 0:
            self._log.info(
                "\n## Step 3B: Verify Classifier is Deleted using -show "
                "option == Failed")
            return 0

        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if cls_uuid:
            self._log.info(
                "\n## Step 4: Re-created a Policy Classifier with default "
                "inorder to delete with ID")
            self._log.info("\n## Step 5: Delete Classifier using UUID  ##")
            if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', cls_uuid):
                self._log.info(
                    "\n## Step 5: Delete Classifier Passed using UUID == %s" %
                    (cls_uuid))
            else:
                self._log.info(
                    "\n##  Step 5: Delete Classifier using UUID == Failed")
            if self.gbpverify.gbp_classif_verify(
                    0, self.cls_name, cls_uuid) != 0:
                self._log.info(
                    "\n##  Step 5A: Verify Classifier is Deleted using "
                    "-list option == Failed")
                return 0
            if self.gbpverify.gbp_classif_verify(
                    1, self.cls_name, id=cls_uuid, shared='False') != 0:
                self._log.info(
                    "\n## Step 5B: Verify Classifier is Deleted using "
                    "-show option == Failed")
                return 0
            self._log.info(
                "\n## Step 5: Delete of Policy Classifier using "
                "UUID == Passed")
        else:
            self._log.info(
                "\n## Step 6: Recreate of Policy Classifier using "
                "Default == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_FUNC_1: PASSED")

    def test_gbp_pc_func_2(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PC_FUNC_2: UPDATE/VERIFY/DELETE/VERIFY EACH "
            "ATTRIB of a POLICY CLASSIFIER\n"
            "TEST_STEP::\n"
            "Create Policy Classifier using Default param values\n"
            "Update Each the Polciy Classifier's editable params one "
            "at a time\n"
            "Verify the Policy Classifier's attributes & values, show "
            "& list cmds\n"
            "Delete the Policy Classifier\n"
            "Verify Policy Classifier successfully deleted\n"
            "##############################################################\n")
        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with default attrib vals##\n")
        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if cls_uuid != 0:
            self._log.info(
                "\n## Step 1: Create Classifier Passed, UUID == %s\n" %
                (cls_uuid))
        else:
            self._log.info("\n## Step 1: Create Classifier == Failed")
            return 0
        # for attr,val in attrib.iteritems():
        self._log.info(
            "\n## Step 2: Update Policy Classifier attributes one at a "
            "time %s ##")
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', cls_uuid, name='grppol_pc') == 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's attribute "
                "Name, Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', cls_uuid, protocol='tcp') == 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's attribute "
                "Protocol, Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', cls_uuid, direction='bi') == 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's attribute "
                "Direction, Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'classifier', cls_uuid, port_range='22:1022') == 0:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's attribute "
                "Port Range, Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(
                0, 'grppol_pc', cls_uuid, 'tcp', 'bi', '22:1022') == 0:
            self._log.info(
                "\n## Step 2A: Verify Policy Classifier Updated Attributes "
                "using -list option == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1,
                'grppol_pc',
                id=cls_uuid,
                protocol='tcp',
                port_range='22:1022',
                direction='bi') == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Classifier Updated Attributes "
                "using -show option == Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', cls_uuid):
            self._log.info(
                "\n## Step 3: Deleted the Classifier == %s\n" %
                (cls_uuid))
        else:
            self._log.info(
                "\n## Step 3: Delete Classifier using Name == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(1, 'grppol_pc', id=cls_uuid) != 0:
            self._log.info(
                "\n## Step 3B: Verify Classifier is Deleted using "
                "-show option == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_FUNC_2: PASSED")

    def test_gbp_pc_func_3(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PC_FUNC_3: UPDATE/VERIFY/DELETE/VERIFY ALL "
            "ATTRIB of a POLICY CLASSIFIER @ ONCE \n"
            "TEST_STEP::\n"
            "Create Policy Classifier using Default param values\n"
            "Update All the Polciy Classifier's editable params at one shot\n"
            "Verify the Policy Classifier's attributes & values, show "
            "& list cmds\n"
            "Delete the Policy Classifier\n"
            "Verify Policy Classifier successfully deleted\n"
            "##############################################################\n")
        # Testcase work-flow starts
        self._log.info(
            "\n## Step 1: Create Classifier with default attrib vals ##\n")
        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if cls_uuid != 0:
            self._log.info(
                "\n## Step 1: Create Classifier Passed, UUID == %s\n" %
                (cls_uuid))
        else:
            self._log.info("\n## Step 1: Create Classifier == Failed")
            return 0
        self._log.info(
            "\n###########################################\n"
            "## Step 2: Update Policy Classifier Attributes ##\n"
            "## protocol, port-range,name,direction,description ##\n"
            "#################################################\n")
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'classifier',
                cls_uuid,
                name='grppol_pc',
                protocol='tcp',
                direction='bi',
                port_range='22:1022',
                description="'For devstack demo'"):
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's Attributes "
                "name,protocol,port-range,name,direction,description, Passed")
        else:
            self._log.info(
                "\n## Step 2: Updating Policy Classifier's Attributes "
                "name,protocol,port-range,name,direction,description, Failed")
            return 0

        if self.gbpverify.gbp_classif_verify(
                0, 'grppol_pc', cls_uuid, 'tcp', '22:1022', 'bi') == 0:
            self._log.info(
                "\n## Step 2A: Verify Policy Classifier Updated "
                "Attributes using -list option == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1,
                'grppol_pc',
                id=cls_uuid,
                protocol='tcp',
                direction='bi',
                port_range='22:1022',
                description='For devstack demo') == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Classifier Updated "
                "Attributes using -show option == Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', 'grppol_pc') == 0:
            self._log.info(
                "\n## Step 3: Delete Classifier using Name == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(1, 'grppol_pc', id=cls_uuid) != 0:
            self._log.info(
                "\n## Step 3B: Verify Classifier is Deleted using "
                "-show option == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_FUNC_3: PASSED")

    def test_gbp_pc_func_4(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PC_FUNC_4: CREATE/SHARE/DELETE/ POLICY CLASSIFIER "
            "among MULTIPLE POLICY RULES \n"
            "TEST_STEP::\n"
            "Create and Verify Policy Classifier with valued attributes\n"
            "Create multiple(n=10) Policy Rules referencing the same "
            "Policy Classifier\n"
            "Verify the Policy Classifier is referenced in all "
            "configured Policy Rules\n"
            "Delete the Policy Classifier, verify it's deletion "
            "fails until all Policy Rules are deleted\n"
            "Verify Policy Classifier successfully deleted\n"
            "##############################################################\n")
        # Testcase work-flow starts
        self._log.info(
            "\n## Step 0: Creating a Policy Action needed for this test\n")
        act_uuid = self.gbpcfg.gbp_policy_cfg_all(1, 'action', self.act_name)
        if act_uuid == 0:
            self._log.info("\n## TESTCASE_GBP_PC_FUNC_4: ABORTED\n")
            os._exit(1)
        self._log.info(
            "\n## Step 1: Create and Verify Classifier with valued "
            "attrib ##\n")
        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'classifier',
            self.cls_name,
            protocol='tcp',
            direction='bi',
            port_range='22:1022',
            description="'For devstack demo'")
        if cls_uuid == 0:
            self._log.info("\n## Step 1A: Create Classifier == Failed")
            return 0
        if self.gbpverify.gbp_classif_verify(
                1,
                self.cls_name,
                id=cls_uuid,
                protocol='tcp',
                direction='bi',
                port_range='22:1022',
                description='For devstack demo') == 0:
            self._log.info(
                "\n## Step 1B: Verify Policy Classifier Attributes using "
                "-show option == Failed")
            return 0
        self._log.info(
            "\n## Step 2: Create Multiple Policy Rules, each referencing "
            "the same classifier ##\n")
        for n in range(1, 11):
            if self.gbpcfg.gbp_policy_cfg_all(
                    1, 'rule', 'grppol_pr_%s' %
                    (n), classifier=cls_uuid, action=act_uuid) == 0:
                self._log.info(
                    "\n## Step 2A: Policy Rule grppol_pr_%s creation, Failed" %
                    (n))
                return 0
            if self.gbpverify.gbp_policy_verify_all(
                    1,
                    'rule',
                    'grppol_pr_%s' %
                    (n),
                    policy_classifier_id=cls_uuid,
                    policy_actions=act_uuid) == 0:
                self._log.info(
                    "\n## Step 2B: Policy Rule grppol_pr_%s referencing "
                    "same classifier, Failed ##\n" %
                    (n))
                return 0
        self._log.info(
            "\n## Step 3: Delete Policy Classifier and Policy Rule and "
            "verify deletion fails ##")
        for i in range(1, 11):
            if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', cls_uuid) != 0:
                self._log.info(
                    "\n## Step 3A: Referenced Policy Classifier's "
                    "deletion DID NOT fail ##")
                return 0
            if self.gbpcfg.gbp_policy_cfg_all(
                    0, 'rule', 'grppol_pr_%s' %
                    (i)) == 0:
                self._log.info(
                    "\n## Step 3B: Referencing Policy Rule's deletion, "
                    "Failed ##")
                return 0
        self._log.info(
            "\n## Step 4: Deletion of Policy Classifier, all referencing "
            "Policy Rules have been deleted ##")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'classifier', cls_uuid) == 0:
            self._log.info(
                "\n## Step 4A: Policy Classifier's deletion, Failed ##")
            return 0
        if self.gbpverify.gbp_classif_verify(1, 'grppol_pc', id=cls_uuid) != 0:
            self._log.info(
                "\n## Step 4B: Verify Classifier is Deleted, Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PC_FUNC_4: PASSED")

if __name__ == '__main__':
    main()
