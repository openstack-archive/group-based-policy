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
import re
import sys

from libs import config_libs
from libs import utils_libs
from libs import verify_libs


def main():

    # Run the Testcase:
    test = test_gbp_pa_func()
    test.test_cr_ver_del_ver_default()
    test.test_upd_ver_del()
    utils_libs.report_results('test_gbp_pa_func', 'test_results.txt')
    sys.exit(1)


class test_gbp_pa_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_pa_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_pa_func.log')
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
            "\n## START OF GBP POLICY_ACTION FUNCTIONALITY TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'demo_act'

    def cleanup(self, cfgobj, uuid_name, tc_name=''):
        if tc_name != '':
            self._log.info('%s FAILED' % (tc_name))
        if isinstance(cfgobj, str):
            cfgobj = [cfgobj]
        if isinstance(uuid_name, str):
            uuid_name = [uuid_name]
        for obj, _id in zip(cfgobj, uuid_name):
            if self.gbpcfg.gbp_policy_cfg_all(0, obj, _id):
                self._log.info(
                    'Success in Clean-up/Delete of Policy Object %s\n' %
                    (obj))
            else:
                self._log.info(
                    'Failed to Clean-up/Delete of Policy Object %s\n' %
                    (obj))
        os._exit(1)

    def test_cr_ver_del_ver_default(self, rep_cr=0, rep_del=0):

        if rep_cr == 0 and rep_del == 0:
            self._log.info(
                "\n###################################################\n"
                "TESTCASE_GBP_PA_FUNC_1: CREATE/VERIFY/DELETE/VERIFY a "
                "POLICY ACTION with DEFAULT ATTR VALUE\n"
                "TEST_STEPS:\n"
                "Create Policy Action Object,default params\n"
                "Verify the attributes & value, show & list cmds\n"
                "Delete Policy Action using Name\n"
                "Verify that PA has got deleted, show & list cmds\n"
                "Recreate Policy Action Object inorder to test Delete "
                "using UUID\n"
                "Delete using UUID\n"
                "Verify that PA has got deleted, show & list cmds\n"
                "###################################################\n")

        # Testcase work-flow starts
        self._log.info(
            '\n## Step 1: Create Action with default attrib values##\n')
        act_uuid = self.gbpcfg.gbp_action_config(1, self.act_name)
        if act_uuid == 0:
            self._log.info("# Step 1: Create Action == Failed")
            return 0
        if self.gbpverify.gbp_action_verify(0, self.act_name, act_uuid) == 0:
            self._log.info(
                "# Step 2A: Verify Action using -list option == Failed")
            return 0
        if self.gbpverify.gbp_action_verify(
                1,
                self.act_name,
                id=act_uuid,
                action_type='allow',
                shared='False') == 0:
            self._log.info(
                "# Step 2B: Verify Action using -show option == Failed")
            return 0
        ######
        self._log.info('\n## Step 3: Delete Action using name ##\n')
        if self.gbpcfg.gbp_action_config(0, self.act_name) == 0:
            self._log.info("# Step 3: Delete Action using Name == Failed")
            return 0
        if self.gbpverify.gbp_action_verify(0, self.act_name, act_uuid) != 0:
            self._log.info(
                "\n## Step 3A: Verify Action is Deleted using -list option "
                "== Failed")
            return 0
        if self.gbpverify.gbp_action_verify(
                1,
                self.act_name,
                id=act_uuid,
                action_type='allow',
                shared='False') != 0:
            self._log.info(
                "\n## Step 3B: Verify Action is Deleted using -show option "
                "== Failed")
            return 0

        act_uuid = self.gbpcfg.gbp_action_config(1, self.act_name)
        if act_uuid:
            self._log.info(
                "Step 4: Re-created a Policy Action with default inorder "
                "to delete with ID")
            self._log.info('\n## Step 5: Delete Action using UUID ##\n')
            if self.gbpcfg.gbp_action_config(0, act_uuid) == 0:
                self._log.info(
                    "\n## Step 5: Delete Action using UUID == Failed")
                return 0
            if self.gbpverify.gbp_action_verify(
                    0, act_uuid, self.act_name) != 0:
                self._log.info(
                    "\n## Step 5A: Verify Action is Deleted using -list "
                    "option == Failed")
                return 0
            if self.gbpverify.gbp_action_verify(
                    1,
                    act_uuid,
                    name=self.act_name,
                    action_type='allow',
                    shared='False') != 0:
                self._log.info(
                    "\n## Step 5B: Verify Action is Deleted using -show "
                    "option == Failed")
                return 0
            self._log.info(
                "\n## Step 5: Delete of Policy Action using UUID == Passed")
        else:
            self._log.info(
                "\n## Step 6: Recreate of Policy Action using Default "
                "== Failed")
            return 0
        if rep_cr == 0 and rep_del == 0:
            self._log.info("\n## TESTCASE_GBP_PA_FUNC_1: PASSED")
        return 1

    def test_upd_ver_del(self):
        self._log.info(
            "\n###################################################\n"
            "TESTCASE_GBP_PA_FUNC_2: UPDATE/VERIFY/DELETE EDITABLE ATTRIBs "
            "of a POLICY ACTION \n"
            "TEST_STEPS::\n"
            "Create Policy Action using Default param values\n"
            "Update the Polciy Action's editable params\n"
            "Verify the Policy Action's attributes & values, show & list "
            "cmds\n"
            "Delete the Policy Action\n"
            "Verify Policy Action successfully deleted\n"
            "###################################################\n")

        # Testcase work-flow starts
        self._log.info(
            '\n##Step 1: Create Action with default attrib vals ##\n')
        act_uuid = self.gbpcfg.gbp_action_config(1, self.act_name)
        if act_uuid == 0:
            self._log.info("## Step 1: Create Action == Failed")
            return 0
        self._log.info(
            "\n## Step 1A: Creating a Service Chain Spec to be used for "
            "UPdating Polic Action")
        spec_cr_cmd = ('gbp servicechain-spec-create demo_spec | grep id | '
                       'head -1')
        cmd_out = commands.getoutput(spec_cr_cmd)
        spec_id = re.search("\\bid\\b\s+\| (.*) \|", cmd_out, re.I).group(1)
        self._log.info(
            '\n##Step 2: Update Policy Action Attributes name and '
            'action_value##\n')
        if self.gbpcfg.gbp_action_config(
                2,
                act_uuid,
                name='grppol_act',
                action_value=spec_id) == 0:
            self._log.info(
                "\n##Step 2: Updating Policy Action's Attributes name "
                "& action_value, Failed")
            return 0

        if self.gbpverify.gbp_action_verify(
                0, 'grppol_act', act_uuid, spec_id) == 0:
            self._log.info(
                "\n## Step 2A: Verify Policy Action Updated Attributes "
                "using -list option == Failed")
            return 0
        if self.gbpverify.gbp_action_verify(
                1,
                'grppol_act',
                id=act_uuid,
                action_type='allow',
                shared='False',
                action_value=spec_id) == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Action Updated Attributes "
                "using -show option == Failed")
            return 0
        if self.gbpcfg.gbp_action_config(0, act_uuid) == 0:
            self._log.info("## Step 3: Delete Action using Name == Failed")
            return 0
        self._log.info("\n## Step 3A: Now delete the service chain spec")
        spec_del_cmd = 'gbp servicechain-spec-delete %s' % (spec_id)
        cmd_out = commands.getoutput(spec_del_cmd)
        if self.gbpverify.gbp_action_verify(
                1,
                'grppol_act',
                id=act_uuid,
                action_type='allow',
                shared='False') != 0:
            self._log.info(
                "\n## Step 3B: Verify Action is Deleted using -show "
                "option == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PA_FUNC_2: PASSED")
        return 1

if __name__ == '__main__':
    main()
