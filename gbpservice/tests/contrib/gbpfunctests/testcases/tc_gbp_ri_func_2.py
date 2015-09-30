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
    test = test_gbp_ri_func_2()
    test.run()


class test_gbp_ri_func_2(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_ri_func_2.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_ri_func_2.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):
        """
        Init def
        """
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.l3pol_name = 'demo_l3pol'
        self.l2pol_name = 'demo_l2pol'
        self.ptg_name = 'demo_ptg'

    def cleanup(self, cfgobj, uuid_name, tc_name='', fail=0):
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
        if fail != 0:
            self._log.info("\n## TESTCASE_GBP_RI_FUNC_2: FAILED")
            commands.report_results('test_gbp_ri_func_2', 'test_results.txt')
            sys.exit(1)

    def run(self):
        self._log.info(
            "\n## TESTCASE_GBP_RI_FUNC_2A: RESOURCE INTEGRITY AMONG "
            "L2POLICY and L3POLICY OBJs")
        # Testcase work-flow starts
        # ============ ALL POLICY OBJECTS ARE TO BE CREATED AND VERIFIED =
        self._log.info("\n##  Step 1: Create L3Policy ##\n")
        l3p_uuid = self.gbpcfg.gbp_policy_cfg_all(1, 'l3p', self.l3pol_name)
        if l3p_uuid == 0:
            self._log.info("# Step 1: Create L3Policy == Failed")
            self.cleanup(
                'l3p',
                l3p_uuid,
                tc_name='TESTCASE_GBP_RI_FUNC_2A',
                fail=1)
        ######
        self._log.info("\n## Step 2: Create L2Policy using L3Policy ##\n")
        l2p_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'l2p', self.l2pol_name, l3_policy=l3p_uuid)
        # this is needed for cleanup,can append and sort for the sake
        # of order.. but it kept it simple. l2p_uuid[1] is same as l3p_uuid,
        # just that cfg_all func returns both uuid when l2p is obj
        objs, names = ['l2p', 'l3p'], [l2p_uuid[0], l2p_uuid[1]]
        if l2p_uuid == 0:
            self._log.info("# Step 2: Create L2Policy == Failed")
            self.cleanup(objs, names, fail=1)
        self._log.info("\n## Step 3: Delete in-use L3Policy ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'l3p', l3p_uuid) != 0:
            self._log.info(
                "\n# Step 4A: Delete in-use L3Policy did not fail #")
            self.cleanup(
                objs,
                names,
                tc_name='TESTCASE_GBP_RI_FUNC_2A',
                fail=1)
        else:
            self._log.info("\n## TESTCASE_GBP_RI_FUNC_2A: PASSED")
        ######
        self._log.info(
            "\n## TESTCASE_GBP_RI_FUNC_2B: RESOURCE INTEGRITY AMONG L2POLICY "
            "and PTG OBJs")
        self._log.info("\n## Step 5: Create Policy Target-Grp ##\n")
        uuids = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', self.ptg_name, l2_policy=l2p_uuid[0])
        if uuids != 0:
            objs, names = ['group', 'l2p', 'l3p'],\
                [self.ptg_name, l2p_uuid[0], l3p_uuid]
        else:
            self._log.info("# Step 5: Create Policy Target-Grp == Failed")
            self.cleanup(
                objs,
                names,
                tc_name='TESTCASE_GBP_RI_FUNC_2B',
                fail=1)

        self._log.info("\n## Step 5A: Delete in-use L2 Policy ##")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'l2p', l2p_uuid[0]) != 0:
            self._log.info("\n# Step 5A: Delete in-use L2Policy did not fail")
            self.cleanup(
                objs,
                names,
                tc_name='TESTCASE_GBP_RI_FUNC_2B',
                fail=1)
        else:
            self._log.info("\n## TESTCASE_GBP_RI_FUNC_2B: PASSED")
        self.cleanup(objs, names)  # Cleanup the system now
        utils_libs.report_results('test_gbp_ri_func_2', 'test_results.txt')
        sys.exit(1)

if __name__ == '__main__':
    main()
