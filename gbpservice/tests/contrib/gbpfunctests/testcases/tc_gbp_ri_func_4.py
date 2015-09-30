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
    test = test_gbp_ri_func_4()
    test.run()


class test_gbp_ri_func_4(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_ri_func_4.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_ri_func_4.log')
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
        self.spec_name = 'demo_sc_spec'
        self.fw_name = 'demo_fw'
        self.lb_name = 'demo_lb'

    def cleanup(self, fail=0):
        for obj in ['node', 'spec']:
            self.gbpcfg.gbp_del_all_anyobj(obj)
        if fail != 0:
            self._log.info("\n## TESTCASE_GBP_RI_FUNC_4: FAILED")
            utils_libs.report_results('test_gbp_ri_func_4', 'test_results.txt')
            sys.exit(1)

    def run(self):
        self._log.info(
            "\n## TESTCASE_GBP_RI_FUNC_4: RESOURCE INTEGRITY AMONG "
            "SERVICE-CHAIN OBJECTS")
        # Testcase work-flow starts
        # ============ ALL POLICY OBJECTS ARE TO BE CREATED AND VERIFIED =
        self._log.info("\n##  Step 1: Create Service Chain Nodes LB & FW ##\n")
        lb_uuid = self.gbpcfg.gbp_sc_cfg_all(1, 'node', self.lb_name)
        if lb_uuid == 0:
            self._log.info(
                "# Step 1: Create Service Chain Loadbalance Node == Failed")
            self.cleanup(fail=1)
        fw_uuid = self.gbpcfg.gbp_sc_cfg_all(1, 'node', self.lb_name)
        if fw_uuid == 0:
            self._log.info(
                "# Step 1A: Create Service Chain Firewall Node == Failed")
            self.cleanup(fail=1)
        ######
        self._log.info("\n## Step 2: Create ServiceChain Spec ##\n")
        # Ensur that node names or node uuids passed as val to param
        # 'nodes',MUST be in order of FW and then LB.. this order is required
        # from gbp pov
        spec_uuid = self.gbpcfg.gbp_sc_cfg_all(
            1, 'spec', self.spec_name, nodes='%s %s' %
            (fw_uuid, lb_uuid))
        if spec_uuid == 0:
            self._log.info("# Step 2: Create ServiceChain Spec == Failed")
            self.cleanup(fail=1)
        ######
        self._log.info("\n## Step 3: Delete the Service Chain Nodes ##\n")
        cnt = 0
        for nodeid in [lb_uuid, fw_uuid]:
            if self.gbpcfg.gbp_sc_cfg_all(0, 'node', nodeid) != 0:
                self._log.info(
                    "# Step 4: Deletion of ServiceChain did NOT fail")
                cnt += 1
        if cnt > 0:
            self.cleanup(fail=1)
        else:
            self._log.info("\n## TESTCASE_GBP_RI_FUNC_4: PASSED")
            self.cleanup()
        utils_libs.report_results('test_gbp_ri_func_4', 'test_results.txt')
        sys.exit(1)

if __name__ == '__main__':
    main()
