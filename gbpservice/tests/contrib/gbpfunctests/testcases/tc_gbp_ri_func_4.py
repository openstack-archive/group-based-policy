#!/usr/bin/python

import sys
import logging
import os
import datetime

from libs.config_libs import *
from libs.verify_libs import *
from libs.utils_libs import *

def main():

    #Run the Testcase:
    test = test_gbp_ri_func_4()
    test.run()

class test_gbp_ri_func_4(object):

    # Initialize logging
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s - %(message)s', level=logging.WARNING)
    _log = logging.getLogger( __name__ )
    cmd = 'rm /tmp/test_gbp_ri_func_4.log'
    getoutput(cmd)
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
      self.gbpcfg = Gbp_Config()
      self.gbpverify = Gbp_Verify()
      self.spec_name = 'demo_sc_spec'
      self.fw_name = 'demo_fw'
      self.lb_name = 'demo_lb'

    def cleanup(self,fail=0):
        for obj in ['node','spec']:
            self.gbpcfg.gbp_del_all_anyobj(obj)
        if fail != 0:
           self._log.info("\n## TESTCASE_GBP_RI_FUNC_4: FAILED")
           report_results('test_gbp_ri_func_4','test_results.txt')
           sys.exit(1)

    def run(self):
        self._log.info("\n## TESTCASE_GBP_RI_FUNC_4: RESOURCE INTEGRITY AMONG SERVICE-CHAIN OBJECTS")
        ###### Testcase work-flow starts 
        ####### ============ ALL POLICY OBJECTS ARE TO BE CREATED AND VERIFIED ============ #######
	self._log.info("\n##  Step 1: Create Service Chain Nodes LB & FW ##\n")
        lb_uuid = self.gbpcfg.gbp_sc_cfg_all(1,'node',self.lb_name)
        if lb_uuid == 0:
            self._log.info("# Step 1: Create Service Chain Loadbalance Node == Failed")
            self.cleanup(fail=1)
        fw_uuid = self.gbpcfg.gbp_sc_cfg_all(1,'node',self.lb_name)
        if fw_uuid == 0:
            self._log.info("# Step 1A: Create Service Chain Firewall Node == Failed")
            self.cleanup(fail=1)
        ###### 
        self._log.info("\n## Step 2: Create ServiceChain Spec ##\n")
        spec_uuid = self.gbpcfg.gbp_sc_cfg_all(1,'spec',self.spec_name,nodes='%s %s' %(fw_uuid,lb_uuid)) ## Ensur that node names or node uuids passed as val to param 'nodes',MUST be in order of FW and then LB.. this order is required from gbp pov
        if spec_uuid ==0:
            self._log.info("# Step 2: Create ServiceChain Spec == Failed")
            self.cleanup(fail=1)
        ######
        self._log.info("\n## Step 3: Delete the Service Chain Nodes ##\n")
        cnt=0
        for nodeid in [lb_uuid,fw_uuid]:
            if self.gbpcfg.gbp_sc_cfg_all(0,'node',nodeid) != 0:
               self._log.info("# Step 4: Deletion of ServiceChain did NOT fail")
               cnt+=1
        if cnt > 0:
           self.cleanup(fail=1)
        else:
           self._log.info("\n## TESTCASE_GBP_RI_FUNC_4: PASSED")
           self.cleanup()
        report_results('test_gbp_ri_func_4','test_results.txt')
        sys.exit(1)

if __name__ == '__main__':
    main()



