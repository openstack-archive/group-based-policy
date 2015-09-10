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
    test = test_gbp_ri_func_3()
    test.run()

class test_gbp_ri_func_3(object):

    # Initialize logging
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s - %(message)s', level=logging.WARNING)
    _log = logging.getLogger( __name__ )
    cmd = 'rm /tmp/test_gbp_ri_func_3.log'
    getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_ri_func_3.log')
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
      self.act_name = 'demo_act'
      self.spec_name = 'demo_sc_spec'

    def cleanup(self,cfgobj,uuid_name,fail=0):
        if isinstance(cfgobj,str):
           cfgobj=[cfgobj]
        if isinstance(uuid_name,str):
           uuid_name=[uuid_name]
        for obj,_id in zip(cfgobj,uuid_name):
          if obj == 'action':
             if self.gbpcfg.gbp_policy_cfg_all(0,obj,_id) == 0:
                self._log.info('Failed to Clean-up/Delete of Policy Object %s\n' %(obj))
          else:
             if self.gbpcfg.gbp_sc_cfg_all(0,obj,_id) == 0:
                self._log.info('Failed to Clean-up/Delete of Policy Object %s\n' %(obj))
        if fail != 0:
           self._log.info("\n## TESTCASE_GBP_RI_FUNC_3: FAILED")
           report_results('test_gbp_ri_func_3','test_results.txt')
           sys.exit(1)

    def run(self):
        self._log.info("\n## TESTCASE_GBP_RI_FUNC_3: RESOURCE INTEGRITY AMONG POLICY ACTION and SC OBJs")
        ###### Testcase work-flow starts 
        ####### ============ ALL POLICY OBJECTS ARE TO BE CREATED AND VERIFIED ============ #######
	self._log.info("\n##  Step 1: Create Policy Action with type Redirect ##\n")
        act_uuid = self.gbpcfg.gbp_action_config(1,self.act_name)
        if act_uuid == 0:
            self._log.info("# Step 1: Create Action == Failed")
            self.cleanup('action',act_uuid, fail=1)
        ###### 
        self._log.info("\n## Step 2: Create ServiceChain Spec ##\n")
        spec_uuid = self.gbpcfg.gbp_sc_cfg_all(1,'spec',self.spec_name)
        objs,names=['action','spec'],[act_uuid,spec_uuid] ## this is needed for cleanup,can append and sort for the sake of order.. but it kept it simple
        if spec_uuid ==0:
            self._log.info("# Step 2: Create Classifier == Failed")
            self.cleanup(objs,names,fail=1)
        ######
        self._log.info("\n## Step 3: Update the Policy Action with SCSpec ##\n")
        if self.gbpcfg.gbp_action_config(2,act_uuid,action_value=spec_uuid) == 0:
           self._log.info("\n##Step 2: Updating Policy Action's Attributes name & action_value == Failed")
           self.cleanup(objs,names,fail=1)
        ######
        self._log.info("\n## Step 4: Delete ServiceChain Spec ##\n")
        if self.gbpcfg.gbp_sc_cfg_all(0,'spec',spec_uuid) != 0:
           self._log.info("# Step 4: Deletion of ServiceChain did NOT fail")
           self.cleanup(objs,names,fail=1)
        else:
           self._log.info("\n## TESTCASE_GBP_RI_FUNC_3: PASSED")
        self.cleanup(objs,names)
        report_results('test_gbp_ri_func_3','test_results.txt')
        sys.exit(1)

if __name__ == '__main__':
    main()



