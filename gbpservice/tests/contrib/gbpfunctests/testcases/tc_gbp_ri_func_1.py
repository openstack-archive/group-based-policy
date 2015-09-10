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
    test = test_gbp_ri_func_1()
    test.run()

class test_gbp_ri_func_1(object):

    # Initialize logging
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s - %(message)s', level=logging.WARNING)
    _log = logging.getLogger( __name__ )
    cmd = 'rm /tmp/test_gbp_ri_func_1.log'
    getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_ri_func_1.log')
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
      self.act_name = 'allow_all'
      self.class_name = 'pc_icmp'
      self.rule_name = 'pr_icmp'
      self.ruleset_name = 'prs_icmp'
      self.ptg_name = 'pg_icmp'	
      self.tg_name= 'tg_icmp'

    def cleanup(self,cfgobj,uuid_name,fail=0):
        if isinstance(cfgobj,str):
           cfgobj=[cfgobj]
        if isinstance(uuid_name,str):
           uuid_name=[uuid_name]
        for obj,_id in zip(cfgobj,uuid_name):
          if self.gbpcfg.gbp_policy_cfg_all(0,obj,_id):
             self._log.info('Success in Clean-up/Delete of Policy Object %s\n' %(obj))
          else:
             self._log.info('Failed to Clean-up/Delete of Policy Object %s\n' %(obj))
        if fail != 0:
           self._log.info("\n## TESTCASE_GBP_RI_FUNC_1: FAILED")
           report_results('test_gbp_ri_func_1','test_results.txt')
           sys.exit(1)

    def run(self):
        self._log.info("\n## TESTCASE_GBP_RI_FUNC_1: RESOURCE INTEGRITY AMONG GBP's PA,PC,PR,PRS,PTG,PT OBJs")
        ###### Testcase work-flow starts 
        ####### ============ ALL POLICY OBJECTS ARE TO BE CREATED AND VERIFIED ============ #######
	self._log.info("\n## Step 1: Create Action ##\n")
        act_uuid = self.gbpcfg.gbp_action_config(1,self.act_name)
        if act_uuid == 0:
	    self._log.info("# Step 1: Create Action == Failed")
            self.cleanup('action',act_uuid, fail=1)
        ###### 
        self._log.info("\n## Step 2: Create Classifier ##\n")
        cls_uuid = self.gbpcfg.gbp_policy_cfg_all(1,'classifier',self.class_name,protocol='icmp',direction='bi')
        objs,names=['classifier','action'],[cls_uuid,act_uuid] ## this is needed for cleanup,can append and sort for the sake of order.. but it kept it simple
	if cls_uuid ==0:
            self._log.info("# Step 2: Create Classifier == Failed")
            self.cleanup(objs,names,fail=1)
        ######
        self._log.info("\n## Step 3: Create Policy Rule ##\n")
        rule_uuid = self.gbpcfg.gbp_policy_cfg_all(1,'rule',self.rule_name,classifier=self.class_name,action=self.act_name)
        objs,names=['rule','classifier','action'],[rule_uuid,cls_uuid,act_uuid]
        if rule_uuid ==0:
            self._log.info("# Step 3: Create Policy Rule == Failed")
            self.cleanup(objs,names,fail=1)
        self._log.info("\n## Step 4: Delete in-use Policy Action & Classifier ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(0,'classifier',self.class_name)!=0:
           self._log.info("\n# Step 4A: Delete in-use Policy Classifier did not fail #")
           self.cleanup(objs,names,fail=1)
        if self.gbpcfg.gbp_action_config(0,self.act_name)!=0:
           self._log.info("\n# Step 4B: Delete in-use Policy Action did not fail #")
           self.cleanup(objs,names,fail=1)
        ######
        self._log.info("\n## Step 5: Create Policy Rule-Set ##\n")
        ruleset_uuid = self.gbpcfg.gbp_policy_cfg_all(1,'ruleset',self.ruleset_name,policy_rules=self.rule_name)
        objs,names=['ruleset','rule','classifier','action'],\
                   [ruleset_uuid,rule_uuid,cls_uuid,act_uuid]
        if ruleset_uuid ==0:
            self._log.info("# Step 5: Create Policy Rule-Set == Failed")
            self.cleanup(objs,names,fail=1)
            
        self._log.info("\n## Step 5A: Delete of in-use Policy Rule ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(0,'rule',self.rule_name)!=0:
           self._log.info("\n# Step 5A: Delete in-use Policy Rule did not fail")
           self.cleanup(objs,names,fail=1)
        ##### 
        self._log.info("\n## Step 7: Create Policy Target-Grp ##\n")
        uuids = self.gbpcfg.gbp_policy_cfg_all(1,'group',self.ptg_name,consumed_policy_rule_sets='%s=scope' %(self.ruleset_name))
        if uuids !=0:
            ptg_uuid = uuids[0].rstrip()
            objs,names=['group','ruleset','rule','classifier','action'],\
                    [ptg_uuid,ruleset_uuid,rule_uuid,cls_uuid,act_uuid]
        else:
            self._log.info("# Step 7: Create Policy Target-Grp == Failed")
            self.cleanup(objs,names,fail=1)
         
        self._log.info("\n## Step 7A: Delete in-use Policy RuleSet ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(0,'ruleset',self.ruleset_name)!=0:
            self._log.info("\n# Step 7A: Delete in-use Policy RuleSet did not fail")
            self.cleanup(objs,names,fail=1)
            
        self._log.info("\n## Step 8: Create Policy Targets ##\n")
        ret_uuids=self.gbpcfg.gbp_policy_cfg_all(1,'target',self.tg_name,policy_target_group=self.ptg_name)
        if ret_uuids != 0 and len(ret_uuids) == 2:
           pt_uuid,port_uuid = ret_uuids[0],ret_uuids[1]
           objs,names=['target','group','ruleset','rule','classifier','action'],\
                      [pt_uuid,ptg_uuid,ruleset_uuid,rule_uuid,cls_uuid,act_uuid]
           self._log.info("# Step 8: Creation of Policy Target Passed, UUID == %s\n" %(pt_uuid))
        else:
           self._log.info("# Step 8: Creation of Policy Target == Failed")
           self.cleanup(objs,names,fail=1)

        self._log.info("\n## Step 8: Delete in-use Policy Target Group ##\n")
        if self.gbpcfg.gbp_policy_cfg_all(0,'ruleset',self.ruleset_name)!=0:
            self._log.info("\n# Step 8A: Delete in-use Policy RuleSet did not fail")
            self.cleanup(objs,names,fail=1)
        self._log.info("\n## TESTCASE_GBP_RI_FUNC_1: PASSED")
        self.cleanup(objs,names) ## Cleanup the system
        report_results('test_gbp_ri_func_1','test_results.txt')
        sys.exit(1)

if __name__ == '__main__':
    main()
