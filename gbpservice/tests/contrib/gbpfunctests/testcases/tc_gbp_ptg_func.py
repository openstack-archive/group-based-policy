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
    env_flag = sys.argv[1]
    test = test_gbp_ptg_func(env_flag)
    test.global_cfg()
    if test.test_gbp_ptg_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PTG_FUNC_1')
        test.global_cfg()  # Making global_cfg available for the subsequent TC
    if test.test_gbp_ptg_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PTG_FUNC_2')
        test.global_cfg()
    if test.test_gbp_ptg_func_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_PTG_FUNC_3')
    test.cleanup()
    utils_libs.report_results('test_gbp_ptg_func', 'test_results.txt')
    sys.exit(1)


class test_gbp_ptg_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    hdlr = logging.FileHandler('/tmp/test_gbp_ptg_func.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self, env_flag):
        """
        Init def
        """
        self._log.info(
            "\n## START OF GBP POLICY_TARGET_GROUP FUNCTIONALITY TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.act_name = 'test_ptg_pa'
        self.cls_name = 'test_ptg_pc'
        self.rule_name = 'test_ptg_pr'
        self.ruleset_name = 'test_ptg_prs'
        self.ptg_name = 'demo_ptg'
        self.l2p_name = 'test_ptg_l2p'
        self.l3p_name = 'test_ptg_l3p'
        self.pt_name = 'test_pt'
        self.env_flag = env_flag
        if self.env_flag == 'aci':
            self.def_ip_pool = '192.168.0.0/16'
            self.cidr = '192.168.0.0/24'
        else:
            self.def_ip_pool = '10.0.0.0/8'
            self.cidr = '10.0.0.0/24'

    def global_cfg(self):
        self._log.info('\n## Step 1: Create a PC needed for PTG Testing ##')
        self.cls_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'classifier', self.cls_name)
        if self.cls_uuid == 0:
            self._log.info(
                "\nReqd Policy Classifier Create Failed, hence GBP "
                "Policy Target-Group Functional Test Suite Run ABORTED\n")
            return 0
        self._log.info('\n## Step 1: Create a PA needed for PTG Testing ##')
        self.act_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'action', self.act_name)
        if self.act_uuid == 0:
            self._log.info(
                "\n## Reqd Policy Action Create Failed, hence GBP "
                "Policy Target-Group Functional Test Suite Run ABORTED\n")
            return 0
        self._log.info('\n## Step 1: Create a PR needed for PTG Testing ##')
        self.rule_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'rule', self.rule_name, classifier=self.cls_name,
            action=self.act_name)
        if self.rule_uuid == 0:
            self._log.info(
                "\n## Reqd Policy Rule Create Failed, hence GBP Policy "
                "Target-Group Functional Test Suite Run ABORTED\n ")
            return 0
        self._log.info('\n## Step 1: Create a PRS needed for PTG Testing ##')
        self.prs_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', self.ruleset_name, policy_rules=self.rule_name)
        if self.prs_uuid == 0:
            self._log.info(
                "\n## Reqd Policy Target-Group Create Failed, hence "
                "GBP Policy Target-Group Functional Test Suite "
                "Run ABORTED\n ")
            return 0
        l3p_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'l3p', self.l3p_name, ip_pool='20.20.0.0/24',
            subnet_prefix_length='28', _proxy_ip_pool='20.20.1.0/24',
            _proxy_subnet_prefix_length='28')
        if l3p_uuid == 0:
            self._log.info(
                "\n## Reqd L3Policy Create Failed, hence GBP Policy "
                "Target-Group Functional Test Suite Run ABORTED\n")
            return 0
        self.gbpcfg.gbp_policy_cfg_all(
            1, 'l2p', self.l2p_name, l3_policy=l3p_uuid)

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('%s: FAILED' % (tc_name))
        for obj in [
                'target',
                'group',
                'l2p',
                'l3p',
                'ruleset',
                'rule',
                'classifier',
                'action']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_ptg_func_1(
            self,
            name_uuid='',
            ptg_uuid='',
            rep_cr=0,
            rep_del=0):

        if rep_cr == 0 and rep_del == 0:
            self._log.info(
                "\n########################################################\n"
                "TESTCASE_GBP_PTG_FUNC_1: TO CREATE/VERIFY/DELETE/VERIFY a "
                "POLICY TARGET-GROUP with DEFAULT ATTRIB VALUE\n"
                "TEST_STEP::\n"
                "Create Policy Target-Group Object\n"
                "Verify the attributes & value, show & list cmds\n"
                "Verify the implicitly GBP(L2P,L3P) & "
                "Neutron(net,subnet,dhcp-port) Objects\n"
                "Delete Policy Target-Group using Name\n"
                "Verify the PTG has got deleted, show & list cmds\n"
                "Verify the implicit GBP & Neutron Objects are deleted\n"
                "##########################################################\n")

        if name_uuid == '':
            name_uuid = self.ptg_name
        # Testcase work-flow starts
        if rep_cr == 0 or rep_cr == 1:
            self._log.info(
                '\n## Step 1: Create Target-Group with default '
                'attrib vals##\n')
            uuids = self.gbpcfg.gbp_policy_cfg_all(1, 'group', name_uuid)
            if uuids != 0:
                ptg_uuid = uuids[0]
                l2pid = uuids[1]
                subnetid = uuids[2]
            else:
                self._log.info("\n## Step 1: Create Target-Group == Failed")
                return 0
            self._log.info('\n## Step 2A: Verify Target-Group using -list cmd')
            if self.gbpverify.gbp_policy_verify_all(
                    0, 'group', name_uuid, ptg_uuid) == 0:
                self._log.info(
                    "\n## Step 2A: Verify Target-Group using -list "
                    "option == Failed")
                return 0
            self._log.info('\n## Step 2B: Verify Target-Group using -show cmd')
            if self.gbpverify.gbp_policy_verify_all(
                    1, 'group', name_uuid, id=ptg_uuid, shared='False') == 0:
                self._log.info(
                    "\n## Step 2B: Verify Target-Group using -show "
                    "option == Failed")
                return 0
            # Verify the implicit objects(gbp & neutron)
            ret_uuid = self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'l2p', self.ptg_name, ret='default', id=l2pid,
                policy_target_groups=ptg_uuid)
            if ret_uuid != 0 and len(ret_uuid) == 2:
                l3pid = ret_uuid[0]
                ntkid = ret_uuid[1]
            else:
                self._log.info(
                    "\n## Step 2C: Verify By-Default L2Policy == Failed")
                return 0
            rtr_uuid = self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1,
                'l3p',
                l3pid,
                ret='default',
                id=l3pid,
                name='default',
                ip_pool=self.def_ip_pool,
                l2_policies=l2pid,
                subnet_prefix_length='24',
                ip_version='4')
            if rtr_uuid != 0 and isinstance(rtr_uuid, str) == 0:
                self._log.info(
                    "# Step 2D: Verify By-Default L3Policy == Failed")
                return 0
            net_name = 'l2p_%s' % (name_uuid)
            if self.gbpverify.neut_ver_all(
                    'net',
                    ntkid,
                    name=net_name,
                    admin_state_up='True',
                    subnets=subnetid) == 0:
                self._log.info(
                    "# Step 2E: Implicit-creation of Neutron Network-Obj "
                    "-show option == Failed")
                return 0
            if self.gbpverify.neut_ver_all(
                    'subnet',
                    subnetid,
                    cidr=self.cidr,
                    enable_dhcp='True',
                    network_id=ntkid) == 0:
                self._log.info(
                    "\n## Step 2F: Implicit-creation of Neutron SubNet-Obj "
                    "== Failed")
                return 0
            if self.env_flag != 'aci':
                if self.gbpverify.neut_ver_all(
                        'router',
                        rtr_uuid,
                        admin_state_up='True',
                        status='ACTIVE') == 0:
                    self._log.info(
                        "\n## Step 2G: Implicit-creation of Neutron "
                        "Router-Obj == Failed")
                    return 0
        # Delete and Verify
        if rep_del == 0 or rep_del > 0:
            self._log.info('\n## Step 3: Delete Target-Group using name  ##\n')
            if self.gbpcfg.gbp_policy_cfg_all(0, 'group', ptg_uuid) == 0:
                self._log.info("\n## Step 3: Delete Target-Group == Failed")
                return 0
            if self.gbpverify.gbp_policy_verify_all(0, 'group', ptg_uuid) != 0:
                self._log.info(
                    "\n## Step 3A: Verify Target-Group is Deleted "
                    "using -list option == Failed")
                return 0
            if self.gbpverify.gbp_policy_verify_all(1, 'group', ptg_uuid) != 0:
                self._log.info(
                    "\n## Step 3B: Verify Target-Group is Deleted "
                    "using -show option == Failed")
                return 0
            if rep_cr == 0 and rep_del == 0:
                self._log.info("\n## TESTCASE_GBP_PTG_FUNC_1: PASSED")
        return 1

    def test_gbp_ptg_func_2(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PTG_FUNC_2: TO CREATE/VERIFY/DELETE/VERIFY "
            "a POLICY TARGET-GROUP with POLICY RULESET\n"
            "TEST_STEPS::\n"
            "Create Policy Target-Group Object with ConsumedPRS=A\n"
            "Verify the attributes & value, show & list cmds\n"
            "Update the PTG's atribute ProvidedPRS=A\n"
            "Create a PRS=B\n"
            "Update the PTG's attributes Consumed & Provided PRS=B\n"
            "Delete Policy Target-Group using Name\n"
            "Verify that Target-Group has got deleted, show & list cmds\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info("\n## Step 1: Create Policy Target-Group with PRS ##")
        uuids = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'group',
            self.ptg_name,
            consumed_policy_rule_sets='%s=scope' %
            (self.ruleset_name))
        if uuids != 0:
            ptg_uuid = uuids[0].rstrip()
            subnetid = uuids[2].rstrip()
        else:
            self._log.info("\n## Step 1: Create Target-Group == Failed")
            return 0
        self._log.info(
            '\n## Step 2A: Verify Policy Target-Group using -list cmd')
        if self.gbpverify.gbp_policy_verify_all(
                0, 'group', self.ptg_name, ptg_uuid) == 0:
            self._log.info(
                "\n## Step 2A: Verify Target-Group using -list "
                "option == Failed")
            return 0
        self._log.info(
            '\n## Step 2B: Verify Policy Target-Group using -show cmd')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'group',
                self.ptg_name,
                id=ptg_uuid,
                shared='False',
                subnets=subnetid,
                consumed_policy_rule_sets=self.prs_uuid) == 0:
            self._log.info(
                "\n## Step 2B: Verify Policy Target-Group using -show "
                "option == Failed")
            return 0
        # Update the PTG's Provided PRS
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'group', ptg_uuid, provided_policy_rule_sets='%s=scope' %
                (self.ruleset_name), name='ptg_new') == 0:
            self._log.info(
                "\n## Step 3: Updating Policy Target-Group == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'group',
                'ptg_new',
                id=ptg_uuid,
                shared='False',
                subnets=subnetid,
                consumed_policy_rule_sets=self.prs_uuid,
                provided_policy_rule_sets=self.prs_uuid) == 0:
            self._log.info(
                "\n## Step 3A: Verify after updating Policy "
                "Target-Group == Failed")
            return 0
        # Create new PRS and update both Provided & Consumed PRS attrs
        new_prs_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'ruleset', 'demo-new-prs', policy_rules=self.rule_name)
        if new_prs_uuid == 0:
            self._log.info(
                "\n## Step 4: Reqd Policy Target-Group Create Failed, "
                "hence Testcase_gbp_ptg_func_2 Run ABORTED\n ")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2,
                'group',
                ptg_uuid,
                provided_policy_rule_sets='demo-new-prs=scope',
                consumed_policy_rule_sets='demo-new-prs=scope') == 0:
            self._log.info(
                "\n## Step 5: Updating Policy Target-Group with new "
                "PRS == Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'group',
                'ptg_new',
                id=ptg_uuid,
                shared='False',
                subnets=subnetid,
                consumed_policy_rule_sets=new_prs_uuid,
                provided_policy_rule_sets=new_prs_uuid) == 0:
            self._log.info(
                "\n## Step 5A: Verify after updating Policy "
                "Target-Group == Failed")
            return 0
        # Delete the PTG and verify
        self.test_gbp_ptg_func_1(ptg_uuid=ptg_uuid, rep_del=2, rep_cr=2)
        self._log.info("\n## TESTCASE_GBP_PTG_FUNC_2: PASSED")
        return 1

    def test_gbp_ptg_func_3(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_PTG_FUNC_3: TO UPDATE A POLICY "
            "TARGET-GROUP AFTER DELETING PT's NEUTRON PORT \n"
            "TEST_STEPS::\n"
            "Create Policy Target-Group using L2P and NO PRS\n"
            "Create a Policy Target using the above Policy-Target-Group\n"
            "Delete the neutron port corresponding to the Policy-Target\n"
            "Update the Policy-Target-Group with a PRS\n"
            "Verify Policy Target-Group successfully updated\n"
            "##############################################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create Policy Target-Group with L2P ##\n')
        uuids = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', self.ptg_name, l2_policy=self.l2p_name)
        if uuids != 0:
            ptg_uuid = uuids[0]
        else:
            self._log.info("\n## Step 1: Create Target-Group == Failed")
            return 0
        self._log.info(
            '\n## Step 2: Create a Policy Target using the above '
            'Policy-Target-Group\n')
        uuids = self.gbpcfg.gbp_policy_cfg_all(
            1, 'target', self.pt_name, policy_target_group=ptg_uuid)
        if uuids != 0:
            pt_uuid = uuids[0]
            neutron_port_id = uuids[1]
        else:
            self._log.info("\n## Step 2: Create Policy Target == Failed")
            return 0
        self._log.info(
            '\n## Step 2A: Verify the Implicit creation of Neutron Port\n')
        if self.gbpverify.neut_ver_all('port', neutron_port_id) == 0:
            self._log.info(
                "\n## Step 2A: Implicit creation neutron port-object "
                "== Failed")
            return 0
        self._log.info(
            '\n## Step 3: Delete the neutron port corresponding to the '
            'Policy-Target\n')
        cmd = 'neutron port-delete %s' % (neutron_port_id)
        if self.gbpcfg.cmd_error_check(commands.getoutput(cmd)) == 0:
            self._log.info(
                "\n## Step 3: Deletion of the neutron port corresponding "
                "to the Policy-Target = Failed")
            return 0
        self._log.info(
            '\n## Step 4: Update the Policy-Target-Group with a PRS\n')
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'group', ptg_uuid, provided_policy_rule_sets='%s=scope' %
                (self.prs_uuid), consumed_policy_rule_sets='%s=scope' %
                (self.prs_uuid)) == 0:
            self._log.info(
                "\n## Step 4: Updating Policy Target-Group with "
                "new PRS == Failed")
            return 0
        self._log.info(
            '\n## Step 5: Verify Policy Target-Group successfully updated\n')
        if self.gbpverify.gbp_policy_verify_all(
                1,
                'group',
                self.ptg_name,
                id=ptg_uuid,
                shared='False',
                policy_targets=pt_uuid,
                consumed_policy_rule_sets=self.prs_uuid,
                provided_policy_rule_sets=self.prs_uuid) == 0:
            self._log.info(
                "\n## Step 5A: Verify after updating Policy "
                "Target-Group == Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_PTG_FUNC_3: PASSED")
        return 1

if __name__ == '__main__':
    main()
