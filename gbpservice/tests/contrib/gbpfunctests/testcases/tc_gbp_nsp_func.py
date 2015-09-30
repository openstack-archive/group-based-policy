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
    test = test_gbp_nsp_func()
    if test.test_gbp_nsp_func_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_NSP_FUNC_1')
    if test.test_gbp_nsp_func_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_NSP_FUNC_2')
    if test.test_gbp_nsp_func_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_NSP_FUNC_3')
    test.cleanup()
    utils_libs.report_results('test_gbp_nsp_func', 'test_results.txt')
    sys.exit(1)


class test_gbp_nsp_func(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_nsp_func.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_nsp_func.log')
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
            "\n## START OF GBP NETWORK_SERVICE_POLICY FUNCTIONALITY "
            "TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.nsp_name = 'demo_nsp'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('Testcase %s: FAILED' % (tc_name))
        for obj in ['group', 'nsp']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_nsp_func_1(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_NSP_FUNC_1: TO CREATE/REFER/DELETE/VERIFY "
            "NTK-SVC-POLICY in PTG\n"
            "TEST_STEPS::\n"
            "Create two NSPs one with type:ip-pool & ip-single, "
            "value:self_subnet and self_subnet\n"
            "Verify the attributes & values\n"
            "Create two PTGs and reference each one of the above "
            "NSP in one of the PTG\n"
            "Verify the NSP reference in the PTGs\n"
            "Delete the PTG and the NSP\n"
            "Verify that NSP got deleted\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create and Verify NSPolicy with type=ip_single & ip-single,
        # name:self_subnet & self_subnet
        self._log.info(
            '\n## Step 1: Create NSPolicy with type=ip_single & '
            'name:self_subnet ##\n')
        nsp1_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'nsp',
            'demo_nsp_1',
            network_service_params="type=ip_single,name=vip_ip1,"
                                   "value=self_subnet")
        if nsp1_uuid == 0:
            self._log.info(
                "\n## Step 1A: Create NSPolicy with type=ip_single & "
                "name:self_subnet == Failed")
            return 0
        nsp2_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'nsp',
            'demo_nsp_2',
            network_service_params="type=ip_single,name=vip_ip2,"
                                   "value=self_subnet")
        if nsp2_uuid == 0:
            self._log.info(
                "\n## Step 1B: Create NSPolicy with type=ip_single & "
                "name:self_subnet == Failed")
            return 0
        # Verify
        self._log.info(
            "\n## Step 2: Verify NSPolicies are successfully created")
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1,
                'nsp',
                nsp1_uuid,
                name='demo_nsp_1',
                network_service_params='{"type": "ip_single", "name": '
                                       '"vip_ip1", "value": '
                                       '"self_subnet"}') == 0:
            self._log.info(
                "\n## Step 2A: Verify NSPolicy demo_nsp_1 with valued "
                "attributes, Failed")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1,
                'nsp',
                nsp2_uuid,
                name='demo_nsp_2',
                network_service_params='{"type": "ip_single", '
                                       '"name": "vip_ip2", "value": '
                                       '"self_subnet"}') == 0:
            self._log.info(
                "\n## Step 2A: Verify NSPolicy demo_nsp_2 with "
                "valued attributes, Failed")
            return 0
        # Create two PTGs, each referencing one of the two NSPs
        self._log.info(
            "\n## Step 3: Create and Verify two PTGs each "
            "referencing one of the two NSPs")
        uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', 'demo_ptg_1', network_service_policy=nsp1_uuid)
        if uuid == 0:
            self._log.info(
                "\n## Step 3A: Create PTG using NSP demo_nsp_1,Failed")
            return 0
        else:
            ptg1_uuid = uuid[0]
        _uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', 'demo_ptg_2', network_service_policy=nsp2_uuid)
        if _uuid == 0:
            self._log.info(
                "\n## Step 3B: Create PTG using NSP demo_nsp_2,Failed")
            return 0
        else:
            ptg2_uuid = _uuid[0]
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp1_uuid, policy_target_groups=ptg1_uuid) == 0:
            self._log.info(
                "\n## Step 3C: Verify PTG demo_ptg_1 seen in NSP "
                "demo_nsp_1, Failed")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp2_uuid, policy_target_groups=ptg2_uuid) == 0:
            self._log.info(
                "\n## Step 3C: Verify PTG demo_ptg_2 seen in NSP "
                "demo_nsp_2, Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg1_uuid,
                network_service_policy_id=nsp1_uuid) == 0:
            self._log.info(
                "\n## Step 3D: Verify PTG demo_ptg_1 references NSP "
                "demo_nsp_1, Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg2_uuid,
                network_service_policy_id=nsp2_uuid) == 0:
            self._log.info(
                "\n## Step 3D: Verify PTG demo_ptg_2 references NSP "
                "demo_nsp_2, Failed")
            return 0
        # Delete PTGs & NSPs
        self._log.info(
            "\n## Step 4: Delete and Verify two PTGs each referencing "
            "one of the two NSPs")
        ptg_list = [ptg1_uuid, ptg2_uuid]
        nsp_list = [nsp1_uuid, nsp2_uuid]
        for i in range(len(ptg_list)):
            if self.gbpcfg.gbp_policy_cfg_all(0, 'group', ptg_list[i]) == 0:
                self._log.info(
                    "\n## Step 4A: Deletion of PTG %s, Failed" %
                    (ptg_list[i]))
                return 0
            if self.gbpcfg.gbp_policy_cfg_all(0, 'nsp', nsp_list[i]) == 0:
                self._log.info(
                    "\n## Step 4B: Deletion of NSP %s, Failed" %
                    (nsp_list[i]))
                return 0
        # Verify
        for n in range(len(nsp_list)):
            if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                    1, 'nsp', nsp_list[n]) != 0:
                self._log.info("\n## Step 4C: Verify deletion of NSP, Failed")
                return 0
        self._log.info("\n## TESTCASE_GBP_NSP_FUNC_1: PASSED")
        return 1

    def test_gbp_nsp_func_2(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_NSP_FUNC_2: TO CREATE/UPDATE/DELETE/VERIFY a PTG "
            "with NTK-SVC-POLICY with MULTIPLE PTGs\n"
            "TEST_STEPS::\n"
            "Create two NSPolicy Object with non-default params\n"
            "Create PTG using one of the two NSPs\n"
            "Verify the PTG and NSP are reflecting in each other in the DB\n"
            "Update the PTG to use the second NSP\n"
            "Verify the PTG and NSP are reflecting in each other in the DB\n"
            "Update/Revert the PTG so that it refers to the initial NSP\n"
            "Delete all PTG, NSP\n"
            "Verify that PTG and NSPs got deleted\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create NSPolicy with non-default attrs
        self._log.info('\n## Step 1: Create two NSPolicy ##\n')
        nsp1_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'nsp',
            'demo_nsp_1',
            network_service_params="type=ip_single,name=vip_ip1,"
                                   "value=self_subnet")
        if nsp1_uuid == 0:
            self._log.info(
                "\n## Step 1A: Create NSPolicy with type=ip_single & "
                "name:self_subnet == Failed")
            return 0
        nsp2_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'nsp',
            'demo_nsp_2',
            network_service_params="type=ip_single,name=vip_ip2,"
                                   "value=self_subnet")
        if nsp2_uuid == 0:
            self._log.info(
                "\n## Step 1B: Create NSPolicy with type=ip_single & "
                "name:self_subnet == Failed")
            return 0
        # Create PTG, referencing one of the two NSPs
        self._log.info(
            "\n## Step 3: Create and Verify PTG referencing one of "
            "the two NSPs")
        uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', 'demo_ptg_1', network_service_policy=nsp1_uuid)
        if uuid == 0:
            self._log.info(
                "\n## Step 3A: Create PTG using NSP demo_nsp_1,Failed")
            return 0
        else:
            ptg1_uuid = uuid[0]
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp1_uuid, policy_target_groups=ptg1_uuid) == 0:
            self._log.info(
                "\n## Step 3B: Verify PTG demo_ptg_1 seen in NSP "
                "demo_nsp_1, Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg1_uuid,
                network_service_policy_id=nsp1_uuid) == 0:
            self._log.info(
                "\n## Step 3C: Verify PTG demo_ptg_1 references "
                "NSP demo_nsp_1, Failed")
            return 0
        self._log.info(
            "\n## Step 4: Update and Verify the PTG with the second NSP")
        # Update the PTG with second NSP and Verify
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'group', ptg1_uuid, network_service_policy=nsp2_uuid) == 0:
            self._log.info(
                "\n## Step 4A: Updating NSP attribute of PTG, Failed")
            return 0
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp1_uuid, policy_target_groups=ptg1_uuid) != 0:
            self._log.info(
                "\n## Step 4B: Verify PTG demo_ptg_1 is NOT seen "
                "in NSP demo_nsp_1, Failed")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp2_uuid, policy_target_groups=ptg1_uuid) == 0:
            self._log.info(
                "\n## Step 4C: Verify PTG demo_ptg_1 is seen in NSP "
                "demo_nsp_2, Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg1_uuid,
                network_service_policy_id=nsp2_uuid) == 0:
            self._log.info(
                "\n## Step 4D: Verify PTG demo_ptg_1 references NSP "
                "demo_nsp_2, Failed")
            return 0
        self._log.info(
            "\n## Step 5: Update/Revert the NSP attr of PTG and Verify")
        # Update the PTG by reverting the NSP to its initial one
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'group', ptg1_uuid, network_service_policy=nsp1_uuid) == 0:
            self._log.info(
                "\n## Step 5A: Reverting the NSP attribute of PTG by "
                "update action, Failed")
            return 0
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp2_uuid, policy_target_groups=ptg1_uuid) != 0:
            self._log.info(
                "\n## Step 5B: Verify PTG demo_ptg_1 is NOT seen in NSP "
                "demo_nsp_2, Failed")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp1_uuid, policy_target_groups=ptg1_uuid) == 0:
            self._log.info(
                "\n## Step 5C: Verify PTG demo_ptg_1 is seen in NSP "
                "demo_nsp_1, Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg1_uuid,
                network_service_policy_id=nsp1_uuid) == 0:
            self._log.info(
                "\n## Step 5D: Verify PTG demo_ptg_1 references NSP "
                "demo_nsp_1, Failed")
            return 0
        self._log.info(
            "\n## Step 6: Delete and Verify two PTGs each referencing "
            "one of the two NSPs")
        # Delete PTG & NSP
        if self.gbpcfg.gbp_policy_cfg_all(0, 'group', ptg1_uuid) == 0:
            self._log.info("\n## Step 6A: Deletion of PTG,Failed")
            return 0
        nsp_list = [nsp1_uuid, nsp2_uuid]
        for i in range(len(nsp_list)):
            if self.gbpcfg.gbp_policy_cfg_all(0, 'nsp', nsp_list[i]) == 0:
                self._log.info(
                    "\n## Step 6B: Deletion of NSP %s, Failed" %
                    (nsp_list[i]))
                return 0
        # Verify
        for n in range(len(nsp_list)):
            if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                    1, 'nsp', nsp_list[n]) != 0:
                self._log.info("\n## Step 6C: Verify deletion of NSP, Failed")
                return 0
        self._log.info("\n## TESTCASE_GBP_NSP_FUNC_2: PASSED")
        return 1

    def test_gbp_nsp_func_3(self):

        self._log.info(
            "\n############################################################\n"
            "TESTCASE_GBP_NSP_FUNC_3: TO CREATE/DELETE/VERIFY "
            "NTK-SVC-POLICY while REFERENCED IN PTG\n"
            "TEST_STEPS::\n"
            "Create NSPolicy Object with non-default params\n"
            "Create PTG referencing the NSP\n"
            "Verify the PTG and NSP are reflecting in each other in the DB\n"
            "Delete and Verify the deletion of referenced NSP fails\n"
            "Delete PTG & NSP, Verify that PTG and NSPs got deleted\n"
            "##############################################################\n")

        # Testcase work-flow starts
        # Create NSPolicy with non-default attrs
        self._log.info(
            '\n## Step 1: Create NSPolicy with non-default params ##\n')
        nsp1_uuid = self.gbpcfg.gbp_policy_cfg_all(
            1,
            'nsp',
            'demo_nsp_1',
            network_service_params="type=ip_single,name=vip_ip1,"
                                   "value=self_subnet")
        if nsp1_uuid == 0:
            self._log.info(
                "\n## Step 1A: Create NSPolicy with type=ip_single & "
                "name:self_subnet == Failed")
            return 0
        # Create PTG, referencing one of the two NSPs
        self._log.info(
            "\n## Step 2: Create and Verify PTG referencing the NSP")
        uuid = self.gbpcfg.gbp_policy_cfg_all(
            1, 'group', 'demo_ptg_1', network_service_policy=nsp1_uuid)
        if uuid == 0:
            self._log.info(
                "\n## Step 2A: Create PTG using NSP demo_nsp_1,Failed")
            return 0
        else:
            ptg1_uuid = uuid[0]
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1, 'nsp', nsp1_uuid, policy_target_groups=ptg1_uuid) == 0:
            self._log.info(
                "\n## Step 2B: Verify PTG demo_ptg_1 seen in NSP demo_nsp_1, "
                "Failed")
            return 0
        if self.gbpverify.gbp_policy_verify_all(
                1, 'group', ptg1_uuid,
                network_service_policy_id=nsp1_uuid) == 0:
            self._log.info(
                "\n## Step 2C: Verify PTG demo_ptg_1 references "
                "NSP demo_nsp_1, Failed")
            return 0
        # Delete the referenced NSP
        self._log.info(
            "\n## Step 3: Delete the NSP while it is still referenced "
            "in a PTG")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'nsp', nsp1_uuid) != 0:
            self._log.info(
                "\n## Step 3A: Deletion of Referenced NSP DID NOT fail")
            return 0
        # Delete PTG & NSP
        self._log.info("\n## Step 4: Delete PTG followed by NSP and Verify")
        if self.gbpcfg.gbp_policy_cfg_all(0, 'group', ptg1_uuid) == 0:
            self._log.info("\n## Step 4A: Deletion of PTG,Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(0, 'nsp', nsp1_uuid) == 0:
            self._log.info("\n## Step 4B: Deletion of NSP,Failed")
            return 0
        # Verify
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(1, 'nsp', nsp1_uuid) != 0:
            self._log.info("\n## Step 4C: Verify deletion of NSP, Failed")
            return 0
        self._log.info("\n## TESTCASE_GBP_NSP_FUNC_3: PASSED")
        return 1

if __name__ == '__main__':
    main()
