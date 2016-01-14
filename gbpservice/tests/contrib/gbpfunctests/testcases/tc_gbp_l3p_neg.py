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
    test = test_gbp_l3p_neg()
    if test.test_gbp_l3p_neg_1() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_L3P_NEG_1')
    if test.test_gbp_l3p_neg_2() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_L3P_NEG_2')
    if test.test_gbp_l3p_neg_3() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_L3P_NEG_3')
    if test.test_gbp_l3p_neg_4() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_L3P_NEG_4')
    if test.test_gbp_l3p_neg_5() == 0:
        test.cleanup(tc_name='TESTCASE_GBP_L3P_NEG_5')
    test.cleanup()
    utils_libs.report_results('test_gbp_l3p_neg', 'test_results.txt')
    sys.exit(1)


class test_gbp_l3p_neg(object):

    # Initialize logging
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        level=logging.WARNING)
    _log = logging.getLogger(__name__)
    cmd = 'rm /tmp/test_gbp_l3p_neg.log'
    commands.getoutput(cmd)
    hdlr = logging.FileHandler('/tmp/test_gbp_l3p_neg.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):
        """
        Init def
        """
        self._log.info("\n## START OF GBP L3_POLICY NEGATIVE TESTSUITE\n")
        self.gbpcfg = config_libs.Gbp_Config()
        self.gbpverify = verify_libs.Gbp_Verify()
        self.l3p_name = 'demo_l3p'

    def cleanup(self, tc_name=''):
        if tc_name != '':
            self._log.info('%s: FAILED' % (tc_name))
        for obj in ['group', 'l2p', 'l3p']:
            self.gbpcfg.gbp_del_all_anyobj(obj)

    def test_gbp_l3p_neg_1(self):

        self._log.info(
            "\n#############################################\n"
            "TESTCASE_GBP_L3P_NEG_1: TO CREATE/VERIFY L3POLICY "
            "with INVALID IP-POOL\n"
            "TEST_STEPS::\n"
            "Create L3Policy Object with Invalid IP-Pool\n"
            "Invalid IP-Pools: x.y.0.0/24, 0.0.0.0/0,255.255.255.255/32,"
            "0.2323.0.0/24\n"
            "Verify the create FAILs and config rolls back\n"
            "############################################\n")

        # Testcase work-flow starts
        count = 0
        invalid_pools = [
            'x.y.0.0/24',
            '0.2323.0.0/24',
            '0.0.0.0/0',
            '255.255.255.255/32']
        for pool in invalid_pools:
            self._log.info(
                "\n## Step 1A: Create L3Policy with Invalid IP-Pool = %s ##" %
                (pool))
            if self.gbpcfg.gbp_policy_cfg_all(
                    1, 'l3p', self.l3p_name, ip_pool=pool) != 0:
                self._log.info(
                    "# Step 1A: Create L3Policy with Invalid IP-Pool %s did "
                    "NOT fail" %
                    (pool))
            self._log.info('# Step 1A: Verify L3Policy did NOT get created')
            if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                    1, 'l3p', self.l3p_name) != 0:
                self._log.info(
                    "# Step 1A: L3Policy did NOT fail to create even with "
                    "Invalid IP-Pool %s" %
                    (pool))
                count += 1
        if count > 0:
            return 0
        else:
            self._log.info("\nTESTCASE_GBP_L3P_NEG_1: PASSED")
            return 1

    def test_gbp_l3p_neg_2(self):

        self._log.info(
            "\n############################################\n"
            "TESTCASE_GBP_L3P_NEG_2: TO CREATE/VERIFY L3POLICY with INVALID "
            "SUBNET-PREF-LENGTH\n"
            "TEST_STEPS::\n"
            "Create L3Policy Object with Invalid Subnet-Prefix-Length\n"
            "Invalid Subnet-Prefix-Lengths: 33,'AB','32'\n"
            "Verify the create FAILs and config rolls back\n"
            "############################################\n")

        # Testcase work-flow starts
        cnt = 0
        invalid_prefix_length = ['33', 'AB', '32']
        for prefix in invalid_prefix_length:
            self._log.info(
                "\n## Step 1A: Create L3Policy with Invalid "
                "Prefix-lenght = %s ##" %
                (prefix))
            if self.gbpcfg.gbp_policy_cfg_all(
                    1, 'l3p', self.l3p_name, subnet_prefix_length=prefix) != 0:
                self._log.info(
                    "# Step 1A: Create L3Policy with Invalid IP-Pool %s "
                    "did NOT fail" %
                    (prefix))
            self._log.info('# Step 1A: Verify L3Policy did NOT get created')
            if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                    1, 'l3p', self.l3p_name) != 0:
                self._log.info(
                    "# Step 1A: L3Policy did NOT fail to create even with "
                    "Invalid IP-Pool %s" %
                    (prefix))
                cnt += 1
        if cnt > 0:
            return 0
        else:
            self._log.info("\nTESTCASE_GBP_L3P_NEG_2: PASSED")
            return 1

    def test_gbp_l3p_neg_3(self):

        self._log.info(
            "\n############################################\n"
            "TESTCASE_GBP_L3P_NEG_3: TO CREATE/VERIFY L3POLICY with mix "
            "of VALID & INVALID ATTRs\n"
            "TEST_STEPS::\n"
            "Create L3Policy with a mix of Valid IP-Pool and Invalid "
            "Subnet-Prefix-Length & Vice-versa\n"
            "Invalid IP-Pool: x.y.0.0/24,Valid Subnet-Pref-Len: 30\n"
            "Valid IP-Pool: 20.20.20.0/24, Invalid Subnet-Pref-Len: 32\n"
            "Verify the create FAILs and config rolls back\n"
            "############################################\n")

        # Testcase work-flow starts
        mix_attr = {'x.y.0.0/24': '30', '20.20.20.0/24': '32'}
        _pass = 0
        for ip, pref in mix_attr.iteritems():
            self._log.info(
                "\n## Step 1A: Create L3Policy with IP-Pool = %s & "
                "Subnet-Pref-Len = %s ##" %
                (ip, pref))
            if self.gbpcfg.gbp_policy_cfg_all(
                    1,
                    'l3p',
                    self.l3p_name,
                    ip_pool=ip,
                    subnet_prefix_length=pref) != 0:
                self._log.info(
                    "# Step 1A: Create L3Policy with mix of valid and "
                    "invalid did NOT fail")
            self._log.info('# Step 1A: Verify L3Policy did NOT get created')
            if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                    1, 'l3p', self.l3p_name) != 0:
                self._log.info(
                    "# Step 1A: L3Policy did NOT fail to create even with "
                    "mix of Valid and Invalid attrs %s")
                _pass += 1
        if _pass > 0:
            return 0
        else:
            self._log.info("\nTESTCASE_GBP_L3P_NEG_3: PASSED")
            return 1

    def test_gbp_l3p_neg_4(self):

        self._log.info(
            "\n#################################################\n"
            "TESTCASE_GBP_L3P_NEG_4: TO UPDATE/VERIFY L3POLICY with "
            "INVALID ATTRs\n"
            "TEST_STEPS::\n"
            "Create a L3Policy with default attr values\n"
            "Update the L3Policy with Invalid Subnet-Prefix-Length\n"
            "Update the L3Policy with Valid IP-Pool, should fail as "
            "ip-pool is Immutable attr\n"
            "Verify the update fails and config roll backs to original "
            "values of the L3Policy\n"
            "###############################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create a L3P with default attribute ##\n')
        l3p_uuid = self.gbpcfg.gbp_policy_cfg_all(1, 'l3p', self.l3p_name)
        if l3p_uuid == 0:
            self._log.info("\n## Step 1: Create L3Policy == Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'l3p', l3p_uuid, subnet_prefix_length='32') != 0:
            self._log.info(
                "\n## Step 2: Updating L3Policy's Subnet-Prefix-Length "
                "with Invalid Value=32 did NOT fail")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'l3p', l3p_uuid, ip_pool='20.20.0.0/24') != 0:
            self._log.info(
                "\n## Step 3: Updating L3Policy's Immutable attr IP-Pool "
                "did NOT fail")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1,
                'l3p',
                l3p_uuid,
                id=l3p_uuid,
                name=self.l3p_name,
                ip_pool='10.0.0.0/8',
                subnet_prefix_length='24') == 0:
            self._log.info(
                "\n## Step 4: L3Policy config did NOT roll back to original "
                "default values")
            return 0
        self.gbpcfg.gbp_policy_cfg_all(
            0, 'l3p', l3p_uuid)  # clean-up before next testcase
        self._log.info("\nTESTCASE_GBP_L3P_NEG_4: PASSED")
        return 1

    def test_gbp_l3p_neg_5(self):

        self._log.info(
            "\n#################################################\n"
            "TESTCASE_GBP_L3P_NEG_5: TO CREATE/UPDATE L3POLICY with "
            "SUBNET-PREF-LENGTH GREATER than IP-POOL's MASK-LENGTH\n"
            "TEST_STEPS::\n"
            "Create a L3Policy with non-default attr, "
            "subnet-pref-length > mask-length of pool\n"
            "Verify the above L3Policy creation fails\n"
            "Create a L3Policy with default attrs\n"
            "Update the L3Policy's subnet-pref-length such that "
            "subnet-pref-length > mask-length of pool\n"
            "Verify the update fails and L3Policy attrs persists with "
            "default values\n"
            "##################################################\n")

        # Testcase work-flow starts
        self._log.info('\n## Step 1: Create a L3P with default attribute ##\n')
        l3p_uuid = self.gbpcfg.gbp_policy_cfg_all(1, 'l3p', self.l3p_name)
        if l3p_uuid == 0:
            self._log.info("\n## Step 1: Create L3Policy == Failed")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                2, 'l3p', l3p_uuid, subnet_prefix_length='4') != 0:
            self._log.info(
                "\n## Step 2: Updating L3Policy's "
                "Subnet-Prefix-Length > default Mask-length(8) did NOT fail")
            return 0
        if self.gbpverify.gbp_l2l3ntk_pol_ver_all(
                1,
                'l3p',
                l3p_uuid,
                id=l3p_uuid,
                name=self.l3p_name,
                ip_pool='10.0.0.0/8',
                subnet_prefix_length='24') == 0:
            self._log.info(
                "\n## Step 3: L3Policy config did NOT roll back "
                "to original default values")
            return 0
        if self.gbpcfg.gbp_policy_cfg_all(
                1,
                'l3p',
                'new_l3p',
                ip_pool='20.20.20.0/24',
                subnet_prefix_length='16') != 0:
            self._log.info(
                "\n## Step 4: Creating L3Policy with "
                "Subnet-Prefix-Length > Mask-Length(24) did NOT fail")
            return 0
        self._log.info("\nTESTCASE_GBP_L3P_NEG_5: PASSED")
        return 1

if __name__ == '__main__':
    main()
