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
import re
import yaml

# Initialize logging
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    level=logging.WARNING)
_log = logging.getLogger()
_log.setLevel(logging.INFO)


orig_getoutput = commands.getoutput


def getoutput(cmd):
    _log.info('Running cmd: %s\n' % (cmd))
    cmd_out = orig_getoutput(cmd)
    _log.info('Cmd output: %s\n' % (cmd_out))
    return cmd_out


commands.getoutput = getoutput


class Gbp_Verify(object):

    def __init__(self):
        """
        Init def
        """
        self.err_strings = [
            'Conflict',
            'Bad Request',
            'Error',
            'Unknown',
            'Unable']

    def gbp_action_verify(self, cmd_val, action_name, *args, **kwargs):
        """
        -- cmd_val== 0:list; 1:show
        -- action_name == UUID or name_string
        List/Show Policy Action
        kwargs addresses the need for passing required/optional params
        """
        if cmd_val == '' or action_name == '':
            _log.info('''Function Usage: gbp_action_verify 0 "abc" \n
                      --cmd_val == 0:list; 1:show\n
                       -- action_name == UUID or name_string\n''')
            return 0
        # Build the command with mandatory param 'action_name'
        if cmd_val == 0:
            cmd = 'gbp policy-action-list | grep %s' % str(action_name)
            for arg in args:
                cmd = cmd + ' | grep %s' % arg
        if cmd_val == 1:
            cmd = "gbp policy-action-show " + str(action_name)

        # Execute the policy-action-verify-cmd
        cmd_out = commands.getoutput(cmd)

        # Catch for non-exception error strings, even though try clause
        # succeded
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(cmd_out)
                _log.info(
                    "Cmd execution failed! with this Return Error: \n%s" %
                    (cmd_out))
                return 0
        if cmd_val == 0:
            for arg in args:
                if cmd_out.find(arg) == -1 or cmd_out.find(action_name) == -1:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s DID NOT MATCH for the Action == %s"
                        "in LIST cmd" % (arg, action_name))
                    return 0
        # If try clause succeeds for "verify" cmd then parse the cmd_out to
        # match the user-fed expected attributes & their values
        if cmd_val == 1:
            for arg, val in kwargs.items():
                if re.search("\\b%s\\b\s+\| \\b%s\\b.*" %
                             (arg, val), cmd_out, re.I) is None:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s and its Value== %s DID NOT MATCH"
                        "for the Action == %s" %
                        (arg, val, action_name))
                    return 0

        return 1

    def gbp_classif_verify(self, cmd_val, classifier_name, *args, **kwargs):
        """
        -- cmd_val== 0:list; 1:show
        -- classifier_name == UUID or name_string
        List/Show Policy Action
        kwargs addresses the need for passing required/optional params
        """
        if cmd_val == '' or classifier_name == '':
            _log.info('''Function Usage: gbp_classif_verify(0,name) \n
                      --cmd_val == 0:list 1:show\n
                       -- classifier_name == UUID or name_string\n''')
            return 0
        # Build the command with mandatory param 'classifier_name'
        if cmd_val == 0:
            cmd = 'gbp policy-classifier-list | grep %s' % str(classifier_name)
            for arg in args:
                cmd = cmd + ' | grep %s' % arg
        if cmd_val == 1:
            cmd = "gbp policy-classifier-show " + str(classifier_name)
        # Execute the policy-classifier-verify-cmd
        cmd_out = commands.getoutput(cmd)

        # Catch for non-exception error strings, even though try clause
        # succeded
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(cmd_out)
                _log.info(
                    "Cmd execution failed! with this Return Error: \n%s" %
                    (cmd_out))
                return 0
        if cmd_val == 0:
            for arg in args:
                if cmd_out.find(arg) == - \
                        1 or cmd_out.find(classifier_name) == -1:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s DID NOT MATCH for the Classifier "
                        "== %s in LIST cmd" %
                        (arg, classifier_name))
                    return 0
        # If try clause succeeds for "verify" cmd then parse the cmd_out to
        # match the user-fed expected attributes & their values
        if cmd_val == 1:
            for arg, val in kwargs.items():
                if re.search("\\b%s\\b\s+\| \\b%s\\b.*" %
                             (arg, val), cmd_out, re.I) is None:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s and its Value== %s DID NOT MATCH "
                        "for the Claasifier == %s" %
                        (arg, val, classifier_name))
                    return 0

        return 1

    def gbp_policy_verify_all(self, cmd_val, verifyobj,
                              name_uuid, *args, **kwargs):
        """
        --verifyobj== policy-*(where *=action;classifer,rule,rule-set,
                      target-group,target)
        --cmd_val== 0:list; 1:show
        kwargs addresses the need for passing required/optional params
        """
        verifyobj_dict = {
            "action": "policy-action",
            "classifier": "policy-classifier",
            "rule": "policy-rule",
            "ruleset": "policy-rule-set",
            "group": "group",
            "target": "policy-target"}
        if verifyobj != '':
            if verifyobj not in verifyobj_dict:
                raise KeyError
        if cmd_val == '' or name_uuid == '':
            _log.info('''Function Usage: gbp_policy_verify_all(0,'action',
                      'name_uuid')\n
                      --cmd_val == 0:list; 1:show\n
                      -- name_uuid == UUID or name_string\n''')
            return 0
        # Build the command with mandatory params
        if cmd_val == 0:
            cmd = 'gbp %s-list | grep ' % verifyobj_dict[
                verifyobj] + str(name_uuid)
            for arg in args:
                cmd = cmd + ' | grep %s' % arg
        if cmd_val == 1:
            cmd = 'gbp %s-show ' % verifyobj_dict[verifyobj] + str(name_uuid)
        # Execute the policy-object-verify-cmd
        cmd_out = commands.getoutput(cmd)
        # Catch for non-exception error strings
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(cmd_out)
                _log.info(
                    "Cmd execution failed! with this Return Error: \n%s" %
                    (cmd_out))
                return 0
        if cmd_val == 0:
            if name_uuid not in cmd_out:  # uuid not found
                return 0
            else:
                for arg in args:
                    if (cmd_out.find(arg) == -1 or
                            cmd_out.find(name_uuid) == -1):
                        _log.info(cmd_out)
                        _log.info(
                            "The Attribute== %s DID NOT MATCH for the "
                            "Policy Object == %s in LIST cmd" %
                            (arg, verifyobj))
                        return 0
        # If "verify" cmd succeeds then parse the cmd_out to match the user-fed
        # expected attributes & their values
        if cmd_val == 1:
            for arg, val in kwargs.items():
                if re.search("\\b%s\\b\s+\| \\b%s\\b.*" %
                             (arg, val), cmd_out, re.I) is None:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s and its Value== %s DID NOT MATCH "
                        "for the PolicyObject == %s" %
                        (arg, val, verifyobj))
                    return 0

        return 1

    def gbp_l2l3ntk_pol_ver_all(
            self, cmd_val, verifyobj, name_uuid, ret='', *args, **kwargs):
        """
        --verifyobj== *policy(where *=l2;l3,network)
        --cmd_val== 0:list; 1:show
        --ret=='default' <<< function will return some attribute values
        depending upon the verifyobj
        kwargs addresses the need for passing required/optional params
        """
        verifyobj_dict = {
            "l2p": "l2policy",
            "l3p": "l3policy",
            "nsp": "network-service-policy"}
        if verifyobj != '':
            if verifyobj not in verifyobj_dict:
                raise KeyError
        if cmd_val == '' or name_uuid == '':
            _log.info('''Function Usage: gbp_l2l3ntk_pol_ver_all(0,
                      'l2p','name') \n
                      --cmd_val == 0:list; 1:show\n
                      --name_uuid == UUID or name_string\n''')
            return 0
        # Build the command with mandatory params
        if cmd_val == 0:
            cmd = 'gbp %s-list | grep ' % verifyobj_dict[
                verifyobj] + str(name_uuid)
            for arg in args:
                cmd += ' | grep %s' % arg
        if cmd_val == 1:
            cmd = 'gbp %s-show ' % verifyobj_dict[verifyobj] + str(name_uuid)
        # Execute the policy-object-verify-cmd
        cmd_out = commands.getoutput(cmd)
        # _log.info(cmd_out)
        # Catch for non-exception error strings
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(cmd_out)
                _log.info(
                    "Cmd execution failed! with this Return Error: \n%s" %
                    (cmd_out))
                return 0
        if cmd_val == 0:
            if name_uuid not in cmd_out:  # uuid not found
                return 0
            else:
                for arg in args:
                    if (cmd_out.find(arg) == -1 or
                            cmd_out.find(name_uuid) == -1):
                        _log.info(cmd_out)
                        _log.info(
                            "The Attribute== %s DID NOT MATCH for the Policy "
                            "Object == %s in LIST cmd" %
                            (arg, verifyobj))
                        return 0
        # If "verify" succeeds cmd then parse the cmd_out to match the user-fed
        # expected attributes & their values
        if cmd_val == 1 and ret == 'default':
            for arg, val in kwargs.items():
                if re.search("\\b%s\\b\s+\| \\b%s\\b.*" %
                             (arg, val), cmd_out, re.I) is None:
                    # incase of attribute has more than one value then
                    # then below function will help us validating the values
                    # or the only value among all for the given attr.
                    # Example: L2P can have multiple PTGs, L3P can have multi
                    # L2Ps
                    if not self.gbp_obj_ver_attr_all_values(
                            verifyobj, name_uuid, arg, [val]):
                        _log.info(
                            "The Attribute== %s and its Value== %s "
                            "DID NOT MATCH "
                            "for the PolicyObject == %s" % (
                                arg, val, verifyobj))
                        return 0
            if verifyobj == "l2p":
                match = re.search(
                    "\\bl3_policy_id\\b\s+\| (.*) \|", cmd_out, re.I)
                l3pid = match.group(1)
                match = re.search(
                    "\\bnetwork_id\\b\s+\| (.*) \|", cmd_out, re.I)
                ntkid = match.group(1)
                return l3pid.rstrip(), ntkid.rstrip()
            if verifyobj == "l3p":
                match = re.search("\\brouters\\b\s+\| (.*) \|", cmd_out, re.I)
                rtrid = match.group(1)
                return rtrid.rstrip()
        elif cmd_val == 1:
            for arg, val in kwargs.items():
                if arg == 'network_service_params':
                    if re.findall('(%s)' % (val), cmd_out) == []:
                        _log.info(cmd_out)
                        _log.info(
                            "The Attribute== %s and its Value== %s DID NOT "
                            "MATCH for the PolicyObject == %s" %
                            (arg, val, verifyobj))
                        return 0
                elif re.search("\\b%s\\b\s+\| \\b%s\\b.*" % (arg, val),
                               cmd_out, re.I) is None:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s and its Value== %s DID NOT MATCH "
                        "for the PolicyObject == %s" %
                        (arg, val, verifyobj))
                    return 0
        else:
            return 1

    def neut_ver_all(self, verifyobj, name_uuid, ret='', **kwargs):
        """
        --verifyobj== net,subnet,port,router
        --ret=='default' <<< function will return some attribute values
                depending upon the verifyobj
        kwargs addresses the need for passing required/optional params
        """
        if name_uuid == '':
            _log.info('''Function Usage: neut_ver_all('net','name')\n
                      -- name_uuid == UUID or name_string\n''')
            return 0

        # Build the command with mandatory params
        cmd = 'neutron %s-show ' % verifyobj + str(name_uuid)
        _log.info('Neutron Cmd == %s\n' % (cmd))
        # Execute the policy-object-verify-cmd
        cmd_out = commands.getoutput(cmd)
        _log.info(cmd_out)
        # Catch for non-exception error strings
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(cmd_out)
                _log.info(
                    "Neutron Cmd execution failed! with this Return Error: "
                    "\n%s" % cmd_out)
                return 0
        if ret != '':
            match = re.search("\\b%s\\b\s+\| (.*) \|" % (ret), cmd_out, re.I)
            if match is not None:
                return match.group(1).rstrip()
            else:
                return 0
        for arg, val in kwargs.items():
            if isinstance(val, list):  # More than 1 value is to be verified
                for i in val:
                    if cmd_out.find(i) == -1:
                        _log.info(cmd_out)
                        _log.info(
                            "The Attribute== %s and its Value== %s DID NOT "
                            "MATCH for the NeutronObject == %s" %
                            (arg, i, verifyobj))
                        return 0
            else:
                if re.search("\\b%s\\b\s+\| \\b%s\\b.*" %
                             (arg, val), cmd_out, re.I) is None:
                    _log.info(cmd_out)
                    _log.info(
                        "The Attribute== %s and its Value== %s DID NOT MATCH "
                        "for the NeutronObject == %s" %
                        (arg, val, verifyobj))
                    return 0
        return 1

    def gbp_obj_ver_attr_all_values(self, verifyobj, name_uuid, attr, values):
        """
        Function will verify multiple entries for any given attribute
        of a Policy Object
        --values=Must be a list
        """
        verifyobj_dict = {
            "action": "policy-action",
            "classifier": "policy-classifier",
            "rule": "policy-rule",
            "ruleset": "policy-rule-set",
            "group": "group",
            "target": "policy-target",
            "l2p": "l2policy",
            "l3p": "l3policy",
            "nsp": "network-service-policy"}
        if verifyobj != '':
            if verifyobj not in verifyobj_dict:
                raise KeyError
        if not isinstance(values, list):
            raise TypeError
        # Build the command with mandatory params
        cmd = ('gbp %s-show ' % verifyobj_dict[verifyobj] +
               str(name_uuid) + ' -F %s' % (attr))
        # Execute the policy-object-verify-cmd
        cmd_out = commands.getoutput(cmd)
        # Catch for non-exception error strings
        for err in self.err_strings:
            if re.search('\\b%s\\b' % (err), cmd_out, re.I):
                _log.info(
                    "Cmd execution failed! with this Return Error: \n%s" %
                    (cmd_out))
                return 0
        _misses = []
        for val in values:
            if cmd_out.find(val) == -1:
                _misses.append(val)
        if len(_misses) > 0:
            _log.info(
                "\nFollowing Values of the Attribute for the Policy Object "
                "was NOT FOUND=%s" %
                (_misses))
            return 0
        return 1

    def get_uuid_from_stack(self, yaml_file, heat_stack_name):
        """
        Fetches the UUID of the GBP Objects created by Heat
        """
        with open(yaml_file, 'rt') as f:
            heat_conf = yaml.load(f)
        obj_uuid = {}
        # This comprise dict with keys as in [outputs] block of yaml-based
        # heat template
        outputs_dict = heat_conf["outputs"]
        print(outputs_dict)
        for key in outputs_dict.iterkeys():
            cmd = 'heat stack-show %s | grep -B 2 %s' % (heat_stack_name, key)
            print(cmd)
            cmd_out = commands.getoutput(cmd)
            print(cmd_out)
            match = re.search('\"\\boutput_value\\b\": \"(.*)\"',
                              cmd_out, re.I)
            if match is not None:
                obj_uuid[key] = match.group(1)
        return obj_uuid
