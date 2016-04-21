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

from subprocess import call
from subprocess import PIPE
from subprocess import Popen
import sys

from oslo_log._i18n import _LE
from oslo_log._i18n import _LI
from oslo_log import log as logging
from oslo_serialization import jsonutils

LOG = logging.getLogger(__name__)


class ConfigureIPtables(object):

    def __init__(self, json_blob):
        ps = Popen(["sysctl", "net.ipv4.ip_forward"], stdout=PIPE)
        output = ps.communicate()[0]
        if "0" in output:
            LOG.info(_LI("Enabling IP forwarding ..."))
            call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        else:
            LOG.info(_LI("IP forwarding already enabled"))
        try:
            self.rules_json = jsonutils.loads(json_blob)
        except ValueError:
            sys.exit('Given json_blob is not a valid json')

    def update_chain(self):
        ps = Popen(["iptables", "-L"], stdout=PIPE)
        output = ps.communicate()[0]

        # check if chain is present if not create new chain
        if "testchain" not in output:
            LOG.info(_LI("Creating new chain ..."))
            call(["iptables", "-F"])
            call(["iptables", "-N", "testchain"])
            call(
                ["iptables", "-t", "filter",
                 "-A", "FORWARD", "-j", "testchain"])
            call(["iptables", "-A", "FORWARD", "-j", "DROP"])

        # flush chain of existing rules
        call(["iptables", "-F", "testchain"])
        # return

        # Update chain with new rules
        LOG.info(_LI("Updating chain with new rules ..."))
        count = 0
        for rule in self.rules_json.get('rules'):
            LOG.info(_LI("adding rule %(count)d") % {'count': count})
            try:
                action_values = ["LOG", "ACCEPT"]
                action = rule['action'].upper()
                if action not in action_values:
                    sys.exit(
                        "Action %s is not valid action! Please enter "
                        "valid action (LOG or ACCEPT)" % (action))
                service = rule['service'].split('/')
            except KeyError as e:
                sys.exit('KeyError: Rule does not have key %s' % (e))

            if len(service) > 1:
                ps = Popen(["iptables", "-A", "testchain", "-p", service[
                           0], "--dport", service[1], "-j", action],
                           stdout=PIPE)
            else:
                ps = Popen(
                    ["iptables", "-A", "testchain", "-p", service[0],
                     "-j", action], stdout=PIPE)
            output = ps.communicate()[0]
            if output:
                LOG.error(_LE("Unable to add rule to chain due to: %(output)s")
                          % {'output': output})
            count = count + 1
        ps = Popen(["iptables", "-A", "testchain", "-m", "state", "--state",
                    "ESTABLISHED,RELATED", "-j", "ACCEPT"], stdout=PIPE)
        output = ps.communicate()[0]
        if output:
            LOG.error(_LE("Unable to add rule to chain due to: %(output)s")
                      % {'output': output})


def main():
    if len(sys.argv) < 2:
        sys.exit('Usage: %s json-blob' % sys.argv[0])
    else:
        json_blob = sys.argv[1]
    test = ConfigureIPtables(json_blob)
    test.update_chain()

if __name__ == "__main__":
    main()
