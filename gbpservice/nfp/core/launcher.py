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

import os
import time

from oslo_service import service as oslo_service

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)
ProcessLauncher = oslo_service.ProcessLauncher

"""Worker process launcher.

    Derives the oslo process launcher to
    launch childrens with python multiprocessing
    as oppose to os.fork(), coz, communication
    is needed from parent->child not just the
    parallel execution.
"""


class NfpLauncher(ProcessLauncher):

    def __init__(self, conf):
        super(NfpLauncher, self).__init__(conf)

    def child(self, service, ppipe, cpipe, controller):
        service.parent_pipe = ppipe
        service.pipe = cpipe
        service.controller = controller
        self.launcher = self._child_process(service)
        while True:
            self._child_process_handle_signal()
            status, signo = self._child_wait_for_exit_or_signal(
                self.launcher)
            if not oslo_service._is_sighup_and_daemon(signo):
                self.launcher.wait()
                break
            self.launcher.restart()

        os._exit(status)

    def _start_child(self, wrap):
        if len(wrap.forktimes) > wrap.workers:
            # Limit ourselves to one process a second (over the period of
            # number of workers * 1 second). This will allow workers to
            # start up quickly but ensure we don't fork off children that
            # die instantly too quickly.
            if time.time() - wrap.forktimes[0] < wrap.workers:
                time.sleep(1)

            wrap.forktimes.pop(0)

        wrap.forktimes.append(time.time())

        pid = self.fork_child(wrap)

        message = "Started Child Process %d" % (pid)
        LOG.debug(message)

        wrap.children.add(pid)
        self.children[pid] = wrap

        return pid

    def fork_child(self, wrap):
        # Default use os.fork to create a child
        pid = os.fork()
        if pid == 0:
            self.launcher = self._child_process(wrap.service)
            while True:
                self._child_process_handle_signal()
                status, signo = self._child_wait_for_exit_or_signal(
                    self.launcher)
                if not oslo_service._is_sighup_and_daemon(signo):
                    self.launcher.wait()
                    break
                self.launcher.restart()

            os._exit(status)
        return pid
