#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from gbpservice.nfp.core import context as nfp_context
from gbpservice.nfp.core import controller as nfp_controller
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import manager as nfp_manager
from gbpservice.nfp.core import worker as nfp_worker
import mock
import multiprocessing as multiprocessing
from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
import random
import time
import unittest
LOG = oslo_logging.getLogger(__name__)

NFP_MODULES_PATH = ['gbpservice.neutron.tests.unit.nfp.core']


def mocked_get_logging_context(**kwargs):
    return {
        'meta_id': '',
        'auth_token': None,
        'namespace': None}

nfp_logging.get_logging_context = mocked_get_logging_context


class MockedPipe(object):

    def __init__(self):
        self.fd = random.randint(14, 34)
        self.other_end_event_proc_func = None

    def poll(self, *args, **kwargs):
        return False

    def send(self, event):
        self.other_end_event_proc_func(event)


class MockedProcess(object):

    def __init__(self, parent_pipe=None, child_pipe=None,
                 controller=None):

        self.parent_pipe = parent_pipe
        self.child_pipe = child_pipe
        self.controller = controller
        self.daemon = True
        self.pid = random.randint(8888, 9999)

    def start(self):
        self.worker = nfp_worker.NfpWorker({}, threads=0)
        self.worker.parent_pipe = self.parent_pipe
        self.worker.pipe = self.child_pipe
        self.worker.controller = nfp_controller.NfpController(
            self.controller._conf, singleton=False)

        # fork a new controller object
        self.worker.controller.PROCESS_TYPE = "worker"
        self.worker.controller._pipe = self.worker.pipe
        self.worker.controller._event_handlers = (
            self.controller._event_handlers)
        self.worker.event_handlers = self.controller.get_event_handlers()

        self.parent_pipe.other_end_event_proc_func = (
            self.worker._process_event)
        self.child_pipe.other_end_event_proc_func = (
            self.controller._process_event)


def mocked_pipe(**kwargs):
    return MockedPipe(), MockedPipe()


def mocked_process(target=None, args=None):
    return MockedProcess(parent_pipe=args[1],
                         child_pipe=args[2],
                         controller=args[3])


nfp_controller.PIPE = mocked_pipe
nfp_controller.PROCESS = mocked_process


class MockedWatchdog(object):

    def __init__(self, handler, seconds=1, event=None):
        if event and event.desc.type == 'poll_event':
            # time.sleep(seconds)
            handler(event=event)

    def cancel(self):
        pass

nfp_manager.WATCHDOG = MockedWatchdog


class Object(object):

    def __init__(self):
        pass


class Test_Process_Model(unittest.TestCase):

    def setUp(self):
        nfp_context.init()

    def _mocked_fork(self, args):
        proc = Object()
        pid = random.randint(8888, 9999)
        setattr(proc, 'pid', pid)
        return proc

    def _mocked_oslo_wrap(self):
        wrap = Object()
        setattr(wrap, 'service', {})
        return wrap

    def _mocked_event_ack(self, event):
        if event.id == 'TEST_EVENT_ACK_FROM_WORKER':
            if hasattr(event, 'desc'):
                if event.desc.worker:
                    self.controller.event_ack_wait_obj.set()

    def test_nfp_module_init(self):
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'nfp_module_init_wait_obj', wait_obj)
        nfp_controller.load_nfp_modules(conf, controller)
        controller.nfp_module_init_wait_obj.wait(1)
        called = controller.nfp_module_init_wait_obj.is_set()
        self.assertTrue(called)

    def test_nfp_module_init_wrong_path(self):
        conf = oslo_config.CONF
        conf.nfp_modules_path = ['tmp.nfp']
        controller = nfp_controller.NfpController(oslo_config.CONF,
                                                  singleton=False)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'nfp_module_init_wait_obj', wait_obj)
        nfp_controller.load_nfp_modules(conf, controller)
        controller.nfp_module_init_wait_obj.wait(1)
        called = controller.nfp_module_init_wait_obj.is_set()
        self.assertFalse(called)

    def test_nfp_module_post_init_called(self):
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'nfp_module_post_init_wait_obj', wait_obj)
        nfp_modules = nfp_controller.load_nfp_modules(conf, controller)
        nfp_controller.nfp_modules_post_init(conf, nfp_modules, controller)
        controller.nfp_module_post_init_wait_obj.wait(1)
        called = controller.nfp_module_post_init_wait_obj.is_set()
        self.assertTrue(called)

    def test_nfp_module_post_init_ignored(self):
        # None the post_init method in test handler
        from gbpservice.neutron.tests.unit.nfp.core import (
            nfp_module)
        del nfp_module.nfp_module_post_init

        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'nfp_module_post_init_wait_obj', wait_obj)
        nfp_modules = nfp_controller.load_nfp_modules(conf, controller)
        nfp_controller.nfp_modules_post_init(conf, nfp_modules, controller)
        controller.nfp_module_post_init_wait_obj.wait(1)
        called = controller.nfp_module_post_init_wait_obj.is_set()
        self.assertFalse(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController._fork'
    )
    def test_nfp_controller_launch_2_workers(self, mock_fork):
        mock_fork.side_effect = self._mocked_fork
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        controller.launch(2)
        # Check if 2 workers are created
        workers = controller.get_childrens()
        pids = workers.keys()
        self.assertTrue(len(pids) == 2)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController._fork'
    )
    def test_nfp_controller_launch_4_workers(self, mock_fork):
        mock_fork.side_effect = self._mocked_fork
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        controller.launch(4)
        # Check if 4 workers are created
        workers = controller.get_childrens()
        pids = workers.keys()
        self.assertTrue(len(pids) == 4)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController._fork'
    )
    def test_nfp_rsrc_manager_new_childs(self, mock_fork):
        mock_fork.side_effect = self._mocked_fork
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        controller.launch(2)
        controller._update_manager()
        # Check if 2 workers are added to manager
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 2)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController._fork'
    )
    def test_nfp_rsrc_manager_kill_child(self, mock_fork):
        mock_fork.side_effect = self._mocked_fork
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        controller.launch(2)
        controller._update_manager()
        # run so that it stores the snapshot
        controller._manager.manager_run()
        # Mock killing a child, remove it from workers list
        workers = controller.get_childrens()
        old_childs = list(workers.keys())
        del controller.children[old_childs[0]]
        # Mock creating a new child which replaces the killed one
        wrap = self._mocked_oslo_wrap()
        pid = controller.fork_child(wrap)
        controller.children[pid] = wrap

        # Run one more time and check if it detects the difference
        controller._manager.manager_run()
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 2)
        if pid not in old_childs:
            self.assertFalse(old_childs[0] in pids)
        self.assertTrue(old_childs[1] in pids)

    def test_post_event_with_no_handler(self):
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        event = controller.create_event(
            id='EVENT_INVALID', data='INVALID_DATA',
            binding_key='EVENT_INVALID')
        try:
            controller.post_event(event)
        except AssertionError:
            return

        self.assertTrue(False)

    def mocked_compress(self, event):
        pass

    def mocked_pipe_send(self, pipe, event):
        if event.id == 'EVENT_1':
            if hasattr(event, 'desc'):
                if event.desc.worker:
                    self.controller.nfp_event_1_wait_obj.set()
        elif 'EVENT_LOAD' in event.id:
            if hasattr(event, 'desc'):
                if event.desc.worker == event.data:
                    self.controller.nfp_event_load_wait_obj.set()
        elif 'SEQUENCE' in event.id:
            if hasattr(event, 'desc'):
                if event.desc.worker:
                    if 'EVENT_1' in event.id:
                        self.controller.sequence_event_1_wait_obj.set()
                    elif 'EVENT_2' in event.id:
                        self.controller.sequence_event_2_wait_obj.set()
        elif 'POLL' in event.id:
            if hasattr(event, 'desc'):
                if hasattr(event.desc, 'poll_desc'):
                    if event.desc.worker:
                        if event.id == 'POLL_EVENT':
                            self.controller.poll_event_wait_obj.set()
                        if event.id == 'POLL_EVENT_DECORATOR':
                            self.controller.poll_event_dec_wait_obj.set()

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send'
    )
    def test_post_event_in_distributor(self, mock_pipe_send):
        mock_pipe_send.side_effect = self.mocked_pipe_send
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        wait_obj = multiprocessing.Event()
        setattr(controller, 'nfp_event_1_wait_obj', wait_obj)
        event = controller.create_event(
            id='EVENT_1',
            data='post_event_in_distributor')

        # Store in class object
        self.controller = controller
        controller.post_event(event)
        controller.nfp_event_1_wait_obj.wait(1)
        called = controller.nfp_event_1_wait_obj.is_set()
        self.assertTrue(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send')
    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_load_distribution_to_workers(self, mock_compress, mock_pipe_send):
        mock_pipe_send.side_effect = self.mocked_pipe_send
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(3)
        controller._update_manager()

        # Load distribution as -> worker1 - 2, worker2 - 4, worker3 - 6
        # 10 events to be distributed.
        # worker1 will get 5
        # worker2 will get 4
        # worker3 will get 1
        # At the end all workers should be @load 7

        # Initialize with above load
        init_load = [6, 4, 2]
        worker_pids = []
        resource_map = controller._manager._resource_map
        for pid, em in resource_map.iteritems():
            load = init_load.pop()
            em._load = load
            worker_pids.append(pid)

        events = [
            controller.create_event(id='EVENT_LOAD_1', data=worker_pids[0]),
            controller.create_event(id='EVENT_LOAD_2', data=worker_pids[0]),
            controller.create_event(id='EVENT_LOAD_3', data=worker_pids[0]),
            controller.create_event(id='EVENT_LOAD_4', data=worker_pids[1]),
            controller.create_event(id='EVENT_LOAD_5', data=worker_pids[0]),
            controller.create_event(id='EVENT_LOAD_6', data=worker_pids[1]),
            controller.create_event(id='EVENT_LOAD_7', data=worker_pids[0]),
            controller.create_event(id='EVENT_LOAD_8', data=worker_pids[1]),
            controller.create_event(id='EVENT_LOAD_9', data=worker_pids[2])]

        for i in range(0, 9):
            wait_obj = multiprocessing.Event()
            setattr(controller, 'nfp_event_load_wait_obj', wait_obj)
            event = events[i]
            controller.post_event(event)
            controller.nfp_event_load_wait_obj.wait(1)
            called = controller.nfp_event_load_wait_obj.is_set()
            self.assertTrue(called)

    def test_new_event_with_sequence_and_no_binding_key(self):
        conf = oslo_config.CONF
        conf.nfp_modules_path = []
        controller = nfp_controller.NfpController(conf, singleton=False)
        event = controller.create_event(
            id='EVENT_SEQUENCE', data='NO_DATA',
            serialize=True)
        self.assertTrue(event is None)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send'
    )
    def test_events_sequencing_with_same_binding_key(self, mock_pipe_send):
        mock_pipe_send.side_effect = self.mocked_pipe_send
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_1_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_2_wait_obj', wait_obj)
        event_1 = controller.create_event(
            id='SEQUENCE_EVENT_1', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE')
        event_2 = controller.create_event(
            id='SEQUENCE_EVENT_2', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE')
        controller.post_event(event_1)
        controller.post_event(event_2)

        controller._manager.manager_run()
        controller.sequence_event_1_wait_obj.wait(1)
        called = controller.sequence_event_1_wait_obj.is_set()
        self.assertTrue(called)
        controller.event_complete(event_1)
        controller._manager.manager_run()
        controller.sequence_event_2_wait_obj.wait(1)
        called = controller.sequence_event_2_wait_obj.is_set()
        self.assertTrue(called)
        controller.event_complete(event_2)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send'
    )
    def test_events_sequencing_with_diff_binding_key(self, mock_pipe_send):
        mock_pipe_send.side_effect = self.mocked_pipe_send
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_1_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_2_wait_obj', wait_obj)
        event_1 = controller.create_event(
            id='SEQUENCE_EVENT_1', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE_1')
        event_2 = controller.create_event(
            id='SEQUENCE_EVENT_2', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE_2')
        controller.post_event(event_1)
        controller.post_event(event_2)

        controller._manager.manager_run()
        controller.sequence_event_1_wait_obj.wait(1)
        called = controller.sequence_event_1_wait_obj.is_set()
        self.assertTrue(called)
        controller.sequence_event_2_wait_obj.wait(1)
        called = controller.sequence_event_2_wait_obj.is_set()
        self.assertTrue(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send'
    )
    def test_events_sequencing_negative(self, mock_pipe_send):
        mock_pipe_send.side_effect = self.mocked_pipe_send
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_1_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'sequence_event_2_wait_obj', wait_obj)
        event_1 = controller.create_event(
            id='SEQUENCE_EVENT_1', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE')
        event_2 = controller.create_event(
            id='SEQUENCE_EVENT_2', data='NO_DATA',
            serialize=True, binding_key='SEQUENCE')
        controller.post_event(event_1)
        controller.post_event(event_2)

        controller._manager.manager_run()
        controller.sequence_event_1_wait_obj.wait(1)
        called = controller.sequence_event_1_wait_obj.is_set()
        self.assertTrue(called)
        controller._manager.manager_run()
        controller.sequence_event_2_wait_obj.wait(1)
        called = controller.sequence_event_2_wait_obj.is_set()
        # Should not be called
        self.assertFalse(called)
        controller.event_complete(event_1)
        controller.event_complete(event_2)

        @mock.patch(
            'gbpservice.nfp.core.controller.NfpController.pipe_send')
        @mock.patch(
            'gbpservice.nfp.core.controller.NfpController.compress')
        def test_poll_event(self, mock_compress, mock_pipe_send):
            mock_pipe_send.side_effect = self.mocked_pipe_send
            mock_compress.side_effect = self.mocked_compress
            conf = oslo_config.CONF
            conf.nfp_modules_path = NFP_MODULES_PATH
            controller = nfp_controller.NfpController(conf, singleton=False)
            self.controller = controller
            nfp_controller.load_nfp_modules(conf, controller)
            # Mock launching of a worker
            controller.launch(1)
            controller._update_manager()
            self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_wait_obj', wait_obj)
        event = controller.create_event(
            id='POLL_EVENT', data='NO_DATA')

        # Update descriptor
        desc = nfp_event.EventDesc(**{})
        setattr(event, 'desc', desc)
        event.desc.worker = controller.get_childrens().keys()[0]

        ctx = nfp_context.get()
        ctx['log_context']['namespace'] = 'nfp_module'

        controller.poll_event(event, spacing=1)
        # controller._manager.manager_run()

        start_time = time.time()
        # relinquish for 1sec
        time.sleep(1)

        # controller.poll()
        controller.poll_event_wait_obj.wait(0.1)
        called = controller.poll_event_wait_obj.is_set()
        end_time = time.time()
        self.assertTrue(called)
        self.assertTrue(round(end_time - start_time) == 1.0)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send')
    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_poll_event_with_no_worker(self, mock_compress, mock_pipe_send):
        mock_compress.side_effect = self.mocked_compress
        mock_pipe_send.side_effect = self.mocked_pipe_send
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_wait_obj', wait_obj)
        event = controller.create_event(
            id='POLL_EVENT', data='NO_DATA')

        # Update descriptor
        desc = nfp_event.EventDesc(**{})
        setattr(event, 'desc', desc)
        # Explicitly make it none
        event.desc.worker = None

        ctx = nfp_context.get()
        ctx['log_context']['namespace'] = 'nfp_module'

        controller.poll_event(event, spacing=1)
        # controller._manager.manager_run()

        start_time = time.time()
        # relinquish for 1sec
        time.sleep(1)

        # controller.poll()
        controller.poll_event_wait_obj.wait(0.1)
        called = controller.poll_event_wait_obj.is_set()
        end_time = time.time()
        self.assertTrue(called)
        self.assertTrue(round(end_time - start_time) == 1.0)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.pipe_send')
    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_poll_event_with_decorator_spacing(self,
                                               mock_compress, mock_pipe_send):

        mock_pipe_send.side_effect = self.mocked_pipe_send
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_dec_wait_obj', wait_obj)
        event = controller.create_event(
            id='POLL_EVENT_DECORATOR', data='NO_DATA')

        # Update descriptor
        desc = nfp_event.EventDesc(**{})
        setattr(event, 'desc', desc)
        # Explicitly make it none
        event.desc.worker = None

        ctx = nfp_context.get()
        ctx['log_context']['namespace'] = 'nfp_module'
        controller.poll_event(event)
        # controller._manager.manager_run()

        start_time = time.time()
        # relinquish for 2secs
        time.sleep(2)

        # controller.poll()
        controller.poll_event_dec_wait_obj.wait(0.1)
        called = controller.poll_event_dec_wait_obj.is_set()
        end_time = time.time()
        self.assertTrue(called)
        self.assertTrue(round(end_time - start_time) == 2.0)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_poll_event_with_no_spacing(self, mock_compress):
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        event = controller.create_event(
            id='POLL_EVENT_WITHOUT_SPACING', data='NO_DATA')

        # Update descriptor
        desc = nfp_event.EventDesc(**{})
        setattr(event, 'desc', desc)
        # Explicitly make it none
        event.desc.worker = None

        try:
            controller.poll_event(event)
        except AssertionError as aerr:
            if aerr.message == "No spacing specified for polling":
                self.assertTrue(True)
                return

        # self.assertTrue(False)
        self.assertTrue(True)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_poll_event_with_no_handler(self, mock_compress):
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        event = controller.create_event(
            id='POLL_EVENT_WITHOUT_HANDLER', data='NO_DATA')

        # Update descriptor
        desc = nfp_event.EventDesc(**{})
        setattr(event, 'desc', desc)
        # Explicitly make it none
        event.desc.worker = None

        try:
            controller.poll_event(event, spacing=1)
        except AssertionError as aerr:
            if "No poll handler found for event" in aerr.message:
                self.assertTrue(True)
                return

        self.assertTrue(False)

    @mock.patch(
        'gbpservice.nfp.core.manager.NfpResourceManager._event_acked')
    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress')
    def test_event_ack_from_worker(self, mock_event_acked, mock_compress):
        mock_event_acked.side_effect = self._mocked_event_ack
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        # Check if 1 worker is added to manager
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 1)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

        wait_obj = multiprocessing.Event()
        setattr(controller, 'event_ack_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'event_ack_handler_cb_obj', wait_obj)
        event = controller.create_event(
            id='TEST_EVENT_ACK_FROM_WORKER', data='NO_DATA')
        controller.post_event(event)
        controller._manager.manager_run()

        # wait for event to be acked
        controller.event_ack_wait_obj.wait(1)
        called = controller.event_ack_wait_obj.is_set()
        self.assertTrue(called)

        # Check if event handler callback is invoked
        controller.event_ack_handler_cb_obj.wait(1)
        called = controller.event_ack_handler_cb_obj.is_set()
        self.assertTrue(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress'
    )
    def test_post_event_from_worker(self, mock_compress):
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        # Check if 1 worker is added to manager
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 1)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

        wait_obj = multiprocessing.Event()
        setattr(controller, 'post_event_worker_wait_obj', wait_obj)
        event = controller.create_event(
            id='TEST_POST_EVENT_FROM_WORKER', data='NO_DATA')
        worker_process = controller._worker_process.values()[0]
        worker_process.worker.controller.post_event(event)

        controller._manager.manager_run()

        # Check if event handler callback is invoked
        controller.post_event_worker_wait_obj.wait(1)
        called = controller.post_event_worker_wait_obj.is_set()
        self.assertTrue(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress'
    )
    def test_poll_event_from_worker(self, mock_compress):
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        # Check if 1 worker is added to manager
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 1)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_worker_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_poll_wait_obj', wait_obj)

        event = controller.create_event(
            id='TEST_POLL_EVENT_FROM_WORKER', data='NO_DATA')
        worker_process = controller._worker_process.values()[0]
        worker_process.worker.controller.post_event(event)

        controller._manager.manager_run()

        # Check if event handler callback is invoked
        controller.poll_event_worker_wait_obj.wait(1)
        called = controller.poll_event_worker_wait_obj.is_set()
        self.assertTrue(called)

        time.sleep(1)
        # controller.poll()

        controller.poll_event_poll_wait_obj.wait(1)
        called = controller.poll_event_poll_wait_obj.is_set()
        self.assertTrue(called)

    @mock.patch(
        'gbpservice.nfp.core.controller.NfpController.compress'
    )
    def test_poll_event_cancelled_from_worker(self, mock_compress):
        mock_compress.side_effect = self.mocked_compress
        conf = oslo_config.CONF
        conf.nfp_modules_path = NFP_MODULES_PATH
        controller = nfp_controller.NfpController(conf, singleton=False)
        self.controller = controller
        nfp_controller.load_nfp_modules(conf, controller)
        # Mock launching of a worker
        controller.launch(1)
        controller._update_manager()
        self.controller = controller

        # Check if 1 worker is added to manager
        pids = controller._manager._resource_map.keys()
        self.assertTrue(len(pids) == 1)
        self.assertTrue(pid in range(8888, 9999) for pid in pids)

        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_worker_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_poll_wait_obj', wait_obj)
        wait_obj = multiprocessing.Event()
        setattr(controller, 'poll_event_poll_cancel_wait_obj', wait_obj)

        event = controller.create_event(
            id='TEST_POLL_EVENT_CANCEL_FROM_WORKER', data='NO_DATA')
        worker_process = controller._worker_process.values()[0]
        worker_process.worker.controller.post_event(event)

        controller._manager.manager_run()

        # Check if event handler callback is invoked
        controller.poll_event_worker_wait_obj.wait(1)
        called = controller.poll_event_worker_wait_obj.is_set()
        self.assertTrue(called)

        time.sleep(1)
        # controller.poll()

        controller.poll_event_poll_wait_obj.wait(1)
        called = controller.poll_event_poll_wait_obj.is_set()
        self.assertTrue(called)

        time.sleep(1)
        # controller.poll()

        controller.poll_event_poll_wait_obj.wait(1)
        called = controller.poll_event_poll_wait_obj.is_set()
        self.assertTrue(called)

        controller.poll_event_poll_cancel_wait_obj.wait(1)
        called = controller.poll_event_poll_cancel_wait_obj.is_set()
        self.assertTrue(called)

if __name__ == '__main__':
    unittest.main()
