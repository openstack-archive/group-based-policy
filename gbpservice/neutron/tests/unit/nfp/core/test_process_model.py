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

from gbpservice.nfp.core import cfg as nfp_config
from gbpservice.nfp.core import controller
import mock
import multiprocessing as multiprocessing
# from neutron.agent.common import config as n_config
import os
from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
import random
import sys
import time
import unittest
LOG = oslo_logging.getLogger(__name__)

oslo_config.CONF.register_opts(nfp_config.OPTS)
oslo_config.CONF.workers = 1

service1 = {
    'id': 'sc2f2b13-e284-44b1-9d9a-2597e216271a',
    'tenant': '40af8c0695dd49b7a4980bd1b47e1a1b',
    'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e2161c',
    'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216561d',
    'vip_id': '13948da4-8dd9-44c6-adef-03a6d8063daa',
    'service_vendor': 'haproxy',
    'service_type': 'loadbalancer',
    'ip': '192.168.20.199'
}
service2 = {
    'id': 'sc2f2b13-e284-44b1-9d9a-2597e216272a',
    'tenant': '40af8c0695dd49b7a4980bd1b47e1a2b',
    'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e216562c',
    'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216562d',
    'mac_address': 'fa:16:3e:3f:93:05',
    'service_vendor': 'vyos',
    'service_type': 'firewall',
    'ip': '192.168.20.197'
}


class Test_Process_Model(unittest.TestCase):

    @mock.patch(
        'gbpservice.nfp.core.controller.Controller._pipe_send'
    )
    def test_event_create(self, mock_put):
        event = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT1', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(event)
        self.assertIsNotNone(event.desc.worker_attached)
        pipe = self.sc._worker_pipe_map[event.desc.worker_attached]
        mock_put.assert_called_once_with(pipe, event)

    @mock.patch(
        'gbpservice.nfp.core.controller.Controller._pipe_send'
    )
    def test_events_with_same_binding_keys(self, mock_put):
        event1 = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT1', data=service1,
            binding_key=service1['tenant'],
            key=service1['id'], serialize=True
        )
        event2 = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT2', data=service1,
            binding_key=service1['tenant'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(event1)
        self.sc.post_event(event2)
        self.assertIsNotNone(event1.desc.worker_attached)
        self.assertIsNotNone(event2.desc.worker_attached)
        self.assertEqual(
            event1.desc.worker_attached, event2.desc.worker_attached)
        self.assertEqual(mock_put.call_count, 2)

    @mock.patch(
        'gbpservice.nfp.core.controller.Controller._pipe_send'
    )
    def __test_events_with_no_binding_key(self, mock_put):
        event1 = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT1', data=service1,
            key=service1['id'], serialize=False
        )
        event2 = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT2', data=service1,
            key=service1['id'], serialize=False
        )
        self.sc.post_event(event1)
        self.sc.post_event(event2)
        self.assertIsNotNone(event1.desc.worker_attached)
        self.assertIsNotNone(event2.desc.worker_attached)
        self.assertNotEqual(
            event1.desc.worker_attached, event2.desc.worker_attached)
        self.assertEqual(mock_put.call_count, 2)

    @mock.patch(
        'gbpservice.nfp.core.controller.Controller._pipe_send'
    )
    def test_loadbalancing_events(self, mock_put):
        event1 = self.sc.new_event(
            id='SERVICE_CREATE', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=False
        )
        self.sc.post_event(event1)
        count = 0
        for worker in self.sc._workers:
            if event1.desc.worker_attached == worker[0].pid:
                rrid_event1 = count
                break
            count = count + 1

        event2 = self.sc.new_event(
            id='SERVICE_CREATE', data=service2,
            binding_key=service2['id'],
            key=service2['id'], serialize=False
        )
        self.sc.post_event(event2)
        if rrid_event1 + 1 == len(self.sc._workers):
            self.assertEqual(event2.desc.worker_attached,
                             self.sc._workers[0][0].pid)
        else:
            self.assertEqual(
                event2.desc.worker_attached,
                self.sc._workers[rrid_event1 + 1][0].pid
            )
        self.assertEqual(mock_put.call_count, 2)

    @mock.patch('gbpservice.nfp.core.controller.EventSequencer.add')
    def test_serialize_events_serialize_false(self, mock_sequencer):
        event1 = self.mock_event(
            id='SERVICE_CREATE', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=False,
            worker_attached=self.sc._workers[0][0].pid
        )
        sequenced_event1 = self.sc.sequencer_put_event(event1)
        self.assertEqual(mock_sequencer.call_count, 0)
        self.assertEqual(sequenced_event1, event1)

    @mock.patch('gbpservice.nfp.core.controller.EventSequencer.add')
    def test_serialize_events_serialze_true(self, mock_sequencer):
        event1 = self.mock_event(
            id='SERVICE_CREATE', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True,
            worker_attached=self.sc._workers[0][0].pid
        )
        mock_sequencer.return_value = True
        sequenced_event1 = self.sc.sequencer_put_event(event1)
        mock_sequencer.assert_called_once_with(event1)
        self.assertEqual(sequenced_event1, None)
        mock_sequencer.return_value = False
        sequenced_event1 = self.sc.sequencer_put_event(event1)
        self.assertEqual(sequenced_event1, event1)

    @mock.patch('gbpservice.nfp.core.controller.EventSequencer')
    def test_EventSequencer_add(self, mocked_sequencer):
        event1 = self.mock_event(
            id='SERVICE_CREATE', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True,
            worker_attached=self.sc._workers[0][0].pid
        )
        mocked_sequencer_map = mock.Mock()
        mocked_sequencer._sequencer_map = mocked_sequencer_map
        mocked_sequencer_map = {}
        self.assertFalse(self.EventSequencer.add(event1))
        mocked_sequencer_map = self.create_sequencer_map(
            self.sc._workers[0][0].pid,
            service1['id']
        )
        self.assertTrue(self.EventSequencer.add(event1))

    def __test_handle_event_on_queue(self):
        event1 = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT1', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(event1)
        time.sleep(10)
        handle_event_invoked = self.sc._event.wait(1)
        self.assertTrue(handle_event_invoked)

    def __test_poll_handle_event(self):
        ev = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT2', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(ev)
        time.sleep(30)
        poll_handle_event_invoked = self.sc._event.wait(1)
        self.assertTrue(poll_handle_event_invoked)

    def __test_poll_event_maxtimes(self):
        ev = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT3', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(ev)
        time.sleep(80)
        event_polled_maxtimes = self.sc._event.wait(1)
        self.assertTrue(event_polled_maxtimes)

    def __test_poll_event_done(self):
        ev = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT4', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True
        )
        self.sc.post_event(ev)
        time.sleep(30)
        sc_event_set = self.sc._event.wait(1)
        self.assertFalse(sc_event_set)

    def __test_periodic_method_withspacing_10(self):
        ev = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT5', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True)
        self.sc.post_event(ev)
        time.sleep(30)
        called_with_correct_spacing = self.sc._event.wait(1)
        self.assertTrue(called_with_correct_spacing)

    def __test_periodic_method_withspacing_20(self):
        ev = self.sc.new_event(
            id='DUMMY_SERVICE_EVENT6', data=service1,
            binding_key=service1['id'],
            key=service1['id'], serialize=True)
        self.sc.post_event(ev)
        time.sleep(30)
        called_with_correct_spacing = self.sc._event.wait(1)
        self.assertTrue(called_with_correct_spacing)

    def __test_worker_process_initilized(self):
        workers = self.sc._workers
        test_process = multiprocessing.Process()
        self.assertEqual(len(workers), 4)
        for worker in workers:
            self.assertTrue(type(worker[0]), type(test_process))

    def create_sequencer_map(self, worker_attached, binding_key):
        sequencer_map = {}
        sequencer_map[worker_attached] = {}
        mapp = sequencer_map[worker_attached]
        mapp[binding_key] = {'in_use': True, 'queue': []}
        return sequencer_map

    def mock_event(self, **kwargs):
        event = self.sc.new_event(**kwargs)
        event.desc.poll_event = \
            kwargs.get('poll_event') if 'poll_event' in kwargs else None
        event.desc.worker_attached = \
            kwargs.get(
                'worker_attached') if 'worker_attached' in kwargs else None
        event.last_run = kwargs.get(
            'last_run') if 'last_run' in kwargs else None
        event.max_times = kwargs.get(
            'max_times') if 'max_times' in kwargs else -1
        return event

    def modules_import(self):
        modules = []
        modules_dir = 'gbpservice.neutron.tests.unit.nfp.core.EventHandler'
        base_module = __import__(
            modules_dir,
            globals(), locals(),
            ['modules'], -1
        )
        modules_dir_test = base_module.__path__[0]
        syspath = sys.path
        sys.path = [modules_dir_test] + syspath
        try:
            files = os.listdir(modules_dir_test)
        except OSError:
            LOG.error(_("Failed to read files.."))
            files = []
        for fname in files:
            if fname.endswith(".py") and fname != '__init__.py':
                module = __import__(
                    modules_dir,
                    globals(), locals(),
                    [fname[:-3]], -1
                )
                modules += [__import__(fname[:-3])]
        sys.path = syspath
        return modules

    def setUp(self):
        self.sc = controller.Controller(oslo_config.CONF, [])
        self.EventSequencer = controller.EventSequencer(self.sc)
        self.sc._init()
        # Mock the worker pid
        worker = self.sc._workers[0]
        multiprocessing.Process.pid = random.randint(2034, 2134)
        self.sc._worker_pipe_map[worker[0].pid] = worker[1]
        return
        '''
        oslo_config.CONF.register_opts(nfp_config.OPTS)
        modules = self.modules_import()
        n_config.register_interface_driver_opts_helper(oslo_config.CONF)
        n_config.register_agent_state_opts_helper(oslo_config.CONF)
        n_config.register_root_helper(oslo_config.CONF)
        oslo_config.CONF.workers = 4
        service1 = {
            'id': 'sc2f2b13-e284-44b1-9d9a-2597e216271a',1
            'tenant': '40af8c0695dd49b7a4980bd1b47e1a1b',
            'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e2161c',
            'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216561d',
            'vip_id': '13948da4-8dd9-44c6-adef-03a6d8063daa',
            'service_vendor': 'haproxy',
            'service_type': 'loadbalancer',
            'ip': '192.168.20.199'
        }
        service2 = {
            'id': 'sc2f2b13-e284-44b1-9d9a-2597e216272a',
            'tenant': '40af8c0695dd49b7a4980bd1b47e1a2b',
            'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e216562c',
            'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216562d',
            'mac_address': 'fa:16:3e:3f:93:05',
            'service_vendor': 'vyos',
            'service_type': 'firewall',
            'ip': '192.168.20.197'
        }
        n_config.setup_logging()
        self._conf = oslo_config.CONF
        self._modules = modules
        self.sc = controller.Controller(oslo_config.CONF, modules)
        self.EventSequencer = controller.EventSequencer(self.sc)
        self.sc.start()
        '''
if __name__ == '__main__':
    unittest.main()
