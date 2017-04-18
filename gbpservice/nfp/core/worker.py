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

import eventlet
import greenlet
import os
import sys
import time
import traceback

from oslo_service import service as oslo_service

from gbpservice.nfp.core import common as nfp_common
from gbpservice.nfp.core import context
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import watchdog as nfp_watchdog

LOG = nfp_logging.getLogger(__name__)
Service = oslo_service.Service
identify = nfp_common.identify
WATCHDOG = nfp_watchdog.Watchdog

DEFAULT_THREAD_TIMEOUT = (10 * 60)

"""Implements worker process.

    Derives from oslo service.
    Implements the worker functionality.
    Waits for the events from distributor, handles them,
    invokes the registered event handler in a thread.
"""


class NfpWorker(Service):

    def __init__(self, conf, threads=10):
        # REVISIT(mak): Should #threads be a conf ?
        Service.__init__(self, threads=threads)
        # Parent end of duplex pipe
        self.parent_pipe = None
        # Pipe to recv/send messages to distributor
        self.pipe = None
        # Cache of event handlers
        self.controller = None
        self._conf = conf
        self._threads = threads

    def start(self):
        """Service start, runs here till dies.

            When a oslo service is launched, this method
            is invoked.
            Polls for messages from distributor and process
            them.
        """
        # Update the process type in controller.
        self.controller.PROCESS_TYPE = "worker"
        self.controller._pipe = self.pipe
        self.event_handlers = self.controller.get_event_handlers()

        eventlet.spawn_n(self.controller._resending_task)

        while True:
            try:
                event = None
                if self.pipe.poll(0.1):
                    event = self.controller.pipe_recv(self.pipe)
                if event:
                    message = "%s - received event" % (
                        self._log_meta(event))
                    LOG.debug(message)
                    self.controller.decompress(event)
                    self._process_event(event)
            except Exception as e:
                message = "Exception - %s" % (e)
                LOG.error(message)
            # Yeild cpu
            time.sleep(0)

    def _log_meta(self, event=None):
        if event:
            return "(event - %s) - (worker - %d)" % (
                event.identify(), os.getpid())
        else:
            return "(worker - %d)" % (os.getpid())

    def _send_event_ack(self, event):
        # Create new event from existing one
        ack_event = nfp_event.Event(id=event.id)
        ack_event.id = event.id
        desc = nfp_event.EventDesc(**event.desc.__dict__)
        desc.uuid = event.desc.uuid
        desc.flag = nfp_event.EVENT_ACK
        setattr(ack_event, 'desc', desc)
        self.controller.pipe_send(self.pipe, ack_event)

    def _process_event(self, event):
        """Process & dispatch the event.

            Decodes the event type and performs the required
            action.
            Executes the registered event handler in one of the
            thread.
        """
        if event.id == 'RELOAD_CONFIG_FILES':
            self._handle_reload_config_files_event(event)
        elif event.desc.type == nfp_event.SCHEDULE_EVENT:
            eh, _ = (
                self.event_handlers.get_event_handler(
                    event.id, module=event.desc.target))
            self.dispatch(eh.handle_event, event, eh=eh)
        elif event.desc.type == nfp_event.POLL_EVENT:
            self.dispatch(self._handle_poll_event, event)

    def _repoll(self, ret, event, eh):
        if ret.get('poll', False):
            message = ("(event - %s) - repolling event -"
                       "pending times - %d") % (
                event.identify(), event.desc.poll_desc.max_times)
            LOG.debug(message)
            if event.desc.poll_desc.max_times:
                self.controller.poll_event(
                    event,
                    spacing=event.desc.poll_desc.spacing,
                    max_times=event.desc.poll_desc.max_times)
            else:
                message = ("(event - %s) - max timed out,"
                           "calling event_cancelled") % (event.identify())
                LOG.debug(message)
                eh.event_cancelled(event, 'MAX_TIMED_OUT')

    def _handle_poll_event(self, event):
        ret = {'poll': False}
        event.desc.poll_desc.max_times -= 1
        module = event.desc.target
        poll_handler, _ = (
            self.event_handlers.get_poll_handler(event.id, module=module))
        event_handler, _ = (
            self.event_handlers.get_event_handler(event.id, module=module))
        try:
            try:
                ret = poll_handler(event)
            except TypeError:
                ret = poll_handler(event_handler, event)
            if not ret:
                ret = {'poll': True}
        except greenlet.GreenletExit:
            pass
        except Exception as exc:
            message = "Exception - %r" % (exc)
            LOG.error(message)
            ret = self.dispatch_exception(event_handler, event, exc)
            if not ret:
                ret = {'poll': False}

        self._repoll(ret, event, event_handler)

    def _handle_reload_config_files_event(self, event):
        try:
            LOG.debug("Reloading config files")
            self._conf.reload_config_files()
        except Exception as e:
            message = 'Error in reloading config files. Error: %s' % e
            LOG.error(message)

    def _dispatch(self, handler, event, *args, **kwargs):
        event.context['log_context']['namespace'] = event.desc.target
        context.init(event.context)
        try:
            handler(event, *args)
        except greenlet.GreenletExit:
            self.controller.event_complete(event, result='FAILED')
        except Exception as exc:
            # How to log traceback propery ??
            message = "Exception - %r" % (exc)
            LOG.error(message)
            self.dispatch_exception(kwargs.get('eh'), event, exc)
            self.controller.event_complete(event, result="FAILED")
        finally:
            self._send_event_ack(event)

    def dispatch_exception(self, event_handler, event, exception):
        ret = {}
        try:
            ret = event_handler.handle_exception(event, exception)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            message = "Traceback: %s" % traceback.format_exception(
                exc_type, exc_value, exc_traceback)
            LOG.error(message)
        finally:
            return ret

    def thread_done(self, th, watchdog=None):
        if watchdog:
            watchdog.cancel()

    def thread_timedout(self, thread=None):
        if thread:
            eventlet.greenthread.kill(thread.thread)

    def dispatch(self, handler, event, *args, **kwargs):
        if self._threads:
            th = self.tg.add_thread(
                self._dispatch, handler, event, *args, **kwargs)
            message = "%s - (handler - %s) - dispatched to thread " % (
                self._log_meta(), identify(handler))
            LOG.debug(message)
            wd = WATCHDOG(self.thread_timedout,
                          seconds=DEFAULT_THREAD_TIMEOUT, thread=th)
            th.link(self.thread_done, watchdog=wd)
        else:
            try:
                handler(event, *args)
                message = "%s - (handler - %s) - invoked" % (
                    self._log_meta(), identify(handler))
                LOG.debug(message)
                self._send_event_ack(event)
            except Exception as exc:
                message = "Exception from module's event handler - %s" % (exc)
                LOG.error(message)
                self.dispatch_exception(kwargs.get('eh'), event, exc)
