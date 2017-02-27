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

from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
from oslo_utils import importutils

from gbpservice.nfp.core import context

import logging
import os
import sys

EVENT = 50
logging.addLevelName(EVENT, "EVENT")
CONF = oslo_config.CONF


if hasattr(sys, 'frozen'):  # support for py2exe
    _srcfile = "logging%s__init__%s" % (os.sep, __file__[-4:])
elif __file__[-4:].lower() in ['.pyc', '.pyo']:
    _srcfile = __file__[:-4] + '.py'
else:
    _srcfile = __file__
_srcfile = os.path.normcase(_srcfile)


def currentframe():
    """Return the frame object for the caller's stack frame."""
    try:
        raise Exception
    except Exception:
        return sys.exc_info()[2].tb_frame.f_back


if hasattr(sys, '_getframe'):
    currentframe = lambda: sys._getframe(3)


class NfpLogAdapter(oslo_logging.KeywordArgumentAdapter):

    def event(self, msg, *args, **kwargs):
        self.log(EVENT, msg, *args, **kwargs)


class WrappedLogger(logging.Logger):

    def __init__(self, name):
        logging.Logger.__init__(self, name)

    def findCaller(self):
        """
        Find the stack frame of the caller so that we can note the source
        file name, line number and function name.
        """
        f = currentframe()
        # On some versions of IronPython, currentframe() returns None if
        # IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back
            if f.f_back:
                f = f.f_back
        rv = "(unknown file)", 0, "(unknown function)"
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename == _srcfile:
                f = f.f_back
                continue
            rv = (co.co_filename, f.f_lineno, co.co_name)
            break
        return rv

    def _get_nfp_msg(self, msg):
        nfp_context = context.get()
        log_context = nfp_context['log_context']
        if log_context:
            ctxt = "[%s] [NFI:%s] [NFD:%s]" % (log_context.get(
                'meta_id', '-'),
                log_context.get('nfi_id', '-'),
                log_context.get('nfd_id', '-'))
            msg = "%s %s" % (ctxt, msg)

        component = ''
        if hasattr(CONF, 'module'):
            component = CONF.module
        msg = "[%s] %s" % (component, msg)
        return msg

    def makeRecord(self, name, level, fn,
                   lno, msg, args, exc_info, func=None, extra=None):
        # Prefix log meta id with every log if project is 'nfp'
        if extra and extra.get('project') == 'nfp':
            msg = self._get_nfp_msg(msg)
        return super(WrappedLogger, self).makeRecord(
            name, level, fn, lno, msg,
            args, exc_info, func=func, extra=extra)


def init_logger(logger_class):
    logging.setLoggerClass(importutils.import_class(logger_class))


def getLogger(name, **kwargs):
    kwargs.update(project='nfp')
    logger = NfpLogAdapter(logging.getLogger(name),
                           kwargs)
    return logger
