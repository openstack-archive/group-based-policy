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

import sys
import time
import warnings

# Override unnecessary Octavia config import
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v2.haproxy \
    import config
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v2.haproxy.\
    config import cfg
sys.modules['octavia.common.config'] = config
sys.modules['octavia.common.config.cfg'] = cfg

from octavia.amphorae.driver_exceptions import exceptions as driver_except
from octavia.amphorae.drivers.haproxy import rest_api_driver
from octavia.common.jinja.haproxy import jinja_cfg
from oslo_config import cfg
import requests

from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v2.haproxy.\
    local_cert_manager import LocalCertManager
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)
API_VERSION = rest_api_driver.API_VERSION
OCTAVIA_API_CLIENT = rest_api_driver.OCTAVIA_API_CLIENT

CONF = cfg.CONF
CONF.import_group('haproxy_amphora', 'octavia.common.config')


class HaproxyAmphoraLoadBalancerDriver(
        rest_api_driver.HaproxyAmphoraLoadBalancerDriver):

    def __init__(self):
        super(rest_api_driver.HaproxyAmphoraLoadBalancerDriver,
              self).__init__()
        self.client = AmphoraAPIClient()
        self.cert_manager = LocalCertManager()
        self.jinja = jinja_cfg.JinjaTemplater(
            base_amp_path=CONF.haproxy_amphora.base_path,
            base_crt_dir=CONF.haproxy_amphora.base_cert_dir,
            haproxy_template=CONF.haproxy_amphora.haproxy_template)


class AmphoraAPIClient(rest_api_driver.AmphoraAPIClient):
    """Removed SSL verification from original api client"""

    def __init__(self):
        super(AmphoraAPIClient, self).__init__()
        self.session = requests.Session()

    def _base_url(self, ip):
        return "http://{ip}:{port}/{version}/".format(
            ip=ip,
            port=CONF.haproxy_amphora.bind_port,
            version=API_VERSION)

    def request(self, method, amp, path='/', **kwargs):
        LOG.debug("request url %s", path)
        _request = getattr(self.session, method.lower())
        _url = self._base_url(amp.lb_network_ip) + path
        LOG.debug("request url " + _url)
        timeout_tuple = (CONF.haproxy_amphora.rest_request_conn_timeout,
                         CONF.haproxy_amphora.rest_request_read_timeout)
        reqargs = {
            'url': _url,
            'timeout': timeout_tuple, }
        reqargs.update(kwargs)
        headers = reqargs.setdefault('headers', {})

        headers['User-Agent'] = OCTAVIA_API_CLIENT
        # Keep retrying
        for a in range(CONF.haproxy_amphora.connection_max_retries):
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message="A true SSLContext object is not available"
                    )
                    r = _request(**reqargs)
                LOG.debug("Connected to amphora. Response: {resp}".format(
                    resp=r))
                return r
            except (requests.ConnectionError, requests.Timeout):
                LOG.warning("Could not connect to instance. Retrying.")
                time.sleep(CONF.haproxy_amphora.connection_retry_interval)

        LOG.error("Connection retries (currently set to %s) "
                  "exhausted.  The amphora is unavailable.",
                  CONF.haproxy_amphora.connection_max_retries)
        raise driver_except.TimeOutException()
