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


from gbpservice._i18n import _LI
from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

from neutron.common import rpc as n_rpc
from oslo_config import cfg
import oslo_messaging as messaging

n_rpc.init(cfg.CONF)

LOG = nfp_logging.getLogger(__name__)


class AgentBaseRPCManager(object):
    """Implements base class for all service agents.

    Common methods for service agents are implemented in this class.
    Configurator module invokes these methods through the service
    agent's child class instance.

    """

    def __init__(self, sc, conf):
        self.sc = sc
        self.conf = conf

    def validate_request(self, sa_req_list, notification_data):
        """Preliminary validation of function input.

        :param sa_req_list: List of data blobs prepared by de-multiplexer
        for service agents processing.
        :param notification_data: Notification blobs prepared by the service
        agents after processing requests blobs. Each request blob will have
        a corresponding notification blob.

        Returns: True if validation passes. False if validation fails.

        """

        if (isinstance(sa_req_list, list) and
                isinstance(notification_data, dict)):
            return True
        else:
            return False

    def get_diff_of_dict(self, old_dict, new_dict):
        """Getting difference between two dict.

        :param Two dictionary

        Returns: Two dictionary which has different values for same keys.

        """
        diff_values = []
        new_val = {}
        old_val = {}
        for key in new_dict:
            if old_dict.get(key) != new_dict.get(key):
                diff_values.append(key)

        for value in diff_values:
            if value == 'description':
                pass
            else:
                new_val[value] = new_dict.get(value)
                old_val[value] = old_dict.get(value)
        return old_val, new_val

    def process_request(self, sa_req_list, notification_data):
        """Forwards the RPC message from configurator to service agents.

        Checks if the request message contains multiple data blobs. If multiple
        data blobs are found, a batch event is generated otherwise a single
        event.

        :param sa_req_list: List of data blobs prepared by de-multiplexer
        for service agents processing.
        :param notification_data: Notification blobs prepared by the service
        agents after processing requests blobs. Each request blob will have
        a corresponding notification blob.

        Returns: None

        """

        # In case of malformed input, send failure notification
        if not self.validate_request(sa_req_list, notification_data):
            # REVISIT(JAGADISH): Need to send failure notification
            return

        # Multiple request data blobs needs batch processing. Send batch
        # processing event or do direct processing of single request data blob
        if (len(sa_req_list) > 1):
            LOG.info(_LI("Creating event PROCESS BATCH"))
            args_dict = {
                'sa_req_list': sa_req_list,
                'notification_data': notification_data
            }
            ev = self.sc.new_event(id=const.EVENT_PROCESS_BATCH,
                                   data=args_dict, key=None)
            self.sc.post_event(ev)
        else:
            agent_info = sa_req_list[0]['agent_info']
            # Renaming the neutron context in resource data of *aaS to context.
            # Adding agent_info which contains information required for
            # demux and response data in agent to neutron_context in *aaS
            if not sa_req_list[0]['is_generic_config'] and not (
                    agent_info['resource'] in const.NFP_SERVICE_LIST):
                # Here, the neutron context is overloaded with agent_info
                # dict which contains the API context in addition to other
                # fields like service type, service vendor, resource etc.
                # The agent_info dict is constructed inside the demuxer library
                sa_req_list[0]['resource_data']['neutron_context'].update(
                    {'agent_info': agent_info})
                # When calling the *aaS or NFPService agents, the
                # "neutron context" passed inside the resource data is
                # renamed to "context"
                sa_req_list[0]['resource_data']['context'] = sa_req_list[0][
                    'resource_data'].pop('neutron_context')
                getattr(self, sa_req_list[0]['method'])(
                    **sa_req_list[0]['resource_data'])
            else:
                sa_req_list[0]['agent_info'].update(
                    {'notification_data': notification_data})
                getattr(self, sa_req_list[0]['method'])(
                    agent_info, sa_req_list[0]['resource_data'])


class AgentBaseNotification(object):
    """Enqueues notification event into notification queue

    Responses from the REST calls made to the VM are fed to under the
    cloud components using this notification handle.
    """

    API_VERSION = '1.0'

    def __init__(self, sc):
        self.sc = sc
        self.topic = const.NOTIFICATION_QUEUE
        target = messaging.Target(topic=self.topic,
                                  version=self.API_VERSION)
        self.client = n_rpc.get_client(target)
        self.cctxt = self.client.prepare(version=self.API_VERSION,
                                         topic=self.topic)

    def _notification(self, data):
        """Enqueues notification event into const.NOTIFICATION_QUEUE

        These events are enqueued into notification queue and are retrieved
        when get_notifications() API lands on configurator.

        :param data: Event data blob

        Returns: None

        """
        self.cctxt.cast(self, 'send_notification', notification_data=[data])

    def to_dict(self):
        return {}


class AgentBaseEventHandler(nfp_api.NfpEventHandler):
    """ Super class for all agents to handle batch events.

    """

    def __init__(self, sc, drivers, rpcmgr):
        self.sc = sc
        self.drivers = drivers
        self.rpcmgr = rpcmgr
        self.notify = AgentBaseNotification(self.sc)

    def process_batch(self, ev):
        """Processes a request with multiple data blobs.

        Configurator processes the request with multiple data blobs and sends
        a list of service information to be processed. This function goes
        through the list of service information and invokes specific service
        driver methods. After processing each request data blob, notification
        data blob is prepared.

        :param ev: Event instance that contains information of event type and
        corresponding event data to be processed.

        """

        # Get service agent information list and notification data list
        # from the event data
        sa_req_list = ev.data.get('sa_req_list')
        notification_data = ev.data.get('notification_data')

        for request in sa_req_list:
            try:
                # Process the first data blob from the request list.
                # Get necessary parameters needed for driver method invocation.
                method = request['method']
                is_generic_config = request['is_generic_config']
                resource_data = request['resource_data']
                agent_info = request['agent_info']
                resource = agent_info['resource']
                # agent_info contains the API context.
                context = agent_info['context']
                service_vendor = agent_info['service_vendor']
                service_type = agent_info['resource_type']
                service_feature = agent_info['service_feature']
                if not is_generic_config:
                    sa_req_list[0]['resource_data']['context'] = sa_req_list[
                        0]['resource_data'].pop('neutron_context')

                # Get the service driver and invoke its method
                driver = self._get_driver(service_type, service_vendor,
                                          service_feature)

                # Service driver should return "success" on successful API
                # processing. All other return values and exceptions are
                # treated as failures.
                if is_generic_config:
                    result = getattr(driver, method)(context, resource_data)
                else:
                    result = getattr(driver, method)(**resource_data)
                success = True if result == 'SUCCESS' else False
            except Exception as err:
                result = ("Failed to process %s request. %s" %
                          (method, str(err).capitalize()))
                success = False
            finally:
                # Prepare success notification and populate notification
                # data list
                if result in const.SUCCESS:
                    data = {'status_code': const.SUCCESS}
                else:
                    data = {'status_code': const.FAILURE,
                            'error_msg': result}

                msg = {'info': {'service_type': service_type,
                                'context': context},
                       'notification': [{'resource': resource,
                                         'data': data}]
                       }
                # If the data processed is first one, then prepare notification
                # dict. Otherwise, append the notification to the kwargs list.
                # Whether it is a data batch or single data blob request,
                # notification generated will be single dictionary. In case of
                # batch, multiple notifications are sent in the kwargs list.
                if not notification_data:
                    notification_data.update(msg)
                else:
                    data = {'resource': resource,
                            'data': data}
                    notification_data['notification'].append(data)

            if not success:
                self.notify._notification(notification_data)
                raise Exception(msg)

        self.notify._notification(notification_data)


def init_agent_complete(cm, sc, conf):
    """Placeholder method to satisfy configurator module agent loading."""
    pass


def init_agent(cm, sc, conf):
    """Placeholder method to satisfy configurator module agent loading."""
    pass
