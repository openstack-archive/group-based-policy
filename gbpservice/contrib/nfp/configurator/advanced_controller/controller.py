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

import oslo_serialization.jsonutils as jsonutils

from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
import pecan
import pika

from gbpservice.nfp.pecan import base_controller

LOG = logging.getLogger(__name__)
n_rpc.init(cfg.CONF)


class Controller(base_controller.BaseController):
    """Implements all the APIs Invoked by HTTP requests.

    Implements following HTTP methods.
        -get
        -post
        -put
    According to the HTTP request received from config-agent this class make
    call/cast to configurator and return response to config-agent

    """

    def __init__(self, method_name):
        try:
            self.method_name = method_name
            self.services = pecan.conf['cloud_services']
            self.rpc_routing_table = {}
            for service in self.services:
                self._entry_to_rpc_routing_table(service)

            configurator_notifications = self.services[0]['notifications']
            self.rmqconsumer = RMQConsumer(configurator_notifications['host'],
                                           configurator_notifications['queue']
                                           )
            super(Controller, self).__init__()
        except Exception as err:
            msg = (
                "Failed to initialize Controller class  %s." %
                str(err).capitalize())
            LOG.error(msg)

    def _entry_to_rpc_routing_table(self, service):
        """Prepares routing table based on the uservice configuration.
           This routing table is used to route the rpcs to all interested
           uservices. Key used for routing is the uservice[apis].

        :param uservice
        e.g uservice = {'service_name': 'configurator',
                        'topic': 'configurator',
                        'reporting_interval': '10',  # in seconds
                        'apis': ['CONFIGURATION', 'EVENT']
                        }
        Returns: None

        Prepares: self.rpc_routing_table
            e.g self.rpc_routing_table = {'CONFIGURATION': [rpc_client, ...],
                                          'EVENT': [rpc_client, ...]
                                          }
        """
        for api in service['apis']:
            if api not in self.rpc_routing_table:
                self.rpc_routing_table[api] = []

            self.rpc_routing_table[api].append(CloudService(**service))

    @pecan.expose(method='GET', content_type='application/json')
    def get(self):
        """Method of REST server to handle request get_notifications.

        This method send an RPC call to configurator and returns Notification
        data to config-agent

        Returns: Dictionary that contains Notification data

        """

        try:
            if self.method_name == 'get_notifications':
                notification_data = self.rmqconsumer.pull_notifications()
                msg = ("NOTIFICATION_DATA sent to config_agent %s"
                       % notification_data)
                LOG.info(msg)
                return jsonutils.dumps(notification_data)

        except Exception as err:
            pecan.response.status = 400
            msg = ("Failed to handle request=%s. Reason=%s."
                   % (self.method_name, str(err).capitalize()))
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    @pecan.expose(method='POST', content_type='application/json')
    def post(self, **body):
        """Method of REST server to handle all the post requests.

        This method sends an RPC cast to configurator according to the
        HTTP request.

        :param body: This method excepts dictionary as a parameter in HTTP
        request and send this dictionary to configurator with RPC cast.

        Returns: None

        """

        try:
            body = None
            if pecan.request.is_body_readable:
                body = pecan.request.json_body

            routing_key = body.pop("routing_key", "CONFIGURATION")
            for uservice in self.rpc_routing_table[routing_key]:
                uservice.rpcclient.cast(self.method_name, body)
                msg = ('Sent RPC to %s' % (uservice.topic))
                LOG.info(msg)

            msg = ("Successfully served HTTP request %s" % self.method_name)
            LOG.info(msg)

        except Exception as err:
            pecan.response.status = 400
            msg = ("Failed to serve HTTP post request %s %s."
                   % (self.method_name, str(err).capitalize()))
            # extra_import = ("need to remove this import %s" % config)
            # LOG.debug(extra_import)
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    @pecan.expose(method='PUT', content_type='application/json')
    def put(self, **body):
        """Method of REST server to handle all the put requests.

        This method sends an RPC cast to configurator according to the
        HTTP request.

        :param body: This method excepts dictionary as a parameter in HTTP
        request and send this dictionary to configurator with RPC cast.

        Returns: None

        """
        try:
            body = None
            if pecan.request.is_body_readable:
                body = pecan.request.json_body

            routing_key = body.pop("routing_key", "CONFIGURATION")
            for uservice in self.rpc_routing_table[routing_key]:
                uservice.rpcclient.cast(self.method_name, body)
                msg = ('Sent RPC to %s' % (uservice.topic))
                LOG.info(msg)
            msg = ("Successfully served HTTP request %s" % self.method_name)
            LOG.info(msg)

        except Exception as err:
            pecan.response.status = 400
            msg = ("Failed to serve HTTP put request %s %s."
                   % (self.method_name, str(err).capitalize()))
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    def _format_description(self, msg):
        """This methgod formats error description.

        :param msg: An error message that is to be formatted

        Returns: error_data dictionary
        """

        error_data = {'failure_desc': {'msg': msg}}
        return error_data


class RPCClient(object):
    """Implements call/cast methods used in REST Controller.

    Implements following methods.
        -call
        -cast
    This class send an RPC call/cast to configurator according to the data sent
    by Controller class of REST server.

     """

    API_VERSION = '1.0'

    def __init__(self, topic):

        self.topic = topic
        target = oslo_messaging.Target(
            topic=self.topic,
            version=self.API_VERSION)
        self.client = n_rpc.get_client(target)

    def call(self, method_name):
        """Method for sending call request on behalf of REST Controller.

        This method sends an RPC call to configurator.

        Returns: Notification data sent by configurator.

        """
        cctxt = self.client.prepare(version=self.API_VERSION,
                                    topic=self.topic)
        return cctxt.call(self, method_name)

    def cast(self, method_name, request_data):
        """Method for sending cast request on behalf of REST Controller.

        This method sends an RPC cast to configurator according to the
        method_name passed by COntroller class of REST server.

        :param method_name:method name can be any of the following.


        Returns: None.

        """
        cctxt = self.client.prepare(version=self.API_VERSION,
                                    topic=self.topic)

        return cctxt.cast(self,
                          method_name,
                          request_data=request_data)

    def to_dict(self):
        """This function return empty dictionary.

        For making RPC call/cast it internally requires context class that
        contains to_dict() function. Here we are sending context inside
        request data so we are passing class itself as a context that
        contains to_dict() function.

        Returns: Dictionary.

        """
        return {}


class CloudService(object):
    """ CloudService keeps all information of uservice along with initialized
        RPCClient object using which rpc is routed to over the cloud service.
    """

    def __init__(self, **kwargs):
        self.service_name = kwargs.get('service_name')
        self.topic = kwargs.get('topic')
        self.reporting_interval = kwargs.get('reporting_interval')
        self.rpcclient = RPCClient(topic=self.topic)


class RMQConsumer(object):
    """RMQConsumer for over the cloud services.

    This class access rabbitmq's 'configurator-notifications' queue
    to pull all the notifications came from over the cloud services.

    """

    def __init__(self, rabbitmq_host, queue):
        self.rabbitmq_host = rabbitmq_host
        self.queue = queue
        self.create_connection()

    def create_connection(self):
        try:
            self.connection = pika.BlockingConnection(
                                    pika.ConnectionParameters
                                    (host=self.rabbitmq_host))
        except Exception as e:
            msg = ("Failed to create rmq connection %s" % (e))
            LOG.error(msg)

    def _fetch_data_from_wrapper_strct(self, oslo_notifications):
        notifications = []
        for oslo_notification_data in oslo_notifications:
            notification_data = jsonutils.loads(
                oslo_notification_data["oslo.message"]
            )["args"]["notification_data"]
            notifications.extend(notification_data)
        return notifications

    def pull_notifications(self):
        notifications = []
        msgs_acknowledged = False
        try:
            self.channel = self.connection.channel()
            self.queue_declared = self.channel.queue_declare(queue=self.queue,
                                                             durable=True)
            self.channel.queue_bind(self.queue, 'openstack')
            pending_msg_count = self.queue_declared.method.message_count
            log = ('[notifications queue:%s, pending notifications:%s]'
                   % (self.queue, pending_msg_count))
            LOG.info(log)
            for i in range(pending_msg_count):
                method, properties, body = self.channel.basic_get(self.queue)
                notifications.append(jsonutils.loads(body))

            # Acknowledge all messages delivery
            if pending_msg_count > 0:
                self.channel.basic_ack(delivery_tag=method.delivery_tag,
                                       multiple=True)
                msgs_acknowledged = True

            self.channel.close()
            return self._fetch_data_from_wrapper_strct(notifications)

        except pika.exceptions.ConnectionClosed:
            msg = ("Caught ConnectionClosed exception.Creating new connection")
            LOG.error(msg)
            self.create_connection()
            return self._fetch_data_from_wrapper_strct(notifications)
        except pika.exceptions.ChannelClosed:
            msg = ("Caught ChannelClosed exception.")
            LOG.error(msg)
            if msgs_acknowledged is False:
                return self.pull_notifications()
            else:
                return self._fetch_data_from_wrapper_strct(notifications)
