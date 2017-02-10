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

import subprocess

import netaddr
import netifaces
from oslo_log._i18n import _LE
from oslo_log._i18n import _LI
from oslo_log import log as logging
import oslo_serialization.jsonutils as jsonutils
import pecan
from pecan import rest
import time
import yaml

LOG = logging.getLogger(__name__)
SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

notifications = []
FW_SCRIPT_PATH = ("/usr/local/lib/python2.7/dist-packages/" +
                  "gbpservice/tests/contrib/nfp_service/" +
                  "reference_configurator/scripts/configure_fw_rules.py")


class Controller(rest.RestController):

    """Implements all the APIs Invoked by HTTP requests.

    Implements following HTTP methods.
        -get
        -post

    """
    def __init__(self, method_name):
        try:
            self.method_name = "network_function_device_notification"
            super(Controller, self).__init__()
            ip_a = subprocess.Popen('ifconfig -a', shell=True,
                                    stdout=subprocess.PIPE).stdout.read()
            out1 = subprocess.Popen('dhclient eth0', shell=True,
                                    stdout=subprocess.PIPE).stdout.read()
            out2 = subprocess.Popen('dhclient eth0', shell=True,
                                    stdout=subprocess.PIPE).stdout.read()
            output = "%s\n%s\n%s" % (ip_a, out1, out2)
            LOG.info(_LI("Dhclient on eth0, result: %(output)s") %
                     {'output': output})
        except Exception as err:
            msg = (
                "Failed to initialize Controller class  %s." %
                str(err).capitalize())
            LOG.error(msg)

    def _push_notification(self, context,
                           notification_data, service_type):
        response = {'info': {'service_type': service_type,
                             'context': context},
                    'notification': notification_data
                    }

        notifications.append(response)

    @pecan.expose(method='GET', content_type='application/json')
    def get(self):
        """Method of REST server to handle request get_notifications.

        This method send an RPC call to configurator and returns Notification
        data to config-agent

        Returns: Dictionary that contains Notification data

        """

        global notifications
        try:
            notification_data = jsonutils.dumps(notifications)
            msg = ("NOTIFICATION_DATA sent to config_agent %s"
                   % notification_data)
            LOG.info(msg)
            notifications = []
            return notification_data
        except Exception as err:
            pecan.response.status = 500
            msg = ("Failed to get notification_data  %s."
                   % str(err).capitalize())
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    @pecan.expose(method='POST', content_type='application/json')
    def post(self, **body):
        try:
            body = None
            if pecan.request.is_body_readable:
                body = pecan.request.json_body

            msg = ("Request data:: %s" % body)
            LOG.debug(msg)

            config_datas = body['config']
            service_type = body['info']['service_type']
            notification_data = []

            for config_data in config_datas:
                try:
                    resource = config_data['resource']
                    if resource == 'healthmonitor':
                        self._configure_healthmonitor(config_data)
                    elif resource == 'interfaces':
                        self._configure_interfaces(config_data)
                    elif resource == 'routes':
                        self._add_routes(config_data)
                    elif (config_data['resource'] in ['ansible', 'heat',
                                                      'custom_json']):
                        self._apply_user_config(config_data)
                    else:
                        status_msg = 'Unsupported resource'
                        notification_data.append(
                                {'resource': resource,
                                 'data': {'status_code': FAILED,
                                          'status_msg': status_msg}})
                    notification_data.append(
                                {'resource': config_data['resource'],
                                 'data': {'status_code': SUCCESS}})
                except Exception as ex:
                    notification_data.append(
                                {'resource': resource,
                                 'data': {'status_code': FAILED,
                                          'status_msg': str(ex)}})

            context = body['info']['context']
            self._push_notification(context, notification_data,
                                    service_type)
        except Exception as err:
            pecan.response.status = 500
            msg = ("Failed to serve HTTP post request %s %s."
                   % (self.method_name, str(err).capitalize()))
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    def _format_description(self, msg):
        """This method formats error description.

        :param msg: An error message that is to be formatted

        Returns: error_data dictionary
        """

        return {'failure_desc': {'msg': msg}}

    def _configure_healthmonitor(self, config_data):
        LOG.info(_LI("Configures healthmonitor with configuration "
                 "data : %(healthmonitor_data)s ") %
                 {'healthmonitor_data': config_data})

    def _configure_interfaces(self, config_data):
        out1 = subprocess.Popen('sudo dhclient eth1', shell=True,
                                stdout=subprocess.PIPE).stdout.read()
        out2 = subprocess.Popen('sudo dhclient eth2', shell=True,
                                stdout=subprocess.PIPE).stdout.read()
        out3 = subprocess.Popen('cat /etc/network/interfaces', shell=True,
                                stdout=subprocess.PIPE).stdout.read()
        output = "%s\n%s\n%s" % (out1, out2, out3)
        LOG.info(_LI("Dhclient on eth0, result: %(initial_data)s") %
                 {'initial_data': output})
        LOG.info(_LI("Configures interfaces with configuration "
                 "data : %(interface_data)s ") %
                 {'interface_data': config_data})

    def get_source_cidrs_and_gateway_ip(self, route_info):
        nfds = route_info['resource_data']['nfds']
        source_cidrs = []
        for nfd in nfds:
            for network in nfd['networks']:
                source_cidrs.append(network['cidr'])
                if network['type'] == 'stitching':
                    gateway_ip = network['gw_ip']
        return source_cidrs, gateway_ip

    def _add_routes(self, route_info):
        LOG.info(_LI("Configuring routes with configuration "
                 "data : %(route_data)s ") %
                 {'route_data': route_info['resource_data']})
        source_cidrs, gateway_ip = self.get_source_cidrs_and_gateway_ip(
                                        route_info)
        default_route_commands = []
        for cidr in source_cidrs:
            try:
                source_interface = self._get_if_name_by_cidr(cidr)
            except Exception:
                raise Exception("Some of the interfaces do not have "
                                "IP Address")
            try:
                interface_number_string = source_interface.split("eth", 1)[1]
            except IndexError:
                LOG.error(_LE("Retrieved wrong interface %(interface)s for "
                          "configuring routes") %
                          {'interface': source_interface})
            try:
                routing_table_number = 20 + int(interface_number_string)

                ip_rule_command = "ip rule add from %s table %s" % (
                    cidr, routing_table_number)
                out1 = subprocess.Popen(ip_rule_command, shell=True,
                                        stdout=subprocess.PIPE).stdout.read()
                ip_rule_command = "ip rule add to %s table main" % (cidr)
                out2 = subprocess.Popen(ip_rule_command, shell=True,
                                        stdout=subprocess.PIPE).stdout.read()
                ip_route_command = "ip route add table %s default via %s" % (
                                        routing_table_number, gateway_ip)
                default_route_commands.append(ip_route_command)
                output = "%s\n%s" % (out1, out2)
                LOG.info(_LI("Static route configuration result: %(output)s") %
                         {'output': output})
            except Exception as ex:
                raise Exception("Failed to add static routes: %(ex)s" % {
                                'ex': str(ex)})
        for command in default_route_commands:
            try:
                out = subprocess.Popen(command, shell=True,
                                       stdout=subprocess.PIPE).stdout.read()
                LOG.info(_LI("Static route configuration result: %(output)s") %
                         {'output': out})
            except Exception as ex:
                raise Exception("Failed to add static routes: %(ex)s" % {
                                'ex': str(ex)})

    def _get_if_name_by_cidr(self, cidr):
        interfaces = netifaces.interfaces()
        retry_count = 0
        while True:
            all_interfaces_have_ip = True
            for interface in interfaces:
                inet_list = netifaces.ifaddresses(interface).get(
                    netifaces.AF_INET)
                if not inet_list:
                    all_interfaces_have_ip = False
                for inet_info in inet_list or []:
                    netmask = inet_info.get('netmask')
                    ip_address = inet_info.get('addr')
                    subnet_prefix = cidr.split("/")
                    if (ip_address == subnet_prefix[0] and (
                         len(subnet_prefix) == 1 or subnet_prefix[1] == "32")):
                        return interface
                    ip_address_netmask = '%s/%s' % (ip_address, netmask)
                    interface_cidr = netaddr.IPNetwork(ip_address_netmask)
                    if str(interface_cidr.cidr) == cidr:
                        return interface
            # Sometimes the hotplugged interface takes time to get IP
            if not all_interfaces_have_ip:
                if retry_count < 10:
                    time.sleep(3)
                    retry_count = retry_count + 1
                    continue
                else:
                    raise Exception("Some of the interfaces do not have "
                                    "IP Address")

    def _apply_user_config(self, config_data):
        LOG.info(_LI("Applying user config with configuration "
                 "type : %(config_type)s and "
                 "configuration data : %(config_data)s ") %
                 {'config_type': config_data['resource'],
                  'config_data': config_data['resource_data']})
        service_config = config_data['resource_data'][
                                     'config_string']
        service_config = str(service_config)
        if config_data['resource'] == 'ansible':
            config_str = service_config.lstrip('ansible:')
            rules = config_str
        elif config_data['resource'] == 'heat':
            config_str = service_config.lstrip('heat_config:')
            rules = self._get_rules_from_config(config_str)
        elif config_data['resource'] == 'custom_json':
            config_str = service_config.lstrip('custom_json:')
            rules = config_str

        fw_rule_file = FW_SCRIPT_PATH
        command = ("sudo python " + fw_rule_file + " '" +
                   rules + "'")
        subprocess.check_output(command, stderr=subprocess.STDOUT,
                                shell=True)

    def _get_rules_from_config(self, config_str):
        rules_list = []
        try:
            stack_template = (jsonutils.loads(config_str) if
                              config_str.startswith('{') else
                              yaml.load(config_str))
        except Exception:
            return config_str

        resources = stack_template['resources']
        for resource in resources:
            if resources[resource]['type'] == 'OS::Neutron::FirewallRule':
                rule_info = {}
                destination_port = ''
                rule = resources[resource]['properties']
                protocol = rule['protocol']
                rule_info['action'] = 'log'
                rule_info['name'] = protocol
                if rule.get('destination_port'):
                    destination_port = rule['destination_port']
                if protocol == 'tcp':
                    rule_info['service'] = (protocol + '/' +
                                            str(destination_port))
                else:
                    rule_info['service'] = protocol
                rules_list.append(rule_info)

        return jsonutils.dumps({'rules': rules_list})
