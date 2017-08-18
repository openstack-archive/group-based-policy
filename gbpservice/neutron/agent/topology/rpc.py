# Copyright (c) 2017 Cisco Systems Inc.
# All Rights Reserved.
#
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

import oslo_messaging

from neutron.common import rpc

TOPIC_APIC_SERVICE = 'apic-service'


class ApicTopologyServiceNotifierApi(object):

    def __init__(self):
        target = oslo_messaging.Target(topic=TOPIC_APIC_SERVICE, version='1.2')
        self.client = rpc.get_client(target)

    def update_link(self, context, host, interface, mac, switch, module, port,
                    port_description=''):
        cctxt = self.client.prepare(version='1.2', fanout=True)
        cctxt.cast(context, 'update_link', host=host, interface=interface,
                   mac=mac, switch=switch, module=module, port=port,
                   port_description=port_description)

    def delete_link(self, context, host, interface):
        cctxt = self.client.prepare(version='1.2', fanout=True)
        cctxt.cast(context, 'delete_link', host=host, interface=interface,
                   mac=None, switch=0, module=0, port=0)
