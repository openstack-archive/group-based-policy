# Copyright 2015, Instituto de Telecomunicacoes - Polo de Aveiro - ATNoG.
# All rights reserved.
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


from neutron.common import log

from gbpservice.neutron.services.trafficsteering \
    import steering_driver_api as api


class NoopDriver(api.SteeringDriver):

    @log.log
    def initialize(self):
        pass

    @log.log
    def create_port_chain_precommit(self, context):
        pass

    @log.log
    def create_port_chain_postcommit(self, context):
        pass

    @log.log
    def update_port_chain_precommit(self, context):
        pass

    @log.log
    def update_port_chain_postcommit(self, context):
        pass

    @log.log
    def delete_port_chain_precommit(self, context):
        pass

    @log.log
    def delete_port_chain_postcommit(self, context):
        pass