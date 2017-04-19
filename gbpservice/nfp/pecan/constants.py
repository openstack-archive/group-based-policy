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


BASE_CONTROLLER = 'base_controller'
REFERENCE_CONTROLLER = 'reference_controller'
ADVANCED_CONTROLLER = 'advanced_controller'

base_with_vm = 'base_with_vm'
base = 'base'
advanced = 'advanced'
modes = [base, base_with_vm, advanced]

controller_mode_map = {
        base: BASE_CONTROLLER,
        base_with_vm: REFERENCE_CONTROLLER,
        advanced: ADVANCED_CONTROLLER
}

controllers = {
    controller_mode_map[base]: 'gbpservice.nfp.base_configurator.controllers',
    controller_mode_map[base_with_vm]: ('gbpservice.contrib'
                           '.nfp_service.reference_configurator.controllers'),
    controller_mode_map[advanced]: ('gbpservice.contrib.nfp.configurator'
                          '.advanced_controller.controller_loader')
}
