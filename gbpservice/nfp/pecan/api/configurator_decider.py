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

import pecan

from gbpservice.nfp.pecan import constants


class DecideConfigurator(pecan.commands.serve.ServeCommand):
    ''' decides the type of configurtor to be used
        like base_configurator or reference_configurator
    '''
    arguments = pecan.commands.serve.ServeCommand.arguments + ({
        'name': '--mode',
        'help': 'decides the type of configurtor to be used',
        'choices': constants.modes,
    },)

    def run(self, args):
        setattr(pecan, 'mode', args.mode)
        super(DecideConfigurator, self).run(args)
