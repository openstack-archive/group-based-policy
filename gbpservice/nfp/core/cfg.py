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

CONF = oslo_config.CONF

NFP_OPTS = [
    oslo_config.IntOpt(
        'workers',
        default=1,
        help='Number of event worker process to be created.'
    ),
    oslo_config.ListOpt(
        'nfp_modules_path',
        default='gbpservice.nfp.core.test',
        help='Path for NFP modules.'
        'All modules from this path are autoloaded by framework'
    ),
    oslo_config.StrOpt(
        'backend',
        default='rpc',
        help='Backend Support for communicationg with configurator.'
    )
]

EXTRA_OPTS = [
    oslo_config.StrOpt(
        'logger_class',
        default='gbpservice.nfp.core.log.WrappedLogger',
        help='logger class path to handle logging seperately.'
    ),
]


def init(module, args, **kwargs):
    """Initialize the configuration. """
    oslo_config.CONF.register_opts(EXTRA_OPTS)
    oslo_config.CONF.register_opts(NFP_OPTS, module)
    oslo_config.CONF(args=args, project='nfp',
                     version='%%(prog)s %s' % ('version'),
                     **kwargs)

    return oslo_config.CONF
