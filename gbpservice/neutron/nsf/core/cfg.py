from oslo.config import cfg

SERVER='rpc'

OPTS = [
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Seconds between periodic task runs')
    ),
    cfg.StrOpt(
        'oc_es_user',
        default='adminii',
        help=_('Seconds between periodic task runs')
    ),
    cfg.StrOpt(
        'oc_es_password',
        default='default',
        help=_('Seconds between periodic task runs'),
        secret="True"
    ),
    cfg.StrOpt(
        'oc_es_tenant',
        default='admin',
        help=_('Seconds between periodic task runs')
    ),
    cfg.StrOpt(
        'ext_network',
        default='',
        help=_('Seconds between periodic task runs')
    ),
    cfg.IntOpt(
        'workers',
        default=1,
        help=_('#of workers to create.')
    ),
    cfg.StrOpt(
        'RpcLoadBalancer',
        default='RoundRobin',
        choices=['RoundRobin', 'StickyRoundRobin'],
        help=_('Check sc/core/lb.py for supported rpc lb algos')
    ),
    cfg.StrOpt(
        'modules_dir',
        default='gbpservice.neutron.nsf.modules',
        help=_('Modules path to import ')
    )
]
