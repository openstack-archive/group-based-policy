from oslo_config import cfg

OPTS = [
    cfg.IntOpt(
        'workers',
        default=1,
        help=_('Number of event worker process to be created.')
    ),
    cfg.StrOpt(
        'rpc_loadbalancer',
        default='StickyRoundRobin',
        choices=['RoundRobin', 'StickyRoundRobin'],
        help=_('Select one of the available loadbalancers for'
               'rpc loadbalancing, Check sc / core / lb.py'
               'for supported rpc lb algos')
    ),
    cfg.StrOpt(
        'modules_dir',
        default='gbpservice.nfp.core.test',
        help=_('Path for NFP modules.'
               'All modules from this path are autloaded by framework')
    ),
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Interval for event polling task in seconds.'
               'Polling task wakesup with this interval and'
               'checks for timedout events.')
    ),
    cfg.IntOpt(
        'reportstate_interval',
        default=10,
        help=_('Interval for report state task in seconds.'
               'Reporting task will report neutron agents state'
               'to the plugins at this interval')
    )
]
